/*
 * smbpal-helper -- the only part of SMBPal that runs as root on macOS.
 *
 * Why this exists in C, when everything else is Python. The Homebrew prefix is
 * admin-writable, interpreter symlink and site-packages included, so a root
 * LaunchDaemon running `smbpald` would let any member of `admin` execute code
 * as root with no password. That is the escalation measured in
 * docs/phase-2/macos-helper-spike.md §0. A compiled binary in root-owned
 * storage has no interpreter and no import path, so the escalation is dissolved
 * rather than worked around -- §9, candidate 2.
 *
 * Why it is small, and must stay small. §4 enumerated the privileged surface:
 * six `dscl` calls, four OpenDirectory calls, `chmod +a`, `sharing`, one file
 * write, and this directory. Nothing in it needs SMBPal's config engine, its
 * IPC server or discovery, all of which stay in Python where their tests are.
 *
 * **The thing that asks is not trusted.** `smbpald` is admin-writable code, so
 * a helper that performs whatever it is asked is a root-escalation service with
 * a socket on it. §9 sets three rules, and they are requirements:
 *
 *   1. A fixed vocabulary of verbs. No pass-through exec, no caller-supplied
 *      command, no arguments in job A at all.
 *   2. Arguments validated against what the helper owns, never relayed.
 *   3. Never a shell. execv with a vector this file built itself.
 *
 * Job A is the runtime directory, the socket and one read-only verb. It holds
 * no credential and performs no mutation; `share.list` was chosen first exactly
 * because there is nothing to undo if it is wrong.
 */

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#define RUNTIME_DIR "/var/run/smbpal"
#define HELPER_SOCK RUNTIME_DIR "/helper.sock"
#define SOCKET_GROUP "smbpal"
#define SERVICE_USER "_smbpald"
#define SHARING "/usr/sbin/sharing"
#define DSCL "/usr/bin/dscl"
#define STATE_DIR "/var/db/smbpal"
#define CREATED_FILE STATE_DIR "/created"
#define CONFIG_DIR "/etc/smbpal"
/* **The daemon needs a log directory it owns, and that is not cosmetic.**
 * launchd opens `StandardErrorPath` *as the job's user* before it execs the
 * program, so a non-root job pointed at root-owned `/var/log` fails its own
 * configuration with EX_CONFIG and the program never runs -- with no log,
 * because the log is what could not be created. Measured 11 October 2026 on the
 * first real start.
 *
 * The helper's log deliberately stays outside this directory. It records
 * refused uids, and the unprivileged component must not be able to edit the
 * root component's account of what it refused. */
#define LOG_DIR "/var/log/smbpal"
#define DAEMON_LOG LOG_DIR "/daemon.log"
#define HELPER_LOG "/var/log/" HELPER_LABEL ".log"
#define LAUNCHD_DIR "/Library/LaunchDaemons"
#define HELPER_LABEL "app.smbpal.helper"
#define DAEMON_LABEL "app.smbpal.daemon"
#define HELPER_PLIST LAUNCHD_DIR "/" HELPER_LABEL ".plist"
#define DAEMON_PLIST LAUNCHD_DIR "/" DAEMON_LABEL ".plist"
#define LAUNCHCTL "/bin/launchctl"
#define SELF "/usr/local/libexec/smbpal/smbpal-helper"

/* 450 is the preference and not the value. §9: 450-499 is where Apple puts role
 * accounts -- `sysadminctl -addUser -roleAccount` requires it, measured
 * 11 October 2026 -- which is fifty slots with no registry and any installer
 * free to take one. A collision is not benign: two accounts sharing a uid are
 * indistinguishable for file ownership, so files SMBPal owns would be theirs
 * too. Hence prefer, then scan, then record what it landed on. */
#define ID_PREFERRED 450
#define ID_MIN 450
#define ID_MAX 499

/* A request is one line naming a verb. Bounded, because an unbounded read from
 * a socket is a denial of service with extra steps. */
#define REQUEST_MAX 64
/* `sharing -l -f json` on a machine with a plausible number of shares. The read
 * loop stops at the limit rather than growing, so a surprising amount of output
 * truncates instead of becoming an allocation this file has to reason about. */
#define OUTPUT_MAX (256 * 1024)

static uid_t expected_peer = (uid_t)-1;

static void fail(const char *what) {
    fprintf(stderr, "smbpal-helper: %s: %s\n", what, strerror(errno));
    exit(1);
}

/* The runtime directory, which the daemon cannot create for itself because on
 * macOS it does not run as root (§9). `/var/run` is root:daemon and `/run`
 * cannot exist at all -- the Signed System Volume, §6.20.
 *
 * **Owned by the service account, not by root, and that was a bug the first
 * time.** §9 specified `root:smbpal 0750` by copying Linux, where the daemon is
 * root and the write bit on this directory is irrelevant. On macOS the daemon
 * binds its socket here as the service account, and **creating a file needs
 * write on the directory** -- group `smbpal` has `r-x`. So the daemon failed
 * with `cannot bind /var/run/smbpal/smbpald.sock: [Errno 13] Permission
 * denied`, measured 11 October 2026.
 *
 * `0750` with the service account as owner is the narrowest thing that works:
 * the daemon writes its socket, members of `smbpal` traverse to reach it, and
 * nobody else gets in. `0770 root:smbpal` would also have worked and would have
 * let every human in the group delete the socket. */
static void ensure_runtime_dir(uid_t uid, gid_t gid) {
    if (mkdir(RUNTIME_DIR, 0750) != 0 && errno != EEXIST) fail("mkdir " RUNTIME_DIR);
    if (chown(RUNTIME_DIR, uid, gid) != 0) fail("chown " RUNTIME_DIR);
    /* After chown, because chown clears set-id bits and we want the mode we
     * asked for rather than the mode mkdir was allowed by the umask. */
    if (chmod(RUNTIME_DIR, 0750) != 0) fail("chmod " RUNTIME_DIR);
}

/* Owned by the service account with mode 0600, which admits that uid and root
 * and nobody else. **Deliberately not group-guarded**: `smbpal` answers "may
 * this person ask the daemon to do things" and must never answer "may this
 * person ask root to do things". §9 had this wrong in its first draft. */
static int listen_on_socket(void) {
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) fail("socket");

    if (unlink(HELPER_SOCK) != 0 && errno != ENOENT) fail("unlink " HELPER_SOCK);

    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    if (strlen(HELPER_SOCK) >= sizeof addr.sun_path) {
        fprintf(stderr, "smbpal-helper: socket path too long\n");
        exit(1);
    }
    strncpy(addr.sun_path, HELPER_SOCK, sizeof addr.sun_path - 1);

    /* Bind under a tight umask so the socket is never briefly world-reachable
     * between bind and chmod. */
    mode_t saved = umask(0177);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) fail("bind " HELPER_SOCK);
    umask(saved);

    if (chown(HELPER_SOCK, expected_peer, 0) != 0) fail("chown " HELPER_SOCK);
    if (chmod(HELPER_SOCK, 0600) != 0) fail("chmod " HELPER_SOCK);
    if (listen(fd, 8) != 0) fail("listen");
    return fd;
}

/* Rule 3: execv with a vector built here, and a pipe rather than popen, because
 * popen is a shell. */
static int run_captured(char *const argv[], char *out, size_t cap, size_t *len) {
    int pipefd[2];
    pid_t pid;
    int status = -1;
    *len = 0;

    if (pipe(pipefd) != 0) return -1;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
        /* stderr to the journal, not to the caller: the daemon gets a result or
         * an error of our choosing, never a tool's prose. §4 is the reason --
         * `sysadminctl` reports failure in at least two formats, one of them
         * indistinguishable from chatter. */
        execv(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    for (;;) {
        ssize_t n = read(pipefd[0], out + *len, cap - *len);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        *len += (size_t)n;
        if (*len >= cap) break;
    }
    close(pipefd[0]);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) continue;
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

/* Like `run_captured` but for writes, where the output is noise and the effect
 * is the result. **The exit status is checked and then not believed**: §4 found
 * `sysadminctl` exits 0 while printing failure in at least two formats, one of
 * them indistinguishable from chatter, and the only reliable check turned out
 * to be reading the state back. `dscl` has not been caught doing it, which is
 * not the same as being known not to. */
static int run_quiet(char *const argv[]) {
    pid_t pid = fork();
    int status = -1;
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            close(devnull);
        }
        execv(argv[0], argv);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) continue;
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static int dscl_set(const char *path, const char *key, const char *value) {
    char *const argv[] = {(char *)DSCL, ".", "-create", (char *)path,
                          (char *)key, (char *)value, NULL};
    return run_quiet(argv);
}

/* Prefer `ID_PREFERRED`, else the first free slot in the range. Both namespaces
 * are checked for both kinds, because a uid and a gid that differ for the same
 * component is a thing nobody wants to debug at two in the morning. */
static int find_free_id(void) {
    for (int candidate = ID_PREFERRED; candidate <= ID_MAX; candidate++) {
        if (getpwuid((uid_t)candidate) == NULL && getgrgid((gid_t)candidate) == NULL)
            return candidate;
    }
    for (int candidate = ID_MIN; candidate < ID_PREFERRED; candidate++) {
        if (getpwuid((uid_t)candidate) == NULL && getgrgid((gid_t)candidate) == NULL)
            return candidate;
    }
    return -1;
}

static void note_created(const char *kind, const char *name, int id) {
    FILE *fh;
    if (mkdir(STATE_DIR, 0755) != 0 && errno != EEXIST) fail("mkdir " STATE_DIR);
    /* §10.6 removes what SMBPal created and nothing else. An account that was
     * already there when we arrived is somebody else's, and the only way to
     * know the difference later is to have written it down now. The numbers go
     * in beside the names because §9 asks for them; operation resolves by name,
     * which cannot go stale the way a cached number can. */
    if ((fh = fopen(CREATED_FILE, "a")) == NULL) fail("open " CREATED_FILE);
    fprintf(fh, "%s %s %d\n", kind, name, id);
    fclose(fh);
    chmod(CREATED_FILE, 0644);
}

/* The plists are written here rather than substituted from a shipped template,
 * so there is one source of truth for what launchd is told. A `.in` file and
 * this function would be two, and the one that drifts is always the one nobody
 * runs. */
static int write_plist(const char *path, const char *label, const char *const args[],
                       const char *user, const char *stderr_path) {
    FILE *fh = fopen(path, "w");
    if (fh == NULL) return -1;
    fprintf(fh, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
                "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                "<!-- Written by smbpal-helper install. Do not edit. -->\n"
                "<plist version=\"1.0\">\n<dict>\n"
                "  <key>Label</key><string>%s</string>\n", label);
    if (user != NULL)
        fprintf(fh, "  <key>UserName</key><string>%s</string>\n", user);
    fprintf(fh, "  <key>ProgramArguments</key>\n  <array>\n");
    for (int i = 0; args[i] != NULL; i++)
        fprintf(fh, "    <string>%s</string>\n", args[i]);
    /* No KeepAlive. A component that respawns after refusing something hides
     * the refusal, and launchd's own log is the record. */
    fprintf(fh, "  </array>\n"
                "  <key>RunAtLoad</key><true/>\n"
                "  <key>StandardErrorPath</key><string>%s</string>\n"
                "</dict>\n</plist>\n", stderr_path);
    if (fclose(fh) != 0) return -1;
    if (chown(path, 0, 0) != 0) return -1;
    return chmod(path, 0644);
}

static int bootstrap(const char *path) {
    char *const argv[] = {(char *)LAUNCHCTL, "bootstrap", "system", (char *)path, NULL};
    return run_quiet(argv);
}

static int bootout(const char *label) {
    char target[128];
    snprintf(target, sizeof target, "system/%s", label);
    char *const argv[] = {(char *)LAUNCHCTL, "bootout", target, NULL};
    return run_quiet(argv);
}

static int install(int dry_run, const char *daemon_path) {
    struct group *gr = getgrnam(SOCKET_GROUP);
    struct passwd *pw = getpwnam(SERVICE_USER);
    int id = -1;
    char number[16];

    if (gr != NULL && pw != NULL && !dry_run) {
        /* **Refuse rather than repair.** A second install would have to decide
         * whether to re-bootstrap, re-chown and rewrite plists it may not have
         * written, against identities it may not have created -- and the state
         * file is the only record of which. Removing and installing is two
         * commands that each do one knowable thing. */
        fprintf(stderr,
                "smbpal-helper: already installed (%s uid=%u, %s gid=%u)\n"
                "  to change it: sudo %s uninstall, then install again\n",
                SERVICE_USER, (unsigned)pw->pw_uid, SOCKET_GROUP,
                (unsigned)gr->gr_gid, SELF);
        return 1;
    }

    if (gr == NULL || pw == NULL) {
        id = find_free_id();
        if (id < 0) {
            fprintf(stderr, "smbpal-helper: no free id in %d-%d\n", ID_MIN, ID_MAX);
            return 1;
        }
    }
    snprintf(number, sizeof number, "%d", id);

    if (dry_run) {
        /* Needs no root, so it is the one thing a person can run to see what
         * the install would choose before being asked for a password. */
        if (gr == NULL) printf("would create group %s gid=%d\n", SOCKET_GROUP, id);
        else printf("group %s exists, gid=%u\n", SOCKET_GROUP, (unsigned)gr->gr_gid);
        if (pw == NULL) printf("would create user %s uid=%d\n", SERVICE_USER, id);
        else printf("user %s exists, uid=%u\n", SERVICE_USER, (unsigned)pw->pw_uid);
        return 0;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "smbpal-helper: install must run as root\n");
        return 1;
    }

    if (gr == NULL) {
        if (dscl_set("/Groups/" SOCKET_GROUP, "PrimaryGroupID", number) != 0 ||
            dscl_set("/Groups/" SOCKET_GROUP, "RealName", "SMBPal") != 0 ||
            dscl_set("/Groups/" SOCKET_GROUP, "Password", "*") != 0) {
            fprintf(stderr, "smbpal-helper: could not create group " SOCKET_GROUP "\n");
            return 1;
        }
        /* Read it back. §4's rule: verify the effect, do not parse the tool. */
        if ((gr = getgrnam(SOCKET_GROUP)) == NULL) {
            fprintf(stderr, "smbpal-helper: group " SOCKET_GROUP
                            " did not appear after creating it\n");
            return 1;
        }
        note_created("group", SOCKET_GROUP, (int)gr->gr_gid);
        printf("created group %s gid=%u\n", SOCKET_GROUP, (unsigned)gr->gr_gid);
    }

    if (pw == NULL) {
        char gidnum[16];
        snprintf(gidnum, sizeof gidnum, "%u", (unsigned)gr->gr_gid);
        /* **`Password "*"` is the point of this account, not a detail.** It is a
         * process identity: it runs `smbpald` and must never authenticate to
         * anything. Job B's SMB account is a different account for exactly that
         * reason -- it carries `SMB-NT` and a real password, and merging the two
         * would turn the identity the daemon runs as into a login credential. */
        if (dscl_set("/Users/" SERVICE_USER, "UniqueID", number) != 0 ||
            dscl_set("/Users/" SERVICE_USER, "PrimaryGroupID", gidnum) != 0 ||
            dscl_set("/Users/" SERVICE_USER, "RealName", "SMBPal daemon") != 0 ||
            dscl_set("/Users/" SERVICE_USER, "NFSHomeDirectory", "/var/empty") != 0 ||
            dscl_set("/Users/" SERVICE_USER, "UserShell", "/usr/bin/false") != 0 ||
            dscl_set("/Users/" SERVICE_USER, "IsHidden", "1") != 0 ||
            dscl_set("/Users/" SERVICE_USER, "Password", "*") != 0) {
            fprintf(stderr, "smbpal-helper: could not create user " SERVICE_USER "\n");
            return 1;
        }
        if ((pw = getpwnam(SERVICE_USER)) == NULL) {
            fprintf(stderr, "smbpal-helper: user " SERVICE_USER
                            " did not appear after creating it\n");
            return 1;
        }
        note_created("user", SERVICE_USER, (int)pw->pw_uid);
        printf("created user %s uid=%u\n", SERVICE_USER, (unsigned)pw->pw_uid);
    }

    /* Membership, so the service account can traverse the 0750 runtime
     * directory it binds in. §4 measured that the guard transfers with no
     * re-login, because macOS resolves membership through `membershipd`. */
    {
        char *const argv[] = {(char *)DSCL, ".", "-append",
                              (char *)"/Groups/" SOCKET_GROUP,
                              (char *)"GroupMembership", (char *)SERVICE_USER, NULL};
        run_quiet(argv);
    }
    /* The config tree, owned by the account that writes it. §9: on macOS the
     * daemon is not root, so root-owned config would be unwritable -- and what
     * contains an admin rewriting it is the helper validating intents, not the
     * mode on this directory. */
    if (mkdir(CONFIG_DIR, 0750) != 0 && errno != EEXIST) fail("mkdir " CONFIG_DIR);
    if (chown(CONFIG_DIR, pw->pw_uid, gr->gr_gid) != 0) fail("chown " CONFIG_DIR);
    if (chmod(CONFIG_DIR, 0750) != 0) fail("chmod " CONFIG_DIR);

    /* Created here as well as in `serve`, because launchd gives no ordering
     * between two jobs and the daemon cannot make this directory itself. If the
     * daemon won the race it would fail to bind and, having no KeepAlive, stay
     * down. **This closes the install-time race and not the boot-time one**:
     * whether `/var/run` survives a reboot on macOS has not been measured, and
     * if it does not then the ordering question is real and open. */
    ensure_runtime_dir(pw->pw_uid, gr->gr_gid);

    /* Before the plists, because launchd will try to open the file the moment
     * the job is bootstrapped. */
    if (mkdir(LOG_DIR, 0750) != 0 && errno != EEXIST) fail("mkdir " LOG_DIR);
    if (chown(LOG_DIR, pw->pw_uid, gr->gr_gid) != 0) fail("chown " LOG_DIR);
    if (chmod(LOG_DIR, 0750) != 0) fail("chmod " LOG_DIR);

    {
        const char *helper_args[] = {SELF, "serve", "--service-user", SERVICE_USER, NULL};
        /* **The daemon's plist may point into the Homebrew prefix and the
         * helper's may not**, and the asymmetry is the whole architecture: §0
         * forbids *root* executing admin-writable code, and the daemon does not
         * run as root. So this path is checked for being absolute and
         * executable and is deliberately not checked for being admin-writable,
         * because it will be. */
        const char *daemon_args[] = {daemon_path, "--socket",
                                     RUNTIME_DIR "/smbpald.sock", NULL};
        if (write_plist(HELPER_PLIST, HELPER_LABEL, helper_args, NULL, HELPER_LOG) != 0)
            fail("write " HELPER_PLIST);
        if (write_plist(DAEMON_PLIST, DAEMON_LABEL, daemon_args, SERVICE_USER,
                        DAEMON_LOG) != 0)
            fail("write " DAEMON_PLIST);
        if (bootstrap(HELPER_PLIST) != 0)
            fprintf(stderr, "smbpal-helper: warning: bootstrap of " HELPER_LABEL
                            " did not succeed; see launchctl error\n");
        if (bootstrap(DAEMON_PLIST) != 0)
            fprintf(stderr, "smbpal-helper: warning: bootstrap of " DAEMON_LABEL
                            " did not succeed; see launchctl error\n");
    }

    /* The uid is named because the scan may not have landed on the preference,
     * and a service account quietly sitting on 467 is a surprise somebody finds
     * out about while debugging something else. */
    printf("installed\n"
           "  user   %s  uid %u\n"
           "  group  %s  gid %u\n"
           "  helper %s\n"
           "  daemon %s\n"
           "  logs   %s and %s\n",
           SERVICE_USER, (unsigned)pw->pw_uid, SOCKET_GROUP,
           (unsigned)gr->gr_gid, HELPER_PLIST, DAEMON_PLIST, HELPER_LOG, DAEMON_LOG);
    return 0;
}

/* Removes what the install recorded and nothing else -- §10.6. The order is
 * §4's, learned on 11 October 2026: an ACE outlives the account it names and
 * orphans to a raw UUID, and ownership does the same, so files go before the
 * account and the account before the group. */
static int uninstall(void) {
    FILE *fh;
    char kind[32], name[128];
    int id;
    int removed = 0;

    if (geteuid() != 0) {
        fprintf(stderr, "smbpal-helper: uninstall must run as root\n");
        return 1;
    }

    bootout(DAEMON_LABEL);
    bootout(HELPER_LABEL);
    unlink(DAEMON_PLIST);
    unlink(HELPER_PLIST);
    unlink(HELPER_SOCK);
    unlink(RUNTIME_DIR "/smbpald.sock");
    rmdir(RUNTIME_DIR);
    /* The logs go, because SMBPal made them and §10.6 says it leaves nothing.
     * Said out loud, so anybody uninstalling after a problem knows to copy the
     * log first rather than discovering it afterwards. */
    unlink(DAEMON_LOG);
    rmdir(LOG_DIR);
    printf("removed " LOG_DIR " and its log; " HELPER_LOG " is left for launchd\n");

    if ((fh = fopen(CREATED_FILE, "r")) == NULL) {
        printf("nothing recorded as created; left the identities alone\n");
        return 0;
    }
    /* Users before groups regardless of the order they were written, because a
     * group with a member still in it is a group that does not go away. */
    for (int pass = 0; pass < 2; pass++) {
        rewind(fh);
        while (fscanf(fh, "%31s %127s %d", kind, name, &id) == 3) {
            int want_user = (pass == 0);
            if ((strcmp(kind, "user") == 0) != want_user) continue;
            char path[160];
            snprintf(path, sizeof path, "/%s/%s",
                     want_user ? "Users" : "Groups", name);
            char *const argv[] = {(char *)DSCL, ".", "-delete", path, NULL};
            run_quiet(argv);
            /* §4 says verify the effect rather than the exit code. **Verify it
             * through the interface that wrote it**, which this did not do the
             * first time: `getgrnam` answers from opendirectoryd's cache, and
             * on 11 October 2026 it still reported the group one instruction
             * after `dscl` had deleted it -- so uninstall said
             * `COULD NOT REMOVE group smbpal` about a group that was gone, and
             * the install a moment later created it afresh. `dscl -read` asks
             * the node the write went to. */
            char *const check[] = {(char *)DSCL, ".", "-read", path, "RecordName", NULL};
            int gone = run_quiet(check) != 0;
            printf("%s %s %s\n", gone ? "removed" : "COULD NOT REMOVE", kind, name);
            if (gone) removed++;
        }
    }
    fclose(fh);
    unlink(CREATED_FILE);
    rmdir(STATE_DIR);
    printf("removed %d recorded %s\n", removed, removed == 1 ? "identity" : "identities");
    printf("left alone: " CONFIG_DIR " and anything under it\n");
    return 0;
}

/* Rule 1: the whole vocabulary, and it is one verb. Anything else is refused
 * without being echoed back -- a helper that repeats what it was asked is a
 * helper that can be used to probe it. */
static void serve_one(int conn) {
    char request[REQUEST_MAX + 1];
    ssize_t n = read(conn, request, REQUEST_MAX);
    uid_t uid;
    gid_t gid;

    if (getpeereid(conn, &uid, &gid) != 0) {
        /* `ipc/peer.py` documents this as the macOS-correct call: uid and gid
         * and no pid, which is why `daemon/polkit.py` records that no subject
         * can be identified to polkit here. Defence in depth behind the 0600,
         * not instead of it. */
        write(conn, "ERR peer\n", 9);
        return;
    }
    if (uid != expected_peer) {
        fprintf(stderr, "smbpal-helper: refused uid %u\n", (unsigned)uid);
        write(conn, "ERR refused\n", 12);
        return;
    }
    if (n <= 0) return;
    request[n] = '\0';
    char *nl = strchr(request, '\n');
    if (nl) *nl = '\0';

    if (strcmp(request, "share.list") == 0) {
        static char out[OUTPUT_MAX];
        size_t len = 0;
        char *const argv[] = {(char *)SHARING, "-l", "-f", "json", NULL};
        int rc = run_captured(argv, out, sizeof out, &len);
        if (rc != 0) {
            write(conn, "ERR sharing\n", 12);
            return;
        }
        /* The response is the payload and then a half-close, so the caller
         * reads to EOF. Job B needs real framing for arguments and errors; one
         * verb with no arguments does not, and inventing a protocol before
         * there is a second verb would be guessing at its shape. */
        size_t off = 0;
        while (off < len) {
            ssize_t w = write(conn, out + off, len - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
    } else {
        write(conn, "ERR verb\n", 9);
    }
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage: %s install --daemon <path to smbpald> [--dry-run]\n"
            "       %s uninstall\n"
            "       %s serve --service-user <name> [--check]\n",
            program, program, program);
}

int main(int argc, char **argv) {
    const char *service = NULL;
    struct passwd *pw;
    struct group *gr;
    int check_only = 0;
    int dry_run = 0;
    int listener;

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "install") == 0) {
        const char *daemon_path = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--dry-run") == 0) {
                dry_run = 1;
            } else if (strcmp(argv[i], "--daemon") == 0 && i + 1 < argc) {
                daemon_path = argv[++i];
            } else {
                usage(argv[0]);
                return 2;
            }
        }
        if (!dry_run) {
            /* The path comes from the caller because the Homebrew prefix is not
             * one place: /opt/homebrew on Apple silicon, /usr/local on Intel.
             * `smbpal setup` knows its own and prints it, which is why that is
             * the documented front door. */
            if (daemon_path == NULL) {
                fprintf(stderr, "smbpal-helper: --daemon <path to smbpald> is required\n");
                return 2;
            }
            if (daemon_path[0] != '/') {
                fprintf(stderr, "smbpal-helper: --daemon must be an absolute path\n");
                return 2;
            }
            if (access(daemon_path, X_OK) != 0) {
                fprintf(stderr, "smbpal-helper: --daemon %s is not executable\n",
                        daemon_path);
                return 2;
            }
        }
        return install(dry_run, daemon_path);
    }
    if (strcmp(argv[1], "uninstall") == 0) {
        if (argc != 2) {
            usage(argv[0]);
            return 2;
        }
        return uninstall();
    }
    if (strcmp(argv[1], "serve") != 0) {
        usage(argv[0]);
        return 2;
    }

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--service-user") == 0 && i + 1 < argc) {
            service = argv[++i];
        } else if (strcmp(argv[i], "--check") == 0) {
            check_only = 1;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (service == NULL) {
        fprintf(stderr, "smbpal-helper: --service-user is required\n");
        return 2;
    }

    /* The identities are resolved by name and never compiled in: §9 records
     * that 450-499 has fifty slots, no registry, and that the install scans and
     * records what it landed on. A number in this file would be the bug that
     * rule exists to prevent. */
    if ((pw = getpwnam(service)) == NULL) {
        fprintf(stderr, "smbpal-helper: no such user '%s'\n", service);
        return 1;
    }
    if ((gr = getgrnam(SOCKET_GROUP)) == NULL) {
        fprintf(stderr, "smbpal-helper: no group '%s'\n", SOCKET_GROUP);
        return 1;
    }
    expected_peer = pw->pw_uid;

    /* `--check` reads `passwd` and `group` and touches nothing, so it does not
     * need root. Requiring it would make the one diagnostic a person can run
     * while working out why the helper will not start the thing they have to
     * elevate to try. */
    if (check_only) {
        printf("service=%s uid=%u group=%s gid=%u\n", service,
               (unsigned)pw->pw_uid, SOCKET_GROUP, (unsigned)gr->gr_gid);
        return 0;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "smbpal-helper: must run as root\n");
        return 1;
    }

    ensure_runtime_dir(pw->pw_uid, gr->gr_gid);
    listener = listen_on_socket();
    fprintf(stderr, "smbpal-helper: listening on %s for uid %u\n", HELPER_SOCK,
            (unsigned)expected_peer);

    for (;;) {
        int conn = accept(listener, NULL, NULL);
        if (conn < 0) {
            if (errno == EINTR) continue;
            fail("accept");
        }
        serve_one(conn);
        shutdown(conn, SHUT_WR);
        close(conn);
    }
}
