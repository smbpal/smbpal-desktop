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
 * cannot exist at all -- the Signed System Volume, §6.20. */
static void ensure_runtime_dir(gid_t gid) {
    if (mkdir(RUNTIME_DIR, 0750) != 0 && errno != EEXIST) fail("mkdir " RUNTIME_DIR);
    if (chown(RUNTIME_DIR, 0, gid) != 0) fail("chown " RUNTIME_DIR);
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

static int install(int dry_run) {
    struct group *gr = getgrnam(SOCKET_GROUP);
    struct passwd *pw = getpwnam(SERVICE_USER);
    int id = -1;
    char number[16];

    if (gr != NULL && pw != NULL) {
        printf("already installed: %s uid=%u, %s gid=%u\n", SERVICE_USER,
               (unsigned)pw->pw_uid, SOCKET_GROUP, (unsigned)gr->gr_gid);
        return 0;
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
    printf("installed: %s uid=%u in %s gid=%u\n", SERVICE_USER,
           (unsigned)pw->pw_uid, SOCKET_GROUP, (unsigned)gr->gr_gid);
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
            "usage: %s install [--dry-run]\n"
            "       %s serve --service-user <name> [--check]\n",
            program, program);
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
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--dry-run") == 0) {
                dry_run = 1;
            } else {
                usage(argv[0]);
                return 2;
            }
        }
        return install(dry_run);
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

    ensure_runtime_dir(gr->gr_gid);
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
