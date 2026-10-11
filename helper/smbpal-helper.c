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

#include <Security/Authorization.h>
#include <Security/AuthorizationDB.h>
#include <CoreFoundation/CoreFoundation.h>

#include <errno.h>
#include <grp.h>
#include <signal.h>
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

/* A request is a short sequence of lines ending in `END`. Bounded, because an
 * unbounded read from a socket is a denial of service with extra steps: 1 KiB
 * holds a verb, a 64-character form and four arguments with room to spare, and
 * anything larger is not a request this vocabulary can express. */
#define REQUEST_MAX 1024
/* Four is what the longest planned verb needs (a path, a name and two flags)
 * and is a limit rather than a target. */
#define ARGS_MAX 4
/* Not `ARG_MAX`: that is `sys/syslimits.h`'s, and -Werror caught the shadowing.
 * The prefix is the fix and also the honest name -- this bounds one argument of
 * ours, not the system's exec limit. */
#define REQUEST_ARG_MAX 256
/* Nothing at the far end waits for a person -- §11 measured that the helper
 * cannot prompt even if it wanted to -- so a peer that has not finished a
 * request in this long is not thinking about it. Comfortably longer than
 * `system/helper.py`'s own timeout, so the client gives up first and the
 * helper's limit is the backstop rather than the thing normally hit. */
#define PEER_TIMEOUT_SECONDS 30
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
    /* **No KeepAlive, for either job.** A component that respawns after
     * refusing something hides the refusal, and launchd's own log is the
     * record.
     *
     * `SuccessfulExit false` on the daemon was tried and taken back out, and
     * the reason is worth keeping: launchd cannot tell *why* a job exited
     * non-zero. The daemon returns 2 on an invalid config and means it --
     * "starting with an empty config looks exactly like all your shares are
     * gone, and the next save would make that true" -- so retrying turned a
     * deliberate refusal into a flapping service writing the same three lines
     * into an unrotated log every ten seconds for ever.
     *
     * The boot race it was there for is closed where it actually happens
     * instead: `ipc/server.py` waits a bounded time for the runtime directory,
     * which is the one condition that is genuinely transient. */
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

/* ---------------------------------------------------------------------------
 * Authorization Services: the rights, their rules, and the verify.
 *
 * §10 chose this over polkit because polkit cannot work here at all --
 * `getpeereid` gives no pid, so no subject exists to look up -- and
 * Authorization Services passes the grant instead of an identity.
 *
 * **The verify lives in this file and not in the daemon.** §9 established that
 * `smbpald` is admin-writable code, so a helper that trusted the daemon's
 * verdict would be a root-escalation service with a socket on it: an admin who
 * replaced the daemon could simply not verify. Here it survives a replaced
 * daemon, because a forged external form either fails to import or imports to a
 * reference holding no rights.
 *
 * The rules are written here rather than shipped as a plist for the same reason
 * the launchd plists are, and the rights' names are duplicated in
 * `smbpal/system/authorization.py` by necessity -- one side prompts, one side
 * verifies -- with a test pinning the two together.
 * ------------------------------------------------------------------------- */

/* Pins the 32 in `smbpal/system/authorization.py` to the struct the system
 * actually defines, so the Python constant cannot drift from the C reality. */
_Static_assert(sizeof(AuthorizationExternalForm) == 32,
               "AuthorizationExternalForm is not 32 bytes on this SDK");

struct right_rule {
    const char *name;
    /* Shown in the dialog. macOS renders it as "<app> is trying to <text>", so
     * these are verb phrases and are the `<description>` strings from
     * packaging/polkit/org.smbpal.policy, which is where the wording was
     * argued. §10's second measurement asks whether the prompt is attributed to
     * something a person recognises rather than to `python3.14`; this is the
     * part of that we control. */
    const char *description;
};

/* **Two rights, not the three polkit actions.** `use-connections` is
 * `allow_active yes` on Linux, and the policy file argues why: a configured
 * connection is already reachable without a prompt, so prompting on the button
 * that does the same thing protects nothing. On macOS the mount is the user's
 * own agent acting as themselves (D13), so there is no privilege to ask for
 * either -- and a right in the system database that no component ever checks is
 * dead policy that reads like live policy. */
static const struct right_rule RIGHTS[] = {
    {"app.smbpal.manage-shares", "change the folders this computer shares"},
    {"app.smbpal.manage-connections",
     "change the network shares this computer connects to"},
};
static const size_t RIGHTS_COUNT = sizeof RIGHTS / sizeof RIGHTS[0];

/* Long enough that add / set a password / apply is one authentication rather
 * than three -- the problem `auth_admin_keep` solves on Linux, and the policy
 * file's note on it applies unchanged: three prompts for one intention is how
 * people learn to type their password without reading the box. Short enough
 * that a replayable grant is a five-minute window and not a login session.
 *
 * This number is the security parameter §10 said SMBPal has to choose rather
 * than inherit, because a grant can be replayed for as long as it stays
 * authorised. It happens to equal the `default` rule's 300, measured on this
 * machine -- so the whole value of registering these rights is `shared false`
 * plus a description a person can recognise in the dialog. Worth knowing before
 * anyone concludes the registration is decorative: `shared true` would let a
 * credential obtained elsewhere, for anything, satisfy these rights. */
#define RIGHT_TIMEOUT 300

/* **The rule keys are string literals because this SDK has no macros for
 * them.** `AuthorizationDB.h` defines `kAuthorizationRightRule`,
 * `kAuthorizationRuleClassAllow` and `kAuthorizationRuleClassDeny` and stops
 * there: `kAuthorizationRuleParameterCredentialShared` and
 * `...CredentialTimeout` do not exist here and a build against them fails to
 * parse. Same shape as §4's DirectoryService constant, and the same rule --
 * read the header on the machine, do not trust the memory of a header. */
static CFDictionaryRef rule_for(void) {
    CFMutableDictionaryRef rule = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (rule == NULL) return NULL;
    /* `user` + `group admin` is `auth_admin`, which is what all three polkit
     * actions chose for a non-active session. `authenticate-session-owner`
     * would ask for the person at the machine instead of an administrator, and
     * §10 is right that those are different products: changing what a computer
     * shares with the network is an administrator's decision. */
    CFDictionarySetValue(rule, CFSTR("class"), CFSTR("user"));
    CFDictionarySetValue(rule, CFSTR("group"), CFSTR("admin"));
    /* Explicit, because it is the bit that makes this a prompt at all. */
    CFDictionarySetValue(rule, CFSTR("authenticate-user"), kCFBooleanTrue);
    CFDictionarySetValue(rule, CFSTR("shared"), kCFBooleanFalse);
    /* **`allow-root` is false, and the earlier intent to set it true was
     * wrong.** The reasoning that produced `true` was about the *client*: a
     * `sudo` client is genuinely uid 0, so `allow-root` would make headless
     * macOS mean "mutations need sudo". But the process that calls
     * `AuthorizationCopyRights` here is *this helper*, and it is root. If
     * `allow-root` is honoured for the verifying process, every imported form
     * would verify no matter what it held, and the gate would be off while
     * appearing to be on.
     *
     * **This is the safe default and not a free one, and §11's route is what it
     * costs.** §11 found that a `sudo` client over `ssh` could acquire the
     * right with no prompt and no window server if `allow-root` were true,
     * which turns headless macOS from "cannot mutate" into "mutations need
     * `sudo`". That route needs `true`, and `true` is only safe if an
     * *imported* form ignores `allow-root` -- which nobody has measured. Note
     * that the daemon's own uid-0 shortcut does not substitute for it: this
     * helper sees the daemon's uid on the socket and never the client's, so it
     * cannot exempt root even when root is who is asking.
     *
     * So `false` until that measurement exists (spike §12.3). It can never
     * silently disable the gate; `true` on an unmeasured behaviour can, and
     * would do it while looking correct. If the measurement says imported forms
     * ignore the flag, this becomes `true` and the headless route returns -- one
     * line, once it is knowledge.
     *
     * **Apple agrees.** `security authorizationdb read default` on this machine
     * (11 October 2026) has `allow-root false` on the rule that catches every
     * unregistered right, so this is the system's own choice for the same
     * situation and not a reading of ours against the grain. */
    CFDictionarySetValue(rule, CFSTR("allow-root"), kCFBooleanFalse);
    int timeout = RIGHT_TIMEOUT;
    CFNumberRef seconds = CFNumberCreate(NULL, kCFNumberIntType, &timeout);
    if (seconds != NULL) {
        CFDictionarySetValue(rule, CFSTR("timeout"), seconds);
        CFRelease(seconds);
    }
    return rule;
}

/* §10.6 applies to the authorization database like everything else: the install
 * registers what it needs and the uninstall removes exactly that. */
static int rights_install(void) {
    AuthorizationRef ref = NULL;
    if (AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &ref) !=
        errAuthorizationSuccess) {
        fprintf(stderr, "smbpal-helper: could not open the authorization database\n");
        return -1;
    }
    CFDictionaryRef rule = rule_for();
    if (rule == NULL) {
        AuthorizationFree(ref, kAuthorizationFlagDefaults);
        return -1;
    }
    int failures = 0;
    for (size_t i = 0; i < RIGHTS_COUNT; i++) {
        CFStringRef description = CFStringCreateWithCString(
            NULL, RIGHTS[i].description, kCFStringEncodingUTF8);
        OSStatus st = AuthorizationRightSet(ref, RIGHTS[i].name, rule, description,
                                            NULL, NULL);
        if (description != NULL) CFRelease(description);
        if (st != errAuthorizationSuccess) {
            /* **Named, and the warning does not claim this fails closed,
             * because it does not.** An unregistered right is not an absent
             * right: the database falls back to the `default` rule, and
             * `security authorizationdb read default` on this machine
             * (11 October 2026) is `class user`, `group admin`,
             * `authenticate-user true`, `allow-root false`, `timeout 300` --
             * and `shared true`.
             *
             * So a failed registration still prompts an administrator; what it
             * loses is `shared false`, which is the one field our rule changes.
             * `shared true` means a credential obtained by any other client for
             * anything can satisfy this right with no prompt. That is a real
             * weakening and worth a warning, and it is not the same sentence as
             * "mutations will be refused". */
            fprintf(stderr,
                    "smbpal-helper: could not register %s (OSStatus %d); the "
                    "database's `default` rule applies instead, so the grant "
                    "will be shared with other clients\n",
                    RIGHTS[i].name, (int)st);
            failures++;
        }
    }
    CFRelease(rule);
    AuthorizationFree(ref, kAuthorizationFlagDefaults);
    return failures == 0 ? 0 : -1;
}

static void rights_remove(void) {
    AuthorizationRef ref = NULL;
    if (AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &ref) !=
        errAuthorizationSuccess) {
        fprintf(stderr, "smbpal-helper: COULD NOT REMOVE the rights: "
                        "no handle on the authorization database\n");
        return;
    }
    for (size_t i = 0; i < RIGHTS_COUNT; i++) {
        OSStatus st = AuthorizationRightRemove(ref, RIGHTS[i].name);
        /* `errAuthorizationDenied` is what a right that is not there reports,
         * so it is not an error for a teardown that is meant to be idempotent. */
        if (st != errAuthorizationSuccess && st != errAuthorizationDenied)
            fprintf(stderr, "smbpal-helper: COULD NOT REMOVE right %s (OSStatus %d)\n",
                    RIGHTS[i].name, (int)st);
    }
    AuthorizationFree(ref, kAuthorizationFlagDefaults);
}

static int is_registered_right(const char *right) {
    for (size_t i = 0; i < RIGHTS_COUNT; i++)
        if (strcmp(right, RIGHTS[i].name) == 0) return 1;
    return 0;
}

/* **The one place a grant is evaluated**, shared by the `verify` subcommand and
 * the socket's `auth.check`, so there is no second copy to get subtly wrong.
 * Returns 0 for authorised and non-zero otherwise, and the non-zero values are
 * for the log only: "refused", "malformed" and "expired" are the same answer to
 * the question that was asked, and a caller that could tell them apart would be
 * tempted to treat one of them as a yes. */
static int verify_form(const char *right, const AuthorizationExternalForm *form) {
    AuthorizationRef ref = NULL;
    if (AuthorizationCreateFromExternalForm(form, &ref) != errAuthorizationSuccess) {
        fprintf(stderr, "smbpal-helper: refused %s: the form did not import\n", right);
        return -1;
    }
    AuthorizationItem item = {right, 0, NULL, 0};
    AuthorizationRights rights = {1, &item};
    /* `kAuthorizationFlagExtendRights` and **no**
     * `kAuthorizationFlagInteractionAllowed`: this is a check, not a prompt.
     * The helper has no session to prompt in, §11 measured what happens to
     * anything that tries -- `InteractionNotAllowed`, -60007 -- and §12.2
     * measured that the check itself succeeds there. */
    OSStatus st = AuthorizationCopyRights(ref, &rights, NULL,
                                          kAuthorizationFlagExtendRights, NULL);
    AuthorizationFree(ref, kAuthorizationFlagDefaults);
    if (st == errAuthorizationSuccess) {
        /* A grant leaves a trace for the same reason polkit.py's does: a gate
         * whose successes are silent cannot be told apart from a gate that is
         * not running. */
        fprintf(stderr, "smbpal-helper: allowed %s\n", right);
        return 0;
    }
    fprintf(stderr, "smbpal-helper: refused %s (OSStatus %d)\n", right, (int)st);
    return (int)st;
}

/* Reads an `AuthorizationExternalForm` on stdin and answers whether it carries
 * `right`. Exit 0 is authorised and every other exit is not, because "refused",
 * "malformed" and "expired" are the same answer to the question asked and a
 * caller that could tell them apart would be tempted to treat one as a yes.
 *
 * A subcommand rather than a private function because job B's framed protocol
 * will call this code path, and because it is how §10's first measurement gets
 * taken: does a no-interaction verify work inside a root LaunchDaemon with no
 * session? §8 asked that of `sysadminctl` and the answer was yes, which is not
 * the same as knowing. */
static int verify(const char *right) {
    if (!is_registered_right(right)) {
        fprintf(stderr, "smbpal-helper: %s is not a right this helper registers\n", right);
        return 2;
    }

    AuthorizationExternalForm form;
    size_t got = 0;
    while (got < sizeof form) {
        ssize_t n = read(STDIN_FILENO, ((char *)&form) + got, sizeof form - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    if (got != sizeof form) {
        fprintf(stderr, "smbpal-helper: expected %zu bytes of external form, read %zu\n",
                sizeof form, got);
        return 1;
    }

    return verify_form(right, &form) == 0 ? 0 : 1;
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
     * between two jobs and the daemon cannot make this directory itself: as the
     * service account, `mkdir` under `/var/run` (root:daemon) is EPERM.
     *
     * **The boot-time race is real, measured.** `/var/run` does not survive a
     * reboot on macOS: after one, `/var/run/smbpal` had a birth time of
     * 19:34:32 against a `kern.boottime` of 19:34:26, so it was created six
     * seconds into the boot and not carried over. The helper happened to win by
     * about two seconds, and nothing made it win. So this call closes the
     * install-time race, and the boot-time one is closed in `ipc/server.py`:
     * the daemon waits a bounded time for this directory to appear, because
     * that is the one condition in its startup that is genuinely transient.
     * `KeepAlive` was tried here first and taken out -- launchd cannot tell a
     * lost race from a config the daemon refused to start on, and the daemon
     * means that refusal.
     *
     * Socket activation would remove the race rather than retry it -- launchd
     * would own the socket and the directory would not need to exist when the
     * daemon starts -- but it needs `launch_activate_socket` and a daemon that
     * accepts an inherited fd, so it is the later answer, not this one. */
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

    /* After the jobs, because a registered right with nothing to use it is
     * inert, while a running daemon with no rights registered refuses
     * mutations -- which is the safe order to be caught halfway through. */
    if (rights_install() != 0)
        fprintf(stderr, "smbpal-helper: warning: not every right was registered; "
                        "run uninstall and install again\n");

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
    /* Before the plists are unlinked, so a teardown interrupted here leaves
     * jobs that cannot authorise anything rather than rights with nothing left
     * to check them. */
    rights_remove();
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

/* ---------------------------------------------------------------------------
 * The framed protocol -- job B.
 *
 * A request is lines until `END`:
 *
 *     VERB share.list
 *     END
 *
 *     VERB auth.check
 *     AUTH <64 hex characters>
 *     ARG app.smbpal.manage-shares
 *     END
 *
 * A response is `OK` or `ERR <token>` on one line, then an optional payload to
 * half-close. That keeps `share.list`'s shape -- read to EOF -- while giving
 * errors somewhere to live that is not the payload.
 *
 * **Hex and not base64** for the 32 bytes. The decoder below is obvious on
 * sight, with no alphabet, no padding and no variant to pick wrong, and the
 * component that runs as root should prefer the boring option. 64 characters
 * against 44 is not a cost at this size.
 *
 * **Line framing makes one validation structural.** A newline cannot occur
 * inside an argument, because it ends the line -- so the newline that
 * `config/schema.py` rejects in a path cannot reach a verb here at all, and
 * that does not depend on the daemon having checked. A line without its
 * terminator is a malformed frame rather than a short argument, which is what
 * stops a truncated read from being read as a complete request.
 * ------------------------------------------------------------------------- */

struct request {
    char verb[64];
    int has_auth;
    AuthorizationExternalForm auth;
    char args[ARGS_MAX][REQUEST_ARG_MAX];
    int argc;
};

static void respond(int conn, const char *line) {
    size_t len = strlen(line);
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(conn, line + off, len - off);
        if (w <= 0) return;
        off += (size_t)w;
    }
}

/* Errors are a fixed token and never an echo of the request. A helper that
 * repeats what it was asked is a helper that can be used to probe it. */
static void respond_err(int conn, const char *token) {
    char line[32];
    snprintf(line, sizeof line, "ERR %s\n", token);
    respond(conn, line);
}

static int unhex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Exactly `len` bytes from exactly `2 * len` characters. A short, long or
 * non-hex field is a malformed frame, never a partially decoded form. */
static int unhex(const char *text, unsigned char *out, size_t len) {
    if (strlen(text) != len * 2) return -1;
    for (size_t i = 0; i < len; i++) {
        int hi = unhex_digit(text[i * 2]), lo = unhex_digit(text[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

/* §13 rule 7, applied to every argument at the point of parsing rather than in
 * each verb: printable ASCII only, bounded, non-empty, and **never a leading
 * `-`**. There is no shell here, so option-smuggling is the only injection the
 * fixed vocabulary leaves open -- `sharing` would read `-g` as a flag wherever
 * it appeared. Checking it once, for everything, means a verb added later
 * cannot forget. */
static int copy_token(char *dst, size_t cap, const char *src) {
    size_t len = strlen(src);
    if (len == 0 || len >= cap) return -1;
    if (src[0] == '-') return -1;
    for (size_t i = 0; i < len; i++)
        if ((unsigned char)src[i] < 0x20 || (unsigned char)src[i] > 0x7e) return -1;
    memcpy(dst, src, len + 1);
    return 0;
}

static int read_frame(int conn, char *buf, size_t cap) {
    size_t got = 0;
    for (;;) {
        if (got >= cap) return -1; /* no `END` within the bound */
        ssize_t n = read(conn, buf + got, cap - got);
        if (n < 0) return -1;
        if (n == 0) break; /* peer half-closed without `END` */
        got += (size_t)n;
        buf[got] = '\0';
        /* A NUL in the request would make every `str` call below read a
         * different request than the one that arrived. */
        if (memchr(buf, '\0', got) != NULL) return -1;
        if (strstr(buf, "\nEND\n") != NULL || strncmp(buf, "END\n", 4) == 0) break;
    }
    buf[got] = '\0';
    return (int)got;
}

static int parse_frame(char *buf, struct request *req) {
    memset(req, 0, sizeof *req);
    int ended = 0;
    char *line = buf;
    while (*line != '\0') {
        char *nl = strchr(line, '\n');
        if (nl == NULL) return -1; /* a line with no terminator is truncation */
        *nl = '\0';
        char *next = nl + 1;
        if (strcmp(line, "END") == 0) {
            ended = 1;
            break;
        }
        if (strncmp(line, "VERB ", 5) == 0) {
            if (req->verb[0] != '\0') return -1; /* said twice */
            if (copy_token(req->verb, sizeof req->verb, line + 5) != 0) return -1;
        } else if (strncmp(line, "AUTH ", 5) == 0) {
            if (req->has_auth) return -1;
            if (unhex(line + 5, (unsigned char *)&req->auth, sizeof req->auth) != 0)
                return -1;
            req->has_auth = 1;
        } else if (strncmp(line, "ARG ", 4) == 0) {
            if (req->argc >= ARGS_MAX) return -1;
            if (copy_token(req->args[req->argc], REQUEST_ARG_MAX, line + 4) != 0) return -1;
            req->argc++;
        } else {
            return -1; /* an unknown key is a different protocol, not a hint */
        }
        line = next;
    }
    if (!ended || req->verb[0] == '\0') return -1;
    return 0;
}

/* The whole vocabulary. Two verbs: one read that must not be authorised, and
 * one authorisation that reads nothing. */
static void serve_one(int conn) {
    char buf[REQUEST_MAX + 1];
    struct request req;
    uid_t uid;
    gid_t gid;

    if (getpeereid(conn, &uid, &gid) != 0) {
        /* `ipc/peer.py` documents this as the macOS-correct call: uid and gid
         * and no pid, which is why `daemon/polkit.py` records that no subject
         * can be identified to polkit here. Defence in depth behind the 0600,
         * not instead of it. */
        respond_err(conn, "peer");
        return;
    }
    if (uid != expected_peer) {
        fprintf(stderr, "smbpal-helper: refused uid %u\n", (unsigned)uid);
        respond_err(conn, "refused");
        return;
    }

    int got = read_frame(conn, buf, REQUEST_MAX);
    if (got <= 0) {
        respond_err(conn, "frame");
        return;
    }
    if (parse_frame(buf, &req) != 0) {
        respond_err(conn, "frame");
        return;
    }

    if (strcmp(req.verb, "share.list") == 0) {
        /* **A form is refused rather than ignored.** A read needs no
         * authorisation, so a request that carries one is confused about what
         * it is asking, and quietly accepting it would make a grant look like
         * it had been consumed when nothing checked it. */
        if (req.has_auth || req.argc != 0) {
            respond_err(conn, "args");
            return;
        }
        static char out[OUTPUT_MAX];
        size_t len = 0;
        char *const argv[] = {(char *)SHARING, "-l", "-f", "json", NULL};
        if (run_captured(argv, out, sizeof out, &len) != 0) {
            respond_err(conn, "sharing");
            return;
        }
        respond(conn, "OK\n");
        size_t off = 0;
        while (off < len) {
            ssize_t w = write(conn, out + off, len - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
        return;
    }

    if (strcmp(req.verb, "auth.check") == 0) {
        /* **What every later mutation will call, and it has a consumer now.**
         * §9 gave the config tree to the service account, so the daemon
         * performs its own config writes -- and still needs the authority's
         * answer about whether a grant covers them. This is that question, and
         * the daemon never inspects the bytes it relays.
         *
         * A replaced daemon could decline to ask. It could also have written
         * the config file by hand, so nothing is escalated by the asking being
         * voluntary; what matters is that the *answer* comes from here. */
        if (!req.has_auth || req.argc != 1) {
            respond_err(conn, "args");
            return;
        }
        if (!is_registered_right(req.args[0])) {
            /* Not passed to the system. An unregistered right would be answered
             * by the database's fallback `default` rule, which is an answer
             * about something SMBPal never registered. */
            respond_err(conn, "right");
            return;
        }
        if (verify_form(req.args[0], &req.auth) != 0) {
            respond_err(conn, "denied");
            return;
        }
        respond(conn, "OK\n");
        return;
    }

    respond_err(conn, "verb");
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage: %s install --daemon <path to smbpald> [--dry-run]\n"
            "       %s uninstall\n"
            "       %s serve --service-user <name> [--check]\n"
            "       %s rights install|remove\n"
            "       %s verify <right>   (external form on stdin)\n",
            program, program, program, program, program);
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
    if (strcmp(argv[1], "rights") == 0) {
        /* **The rights are repairable on their own, and the install is not.**
         * `install` refuses to run twice rather than guess which half to
         * repair, which is right for accounts and jobs -- they are the half
         * with state to get wrong. The rights have none: `AuthorizationRightSet`
         * overwrites, and a removal is idempotent.
         *
         * The hole this fills was found by measuring §12.4. Removing a right to
         * learn whether its `cdhash` requirement was enforced left the install
         * half-registered, and the only way back was tearing down the service
         * account and the launchd jobs to rebuild something that was never
         * broken. A root component should be able to repair the part that is
         * cheap to repair. */
        if (argc != 3) {
            usage(argv[0]);
            return 2;
        }
        /* The verb before the privilege check, so a typo is answered with the
         * usage and not with "must run as root" -- which would be a refusal
         * naming a problem the caller does not have. */
        int installing = strcmp(argv[2], "install") == 0;
        if (!installing && strcmp(argv[2], "remove") != 0) {
            usage(argv[0]);
            return 2;
        }
        if (geteuid() != 0) {
            fprintf(stderr, "smbpal-helper: rights must run as root\n");
            return 1;
        }
        if (installing) return rights_install() == 0 ? 0 : 1;
        rights_remove();
        return 0;
    }
    if (strcmp(argv[1], "verify") == 0) {
        if (argc != 3) {
            usage(argv[0]);
            return 2;
        }
        /* Needs no privilege: it asks the system about a grant it was handed,
         * and the answer does not depend on who is asking. Job B calls it as
         * root because that is where it runs, not because it must. */
        return verify(argv[2]);
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

    /* **Without this a client that hangs up mid-response kills the helper.**
     * `write` to a peer that has closed raises SIGPIPE, whose default action is
     * to terminate -- and this component deliberately has no `KeepAlive`, so it
     * would stay down for the rest of the boot and nothing could be authorised
     * until a reboot.
     *
     * Not a theoretical client either: `system/helper.py` has a read timeout
     * and closes the socket when it expires, so a slow `sharing -l -f json`
     * would have killed the authorisation gate by accident rather than by
     * attack. Job A was never exposed to it because job A had no client.
     *
     * Every `write` here already checks its return, so ignoring the signal
     * turns a fatal signal into the `EPIPE` the loops were written for. */
    signal(SIGPIPE, SIG_IGN);

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
        /* **One conversation at a time, so one client must not be able to
         * stop the clock.** A peer that connects and sends nothing, or trickles
         * bytes, would otherwise block the only accept loop for ever and the
         * helper would serve nobody -- availability rather than escalation, but
         * the thing it stops being available for is authorisation.
         *
         * Set on the accepted socket rather than the listener, because these
         * are not reliably inherited. */
        struct timeval limit = {.tv_sec = PEER_TIMEOUT_SECONDS, .tv_usec = 0};
        setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof limit);
        setsockopt(conn, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof limit);
        serve_one(conn);
        shutdown(conn, SHUT_WR);
        close(conn);
    }
}
