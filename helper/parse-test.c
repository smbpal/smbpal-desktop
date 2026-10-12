/* A unit test for the frame parser, which is the new attack surface.
 *
 * **It includes the helper's source and renames its `main`.** The socket needs
 * root and the helper's paths are fixed on purpose, so `serve_one` cannot be
 * exercised from a test -- `tests/test_helper.py` says so and that remains
 * true. But `parse_frame`, `copy_token` and `unhex` are pure, and a parser in a
 * root component that nothing tests until the runbook is a bad trade when the
 * alternative costs one -D flag and no change to the shipped file.
 *
 * The expectations live here and nowhere else, so there is no second table to
 * drift from this one.
 */
#include <stdio.h>
#include <string.h>

#include "smbpal-helper.c"

/* The -D renamed the helper's entry point and would rename this file's too. */
#undef main

static int failures = 0;
static int ran = 0;

/* `parse_frame` writes into its input, so each case gets a fresh copy. */
static void expect(const char *name, const char *frame, int want_ok, const char *want_verb,
                   int want_argc, int want_auth) {
    char buf[REQUEST_MAX + 1];
    struct request req;
    ran++;
    if (strlen(frame) > REQUEST_MAX) {
        printf("FAIL %s: case longer than REQUEST_MAX\n", name);
        failures++;
        return;
    }
    memcpy(buf, frame, strlen(frame) + 1);
    int got = parse_frame(buf, &req) == 0;
    if (got != want_ok) {
        printf("FAIL %s: parse %s, wanted %s\n", name, got ? "accepted" : "rejected",
               want_ok ? "accepted" : "rejected");
        failures++;
        return;
    }
    if (!want_ok) return;
    if (strcmp(req.verb, want_verb) != 0) {
        printf("FAIL %s: verb %s, wanted %s\n", name, req.verb, want_verb);
        failures++;
    }
    if (req.argc != want_argc) {
        printf("FAIL %s: argc %d, wanted %d\n", name, req.argc, want_argc);
        failures++;
    }
    if (req.has_auth != want_auth) {
        printf("FAIL %s: has_auth %d, wanted %d\n", name, req.has_auth, want_auth);
        failures++;
    }
}

static void expect_hex(const char *name, const char *text, size_t len, int want_ok) {
    unsigned char out[32];
    ran++;
    int got = unhex(text, out, len) == 0;
    if (got != want_ok) {
        printf("FAIL %s: unhex %s\n", name, got ? "accepted" : "rejected");
        failures++;
    }
}

/* §13's rules 2-5. The facts are handed in, so no case needs root, a real home
 * directory or a mounted volume -- and rule 1 is `realpath`, which is the
 * caller's half and is not re-tested here. */
static void expect_verdict(const char *name, const char *resolved, mode_t mode, uid_t owner,
                           const char *home, enum path_verdict want) {
    ran++;
    enum path_verdict got = share_path_verdict(resolved, mode, owner, home);
    if (got != want) {
        printf("FAIL %s: %s, wanted %s\n", name, PATH_VERDICTS[got], PATH_VERDICTS[want]);
        failures++;
    }
}

static void expect_name(const char *name, const char *candidate, int want_ok) {
    ran++;
    if (share_name_ok(candidate) != want_ok) {
        printf("FAIL %s: share name %s\n", name, want_ok ? "rejected" : "accepted");
        failures++;
    }
}

static void expect_smb_nt(const char *name, const char *text, int want) {
    ran++;
    if (hashlist_has_smb_nt(text) != want) {
        printf("FAIL %s: SMB-NT %s\n", name, want ? "missed" : "invented");
        failures++;
    }
}

static void expect_user(const char *name, const char *candidate, int want_ok) {
    ran++;
    if (user_name_ok(candidate) != want_ok) {
        printf("FAIL %s: user name %s\n", name, want_ok ? "rejected" : "accepted");
        failures++;
    }
}

/* `ace_add`, `ace_for` and `ace_remove` against a real directory, as the
 * current user: putting an ACE on your own directory needs no root. This is
 * also the measurement the account spike left open -- whether `chmod -a` with
 * the text an ACE was added with removes it after macOS has stored it
 * rewritten. */
static void expect_ace_round_trip(void) {
    char dir[PATH_MAX];
    const char *tmp = getenv("TMPDIR");
    snprintf(dir, sizeof dir, "%s/smbpal-ace-XXXXXX", tmp != NULL ? tmp : "/tmp");
    ran++;
    if (mkdtemp(dir) == NULL) {
        printf("FAIL ace round trip: mkdtemp\n");
        failures++;
        return;
    }
    char resolved[PATH_MAX];
    struct passwd *me = getpwuid(getuid());
    if (realpath(dir, resolved) == NULL || me == NULL) {
        printf("FAIL ace round trip: setup\n");
        failures++;
        rmdir(dir);
        return;
    }
    if (ace_for(resolved, me->pw_uid) != ACCESS_NONE) {
        printf("FAIL ace round trip: a new directory already has an ACE\n");
        failures++;
    }
    ace_add(me->pw_name, resolved);
    if (ace_for(resolved, me->pw_uid) != ACCESS_ALLOW) {
        printf("FAIL ace round trip: the granted ACE does not read back as allow\n");
        failures++;
    }
    ace_remove(me->pw_name, resolved);
    if (ace_for(resolved, me->pw_uid) != ACCESS_NONE) {
        printf("FAIL ace round trip: chmod -a did not remove the rewritten ACE\n");
        failures++;
    }
    rmdir(resolved);
}

int main(void) {
    const char *form64 =
        "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee";

    expect("minimal", "VERB share.list\nEND\n", 1, "share.list", 0, 0);
    expect("crlf is not a terminator", "VERB share.list\r\nEND\r\n", 0, NULL, 0, 0);
    expect("no END", "VERB share.list\n", 0, NULL, 0, 0);
    expect("no verb", "ARG x\nEND\n", 0, NULL, 0, 0);
    expect("unterminated last line", "VERB share.list\nEND", 0, NULL, 0, 0);
    expect("unknown key", "VERB share.list\nWHAT x\nEND\n", 0, NULL, 0, 0);
    expect("verb twice", "VERB a\nVERB b\nEND\n", 0, NULL, 0, 0);
    expect("empty verb", "VERB \nEND\n", 0, NULL, 0, 0);
    expect("no space after key", "VERBshare.list\nEND\n", 0, NULL, 0, 0);
    expect("trailing junk after END is ignored",
           "VERB share.list\nEND\nVERB evil\n", 1, "share.list", 0, 0);

    expect("one arg", "VERB auth.check\nARG app.smbpal.manage-shares\nEND\n", 1,
           "auth.check", 1, 0);
    expect("four args", "VERB v\nARG a\nARG b\nARG c\nARG d\nEND\n", 1, "v", 4, 0);
    expect("five args", "VERB v\nARG a\nARG b\nARG c\nARG d\nARG e\nEND\n", 0, NULL, 0, 0);
    expect("empty arg", "VERB v\nARG \nEND\n", 0, NULL, 0, 0);
    expect("leading dash arg", "VERB v\nARG -g\nEND\n", 0, NULL, 0, 0);
    expect("dash inside an arg is fine", "VERB v\nARG my-share\nEND\n", 1, "v", 1, 0);
    expect("tab in an arg", "VERB v\nARG a\tb\nEND\n", 0, NULL, 0, 0);
    expect("high byte in an arg", "VERB v\nARG caf\xc3\xa9\nEND\n", 0, NULL, 0, 0);
    expect("a path is an ordinary arg", "VERB v\nARG /Users/x/Documents\nEND\n", 1, "v", 1, 0);

    {
        char frame[REQUEST_MAX + 1];
        snprintf(frame, sizeof frame, "VERB auth.check\nAUTH %s\nARG r\nEND\n", form64);
        expect("auth and arg", frame, 1, "auth.check", 1, 1);
        snprintf(frame, sizeof frame, "VERB v\nAUTH %s\nAUTH %s\nEND\n", form64, form64);
        expect("auth twice", frame, 0, NULL, 0, 0);
    }
    expect("short auth", "VERB v\nAUTH 00112233\nEND\n", 0, NULL, 0, 0);
    expect("auth with a non-hex character",
           "VERB v\nAUTH 0011223344556677889900aabbccddeeff001122334455667788"
           "99aabbccddeez\nEND\n", 0, NULL, 0, 0);

    expect_hex("exact length", form64, 32, 1);
    expect_hex("uppercase accepted", "AABB", 2, 1);
    expect_hex("odd length", "ABC", 2, 0);
    expect_hex("too long", "AABBCC", 2, 0);
    expect_hex("empty for a non-zero length", "", 2, 0);

    const mode_t dir = S_IFDIR | 0755;
    expect_verdict("a folder in a home", "/Users/luke/Documents", dir, 501, "/Users/luke", PATH_OK);
    expect_verdict("a folder on a volume", "/Volumes/Backup", dir, 501, "/Users/luke", PATH_OK);
    expect_verdict("a file", "/Users/luke/notes.txt", S_IFREG | 0644, 501, "/Users/luke",
                   PATH_NOT_DIRECTORY);
    expect_verdict("the system volume, resolved", "/", dir, 0, "/var/root", PATH_OUTSIDE_ROOTS);
    expect_verdict("/etc", "/private/etc", dir, 0, "/var/root", PATH_OUTSIDE_ROOTS);
    expect_verdict("/Users itself", "/Users/", dir, 0, "/var/root", PATH_OUTSIDE_ROOTS);
    expect_verdict("a prefix that is not a root", "/Usersfoo/x", dir, 501, "/Users/luke",
                   PATH_OUTSIDE_ROOTS);
    expect_verdict("a whole home", "/Users/luke", S_IFDIR | 0750, 501, "/Users/luke",
                   PATH_HOME_ROOT);
    expect_verdict("somebody else's whole home", "/Users/alice", S_IFDIR | 0750, 502,
                   "/Users/alice", PATH_HOME_ROOT);
    expect_verdict("/Users/Shared is root's", "/Users/Shared", S_IFDIR | 01777, 0, "/var/root",
                   PATH_SYSTEM_OWNED);
    expect_verdict("a role account's folder", "/Volumes/Backup/x", dir, 451, "/var/empty",
                   PATH_SYSTEM_OWNED);
    expect_verdict("no passwd entry for the owner", "/Volumes/Backup", dir, 501, NULL, PATH_OK);

    expect_name("plain", "Media", 1);
    expect_name("spaces inside", "Family Photos", 1);
    expect_name("dash and dot", "my-share.v2", 1);
    expect_name("empty", "", 0);
    expect_name("leading space", " Media", 0);
    expect_name("trailing space", "Media ", 0);
    expect_name("slash would pick another record", "a/b", 0);
    expect_name("apostrophe, as schema.py refuses", "Luke's", 0);
    expect_name("dollar", "admin$", 0);
    expect_name("eighty", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1);
    expect_name("eighty-one",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0);

    /* Shapes from the account spike's readings, with the principal elided. */
    expect_smb_nt("present, last",
                  "AuthenticationAuthority:\n ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2,"
                  "SRP-RFC5054-4096-SHA512-PBKDF2,SMB-NT> ;SecureToken; ;Kerberosv5;;x@LKDC:SHA1.X\n",
                  1);
    expect_smb_nt("absent", " ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2,SRP-RFC5054-4096-SHA512-PBKDF2>\n", 0);
    expect_smb_nt("present, first", ";ShadowHash;HASHLIST:<SMB-NT,SALTED-SHA512-PBKDF2>", 1);
    expect_smb_nt("a longer name is not it", ";ShadowHash;HASHLIST:<SMB-NTLMv2,SALTED-SHA512-PBKDF2>", 0);
    expect_smb_nt("outside the list is not it", ";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2> SMB-NT", 0);
    expect_smb_nt("no list at all", "No such key: AuthenticationAuthority", 0);
    expect_smb_nt("unterminated list", ";ShadowHash;HASHLIST:<SMB-NT", 0);

    expect_ace_round_trip();

    expect_user("plain", "someone", 1);
    expect_user("underscore and dot", "first.last_2", 1);
    expect_user("space would change the ACE", "some one", 0);
    expect_user("comma would change the ACE", "a,b", 0);
    expect_user("colon", "a:b", 0);
    expect_user("empty", "", 0);

    printf("%d cases, %d failures\n", ran, failures);
    return failures == 0 ? 0 : 1;
}
