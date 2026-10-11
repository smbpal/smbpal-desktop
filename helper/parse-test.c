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

    printf("%d cases, %d failures\n", ran, failures);
    return failures == 0 ? 0 : 1;
}
