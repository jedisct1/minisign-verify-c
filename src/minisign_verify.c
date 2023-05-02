#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "minisign_verify.h"
#include "minisign_verify_p.h"

static unsigned char *
message_load_hashed(size_t *message_len, const char *message_file, MinisignError *const err)
{
    crypto_generichash_state hs;
    unsigned char            buf[65536U];
    unsigned char           *message = NULL;
    FILE                    *fp      = NULL;
    size_t                   n;

    if ((fp = fopen(message_file, "rb")) == NULL) {
        *err = MinisignReadError;
        goto err;
    }
    crypto_generichash_init(&hs, NULL, 0U, crypto_generichash_BYTES_MAX);
    while ((n = fread(buf, 1U, sizeof buf, fp)) > 0U) {
        crypto_generichash_update(&hs, buf, n);
    }
    if (!feof(fp)) {
        *err = MinisignReadError;
        goto err;
    }
    if (fclose(fp) != 0) {
        *err = MinisignReadError;
        fp   = NULL;
        goto err;
    }
    fp = NULL;
    if ((message = malloc(crypto_generichash_BYTES_MAX)) == NULL) {
        *err = MinisignOutOfMemory;
        goto err;
    }
    crypto_generichash_final(&hs, message, crypto_generichash_BYTES_MAX);
    *message_len = crypto_generichash_BYTES_MAX;

    return message;

err:
    if (fp != NULL) {
        (void) fclose(fp);
    }
    free(message);
    return NULL;
}

static unsigned char *
message_load(size_t *message_len, const char *message_file, int hashed, MinisignError *const err)
{
    FILE          *fp      = NULL;
    unsigned char *message = NULL;
    off_t          message_len_;

    if (hashed != 0) {
        return message_load_hashed(message_len, message_file, err);
    }
    if ((fp = fopen(message_file, "rb")) == NULL || fseeko(fp, 0, SEEK_END) != 0 ||
        (message_len_ = ftello(fp)) == (off_t) -1) {
        *err = MinisignReadError;
        goto err;
    }
    assert(hashed == 0);
    if ((uintmax_t) message_len_ > (uintmax_t) SIZE_MAX || message_len_ < (off_t) 0) {
        *err = MinisignReadError;
        goto err;
    }
    if ((message = malloc((*message_len = (size_t) message_len_))) == NULL) {
        *err = MinisignOutOfMemory;
        goto err;
    }
    rewind(fp);
    if (*message_len > 0U && fread(message, *message_len, (size_t) 1U, fp) != 1U) {
        *err = MinisignReadError;
        goto err;
    }
    if (fclose(fp) != 0) {
        *err = MinisignReadError;
        fp   = NULL;
        goto err;
    }
    fp = NULL;
    return message;

err:
    if (fp != NULL) {
        (void) fclose(fp);
    }
    free(message);
    return NULL;
}

static int
output_file(const char *message_file, MinisignError *const err)
{
    unsigned char buf[65536U];
    FILE         *fp = NULL;
    size_t        n;

    if ((fp = fopen(message_file, "rb")) == NULL) {
        *err = MinisignWriteError;
        goto err;
    }
    while ((n = fread(buf, 1U, sizeof buf, fp)) > 0U) {
        if (fwrite(buf, 1U, n, stdout) != n) {
            *err = MinisignWriteError;
            goto err;
        }
    }
    if (!feof(fp) || fflush(stdout) != 0) {
        *err = MinisignWriteError;
        goto err;
    }
    if (fclose(fp) != 0) {
        *err = MinisignWriteError;
        fp   = NULL;
        goto err;
    }
    return 0;

err:
    if (fp != NULL) {
        (void) fclose(fp);
    }
    return -1;
}

static int
trim(char *str)
{
    size_t i = strlen(str);
    int    t = 0;

    while (i-- > (size_t) 0U) {
        if (str[i] == '\n') {
            str[i] = 0;
            t      = 1;
        } else if (str[i] == '\r') {
            str[i] = 0;
        }
    }
    return t;
}

#define B64_MAX_LEN_FROM_BIN_LEN(X) (((X) + 2) / 3 * 4 + 1)

static unsigned char *
b64_to_bin(unsigned char *const bin, const char *b64, size_t bin_maxlen, size_t b64_len,
           size_t *const bin_len_p)
{
#define REV64_EOT  128U
#define REV64_NONE 64U
#define REV64_PAD  '='

    static const unsigned char rev64chars[256] = {
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, 62U,        REV64_NONE, REV64_NONE, REV64_NONE, 63U,        52U,
        53U,        54U,        55U,        56U,        57U,        58U,        59U,
        60U,        61U,        REV64_NONE, REV64_NONE, REV64_NONE, REV64_EOT,  REV64_NONE,
        REV64_NONE, REV64_NONE, 0U,         1U,         2U,         3U,         4U,
        5U,         6U,         7U,         8U,         9U,         10U,        11U,
        12U,        13U,        14U,        15U,        16U,        17U,        18U,
        19U,        20U,        21U,        22U,        23U,        24U,        25U,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, 26U,
        27U,        28U,        29U,        30U,        31U,        32U,        33U,
        34U,        35U,        36U,        37U,        38U,        39U,        40U,
        41U,        42U,        43U,        44U,        45U,        46U,        47U,
        48U,        49U,        50U,        51U,        REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE
    };
    const unsigned char *b64_u = (const unsigned char *) b64;
    unsigned char       *bin_w = bin;
    unsigned char        mask  = 0U;
    unsigned char        t0 = 0, t1 = 0, t2 = 0, t3 = 0;
    uint32_t             t = 0;
    size_t               i;

    if (b64_len % 4U != 0U || (i = b64_len / 4U) <= 0U ||
        bin_maxlen <
            i * 3U - (b64_u[b64_len - 1U] == REV64_PAD) - (b64_u[b64_len - 2U] == REV64_PAD)) {
        return NULL;
    }
    while (i-- > 0U) {
        t0   = rev64chars[*b64_u++];
        t1   = rev64chars[*b64_u++];
        t2   = rev64chars[*b64_u++];
        t3   = rev64chars[*b64_u++];
        t    = t3 | ((uint32_t) t2 << 6) | ((uint32_t) t1 << 12) | ((uint32_t) t0 << 18);
        mask = t0 | t1 | t2 | t3;
        if ((mask & (REV64_NONE | REV64_EOT)) != 0U) {
            if ((mask & REV64_NONE) != 0U || i > 0U) {
                return NULL;
            }
            break;
        }
        *bin_w++ = (unsigned char) (t >> 16);
        *bin_w++ = (unsigned char) (t >> 8);
        *bin_w++ = (unsigned char) t;
    }
    if ((mask & REV64_EOT) != 0U) {
        if (((t0 | t1) & REV64_EOT) != 0U || t3 != REV64_EOT) {
            return NULL;
        }
        *bin_w++ = (unsigned char) (t >> 16);
        if (t2 != REV64_EOT) {
            *bin_w++ = (unsigned char) (t >> 8);
        }
    }
    if (bin_len_p != NULL) {
        *bin_len_p = (size_t) (bin_w - bin);
    }
    return bin;
}

static SigStruct *
sig_load(const char *sig_file, unsigned char global_sig[crypto_sign_BYTES], int *hashed,
         char trusted_comment[MINISIGN_TRUSTEDCOMMENTMAXBYTES], size_t trusted_comment_maxlen,
         MinisignError *const err)
{
    char       comment[COMMENTMAXBYTES];
    SigStruct *sig_struct   = NULL;
    FILE      *fp           = NULL;
    char      *global_sig_s = NULL;
    char      *sig_s        = NULL;
    size_t     global_sig_len;
    size_t     global_sig_s_size;
    size_t     sig_s_size;
    size_t     sig_struct_len;

    if ((fp = fopen(sig_file, "r")) == NULL) {
        *err = MinisignReadError;
        goto err;
    }
    if (fgets(comment, (int) sizeof comment, fp) == NULL) {
        *err = MinisignReadError;
        goto err;
    }
    if (trim(comment) == 0) {
        *err = MinisignParseError;
        goto err;
    }
    if (strncmp(comment, COMMENT_PREFIX, (sizeof COMMENT_PREFIX) - 1U) != 0) {
        *err = MinisignParseError;
        goto err;
    }
    sig_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *sig_struct) + 2U;
    sig_s      = malloc(sig_s_size);
    if (sig_s == NULL) {
        *err = MinisignOutOfMemory;
        goto err;
    }
    if (fgets(sig_s, (int) sig_s_size, fp) == NULL) {
        *err = MinisignReadError;
        goto err;
    }
    if (trim(sig_s) == 0) {
        *err = MinisignParseError;
        goto err;
    }
    if (fgets(trusted_comment, (int) trusted_comment_maxlen, fp) == NULL) {
        *err = MinisignParseError;
        goto err;
    }
    if (strncmp(trusted_comment, TRUSTED_COMMENT_PREFIX, (sizeof TRUSTED_COMMENT_PREFIX) - 1U) !=
        0) {
        *err = MinisignParseError;
        goto err;
    }
    memmove(trusted_comment,
            trusted_comment + sizeof TRUSTED_COMMENT_PREFIX - 1U,
            strlen(trusted_comment + sizeof TRUSTED_COMMENT_PREFIX - 1U) + 1U);
    if (trim(trusted_comment) == 0) {
        *err = MinisignParseError;
        goto err;
    }
    global_sig_s_size = B64_MAX_LEN_FROM_BIN_LEN(crypto_sign_BYTES) + 2U;
    global_sig_s      = malloc(global_sig_s_size);
    if (global_sig_s == NULL) {
        *err = MinisignOutOfMemory;
        goto err;
    }
    if (fgets(global_sig_s, (int) global_sig_s_size, fp) == NULL) {
        *err = MinisignReadError;
        goto err;
    }
    trim(global_sig_s);
    if (fclose(fp) != 0) {
        *err = MinisignReadError;
        fp   = NULL;
        goto err;
    }
    fp = NULL;

    sig_struct = malloc(sizeof *sig_struct);
    if (sig_struct == NULL) {
        *err = MinisignOutOfMemory;
        goto err;
    }
    if (b64_to_bin((unsigned char *) (void *) sig_struct, sig_s, sizeof *sig_struct, strlen(sig_s),
                   &sig_struct_len) == NULL ||
        sig_struct_len != sizeof *sig_struct) {
        *err = MinisignParseError;
        goto err;
    }
    free(sig_s);
    sig_s = NULL;
    if (memcmp(sig_struct->sig_alg, SIGALG, sizeof sig_struct->sig_alg) == 0) {
        *hashed = 0;
    } else if (memcmp(sig_struct->sig_alg, SIGALG_HASHED, sizeof sig_struct->sig_alg) == 0) {
        *hashed = 1;
    } else {
        *err = MinisignParseError;
        goto err;
    }
    if (b64_to_bin(global_sig, global_sig_s, crypto_sign_BYTES, strlen(global_sig_s),
                   &global_sig_len) == NULL ||
        global_sig_len != crypto_sign_BYTES) {
        *err = MinisignParseError;
        goto err;
    }
    free(global_sig_s);
    global_sig_s = NULL;

    return sig_struct;

err:
    if (fp != NULL) {
        (void) fclose(fp);
    }
    free(sig_struct);
    free(global_sig_s);
    free(sig_s);
    return NULL;
}

static MinisignPubkeyStruct *
pubkey_load_string(const char *pubkey_s, MinisignError *const err)
{
    MinisignPubkeyStruct *pubkey_struct = NULL;
    size_t                pubkey_struct_len;

    pubkey_struct = sodium_malloc(sizeof *pubkey_struct);
    if (pubkey_struct == NULL) {
        *err = MinisignOutOfMemory;
        goto err;
    }
    if (b64_to_bin((unsigned char *) (void *) pubkey_struct, pubkey_s, sizeof *pubkey_struct,
                   strlen(pubkey_s), &pubkey_struct_len) == NULL ||
        pubkey_struct_len != sizeof *pubkey_struct) {
        *err = MinisignParseError;
        goto err;
    }
    if (memcmp(pubkey_struct->sig_alg, SIGALG, sizeof pubkey_struct->sig_alg) != 0) {
        *err = MinisignParseError;
        goto err;
    }
    return pubkey_struct;

err:
    sodium_free(pubkey_struct);
    return NULL;
}

static MinisignPubkeyStruct *
pubkey_load_file(const char *pk_file, MinisignError *const err)
{
    char                  pk_comment[COMMENTMAXBYTES];
    MinisignPubkeyStruct *pubkey_struct = NULL;
    FILE                 *fp            = NULL;
    char                 *pubkey_s      = NULL;
    size_t                pubkey_s_size;

    if ((fp = fopen(pk_file, "r")) == NULL) {
        *err = MinisignReadError;
        goto err;
    }
    if (fgets(pk_comment, (int) sizeof pk_comment, fp) == NULL) {
        *err = MinisignReadError;
        goto err;
    }
    pubkey_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *pubkey_struct) + 2U;
    pubkey_s      = malloc(pubkey_s_size);
    if (fgets(pubkey_s, (int) pubkey_s_size, fp) == NULL) {
        *err = MinisignReadError;
        goto err;
    }
    trim(pubkey_s);
    if (fclose(fp) != 0) {
        *err = MinisignReadError;
        fp   = NULL;
        goto err;
    }
    fp            = NULL;
    pubkey_struct = pubkey_load_string(pubkey_s, err);
    if (pubkey_struct == NULL) {
        goto err;
    }
    free(pubkey_s);
    pubkey_s = NULL;

    return pubkey_struct;

err:
    if (fp != NULL) {
        (void) fclose(fp);
    }
    free(pubkey_struct);
    free(pubkey_s);
    return NULL;
}

MinisignPubkeyStruct *
minisign_pubkey_load(const char *pk_file, const char *pubkey_s, MinisignError *const err)
{
    if (pk_file != NULL && pubkey_s != NULL) {
        *err = MinisignUsageError;
        goto err;
    }
    if (pubkey_s != NULL) {
        return pubkey_load_string(pubkey_s, err);
    } else if (pk_file != NULL) {
        return pubkey_load_file(pk_file, err);
    }
    *err = MinisignUsageError;

err:
    return NULL;
}

void
minisign_pubkey_free(MinisignPubkeyStruct *pubkey_struct)
{
    sodium_free(pubkey_struct);
}

int
minisign_verify(MinisignPubkeyStruct *pubkey_struct, const char *message_file, const char *sig_file,
                int output, int allow_legacy, char trusted_comment[MINISIGN_TRUSTEDCOMMENTMAXBYTES],
                MinisignError *const err)
{
    unsigned char  global_sig[crypto_sign_BYTES];
    FILE          *info_fp                 = stdout;
    unsigned char *sig_and_trusted_comment = NULL;
    SigStruct     *sig_struct              = NULL;
    unsigned char *message                 = NULL;
    size_t         message_len;
    size_t         trusted_comment_len;
    int            hashed;

    if (output != 0) {
        info_fp = stderr;
    }
    sig_struct = sig_load(sig_file, global_sig, &hashed, trusted_comment,
                          MINISIGN_TRUSTEDCOMMENTMAXBYTES, err);
    if (sig_struct == NULL) {
        goto err;
    }
    if (hashed == 0 && allow_legacy == 0) {
        *err = MinisignLegacySignature;
        goto err;
    }
    message = message_load(&message_len, message_file, hashed, err);
    if (message == NULL) {
        goto err;
    }
    if (memcmp(sig_struct->keynum, pubkey_struct->keynum_pk.keynum, sizeof sig_struct->keynum) !=
        0) {
        *err = MinisignKeyError;
        goto err;
    }
    if (crypto_sign_verify_detached(sig_struct->sig, message, message_len,
                                    pubkey_struct->keynum_pk.pk) != 0) {
        *err = MinisignVerificationFailed;
        goto err;
    }
    free(message);
    message = NULL;

    trusted_comment_len     = strlen(trusted_comment);
    sig_and_trusted_comment = malloc((sizeof sig_struct->sig) + trusted_comment_len);
    if (sig_and_trusted_comment == NULL) {
        *err = MinisignOutOfMemory;
        goto err;
    }
    memcpy(sig_and_trusted_comment, sig_struct->sig, sizeof sig_struct->sig);
    memcpy(sig_and_trusted_comment + sizeof sig_struct->sig, trusted_comment, trusted_comment_len);
    if (crypto_sign_verify_detached(global_sig, sig_and_trusted_comment,
                                    (sizeof sig_struct->sig) + trusted_comment_len,
                                    pubkey_struct->keynum_pk.pk) != 0) {
        *err = MinisignVerificationFailed;
        goto err;
    }
    free(sig_and_trusted_comment);
    sig_and_trusted_comment = NULL;
    free(sig_struct);
    sig_struct = NULL;
    if (output != 0 && output_file(message_file, err) != 0) {
        *err = MinisignUsageError;
        goto err;
    }
    return 0;

err:
    free(message);
    free(sig_and_trusted_comment);
    free(sig_struct);
    return -1;
}

static char *
append_sig_suffix(const char *message_file, MinisignError *const err)
{
    char  *sig_file;
    size_t message_file_len = strlen(message_file);

    sig_file = malloc(message_file_len + sizeof SIG_SUFFIX);
    if (sig_file == NULL) {
        *err = MinisignOutOfMemory;
        goto err;
    }
    memcpy(sig_file, message_file, message_file_len);
    memcpy(sig_file + message_file_len, SIG_SUFFIX, sizeof SIG_SUFFIX);

    return sig_file;

err:
    free(sig_file);
    return NULL;
}

int
main(int argc, char **argv)
{
    return 0;
}
