#ifndef MINISIGN_VERIFY_H
#define MINISIGN_VERIFY_H 1

#include <sodium.h>

#define MINISIGN_KEYNUMBYTES            8
#define MINISIGN_TRUSTEDCOMMENTMAXBYTES 8192

typedef struct MinisignKeynumPK_ {
    unsigned char keynum[MINISIGN_KEYNUMBYTES];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
} MinisignKeynumPK;

typedef enum MinisignError {
    MinisignOutOfMemory,
    MinisignReadError,
    MinisignWriteError,
    MinisignParseError,
    MinisignUsageError,
    MinisignLegacySignature,
    MinisignKeyError,
    MinisignVerificationFailed,
} MinisignError;

typedef struct MinisignPubkeyStruct_ {
    unsigned char    sig_alg[2];
    MinisignKeynumPK keynum_pk;
} MinisignPubkeyStruct;

MinisignPubkeyStruct *minisign_pubkey_load(const char *pk_file, const char *pubkey_s,
                                           MinisignError *const err);

void minisign_pubkey_free(MinisignPubkeyStruct *pubkey_struct);

int minisign_verify(MinisignPubkeyStruct *pubkey_struct, const char *message_file,
                    const char *sig_file, int output, int allow_legacy,
                    char                 trusted_comment[MINISIGN_TRUSTEDCOMMENTMAXBYTES],
                    MinisignError *const err);

#endif