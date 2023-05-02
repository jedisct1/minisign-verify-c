
#ifndef MINISIGN_P_H
#define MINISIGN_P_H 1

#include <sodium.h>

#define COMMENTMAXBYTES                1024
#define PASSWORDMAXBYTES               1024
#define SIGALG                         "Ed"
#define SIGALG_HASHED                  "ED"
#define KDFALG                         "Sc"
#define KDFNONE                        "\0\0"
#define CHKALG                         "B2"
#define COMMENT_PREFIX                 "untrusted comment: "
#define DEFAULT_COMMENT                "signature from minisign secret key"
#define SECRETKEY_DEFAULT_COMMENT      "minisign encrypted secret key"
#define TRUSTED_COMMENT_PREFIX         "trusted comment: "
#define SIG_DEFAULT_CONFIG_DIR         ".minisign"
#define SIG_DEFAULT_CONFIG_DIR_ENV_VAR "MINISIGN_CONFIG_DIR"
#define SIG_DEFAULT_PKFILE             "minisign.pub"
#define SIG_DEFAULT_SKFILE             "minisign.key"
#define SIG_SUFFIX                     ".minisig"

typedef struct SigStruct_ {
    unsigned char sig_alg[2];
    unsigned char keynum[MINISIGN_KEYNUMBYTES];
    unsigned char sig[crypto_sign_BYTES];
} SigStruct;

#endif
