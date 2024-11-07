#ifndef DEF_ECDSA_H
#define DEF_ECDSA_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdint.h>

#define EC_DEFAULT_GROUP NID_secp256k1

struct ecdsa_sig {
    BIGNUM *r;
    BIGNUM *s;
};

struct ecdsa_public_key {
    EC_GROUP *group;
    EC_POINT *dG;
};

struct ecdsa_private_key {
    EC_GROUP *group;
    BIGNUM *d;
};

int ecdsa_generate_keys(struct ecdsa_public_key *public,
                        struct ecdsa_private_key *private);

int ecdsa_sign(struct ecdsa_sig *sig,
               const struct ecdsa_private_key *private,
               const void *buffer, size_t size, BIGNUM *k);

int ecdsa_verify(const struct ecdsa_sig *sig,
                 const struct ecdsa_public_key *public,
                 const void *buffer, size_t size);

int ecdsa_sig_free(struct ecdsa_sig *sig);
int ecdsa_public_key_free(struct ecdsa_public_key *public);
int ecdsa_private_key_free(struct ecdsa_private_key *private);

#define ECDSA_CHECK(c) do { \
        if (!(c)) {                                     \
            fprintf(stderr, "[-] Assert : %s", #c);     \
            exit(EXIT_FAILURE);                         \
        }                                               \
    } while (0)

#endif

