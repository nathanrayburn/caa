#include "ecdsa.h"

/*
 * Free the ecdsa_sig structure.
 */
int ecdsa_sig_free(struct ecdsa_sig *sig) {
    if (sig->r)
        BN_clear_free(sig->r);
    if (sig->s)
        BN_clear_free(sig->s);
    return 1;
}

/*
 * Free the ecdsa_public_key structure.
 */
int ecdsa_public_key_free(struct ecdsa_public_key *public) {
    if (public->group)
        EC_GROUP_clear_free(public->group);
    if (public->dG)
        EC_POINT_clear_free(public->dG);
    return 1;
}

/*
 * Free the ecdsa_private_key structure.
 */
int ecdsa_private_key_free(struct ecdsa_private_key *private) {
    if (private->group)
        EC_GROUP_clear_free(private->group);
    if (private->d)
        BN_clear_free(private->d);
    return 1;
}

/*
 * Compute a SHA256 of the buffer, and convert it to BIGNUM.
 */
static int ecdsa_hash(BIGNUM *h, const void *buffer, size_t size) {
    uint8_t md[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;

    ECDSA_CHECK(SHA256_Init(&ctx));
    ECDSA_CHECK(SHA256_Update(&ctx, buffer, size));
    ECDSA_CHECK(SHA256_Final(md, &ctx));

    ECDSA_CHECK(BN_bin2bn(md, SHA256_DIGEST_LENGTH, h));

    return 1;
}

/*
 * Generate an ECDSA keypair.
 */
int ecdsa_generate_keys(struct ecdsa_public_key *public,
                        struct ecdsa_private_key *private) {
    EC_GROUP *group;
    EC_POINT *dG;
    const EC_POINT *G;
    BIGNUM *d, *order;

    memset(public, 0, sizeof *public);
    memset(private, 0, sizeof *private);

    ECDSA_CHECK((group = EC_GROUP_new_by_curve_name(EC_DEFAULT_GROUP)));
    ECDSA_CHECK((G = EC_GROUP_get0_generator(group)));

    ECDSA_CHECK((d = BN_new()));
    ECDSA_CHECK((order = BN_new()));
    ECDSA_CHECK(EC_GROUP_get_order(group, order, NULL));

    /* Generate private key d */
    ECDSA_CHECK(BN_rand(d, BN_num_bits(order), -1, 0));

    /* Generate public key dG */
    ECDSA_CHECK((dG = EC_POINT_new(group)));
    ECDSA_CHECK(EC_POINT_mul(group, dG, NULL, G, d, NULL));

    public->dG = dG;
    public->group = group;
    private->group = EC_GROUP_dup(group);
    private->d = d;

    BN_free(order);
    return 1;
}

/*
 * Sign a message using ECDSA and random nonce k.
 */
int ecdsa_sign(struct ecdsa_sig *sig,
               const struct ecdsa_private_key *private,
               const void *buffer, size_t size, BIGNUM *k) {
    const EC_GROUP *group;
    BIGNUM *h, *x, *y, *order, *k_inv;
    EC_POINT *kG;
    const EC_POINT *G;
    BN_CTX *ctx;
    int ret = 0;

    memset(sig, 0, sizeof *sig);
    ECDSA_CHECK((group = private->group));

    ECDSA_CHECK((ctx = BN_CTX_new()));
    ECDSA_CHECK((x = BN_new()));
    ECDSA_CHECK((y = BN_new()));
    ECDSA_CHECK((h = BN_new()));
    ECDSA_CHECK((k_inv = BN_new()));
    ECDSA_CHECK((order = BN_new()));
    ECDSA_CHECK((kG = EC_POINT_new(group)));

    /* Get some curve parameters */
    ECDSA_CHECK((G = EC_GROUP_get0_generator(group)));
    ECDSA_CHECK(EC_GROUP_get_order(group, order, NULL));

    /* Check if k is between [1, n-1] */
    if (BN_cmp(k, BN_value_one()) < 0 || BN_cmp(k, order) >= 0)
        goto do_free;

    /* Calculate: H(m) */
    ECDSA_CHECK(ecdsa_hash(h, buffer, size));

    ECDSA_CHECK(EC_POINT_get_affine_coordinates_GF2m(group, G, x, y,
                                                     NULL));

    /* Calculate: (x, y) = kG */
    ECDSA_CHECK(EC_POINT_mul(group, kG, NULL, G, k, NULL));
    ECDSA_CHECK(EC_POINT_get_affine_coordinates_GF2m(group, kG, x, y, NULL));

    /* Calculate: x = x (mod n) */
    ECDSA_CHECK(BN_nnmod(x, x, order, ctx));

    if (BN_is_zero(x))
        goto do_free;

    /* Calculate: k^-1 */
    ECDSA_CHECK(BN_mod_inverse(k_inv, k, order, ctx));

    /* Calculate: y = k^-1(H(m) + dx) */
    ECDSA_CHECK(BN_mod_mul(y, x, private->d, order, ctx));
    ECDSA_CHECK(BN_mod_add(y, y, h, order, ctx));
    ECDSA_CHECK(BN_mod_mul(y, y, k_inv, order, ctx));

    if (BN_is_zero(y))
        goto do_free;

    sig->r = x;
    sig->s = y;
    ret = 1;

do_free:
    BN_free(order);
    BN_clear_free(h);
    BN_clear_free(k_inv);
    EC_POINT_clear_free(kG);
    BN_CTX_free(ctx);

    return ret;
}

/*
 * Verify an ECDSA signature.
 */
int ecdsa_verify(const struct ecdsa_sig *sig,
                 const struct ecdsa_public_key *public,
                 const void *buffer, size_t size) {
    int ret = 0;
    const EC_GROUP *group;
    const EC_POINT *G;
    EC_POINT *ndG, *xG, *yG;
    BIGNUM *order, *x, *y, *h, *s_inv, *i, *j;
    BN_CTX *ctx;

    ECDSA_CHECK((group = public->group));

    ECDSA_CHECK((ctx = BN_CTX_new()));
    ECDSA_CHECK((order = BN_new()));
    ECDSA_CHECK((x = BN_new()));
    ECDSA_CHECK((y = BN_new()));
    ECDSA_CHECK((h = BN_new()));
    ECDSA_CHECK((i = BN_new()));
    ECDSA_CHECK((j = BN_new()));
    ECDSA_CHECK((s_inv = BN_new()));
    ECDSA_CHECK((ndG = EC_POINT_new(group)));
    ECDSA_CHECK((xG = EC_POINT_new(group)));
    ECDSA_CHECK((yG = EC_POINT_new(group)));

    /* Get some curve parameters */
    ECDSA_CHECK((G = EC_GROUP_get0_generator(group)));
    ECDSA_CHECK(EC_GROUP_get_order(group, order, NULL));

    /* Calculate H(m) */
    ECDSA_CHECK(ecdsa_hash(h, buffer, size));

    /* Check if dG != 0 */
    if (EC_POINT_is_at_infinity(group, public->dG))
        goto do_free;

    /* Check if ndG = 0 */
    ECDSA_CHECK(EC_POINT_mul(group, ndG, NULL, public->dG, order, NULL));
    if (!EC_POINT_is_at_infinity(group, ndG))
        goto do_free;

    /* Check if s and r are in [1, n-1] */
    if (BN_cmp(sig->r, BN_value_one()) < 0 || BN_cmp(sig->r, order) >= 0)
        goto do_free;
    if (BN_cmp(sig->s, BN_value_one()) < 0 || BN_cmp(sig->s, order) >= 0)
        goto do_free;

    /* Calculate s^-1 (mod n) */
    ECDSA_CHECK(BN_mod_inverse(s_inv, sig->s, order, ctx));

    /* Calculate xG = H(m)s^-1 * G */
    ECDSA_CHECK(BN_mod_mul(x, h, s_inv, order, ctx));
    ECDSA_CHECK(EC_POINT_mul(group, xG, NULL, G, x, NULL));

    /* Calculate yG = (r*s^-1) * Q */
    ECDSA_CHECK(BN_mod_mul(y, sig->r, s_inv, order, ctx));
    ECDSA_CHECK(EC_POINT_mul(group, yG, NULL, public->dG, y, NULL));

    /* Calculate xG = xG + yG */
    ECDSA_CHECK(EC_POINT_add(group, xG, xG, yG, ctx));

    /* Check if r = xG.x (mod n) */
    ECDSA_CHECK(EC_POINT_get_affine_coordinates_GF2m(group, xG, i, j,
                                                     NULL));
    ECDSA_CHECK(BN_nnmod(i, i, order, ctx));
    if (BN_cmp(i, sig->r))
        goto do_free;

    ret = 1;

do_free:
    BN_CTX_free(ctx);
    BN_free(order);
    BN_clear_free(x);
    BN_clear_free(y);
    BN_clear_free(h);
    BN_clear_free(i);
    BN_clear_free(j);
    BN_clear_free(s_inv);
    EC_POINT_clear_free(ndG);
    EC_POINT_clear_free(xG);
    EC_POINT_clear_free(yG);

    return ret;
}
