#include "tiny_asn1/tiny_asn1.h"

#include <string.h>

static const unsigned char OID_SHA256[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
static const unsigned char OID_SHA384[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
static const unsigned char OID_SHA512[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };

static const unsigned char OID_HMAC_SHA256[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09 };
static const unsigned char OID_HMAC_SHA384[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A };
static const unsigned char OID_HMAC_SHA512[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B };

static const unsigned char OID_SIG_ECDSA_SHA256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };

static const unsigned char OID_CMP_PBM[] = { 0x2A, 0x86, 0x48, 0x86, 0xF6, 0x7D, 0x07, 0x42, 0x0D };
static const unsigned char OID_CMP_IMPLICIT_CONFIRM[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x04, 0x0D };
static const unsigned char OID_RFC4210_HMAC_SHA1[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x02 };

static const unsigned char OID_SECP256R1[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const unsigned char OID_SECP384R1[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };
static const unsigned char OID_SECP521R1[] = { 0x2B, 0x81, 0x04, 0x00, 0x23 };

static int tiny_asn1_set_oid(const unsigned char **dst_oid, size_t *dst_len,
                             const unsigned char *oid, size_t oid_len)
{
    if (dst_oid == NULL || dst_len == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }
    *dst_oid = oid;
    *dst_len = oid_len;
    return 0;
}

static int tiny_asn1_oid_eq(const unsigned char *left, size_t left_len,
                            const unsigned char *right, size_t right_len)
{
    return left_len == right_len && memcmp(left, right, left_len) == 0;
}

int tiny_asn1_oid_from_hash(tiny_asn1_hash_alg alg,
                            const unsigned char **oid, size_t *oid_len)
{
    switch (alg) {
        case TINY_ASN1_HASH_SHA256:
            return tiny_asn1_set_oid(oid, oid_len, OID_SHA256, sizeof(OID_SHA256));
        case TINY_ASN1_HASH_SHA384:
            return tiny_asn1_set_oid(oid, oid_len, OID_SHA384, sizeof(OID_SHA384));
        case TINY_ASN1_HASH_SHA512:
            return tiny_asn1_set_oid(oid, oid_len, OID_SHA512, sizeof(OID_SHA512));
        default:
            return TINY_ASN1_ERR_UNSUPPORTED;
    }
}

int tiny_asn1_hash_from_oid(const unsigned char *oid, size_t oid_len,
                            tiny_asn1_hash_alg *alg)
{
    if (oid == NULL || alg == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }
    if (tiny_asn1_oid_eq(oid, oid_len, OID_SHA256, sizeof(OID_SHA256))) {
        *alg = TINY_ASN1_HASH_SHA256;
        return 0;
    }
    if (tiny_asn1_oid_eq(oid, oid_len, OID_SHA384, sizeof(OID_SHA384))) {
        *alg = TINY_ASN1_HASH_SHA384;
        return 0;
    }
    if (tiny_asn1_oid_eq(oid, oid_len, OID_SHA512, sizeof(OID_SHA512))) {
        *alg = TINY_ASN1_HASH_SHA512;
        return 0;
    }
    return TINY_ASN1_ERR_UNSUPPORTED;
}

int tiny_asn1_oid_from_hmac_hash(tiny_asn1_hash_alg alg,
                                 const unsigned char **oid, size_t *oid_len)
{
    switch (alg) {
        case TINY_ASN1_HASH_SHA256:
            return tiny_asn1_set_oid(oid, oid_len, OID_HMAC_SHA256, sizeof(OID_HMAC_SHA256));
        case TINY_ASN1_HASH_SHA384:
            return tiny_asn1_set_oid(oid, oid_len, OID_HMAC_SHA384, sizeof(OID_HMAC_SHA384));
        case TINY_ASN1_HASH_SHA512:
            return tiny_asn1_set_oid(oid, oid_len, OID_HMAC_SHA512, sizeof(OID_HMAC_SHA512));
        default:
            return TINY_ASN1_ERR_UNSUPPORTED;
    }
}

int tiny_asn1_hmac_hash_from_oid(const unsigned char *oid, size_t oid_len,
                                 tiny_asn1_hash_alg *alg)
{
    if (oid == NULL || alg == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }
    if (tiny_asn1_oid_eq(oid, oid_len, OID_HMAC_SHA256, sizeof(OID_HMAC_SHA256))) {
        *alg = TINY_ASN1_HASH_SHA256;
        return 0;
    }
    if (tiny_asn1_oid_eq(oid, oid_len, OID_HMAC_SHA384, sizeof(OID_HMAC_SHA384))) {
        *alg = TINY_ASN1_HASH_SHA384;
        return 0;
    }
    if (tiny_asn1_oid_eq(oid, oid_len, OID_HMAC_SHA512, sizeof(OID_HMAC_SHA512))) {
        *alg = TINY_ASN1_HASH_SHA512;
        return 0;
    }
    return TINY_ASN1_ERR_UNSUPPORTED;
}

int tiny_asn1_oid_from_sig_alg(tiny_asn1_sig_alg alg,
                               const unsigned char **oid, size_t *oid_len)
{
    switch (alg) {
        case TINY_ASN1_SIG_ECDSA_SHA256:
            return tiny_asn1_set_oid(oid, oid_len,
                                     OID_SIG_ECDSA_SHA256, sizeof(OID_SIG_ECDSA_SHA256));
        default:
            return TINY_ASN1_ERR_UNSUPPORTED;
    }
}

int tiny_asn1_sig_alg_from_oid(const unsigned char *oid, size_t oid_len,
                               tiny_asn1_sig_alg *alg)
{
    if (oid == NULL || alg == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }
    if (tiny_asn1_oid_eq(oid, oid_len, OID_SIG_ECDSA_SHA256, sizeof(OID_SIG_ECDSA_SHA256))) {
        *alg = TINY_ASN1_SIG_ECDSA_SHA256;
        return 0;
    }
    return TINY_ASN1_ERR_UNSUPPORTED;
}

int tiny_asn1_oid_cmp_pbm(const unsigned char **oid, size_t *oid_len)
{
    return tiny_asn1_set_oid(oid, oid_len, OID_CMP_PBM, sizeof(OID_CMP_PBM));
}

int tiny_asn1_oid_cmp_implicit_confirm(const unsigned char **oid, size_t *oid_len)
{
    return tiny_asn1_set_oid(oid, oid_len,
                             OID_CMP_IMPLICIT_CONFIRM, sizeof(OID_CMP_IMPLICIT_CONFIRM));
}

int tiny_asn1_oid_rfc4210_hmac_sha1(const unsigned char **oid, size_t *oid_len)
{
    return tiny_asn1_set_oid(oid, oid_len,
                             OID_RFC4210_HMAC_SHA1, sizeof(OID_RFC4210_HMAC_SHA1));
}

int tiny_asn1_ec_curve_from_name(const char *name, tiny_asn1_ec_curve *curve)
{
    if (name == NULL || curve == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }
    if (strcmp(name, "secp256r1") == 0) {
        *curve = TINY_ASN1_EC_CURVE_SECP256R1;
        return 0;
    }
    if (strcmp(name, "secp384r1") == 0) {
        *curve = TINY_ASN1_EC_CURVE_SECP384R1;
        return 0;
    }
    if (strcmp(name, "secp521r1") == 0) {
        *curve = TINY_ASN1_EC_CURVE_SECP521R1;
        return 0;
    }
    return TINY_ASN1_ERR_UNSUPPORTED;
}

int tiny_asn1_oid_from_ec_curve(tiny_asn1_ec_curve curve,
                                const unsigned char **oid, size_t *oid_len)
{
    switch (curve) {
        case TINY_ASN1_EC_CURVE_SECP256R1:
            return tiny_asn1_set_oid(oid, oid_len, OID_SECP256R1, sizeof(OID_SECP256R1));
        case TINY_ASN1_EC_CURVE_SECP384R1:
            return tiny_asn1_set_oid(oid, oid_len, OID_SECP384R1, sizeof(OID_SECP384R1));
        case TINY_ASN1_EC_CURVE_SECP521R1:
            return tiny_asn1_set_oid(oid, oid_len, OID_SECP521R1, sizeof(OID_SECP521R1));
        default:
            return TINY_ASN1_ERR_UNSUPPORTED;
    }
}
