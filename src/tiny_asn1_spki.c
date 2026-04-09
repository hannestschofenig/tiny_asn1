#include "tiny_asn1/tiny_asn1.h"

#include <stdlib.h>
#include <string.h>

static const unsigned char OID_EC_PUBLIC_KEY[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };

int tiny_asn1_build_ec_subject_public_key_info(tiny_asn1_ec_curve curve,
                                               const unsigned char *public_key,
                                               size_t public_key_len,
                                               unsigned char **out,
                                               size_t *out_len)
{
    unsigned char buf[512];
    unsigned char *p = buf + sizeof(buf);
    const unsigned char *curve_oid = NULL;
    size_t curve_oid_len = 0;
    size_t alg_len = 0;
    size_t total_len = 0;
    int ret;

    if (public_key == NULL || out == NULL || out_len == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }
    *out = NULL;
    *out_len = 0;

    ret = tiny_asn1_oid_from_ec_curve(curve, &curve_oid, &curve_oid_len);
    if (ret != 0) {
        return ret;
    }

    ret = tiny_asn1_write_bit_string(&p, buf, public_key, public_key_len, 0);
    if (ret < 0) {
        return ret;
    }
    total_len += (size_t) ret;

    ret = tiny_asn1_write_oid(&p, buf, curve_oid, curve_oid_len);
    if (ret < 0) {
        return ret;
    }
    alg_len += (size_t) ret;
    ret = tiny_asn1_write_oid(&p, buf, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY));
    if (ret < 0) {
        return ret;
    }
    alg_len += (size_t) ret;
    ret = tiny_asn1_write_len(&p, buf, alg_len);
    if (ret < 0) {
        return ret;
    }
    alg_len += (size_t) ret;
    ret = tiny_asn1_write_tag(&p, buf, TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE);
    if (ret < 0) {
        return ret;
    }
    alg_len += (size_t) ret;
    total_len += alg_len;

    ret = tiny_asn1_write_len(&p, buf, total_len);
    if (ret < 0) {
        return ret;
    }
    total_len += (size_t) ret;
    ret = tiny_asn1_write_tag(&p, buf, TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE);
    if (ret < 0) {
        return ret;
    }
    total_len += (size_t) ret;

    *out = calloc(1, total_len);
    if (*out == NULL) {
        return TINY_ASN1_ERR_ALLOC;
    }
    memcpy(*out, p, total_len);
    *out_len = total_len;
    return 0;
}
