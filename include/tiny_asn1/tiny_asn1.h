#ifndef TINY_ASN1_H
#define TINY_ASN1_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TINY_ASN1_TAG_BOOLEAN             0x01
#define TINY_ASN1_TAG_INTEGER             0x02
#define TINY_ASN1_TAG_BIT_STRING          0x03
#define TINY_ASN1_TAG_OCTET_STRING        0x04
#define TINY_ASN1_TAG_NULL                0x05
#define TINY_ASN1_TAG_OID                 0x06
#define TINY_ASN1_TAG_UTF8_STRING         0x0C
#define TINY_ASN1_TAG_SEQUENCE            0x10
#define TINY_ASN1_TAG_SET                 0x11
#define TINY_ASN1_TAG_PRINTABLE_STRING    0x13
#define TINY_ASN1_TAG_IA5_STRING          0x16
#define TINY_ASN1_TAG_BMP_STRING          0x1E
#define TINY_ASN1_TAG_GENERALIZED_TIME    0x18
#define TINY_ASN1_TAG_CONSTRUCTED         0x20
#define TINY_ASN1_TAG_CONTEXT_SPECIFIC    0x80

#define TINY_ASN1_OK                    0
#define TINY_ASN1_ERR_PARAM           -1
#define TINY_ASN1_ERR_ALLOC           -2
#define TINY_ASN1_ERR_BUF_TOO_SMALL   -3
#define TINY_ASN1_ERR_INVALID_TAG     -4
#define TINY_ASN1_ERR_INVALID_LEN     -5
#define TINY_ASN1_ERR_INVALID_VALUE   -6
#define TINY_ASN1_ERR_UNSUPPORTED     -7
#define TINY_ASN1_ERR_SYNTAX          -8

typedef struct tiny_asn1_tlv {
    unsigned char tag;
    const unsigned char *ptr;
    const unsigned char *value;
    size_t value_len;
    size_t encoded_len;
} tiny_asn1_tlv;

typedef enum tiny_asn1_hash_alg {
    TINY_ASN1_HASH_SHA256 = 1,
    TINY_ASN1_HASH_SHA384 = 2,
    TINY_ASN1_HASH_SHA512 = 3
} tiny_asn1_hash_alg;

typedef enum tiny_asn1_sig_alg {
    TINY_ASN1_SIG_ECDSA_SHA256 = 1
} tiny_asn1_sig_alg;

typedef enum tiny_asn1_ec_curve {
    TINY_ASN1_EC_CURVE_SECP256R1 = 1,
    TINY_ASN1_EC_CURVE_SECP384R1 = 2,
    TINY_ASN1_EC_CURVE_SECP521R1 = 3
} tiny_asn1_ec_curve;

int tiny_asn1_write_raw_buffer(unsigned char **p, unsigned char *start,
                               const unsigned char *buf, size_t len);
int tiny_asn1_write_len(unsigned char **p, unsigned char *start, size_t len);
int tiny_asn1_write_tag(unsigned char **p, unsigned char *start, unsigned char tag);
int tiny_asn1_write_int(unsigned char **p, unsigned char *start, int value);
int tiny_asn1_write_null(unsigned char **p, unsigned char *start);
int tiny_asn1_write_oid(unsigned char **p, unsigned char *start,
                        const unsigned char *oid, size_t oid_len);
int tiny_asn1_write_octet_string(unsigned char **p, unsigned char *start,
                                 const unsigned char *buf, size_t len);
int tiny_asn1_write_bit_string(unsigned char **p, unsigned char *start,
                               const unsigned char *buf, size_t len,
                               unsigned char unused_bits);
int tiny_asn1_write_algorithm_identifier(unsigned char **p, unsigned char *start,
                                         const unsigned char *oid, size_t oid_len,
                                         size_t params_len);

int tiny_asn1_read_tlv(const unsigned char **p, const unsigned char *end,
                       tiny_asn1_tlv *tlv);
int tiny_asn1_expect_tlv(const unsigned char **p, const unsigned char *end,
                         unsigned char expected_tag, tiny_asn1_tlv *tlv);
int tiny_asn1_get_tag(const unsigned char **p, const unsigned char *end,
                      size_t *len, unsigned char expected_tag);
int tiny_asn1_get_int(const unsigned char **p, const unsigned char *end, int *value);
int tiny_asn1_skip_tlv(const unsigned char **p, const unsigned char *end);
int tiny_asn1_parse_algorithm_identifier(const unsigned char **p, const unsigned char *end,
                                         tiny_asn1_tlv *alg_oid, tiny_asn1_tlv *params);

int tiny_asn1_oid_from_hash(tiny_asn1_hash_alg alg,
                            const unsigned char **oid, size_t *oid_len);
int tiny_asn1_hash_from_oid(const unsigned char *oid, size_t oid_len,
                            tiny_asn1_hash_alg *alg);
int tiny_asn1_oid_from_hmac_hash(tiny_asn1_hash_alg alg,
                                 const unsigned char **oid, size_t *oid_len);
int tiny_asn1_hmac_hash_from_oid(const unsigned char *oid, size_t oid_len,
                                 tiny_asn1_hash_alg *alg);
int tiny_asn1_oid_from_sig_alg(tiny_asn1_sig_alg alg,
                               const unsigned char **oid, size_t *oid_len);
int tiny_asn1_sig_alg_from_oid(const unsigned char *oid, size_t oid_len,
                               tiny_asn1_sig_alg *alg);
int tiny_asn1_oid_cmp_pbm(const unsigned char **oid, size_t *oid_len);
int tiny_asn1_oid_cmp_implicit_confirm(const unsigned char **oid, size_t *oid_len);
int tiny_asn1_oid_rfc4210_hmac_sha1(const unsigned char **oid, size_t *oid_len);

int tiny_asn1_ec_curve_from_name(const char *name, tiny_asn1_ec_curve *curve);
int tiny_asn1_oid_from_ec_curve(tiny_asn1_ec_curve curve,
                                const unsigned char **oid, size_t *oid_len);
int tiny_asn1_name_to_der(const char *name, unsigned char **out, size_t *out_len);
int tiny_asn1_name_to_string(const unsigned char *name_der, size_t name_der_len,
                             char *out, size_t out_len);
int tiny_asn1_x509_get_subject_public_key_info(const unsigned char *cert_der,
                                               size_t cert_der_len,
                                               const unsigned char **spki_der,
                                               size_t *spki_der_len);
int tiny_asn1_x509_get_subject_key_identifier(const unsigned char *cert_der,
                                              size_t cert_der_len,
                                              const unsigned char **key_id,
                                              size_t *key_id_len);
int tiny_asn1_build_ec_subject_public_key_info(tiny_asn1_ec_curve curve,
                                               const unsigned char *public_key,
                                               size_t public_key_len,
                                               unsigned char **out,
                                               size_t *out_len);

const char *tiny_asn1_strerror(int code);

#ifdef __cplusplus
}
#endif

#endif
