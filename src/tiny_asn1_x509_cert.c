#include "tiny_asn1/tiny_asn1.h"

#include <string.h>

static const unsigned char OID_SUBJECT_KEY_IDENTIFIER[] = { 0x55, 0x1D, 0x0E };

static int tiny_asn1_oid_equals(const tiny_asn1_tlv *oid_tlv,
                                const unsigned char *oid, size_t oid_len)
{
    return oid_tlv != NULL &&
           oid_tlv->tag == TINY_ASN1_TAG_OID &&
           oid_tlv->value_len == oid_len &&
           memcmp(oid_tlv->value, oid, oid_len) == 0;
}

static int tiny_asn1_x509_get_tbs_certificate(const unsigned char *cert_der,
                                              size_t cert_der_len,
                                              tiny_asn1_tlv *tbs)
{
    const unsigned char *p = cert_der;
    const unsigned char *end = cert_der + cert_der_len;
    tiny_asn1_tlv cert_seq;
    int ret;

    if (cert_der == NULL || tbs == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }

    ret = tiny_asn1_expect_tlv(&p, end,
                               TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE,
                               &cert_seq);
    if (ret != 0) {
        return ret;
    }

    p = cert_seq.value;
    return tiny_asn1_expect_tlv(&p, cert_seq.value + cert_seq.value_len,
                                TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE,
                                tbs);
}

int tiny_asn1_x509_get_subject_public_key_info(const unsigned char *cert_der,
                                               size_t cert_der_len,
                                               const unsigned char **spki_der,
                                               size_t *spki_der_len)
{
    tiny_asn1_tlv tbs;
    tiny_asn1_tlv spki;
    const unsigned char *p;
    const unsigned char *end;
    int ret;

    if (cert_der == NULL || spki_der == NULL || spki_der_len == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }

    ret = tiny_asn1_x509_get_tbs_certificate(cert_der, cert_der_len, &tbs);
    if (ret != 0) {
        return ret;
    }

    p = tbs.value;
    end = tbs.value + tbs.value_len;

    if (p < end &&
        *p == (TINY_ASN1_TAG_CONTEXT_SPECIFIC | TINY_ASN1_TAG_CONSTRUCTED | 0)) {
        ret = tiny_asn1_skip_tlv(&p, end);
        if (ret != 0) {
            return ret;
        }
    }

    ret = tiny_asn1_skip_tlv(&p, end);
    if (ret != 0) {
        return ret;
    }
    ret = tiny_asn1_skip_tlv(&p, end);
    if (ret != 0) {
        return ret;
    }
    ret = tiny_asn1_skip_tlv(&p, end);
    if (ret != 0) {
        return ret;
    }
    ret = tiny_asn1_skip_tlv(&p, end);
    if (ret != 0) {
        return ret;
    }
    ret = tiny_asn1_skip_tlv(&p, end);
    if (ret != 0) {
        return ret;
    }

    ret = tiny_asn1_expect_tlv(&p, end,
                               TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE,
                               &spki);
    if (ret != 0) {
        return ret;
    }

    *spki_der = spki.ptr;
    *spki_der_len = spki.encoded_len;
    return 0;
}

int tiny_asn1_x509_get_subject_key_identifier(const unsigned char *cert_der,
                                              size_t cert_der_len,
                                              const unsigned char **key_id,
                                              size_t *key_id_len)
{
    tiny_asn1_tlv tbs;
    const unsigned char *p;
    const unsigned char *end;
    int ret;

    if (cert_der == NULL || key_id == NULL || key_id_len == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }

    ret = tiny_asn1_x509_get_tbs_certificate(cert_der, cert_der_len, &tbs);
    if (ret != 0) {
        return ret;
    }

    p = tbs.value;
    end = tbs.value + tbs.value_len;

    if (p < end &&
        *p == (TINY_ASN1_TAG_CONTEXT_SPECIFIC | TINY_ASN1_TAG_CONSTRUCTED | 0)) {
        ret = tiny_asn1_skip_tlv(&p, end);
        if (ret != 0) {
            return ret;
        }
    }

    ret = tiny_asn1_skip_tlv(&p, end);
    if (ret != 0) {
        return ret;
    }
    ret = tiny_asn1_skip_tlv(&p, end);
    if (ret != 0) {
        return ret;
    }
    ret = tiny_asn1_skip_tlv(&p, end);
    if (ret != 0) {
        return ret;
    }
    ret = tiny_asn1_skip_tlv(&p, end);
    if (ret != 0) {
        return ret;
    }
    ret = tiny_asn1_skip_tlv(&p, end);
    if (ret != 0) {
        return ret;
    }
    ret = tiny_asn1_skip_tlv(&p, end);
    if (ret != 0) {
        return ret;
    }

    while (p < end &&
           (*p == (TINY_ASN1_TAG_CONTEXT_SPECIFIC | 1) ||
            *p == (TINY_ASN1_TAG_CONTEXT_SPECIFIC | 2))) {
        ret = tiny_asn1_skip_tlv(&p, end);
        if (ret != 0) {
            return ret;
        }
    }

    if (p >= end ||
        *p != (TINY_ASN1_TAG_CONTEXT_SPECIFIC | TINY_ASN1_TAG_CONSTRUCTED | 3)) {
        return TINY_ASN1_ERR_UNSUPPORTED;
    }

    {
        tiny_asn1_tlv ext_wrapper;
        tiny_asn1_tlv ext_seq;

        ret = tiny_asn1_expect_tlv(&p, end,
                                   TINY_ASN1_TAG_CONTEXT_SPECIFIC |
                                   TINY_ASN1_TAG_CONSTRUCTED | 3,
                                   &ext_wrapper);
        if (ret != 0) {
            return ret;
        }

        p = ext_wrapper.value;
        ret = tiny_asn1_expect_tlv(&p, ext_wrapper.value + ext_wrapper.value_len,
                                   TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE,
                                   &ext_seq);
        if (ret != 0) {
            return ret;
        }

        p = ext_seq.value;
        end = ext_seq.value + ext_seq.value_len;
    }

    while (p < end) {
        tiny_asn1_tlv ext;
        tiny_asn1_tlv oid;
        tiny_asn1_tlv extn_value;
        const unsigned char *ext_p;
        const unsigned char *ext_end;

        ret = tiny_asn1_expect_tlv(&p, end,
                                   TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE,
                                   &ext);
        if (ret != 0) {
            return ret;
        }

        ext_p = ext.value;
        ext_end = ext.value + ext.value_len;

        ret = tiny_asn1_expect_tlv(&ext_p, ext_end, TINY_ASN1_TAG_OID, &oid);
        if (ret != 0) {
            return ret;
        }

        if (ext_p < ext_end && *ext_p == TINY_ASN1_TAG_BOOLEAN) {
            ret = tiny_asn1_skip_tlv(&ext_p, ext_end);
            if (ret != 0) {
                return ret;
            }
        }

        ret = tiny_asn1_expect_tlv(&ext_p, ext_end,
                                   TINY_ASN1_TAG_OCTET_STRING, &extn_value);
        if (ret != 0) {
            return ret;
        }
        if (ext_p != ext_end) {
            return TINY_ASN1_ERR_SYNTAX;
        }

        if (tiny_asn1_oid_equals(&oid,
                                 OID_SUBJECT_KEY_IDENTIFIER,
                                 sizeof(OID_SUBJECT_KEY_IDENTIFIER))) {
            tiny_asn1_tlv ski;
            const unsigned char *wrapped = extn_value.value;

            ret = tiny_asn1_expect_tlv(&wrapped,
                                       extn_value.value + extn_value.value_len,
                                       TINY_ASN1_TAG_OCTET_STRING, &ski);
            if (ret != 0) {
                return ret;
            }
            if (wrapped != extn_value.value + extn_value.value_len) {
                return TINY_ASN1_ERR_SYNTAX;
            }

            *key_id = ski.value;
            *key_id_len = ski.value_len;
            return 0;
        }
    }

    return TINY_ASN1_ERR_UNSUPPORTED;
}
