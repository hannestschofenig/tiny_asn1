#include "tiny_asn1/tiny_asn1.h"

#include <limits.h>
#include <string.h>

int tiny_asn1_write_raw_buffer(unsigned char **p, unsigned char *start,
                               const unsigned char *buf, size_t len)
{
    if (p == NULL || *p == NULL || start == NULL || (buf == NULL && len != 0U)) {
        return TINY_ASN1_ERR_PARAM;
    }
    if ((size_t) (*p - start) < len) {
        return TINY_ASN1_ERR_BUF_TOO_SMALL;
    }
    *p -= len;
    if (len > 0U) {
        memcpy(*p, buf, len);
    }
    return (int) len;
}

int tiny_asn1_write_len(unsigned char **p, unsigned char *start, size_t len)
{
    size_t tmp = len;
    size_t octets = 0;

    if (p == NULL || *p == NULL || start == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }

    if (len < 128U) {
        if (*p <= start) {
            return TINY_ASN1_ERR_BUF_TOO_SMALL;
        }
        *--(*p) = (unsigned char) len;
        return 1;
    }

    while (tmp > 0U) {
        if (*p <= start) {
            return TINY_ASN1_ERR_BUF_TOO_SMALL;
        }
        *--(*p) = (unsigned char) (tmp & 0xFFU);
        tmp >>= 8;
        octets++;
    }

    if (*p <= start || octets > 126U) {
        return TINY_ASN1_ERR_BUF_TOO_SMALL;
    }
    *--(*p) = (unsigned char) (0x80U | octets);
    return (int) (octets + 1U);
}

int tiny_asn1_write_tag(unsigned char **p, unsigned char *start, unsigned char tag)
{
    if (p == NULL || *p == NULL || start == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }
    if (*p <= start) {
        return TINY_ASN1_ERR_BUF_TOO_SMALL;
    }
    *--(*p) = tag;
    return 1;
}

int tiny_asn1_write_int(unsigned char **p, unsigned char *start, int value)
{
    unsigned char buf[sizeof(int) + 1U];
    unsigned int uvalue;
    size_t value_len = 0;
    size_t total_len = 0;
    size_t offset = sizeof(buf);
    int ret;

    if (p == NULL || *p == NULL || start == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }
    if (value < 0) {
        return TINY_ASN1_ERR_UNSUPPORTED;
    }

    uvalue = (unsigned int) value;
    do {
        buf[--offset] = (unsigned char) (uvalue & 0xFFU);
        value_len++;
        uvalue >>= 8;
    } while (uvalue > 0U);

    if ((buf[offset] & 0x80U) != 0U) {
        buf[--offset] = 0;
        value_len++;
    }

    ret = tiny_asn1_write_raw_buffer(p, start, buf + offset, value_len);
    if (ret < 0) {
        return ret;
    }
    total_len += (size_t) ret;

    ret = tiny_asn1_write_len(p, start, total_len);
    if (ret < 0) {
        return ret;
    }
    total_len += (size_t) ret;

    ret = tiny_asn1_write_tag(p, start, TINY_ASN1_TAG_INTEGER);
    if (ret < 0) {
        return ret;
    }
    total_len += (size_t) ret;
    return (int) total_len;
}

int tiny_asn1_write_null(unsigned char **p, unsigned char *start)
{
    int ret;
    size_t len = 0;

    ret = tiny_asn1_write_len(p, start, 0);
    if (ret < 0) {
        return ret;
    }
    len += (size_t) ret;
    ret = tiny_asn1_write_tag(p, start, TINY_ASN1_TAG_NULL);
    if (ret < 0) {
        return ret;
    }
    len += (size_t) ret;
    return (int) len;
}

int tiny_asn1_write_oid(unsigned char **p, unsigned char *start,
                        const unsigned char *oid, size_t oid_len)
{
    int ret;
    size_t len = 0;

    ret = tiny_asn1_write_raw_buffer(p, start, oid, oid_len);
    if (ret < 0) {
        return ret;
    }
    len += (size_t) ret;
    ret = tiny_asn1_write_len(p, start, oid_len);
    if (ret < 0) {
        return ret;
    }
    len += (size_t) ret;
    ret = tiny_asn1_write_tag(p, start, TINY_ASN1_TAG_OID);
    if (ret < 0) {
        return ret;
    }
    len += (size_t) ret;
    return (int) len;
}

int tiny_asn1_write_octet_string(unsigned char **p, unsigned char *start,
                                 const unsigned char *buf, size_t len)
{
    int ret;
    size_t written = 0;

    ret = tiny_asn1_write_raw_buffer(p, start, buf, len);
    if (ret < 0) {
        return ret;
    }
    written += (size_t) ret;
    ret = tiny_asn1_write_len(p, start, len);
    if (ret < 0) {
        return ret;
    }
    written += (size_t) ret;
    ret = tiny_asn1_write_tag(p, start, TINY_ASN1_TAG_OCTET_STRING);
    if (ret < 0) {
        return ret;
    }
    written += (size_t) ret;
    return (int) written;
}

int tiny_asn1_write_bit_string(unsigned char **p, unsigned char *start,
                               const unsigned char *buf, size_t len,
                               unsigned char unused_bits)
{
    int ret;
    size_t written = 0;

    if (unused_bits > 7U) {
        return TINY_ASN1_ERR_PARAM;
    }

    ret = tiny_asn1_write_raw_buffer(p, start, buf, len);
    if (ret < 0) {
        return ret;
    }
    written += (size_t) ret;
    if (*p <= start) {
        return TINY_ASN1_ERR_BUF_TOO_SMALL;
    }
    *--(*p) = unused_bits;
    written += 1U;
    ret = tiny_asn1_write_len(p, start, written);
    if (ret < 0) {
        return ret;
    }
    written += (size_t) ret;
    ret = tiny_asn1_write_tag(p, start, TINY_ASN1_TAG_BIT_STRING);
    if (ret < 0) {
        return ret;
    }
    written += (size_t) ret;
    return (int) written;
}

int tiny_asn1_write_algorithm_identifier(unsigned char **p, unsigned char *start,
                                         const unsigned char *oid, size_t oid_len,
                                         size_t params_len)
{
    int ret;
    size_t len = params_len;

    if (params_len == 0U) {
        ret = tiny_asn1_write_null(p, start);
        if (ret < 0) {
            return ret;
        }
        len += (size_t) ret;
    }

    ret = tiny_asn1_write_oid(p, start, oid, oid_len);
    if (ret < 0) {
        return ret;
    }
    len += (size_t) ret;
    ret = tiny_asn1_write_len(p, start, len);
    if (ret < 0) {
        return ret;
    }
    len += (size_t) ret;
    ret = tiny_asn1_write_tag(p, start, TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE);
    if (ret < 0) {
        return ret;
    }
    len += (size_t) ret;
    return (int) len;
}

int tiny_asn1_read_tlv(const unsigned char **p, const unsigned char *end,
                       tiny_asn1_tlv *tlv)
{
    const unsigned char *cur;
    const unsigned char *len_ptr;
    size_t len;
    size_t i;
    unsigned char len_octets;

    if (p == NULL || *p == NULL || end == NULL || tlv == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }
    if (*p >= end) {
        return TINY_ASN1_ERR_INVALID_LEN;
    }

    cur = *p;
    tlv->tag = *cur++;
    tlv->ptr = *p;

    if (cur >= end) {
        return TINY_ASN1_ERR_INVALID_LEN;
    }

    len_ptr = cur;
    if ((*cur & 0x80U) == 0U) {
        len = (size_t) *cur++;
    } else {
        len_octets = (unsigned char) (*cur & 0x7FU);
        cur++;
        if (len_octets == 0U || len_octets > sizeof(size_t) || (size_t) (end - cur) < len_octets) {
            return TINY_ASN1_ERR_INVALID_LEN;
        }
        len = 0U;
        for (i = 0; i < len_octets; ++i) {
            len = (len << 8U) | cur[i];
        }
        cur += len_octets;
    }

    if ((size_t) (end - cur) < len) {
        return TINY_ASN1_ERR_INVALID_LEN;
    }

    tlv->value = cur;
    tlv->value_len = len;
    tlv->encoded_len = (size_t) (cur + len - tlv->ptr);
    *p = cur + len;
    (void) len_ptr;
    return 0;
}

int tiny_asn1_expect_tlv(const unsigned char **p, const unsigned char *end,
                         unsigned char expected_tag, tiny_asn1_tlv *tlv)
{
    int ret;

    ret = tiny_asn1_read_tlv(p, end, tlv);
    if (ret != 0) {
        return ret;
    }
    if (tlv->tag != expected_tag) {
        return TINY_ASN1_ERR_INVALID_TAG;
    }
    return 0;
}

int tiny_asn1_get_tag(const unsigned char **p, const unsigned char *end,
                      size_t *len, unsigned char expected_tag)
{
    tiny_asn1_tlv tlv;
    int ret;

    if (len == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }
    ret = tiny_asn1_expect_tlv(p, end, expected_tag, &tlv);
    if (ret != 0) {
        return ret;
    }
    *len = tlv.value_len;
    *p = tlv.value;
    return 0;
}

int tiny_asn1_get_int(const unsigned char **p, const unsigned char *end, int *value)
{
    tiny_asn1_tlv tlv;
    unsigned int accum = 0;
    size_t i;
    int negative = 0;
    int ret;

    if (value == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }

    ret = tiny_asn1_expect_tlv(p, end, TINY_ASN1_TAG_INTEGER, &tlv);
    if (ret != 0) {
        return ret;
    }
    if (tlv.value_len == 0U || tlv.value_len > sizeof(int) + 1U) {
        return TINY_ASN1_ERR_INVALID_VALUE;
    }

    negative = (tlv.value[0] & 0x80U) != 0U;
    if (negative) {
        return TINY_ASN1_ERR_UNSUPPORTED;
    }

    for (i = 0; i < tlv.value_len; ++i) {
        accum = (accum << 8U) | tlv.value[i];
    }
    if (accum > (unsigned int) INT_MAX) {
        return TINY_ASN1_ERR_INVALID_VALUE;
    }
    *value = (int) accum;
    return 0;
}

int tiny_asn1_skip_tlv(const unsigned char **p, const unsigned char *end)
{
    tiny_asn1_tlv tlv;
    return tiny_asn1_read_tlv(p, end, &tlv);
}

int tiny_asn1_parse_algorithm_identifier(const unsigned char **p, const unsigned char *end,
                                         tiny_asn1_tlv *alg_oid, tiny_asn1_tlv *params)
{
    tiny_asn1_tlv seq;
    const unsigned char *cur;
    int ret;

    if (p == NULL || *p == NULL || end == NULL || alg_oid == NULL || params == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }

    ret = tiny_asn1_expect_tlv(p, end, TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE, &seq);
    if (ret != 0) {
        return ret;
    }

    cur = seq.value;
    ret = tiny_asn1_expect_tlv(&cur, seq.value + seq.value_len, TINY_ASN1_TAG_OID, alg_oid);
    if (ret != 0) {
        return ret;
    }

    memset(params, 0, sizeof(*params));
    if (cur < seq.value + seq.value_len) {
        ret = tiny_asn1_read_tlv(&cur, seq.value + seq.value_len, params);
        if (ret != 0) {
            return ret;
        }
    }

    return cur == seq.value + seq.value_len ? 0 : TINY_ASN1_ERR_SYNTAX;
}

const char *tiny_asn1_strerror(int code)
{
    switch (code) {
        case TINY_ASN1_OK:
            return "success";
        case TINY_ASN1_ERR_PARAM:
            return "invalid parameter";
        case TINY_ASN1_ERR_ALLOC:
            return "allocation failed";
        case TINY_ASN1_ERR_BUF_TOO_SMALL:
            return "buffer too small";
        case TINY_ASN1_ERR_INVALID_TAG:
            return "unexpected tag";
        case TINY_ASN1_ERR_INVALID_LEN:
            return "invalid length";
        case TINY_ASN1_ERR_INVALID_VALUE:
            return "invalid value";
        case TINY_ASN1_ERR_UNSUPPORTED:
            return "unsupported feature";
        case TINY_ASN1_ERR_SYNTAX:
            return "invalid ASN.1 syntax";
        default:
            return "unknown tiny_asn1 error";
    }
}
