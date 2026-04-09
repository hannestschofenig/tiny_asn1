#include "tiny_asn1/tiny_asn1.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

typedef struct tiny_asn1_name_attr {
    const char *name;
    const unsigned char *oid;
    size_t oid_len;
    unsigned char value_tag;
} tiny_asn1_name_attr;

typedef struct tiny_asn1_parsed_rdn {
    const tiny_asn1_name_attr *attr;
    char *value;
} tiny_asn1_parsed_rdn;

static const unsigned char OID_ATTR_CN[] = { 0x55, 0x04, 0x03 };
static const unsigned char OID_ATTR_C[] = { 0x55, 0x04, 0x06 };
static const unsigned char OID_ATTR_L[] = { 0x55, 0x04, 0x07 };
static const unsigned char OID_ATTR_ST[] = { 0x55, 0x04, 0x08 };
static const unsigned char OID_ATTR_STREET[] = { 0x55, 0x04, 0x09 };
static const unsigned char OID_ATTR_O[] = { 0x55, 0x04, 0x0A };
static const unsigned char OID_ATTR_OU[] = { 0x55, 0x04, 0x0B };
static const unsigned char OID_ATTR_SERIAL[] = { 0x55, 0x04, 0x05 };
static const unsigned char OID_ATTR_UID[] = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01 };
static const unsigned char OID_ATTR_DC[] = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19 };
static const unsigned char OID_ATTR_EMAIL[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01 };

static const tiny_asn1_name_attr TINY_ASN1_NAME_ATTRS[] = {
    { "CN", OID_ATTR_CN, sizeof(OID_ATTR_CN), TINY_ASN1_TAG_UTF8_STRING },
    { "commonName", OID_ATTR_CN, sizeof(OID_ATTR_CN), TINY_ASN1_TAG_UTF8_STRING },
    { "C", OID_ATTR_C, sizeof(OID_ATTR_C), TINY_ASN1_TAG_PRINTABLE_STRING },
    { "countryName", OID_ATTR_C, sizeof(OID_ATTR_C), TINY_ASN1_TAG_PRINTABLE_STRING },
    { "L", OID_ATTR_L, sizeof(OID_ATTR_L), TINY_ASN1_TAG_UTF8_STRING },
    { "localityName", OID_ATTR_L, sizeof(OID_ATTR_L), TINY_ASN1_TAG_UTF8_STRING },
    { "ST", OID_ATTR_ST, sizeof(OID_ATTR_ST), TINY_ASN1_TAG_UTF8_STRING },
    { "stateOrProvinceName", OID_ATTR_ST, sizeof(OID_ATTR_ST), TINY_ASN1_TAG_UTF8_STRING },
    { "street", OID_ATTR_STREET, sizeof(OID_ATTR_STREET), TINY_ASN1_TAG_UTF8_STRING },
    { "streetAddress", OID_ATTR_STREET, sizeof(OID_ATTR_STREET), TINY_ASN1_TAG_UTF8_STRING },
    { "O", OID_ATTR_O, sizeof(OID_ATTR_O), TINY_ASN1_TAG_UTF8_STRING },
    { "organizationName", OID_ATTR_O, sizeof(OID_ATTR_O), TINY_ASN1_TAG_UTF8_STRING },
    { "OU", OID_ATTR_OU, sizeof(OID_ATTR_OU), TINY_ASN1_TAG_UTF8_STRING },
    { "organizationalUnitName", OID_ATTR_OU, sizeof(OID_ATTR_OU), TINY_ASN1_TAG_UTF8_STRING },
    { "serialNumber", OID_ATTR_SERIAL, sizeof(OID_ATTR_SERIAL), TINY_ASN1_TAG_PRINTABLE_STRING },
    { "UID", OID_ATTR_UID, sizeof(OID_ATTR_UID), TINY_ASN1_TAG_UTF8_STRING },
    { "DC", OID_ATTR_DC, sizeof(OID_ATTR_DC), TINY_ASN1_TAG_IA5_STRING },
    { "emailAddress", OID_ATTR_EMAIL, sizeof(OID_ATTR_EMAIL), TINY_ASN1_TAG_IA5_STRING },
    { "E", OID_ATTR_EMAIL, sizeof(OID_ATTR_EMAIL), TINY_ASN1_TAG_IA5_STRING }
};

static int tiny_asn1_oid_equals(const unsigned char *left, size_t left_len,
                                const unsigned char *right, size_t right_len)
{
    return left_len == right_len && memcmp(left, right, left_len) == 0;
}

static const char *tiny_asn1_attr_label_from_oid(const unsigned char *oid, size_t oid_len)
{
    if (tiny_asn1_oid_equals(oid, oid_len, OID_ATTR_CN, sizeof(OID_ATTR_CN))) {
        return "CN";
    }
    if (tiny_asn1_oid_equals(oid, oid_len, OID_ATTR_C, sizeof(OID_ATTR_C))) {
        return "C";
    }
    if (tiny_asn1_oid_equals(oid, oid_len, OID_ATTR_L, sizeof(OID_ATTR_L))) {
        return "L";
    }
    if (tiny_asn1_oid_equals(oid, oid_len, OID_ATTR_ST, sizeof(OID_ATTR_ST))) {
        return "ST";
    }
    if (tiny_asn1_oid_equals(oid, oid_len, OID_ATTR_STREET, sizeof(OID_ATTR_STREET))) {
        return "street";
    }
    if (tiny_asn1_oid_equals(oid, oid_len, OID_ATTR_O, sizeof(OID_ATTR_O))) {
        return "O";
    }
    if (tiny_asn1_oid_equals(oid, oid_len, OID_ATTR_OU, sizeof(OID_ATTR_OU))) {
        return "OU";
    }
    if (tiny_asn1_oid_equals(oid, oid_len, OID_ATTR_SERIAL, sizeof(OID_ATTR_SERIAL))) {
        return "serialNumber";
    }
    if (tiny_asn1_oid_equals(oid, oid_len, OID_ATTR_UID, sizeof(OID_ATTR_UID))) {
        return "UID";
    }
    if (tiny_asn1_oid_equals(oid, oid_len, OID_ATTR_DC, sizeof(OID_ATTR_DC))) {
        return "DC";
    }
    if (tiny_asn1_oid_equals(oid, oid_len, OID_ATTR_EMAIL, sizeof(OID_ATTR_EMAIL))) {
        return "emailAddress";
    }
    return NULL;
}

static int tiny_asn1_ascii_casecmp(const char *left, const char *right)
{
    unsigned char lch;
    unsigned char rch;

    if (left == NULL || right == NULL) {
        return left == right ? 0 : (left == NULL ? -1 : 1);
    }

    while (*left != '\0' && *right != '\0') {
        lch = (unsigned char) *left++;
        rch = (unsigned char) *right++;
        if (lch >= 'A' && lch <= 'Z') {
            lch = (unsigned char) (lch - 'A' + 'a');
        }
        if (rch >= 'A' && rch <= 'Z') {
            rch = (unsigned char) (rch - 'A' + 'a');
        }
        if (lch != rch) {
            return (int) lch - (int) rch;
        }
    }
    return (int) (unsigned char) *left - (int) (unsigned char) *right;
}

static void tiny_asn1_trim_span(const char **begin, const char **end)
{
    while (*begin < *end && isspace((unsigned char) **begin)) {
        (*begin)++;
    }
    while (*end > *begin && isspace((unsigned char) (*end)[-1])) {
        (*end)--;
    }
}

static const tiny_asn1_name_attr *tiny_asn1_find_name_attr(const char *key)
{
    size_t i;

    for (i = 0; i < sizeof(TINY_ASN1_NAME_ATTRS) / sizeof(TINY_ASN1_NAME_ATTRS[0]); ++i) {
        if (tiny_asn1_ascii_casecmp(key, TINY_ASN1_NAME_ATTRS[i].name) == 0) {
            return &TINY_ASN1_NAME_ATTRS[i];
        }
    }
    return NULL;
}

static int tiny_asn1_dup_unescaped(const char *begin, const char *end, char **out)
{
    size_t len = 0;
    char *dst;
    const char *cur;

    if (out == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }

    for (cur = begin; cur < end; ++cur) {
        if (*cur == '\\') {
            if (cur + 1 >= end) {
                return TINY_ASN1_ERR_SYNTAX;
            }
            cur++;
        }
        len++;
    }

    dst = calloc(1, len + 1U);
    if (dst == NULL) {
        return TINY_ASN1_ERR_ALLOC;
    }

    len = 0;
    for (cur = begin; cur < end; ++cur) {
        if (*cur == '\\') {
            cur++;
        }
        dst[len++] = *cur;
    }
    dst[len] = '\0';
    *out = dst;
    return 0;
}

static int tiny_asn1_parse_rdn(const char *segment_begin, const char *segment_end,
                               tiny_asn1_parsed_rdn *rdn)
{
    const char *eq = NULL;
    const char *key_begin = segment_begin;
    const char *key_end;
    const char *value_begin;
    const char *value_end = segment_end;
    char *key = NULL;
    int ret;

    if (rdn == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }

    for (eq = segment_begin; eq < segment_end; ++eq) {
        if (*eq == '\\') {
            if (eq + 1 < segment_end) {
                eq++;
            }
            continue;
        }
        if (*eq == '+') {
            return TINY_ASN1_ERR_UNSUPPORTED;
        }
        if (*eq == '=') {
            break;
        }
    }
    if (eq == NULL || eq >= segment_end || *eq != '=') {
        return TINY_ASN1_ERR_SYNTAX;
    }

    key_end = eq;
    value_begin = eq + 1;
    tiny_asn1_trim_span(&key_begin, &key_end);
    tiny_asn1_trim_span(&value_begin, &value_end);

    if (key_begin == key_end) {
        return TINY_ASN1_ERR_SYNTAX;
    }

    ret = tiny_asn1_dup_unescaped(key_begin, key_end, &key);
    if (ret != 0) {
        return ret;
    }

    rdn->attr = tiny_asn1_find_name_attr(key);
    free(key);
    if (rdn->attr == NULL) {
        return TINY_ASN1_ERR_UNSUPPORTED;
    }

    ret = tiny_asn1_dup_unescaped(value_begin, value_end, &rdn->value);
    if (ret != 0) {
        return ret;
    }
    if (rdn->attr->value_tag == TINY_ASN1_TAG_PRINTABLE_STRING &&
        strlen(rdn->value) == 0U) {
        free(rdn->value);
        rdn->value = NULL;
        return TINY_ASN1_ERR_INVALID_VALUE;
    }
    return 0;
}

int tiny_asn1_name_to_der(const char *name, unsigned char **out, size_t *out_len)
{
    tiny_asn1_parsed_rdn *rdns = NULL;
    size_t rdn_count = 0;
    size_t rdns_cap = 0;
    const char *segment_begin;
    const char *cur;
    unsigned char buf[2048];
    unsigned char *p = buf + sizeof(buf);
    size_t total_len = 0;
    size_t i;
    int ret = 0;

    if (name == NULL || out == NULL || out_len == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }
    *out = NULL;
    *out_len = 0;

    segment_begin = name;
    for (cur = name; ; ++cur) {
        int at_end = (*cur == '\0');
        int split = at_end;

        if (!at_end) {
            if (*cur == '\\') {
                if (cur[1] != '\0') {
                    cur++;
                }
                continue;
            }
            split = (*cur == ',');
        }

        if (split) {
            tiny_asn1_parsed_rdn rdn;

            memset(&rdn, 0, sizeof(rdn));
            ret = tiny_asn1_parse_rdn(segment_begin, cur, &rdn);
            if (ret != 0) {
                goto cleanup;
            }

            if (rdn_count == rdns_cap) {
                size_t new_cap = rdns_cap == 0U ? 4U : rdns_cap * 2U;
                tiny_asn1_parsed_rdn *tmp = realloc(rdns, new_cap * sizeof(*rdns));
                if (tmp == NULL) {
                    free(rdn.value);
                    ret = TINY_ASN1_ERR_ALLOC;
                    goto cleanup;
                }
                rdns = tmp;
                rdns_cap = new_cap;
            }
            rdns[rdn_count++] = rdn;
            if (at_end) {
                break;
            }
            segment_begin = cur + 1;
        }
    }

    for (i = rdn_count; i > 0U; --i) {
        const tiny_asn1_parsed_rdn *rdn = &rdns[i - 1U];
        size_t value_len = strlen(rdn->value);
        size_t atv_len = 0;
        size_t set_len = 0;

        ret = tiny_asn1_write_raw_buffer(&p, buf, (const unsigned char *) rdn->value, value_len);
        if (ret < 0) {
            goto cleanup;
        }
        atv_len += (size_t) ret;
        ret = tiny_asn1_write_len(&p, buf, value_len);
        if (ret < 0) {
            goto cleanup;
        }
        atv_len += (size_t) ret;
        ret = tiny_asn1_write_tag(&p, buf, rdn->attr->value_tag);
        if (ret < 0) {
            goto cleanup;
        }
        atv_len += (size_t) ret;
        ret = tiny_asn1_write_oid(&p, buf, rdn->attr->oid, rdn->attr->oid_len);
        if (ret < 0) {
            goto cleanup;
        }
        atv_len += (size_t) ret;
        ret = tiny_asn1_write_len(&p, buf, atv_len);
        if (ret < 0) {
            goto cleanup;
        }
        atv_len += (size_t) ret;
        ret = tiny_asn1_write_tag(&p, buf, TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE);
        if (ret < 0) {
            goto cleanup;
        }
        atv_len += (size_t) ret;

        set_len = atv_len;
        ret = tiny_asn1_write_len(&p, buf, set_len);
        if (ret < 0) {
            goto cleanup;
        }
        set_len += (size_t) ret;
        ret = tiny_asn1_write_tag(&p, buf, TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SET);
        if (ret < 0) {
            goto cleanup;
        }
        set_len += (size_t) ret;
        total_len += set_len;
    }

    ret = tiny_asn1_write_len(&p, buf, total_len);
    if (ret < 0) {
        goto cleanup;
    }
    total_len += (size_t) ret;
    ret = tiny_asn1_write_tag(&p, buf, TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE);
    if (ret < 0) {
        goto cleanup;
    }
    total_len += (size_t) ret;

    *out = calloc(1, total_len);
    if (*out == NULL) {
        ret = TINY_ASN1_ERR_ALLOC;
        goto cleanup;
    }
    memcpy(*out, p, total_len);
    *out_len = total_len;
    ret = 0;

cleanup:
    if (ret != 0) {
        free(*out);
        *out = NULL;
        *out_len = 0;
    }
    for (i = 0; i < rdn_count; ++i) {
        free(rdns[i].value);
    }
    free(rdns);
    return ret;
}

static int tiny_asn1_append_text(char **out, size_t *remaining, const char *text)
{
    size_t len;

    if (out == NULL || *out == NULL || remaining == NULL || text == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }

    len = strlen(text);
    if (*remaining <= len) {
        return TINY_ASN1_ERR_BUF_TOO_SMALL;
    }

    memcpy(*out, text, len);
    *out += len;
    **out = '\0';
    *remaining -= len;
    return 0;
}

static int tiny_asn1_append_char(char **out, size_t *remaining, char ch)
{
    if (out == NULL || *out == NULL || remaining == NULL) {
        return TINY_ASN1_ERR_PARAM;
    }
    if (*remaining <= 1U) {
        return TINY_ASN1_ERR_BUF_TOO_SMALL;
    }

    **out = ch;
    (*out)++;
    **out = '\0';
    *remaining -= 1U;
    return 0;
}

static int tiny_asn1_append_escaped_value(char **out, size_t *remaining,
                                          const unsigned char *value,
                                          size_t value_len)
{
    size_t i;
    int ret;

    if (out == NULL || *out == NULL || remaining == NULL ||
        (value == NULL && value_len != 0U)) {
        return TINY_ASN1_ERR_PARAM;
    }

    for (i = 0; i < value_len; ++i) {
        if (value[i] == ',' || value[i] == '+' || value[i] == '=' || value[i] == '\\') {
            ret = tiny_asn1_append_char(out, remaining, '\\');
            if (ret != 0) {
                return ret;
            }
        }
        ret = tiny_asn1_append_char(out, remaining, (char) value[i]);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

static int tiny_asn1_append_bmp_value(char **out, size_t *remaining,
                                      const unsigned char *value, size_t value_len)
{
    size_t i;
    int ret;
    unsigned char ch;

    if ((value_len % 2U) != 0U) {
        return TINY_ASN1_ERR_SYNTAX;
    }

    for (i = 0; i < value_len; i += 2U) {
        ch = value[i] == 0U ? value[i + 1U] : (unsigned char) '?';
        if (ch == ',' || ch == '+' || ch == '=' || ch == '\\') {
            ret = tiny_asn1_append_char(out, remaining, '\\');
            if (ret != 0) {
                return ret;
            }
        }
        ret = tiny_asn1_append_char(out, remaining, (char) ch);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

int tiny_asn1_name_to_string(const unsigned char *name_der, size_t name_der_len,
                             char *out, size_t out_len)
{
    tiny_asn1_tlv name_seq;
    const unsigned char *p = name_der;
    const unsigned char *end = name_der + name_der_len;
    char *dst = out;
    size_t remaining = out_len;
    int first = 1;
    int ret;

    if (name_der == NULL || out == NULL || out_len == 0U) {
        return TINY_ASN1_ERR_PARAM;
    }

    *out = '\0';

    ret = tiny_asn1_expect_tlv(&p, end,
                               TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE,
                               &name_seq);
    if (ret != 0) {
        return ret;
    }
    if (p != end) {
        return TINY_ASN1_ERR_SYNTAX;
    }

    p = name_seq.value;
    end = name_seq.value + name_seq.value_len;

    while (p < end) {
        tiny_asn1_tlv rdn_set;
        tiny_asn1_tlv atv_seq;
        tiny_asn1_tlv oid;
        tiny_asn1_tlv value;
        const unsigned char *rdn_p;
        const unsigned char *rdn_end;
        const char *label;

        ret = tiny_asn1_expect_tlv(&p, end,
                                   TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SET,
                                   &rdn_set);
        if (ret != 0) {
            return ret;
        }

        rdn_p = rdn_set.value;
        rdn_end = rdn_set.value + rdn_set.value_len;
        ret = tiny_asn1_expect_tlv(&rdn_p, rdn_end,
                                   TINY_ASN1_TAG_CONSTRUCTED | TINY_ASN1_TAG_SEQUENCE,
                                   &atv_seq);
        if (ret != 0) {
            return ret;
        }
        if (rdn_p != rdn_end) {
            return TINY_ASN1_ERR_UNSUPPORTED;
        }

        rdn_p = atv_seq.value;
        rdn_end = atv_seq.value + atv_seq.value_len;

        ret = tiny_asn1_expect_tlv(&rdn_p, rdn_end, TINY_ASN1_TAG_OID, &oid);
        if (ret != 0) {
            return ret;
        }
        ret = tiny_asn1_read_tlv(&rdn_p, rdn_end, &value);
        if (ret != 0) {
            return ret;
        }
        if (rdn_p != rdn_end) {
            return TINY_ASN1_ERR_SYNTAX;
        }

        label = tiny_asn1_attr_label_from_oid(oid.value, oid.value_len);
        if (label == NULL) {
            return TINY_ASN1_ERR_UNSUPPORTED;
        }

        if (!first) {
            ret = tiny_asn1_append_text(&dst, &remaining, ", ");
            if (ret != 0) {
                return ret;
            }
        }
        first = 0;

        ret = tiny_asn1_append_text(&dst, &remaining, label);
        if (ret != 0) {
            return ret;
        }
        ret = tiny_asn1_append_char(&dst, &remaining, '=');
        if (ret != 0) {
            return ret;
        }

        switch (value.tag) {
            case TINY_ASN1_TAG_UTF8_STRING:
            case TINY_ASN1_TAG_PRINTABLE_STRING:
            case TINY_ASN1_TAG_IA5_STRING:
                ret = tiny_asn1_append_escaped_value(&dst, &remaining,
                                                     value.value, value.value_len);
                break;
            case TINY_ASN1_TAG_BMP_STRING:
                ret = tiny_asn1_append_bmp_value(&dst, &remaining,
                                                 value.value, value.value_len);
                break;
            default:
                ret = TINY_ASN1_ERR_UNSUPPORTED;
                break;
        }
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}
