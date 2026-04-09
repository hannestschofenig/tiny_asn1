add_library(tiny_asn1 STATIC
    src/tiny_asn1_der.c
    src/tiny_asn1_oid.c
    src/tiny_asn1_x509_name.c
    src/tiny_asn1_x509_cert.c
    src/tiny_asn1_spki.c
)

target_include_directories(tiny_asn1
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
