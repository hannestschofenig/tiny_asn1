cmake_minimum_required(VERSION 3.14)
project(tiny_asn1 LANGUAGES C VERSION 0.1.0)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

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
