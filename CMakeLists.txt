cmake_minimum_required(VERSION 3.4)
project(makefst)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set( CMAKE_C_STANDARD 11 )
set( CMAKE_CXX_STANDARD 11 )

include_directories(${makefst_SOURCE_DIR})
include_directories(${makefst_SOURCE_DIR}/polarssl)
include_directories(${makefst_SOURCE_DIR}/pki)
include_directories(${makefst_SOURCE_DIR}/ezxml)

set(SOURCE_FILES main.c wup.c wup.h utils.c utils.h tmd.c tmd.h tik.c tik.h certs.c certs.h crypto.c crypto.h types.h lib.h polarssl/aes.c polarssl/aes.h polarssl/base64.c polarssl/base64.h polarssl/bignum.c polarssl/bignum.h polarssl/bn_mul.h polarssl/config.h polarssl/rsa.c polarssl/rsa.h polarssl/sha1.c polarssl/sha1.h polarssl/sha2.c polarssl/sha2.h fst.h ezxml/ezxml.c miniz.c miniz.h)
add_executable(makefst ${SOURCE_FILES})