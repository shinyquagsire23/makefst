/*
 *  makefst - CDN FST packer and packager for Wii U homebrew
 *
 *  This code is licensed to you under the terms of the MIT License;
 *  see file LICENSE for details
 */

#ifndef _WUP_H_
#define _WUP_H_

#include "polarssl/aes.h"
#include "polarssl/rsa.h"
#include "polarssl/sha2.h"
#include "types.h"

typedef struct
{
	u8 ctr[16];
	u8 iv[16];
	aes_context aes;
} wup_aes_context;

typedef struct
{
	rsa_context rsa;
} wup_rsa_context;

typedef struct
{
	sha2_context sha;
} wup_sha256_context;

typedef enum
{
	KEY_ERR_LEN_MISMATCH,
	KEY_ERR_INVALID_NODE,
	KEY_OK
} keystatus;

typedef enum
{
	RSAKEY_INVALID,
	RSAKEY_PRIV,
	RSAKEY_PUB
} rsakeytype;

typedef struct
{
	unsigned char n[256];
	unsigned char e[3];
	unsigned char d[256];
	unsigned char p[128];
	unsigned char q[128];
	unsigned char dp[128];
	unsigned char dq[128];
	unsigned char qp[128];
	rsakeytype keytype;
} rsakey2048;

typedef struct
{
	unsigned char data[16];
	int valid;
} key128;

typedef struct
{
	key128 commonkey;
	key128 titlekey;
	key128 ncchkey;
	key128 ncchfixedsystemkey;
	rsakey2048 ncsdrsakey;
	rsakey2048 ncchrsakey;
	rsakey2048 ncchdescrsakey;
	rsakey2048 firmrsakey;
} keyset;


#ifdef __cplusplus
extern "C" {
#endif

void		wup_set_iv(wup_aes_context *ctx,
					   u8 *iv);

void		wup_add_counter(wup_aes_context *ctx,
							u32 block_num);

void		wup_set_counter(wup_aes_context *ctx,
							u8 *ctr);


void		wup_init_counter(wup_aes_context *ctx,
							 u8 *key,
							 u8 *ctr);


void		wup_crypt_counter_block(wup_aes_context *ctx,
									u8 *input,
									u8 *output);


void		wup_crypt_counter(wup_aes_context *ctx,
							  u8 *input,
							  u8 *output,
							  u32 size);


void		wup_init_cbc_encrypt(wup_aes_context *ctx,
								 u8 *key,
								 u8 *iv);

void		wup_init_cbc_decrypt(wup_aes_context *ctx,
								 u8 *key,
								 u8 *iv);

void		wup_encrypt_cbc(wup_aes_context *ctx,
							u8 *input,
							u8 *output,
							u32 size);

void		wup_decrypt_cbc(wup_aes_context *ctx,
							u8 *input,
							u8 *output,
							u32 size);

void		wup_rsa_init_key_pubmodulus(rsakey2048 *key,
										u8 *modulus);

void		wup_rsa_init_key_pub(rsakey2048 *key,
								 u8 *modulus,
								 u8 *exponent);

int			wup_rsa_init(wup_rsa_context *ctx,
							rsakey2048 *key);


void		wup_rsa_free(wup_rsa_context *ctx);

int			wup_rsa_verify_hash(const u8 *signature,
								   const u8 *hash,
								   rsakey2048 *key);

int			wup_rsa_sign_hash(const u8 *hash,
								 u8 *signature,
								 rsakey2048 *key);

int			wup_rsa_public(const u8 *signature,
							  u8 *output,
							  rsakey2048 *key);

void		wup_sha_256(const u8 *data,
						u32 size,
						u8 *hash);

int			wup_sha_256_verify(const u8 *data,
								  u32 size,
								  const u8 *checkhash);


void		wup_sha_256_init(wup_sha256_context *ctx);

void		wup_sha_256_update(wup_sha256_context *ctx,
							   const u8 *data,
							   u32 size);


void		wup_sha_256_finish(wup_sha256_context *ctx,
							   u8 *hash);

#ifdef __cplusplus
}
#endif

#endif // _WUP_H_
