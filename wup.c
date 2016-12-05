/*
 *  makefst - CDN FST packer and packager for Wii U homebrew
 *
 *  This code is licensed to you under the terms of the MIT License;
 *  see file LICENSE for details
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "wup.h"


void wup_set_iv(wup_aes_context *ctx,
				u8 *iv)
{
	memcpy(ctx->iv, iv, 16);
}

void wup_add_counter(wup_aes_context *ctx,
					 u32 block_num)
{
	u32 i, j;
	for (i = 0; i < block_num; i++) {
		for (j = 0x10; j > 0; j--) {
			// increment u8 by 1
			ctx->ctr[j - 1]++;

			// if it didn't overflow to 0, then we can exit now
			if (ctx->ctr[j - 1])
				break;

			// if we reach here, the next u8 needs to be incremented

			// Loop to beginning back if needed
			if (j == 1)
				j = 0x10;
		}
	}
}
				  
void wup_set_counter(wup_aes_context *ctx,
					 u8 *ctr)
{
	memcpy(ctx->ctr, ctr, 16);
}


void wup_init_counter(wup_aes_context *ctx,
					  u8 *key,
					  u8 *ctr)
{
	aes_setkey_enc(&ctx->aes, key, 128);
	wup_set_counter(ctx, ctr);
}


void wup_crypt_counter_block(wup_aes_context *ctx,
							 u8 *input,
							 u8 *output)
{
	int i;
	u8 stream[16];


	aes_crypt_ecb(&ctx->aes, AES_ENCRYPT, ctx->ctr, stream);


	if (input)
	{
		for(i=0; i<16; i++)
		{
			output[i] = stream[i] ^ input[i];
		}
	}
	else
	{
		for(i=0; i<16; i++)
			output[i] = stream[i];
	}

	wup_add_counter(ctx, 1);
}


void wup_crypt_counter(wup_aes_context *ctx,
					   u8 *input,
					   u8 *output,
					   u32 size)
{
	u8 stream[16];
	u32 i;

	while(size >= 16)
	{
		wup_crypt_counter_block(ctx, input, output);

		if (input)
			input += 16;
		if (output)
			output += 16;

		size -= 16;
	}

	if (size)
	{
		memset(stream, 0, 16);
		wup_crypt_counter_block(ctx, stream, stream);

		if (input)
		{
			for(i=0; i<size; i++)
				output[i] = input[i] ^ stream[i];
		}
		else
		{
			memcpy(output, stream, size);
		}
	}
}

void wup_init_cbc_encrypt(wup_aes_context *ctx,
						  u8 *key,
						  u8 *iv)
{
	aes_setkey_enc(&ctx->aes, key, 128);
	wup_set_iv(ctx, iv);
}

void wup_init_cbc_decrypt(wup_aes_context *ctx,
						  u8 *key,
						  u8 *iv)
{
	aes_setkey_dec(&ctx->aes, key, 128);
	wup_set_iv(ctx, iv);
}

void wup_encrypt_cbc(wup_aes_context *ctx,
					 u8 *input,
					 u8 *output,
					 u32 size)
{
	aes_crypt_cbc(&ctx->aes, AES_ENCRYPT, size, ctx->iv, input, output);
}

void wup_decrypt_cbc(wup_aes_context *ctx,
					 u8 *input,
					 u8 *output,
					 u32 size)
{
	aes_crypt_cbc(&ctx->aes, AES_DECRYPT, size, ctx->iv, input, output);
}

void wup_sha_256(const u8 *data,
				 u32 size,
				 u8 *hash)
{
	sha2(data, size, hash, 0);
}

int wup_sha_256_verify(const u8 *data,
					   u32 size,
					   const u8 *checkhash)
{
	u8 hash[0x20];

	sha2(data, size, hash, 0);

	if (memcmp(hash, checkhash, 0x20) == 0)
		return Good;
	else
		return Fail;
}

void wup_sha_256_init(wup_sha256_context *ctx)
{
	sha2_starts(&ctx->sha, 0);
}

void wup_sha_256_update(wup_sha256_context *ctx,
						const u8 *data,
						u32 size)
{
	sha2_update(&ctx->sha, data, size);
}


void wup_sha_256_finish(wup_sha256_context *ctx,
						u8 *hash)
{
	sha2_finish(&ctx->sha, hash);
}


void wup_rsa_init_key_pubmodulus(rsakey2048 *key, u8 *modulus)
{
	u8 exponent[3] = {0x01, 0x00, 0x01};

	wup_rsa_init_key_pub(key, modulus, exponent);
}

void wup_rsa_init_key_pub(rsakey2048 *key, u8 *modulus, u8 *exponent)
{
	key->keytype = RSAKEY_PUB;
	memcpy(key->n, modulus, 0x100);
	memcpy(key->e, exponent, 3);
}

int wup_rsa_init(wup_rsa_context *ctx, rsakey2048 *key)
{
	rsa_init(&ctx->rsa, RSA_PKCS_V15, 0);
	ctx->rsa.len = 0x100;

	if (key->keytype == RSAKEY_INVALID)
		goto clean;

	if (mpi_read_binary(&ctx->rsa.N, key->n, sizeof(key->n)))
		goto clean;
	if (mpi_read_binary(&ctx->rsa.E, key->e, sizeof(key->e)))
		goto clean;
	if (rsa_check_pubkey(&ctx->rsa))
		goto clean;

	if (key->keytype == RSAKEY_PRIV)
	{
		if (mpi_read_binary(&ctx->rsa.D, key->d, sizeof(key->d)))
			goto clean;
		if (mpi_read_binary(&ctx->rsa.P, key->p, sizeof(key->p)))
			goto clean;
		if (mpi_read_binary(&ctx->rsa.Q, key->q, sizeof(key->q)))
			goto clean;
		if (mpi_read_binary(&ctx->rsa.DP, key->dp, sizeof(key->dp)))
			goto clean;
		if (mpi_read_binary(&ctx->rsa.DQ, key->dq, sizeof(key->dq)))
			goto clean;
		if (mpi_read_binary(&ctx->rsa.QP, key->qp, sizeof(key->qp)))
			goto clean;
		if (rsa_check_privkey(&ctx->rsa))
			goto clean;
	}

	return 1;
clean:
	return 0;
}

int wup_rsa_verify_hash(const u8 *signature, const u8 *hash, rsakey2048 *key)
{
	wup_rsa_context ctx;
	u32 result;
//	u8 output[0x100];

	if (key->keytype == RSAKEY_INVALID)
		return Fail;

	wup_rsa_init(&ctx, key);
// 	memset(output, 0, 0x100);
//	result = wup_rsa_public(signature, output, key);
//	printf("Result = %d\n", result);
//	memdump(stdout, "output: ", output, 0x100);

	//result = rsa_pkcs1_verify(&ctx.rsa, RSA_PUBLIC, SIG_RSA_SHA256, 0x20, hash, (u8*)signature);

	wup_rsa_free(&ctx);

	if (result == 0)
		return Good;
	else
		return Fail;
}


int wup_rsa_sign_hash(const u8 *hash, u8 *signature, rsakey2048 *key)
{
	wup_rsa_context ctx;
	u32 result;

	wup_rsa_init(&ctx, key);

	//result = rsa_pkcs1_verify(&ctx.rsa, RSA_PUBLIC, SIG_RSA_SHA256, 0x20, hash, (u8*)signature);
	//result = rsa_pkcs1_sign(&ctx.rsa, RSA_PRIVATE, SIG_RSA_SHA256, 0x20, hash, signature);

	wup_rsa_free(&ctx);

	if (result == 0)
		return 1;
	else
		return 0;
}

int wup_rsa_public(const u8 *signature, u8 *output, rsakey2048 *key)
{
	wup_rsa_context ctx;
	u32 result;

	wup_rsa_init(&ctx, key);

	result = rsa_public(&ctx.rsa, signature, output);

	wup_rsa_free(&ctx);

	if (result == 0)
		return 1;
	else
		return 0;
}


void wup_rsa_free(wup_rsa_context *ctx)
{
	rsa_free(&ctx->rsa);
}

/*
 * Generate DP, DQ, QP based on private key
 */ 
#if 0
static int ctr_rsa_key_init(wup_rsa_context* ctx )
{
    int ret;
    mpi P1, Q1;

    mpi_init( &P1, &Q1, NULL );

    MPI_CHK( mpi_sub_int( &P1, &ctx->rsa.P, 1 ) );
    MPI_CHK( mpi_sub_int( &Q1, &ctx->rsa.Q, 1 ) );

	/*
     * DP = D mod (P - 1)
     * DQ = D mod (Q - 1)
     * QP = Q^-1 mod P
     */
    MPI_CHK( mpi_mod_mpi( &ctx->rsa.DP, &ctx->rsa.D, &P1 ) );
    MPI_CHK( mpi_mod_mpi( &ctx->rsa.DQ, &ctx->rsa.D, &Q1 ) );
    MPI_CHK( mpi_inv_mod( &ctx->rsa.QP, &ctx->rsa.Q, &ctx->rsa.P ) );

cleanup:

    mpi_free(&Q1, &P1, NULL );

    if( ret != 0 )
    {
        rsa_free( &ctx->rsa );
        return( POLARSSL_ERR_RSA_KEY_GEN_FAILED | ret );
    }

    return( 0 );   
}
#endif
