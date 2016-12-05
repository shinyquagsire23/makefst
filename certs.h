/*
 *  makefst - CDN FST packer and packager for Wii U homebrew
 *
 *  This code is licensed to you under the terms of the MIT License;
 *  see file LICENSE for details
 */

#pragma once

#include "lib.h"

typedef struct
{
	u8 issuer[0x40];
	u8 keyType[4];
	u8 name[0x40];
	u8 id[4];
} cert_hdr;

typedef struct
{
	u8 modulus[0x200];
	u8 pubExponent[4];
	u8 padding[0x34];
} rsa_4096_pubk_struct;

typedef struct
{
	u8 modulus[0x100];
	u8 pubExponent[4];
	u8 padding[0x34];
} rsa_2048_pubk_struct;

typedef struct
{
	u8 pubK[0x3C];
	u8 padding[0x3C];
} ecc_pubk_struct;

// Cert Sizes
u32 GetCertSize(const u8 *cert);
u32 GetCertPubkSectionSize(pubk_types type);

// Issuer/Name Functions
u8 *GetCertIssuer(const u8 *cert);
u8 *GetCertName(const u8 *cert);
void GenCertChildIssuer(u8 *dest, const u8 *cert);

// Pubk
pubk_types GetCertPubkType(const u8 *cert);
u8 *GetCertPubk(const u8 *cert);

bool VerifyCert(u8 *cert, const u8 *pubk);
