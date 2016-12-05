/*
 *  makefst - CDN FST packer and packager for Wii U homebrew
 *
 *  This code is licensed to you under the terms of the MIT License;
 *  see file LICENSE for details
 */

#ifndef _TMD_H_
#define _TMD_H_

#include "types.h"
//#include "settings.h"

#define TMD_MAX_CONTENTS 64

typedef enum
{
	TMD_RSA_2048_SHA256 = 0x00010004,
	TMD_RSA_4096_SHA256 = 0x00010003,
	TMD_RSA_2048_SHA1   = 0x00010001,
	TMD_RSA_4096_SHA1   = 0x00010000
} wup_tmdtype;

typedef enum
{
	APPTYPE_APPLICATION = 0x80000000,
	APPTYPE_SYS = 0x10000000,
	APPTYPE_UNK_20 = 0x20,
} wup_apptype;

typedef struct
{
	unsigned char issuer[0x40];     // 0x140
	unsigned char version;          // 0x180
	unsigned char ca_crl_version;   // 0x181
	unsigned char signer_crl_version; // 0x182
	unsigned char padding2;         // 0x183
	unsigned char systemversion[8]; // 0x184
	unsigned char titleid[8];       // 0x18C
	unsigned char titletype[4];     // 0x194
	unsigned char groupid[2];       // 0x198
	unsigned char apptype[4];       // 0x19A
	unsigned char unknown[4];       // 0x19E
	unsigned char unknown2[4];      // 0x1A2
	unsigned char twlflag;          // 0x1A6
	unsigned char padding4[0x31];   // 0x1A7
	unsigned char accessrights[4];  // 0x1D8
	unsigned char titleversion[2];  // 0x1DC
	unsigned char contentcount[2];  // 0x1DE
	unsigned char bootcontent[2];   // 0x1C0    
	unsigned char padding5[2];      // 0x1C2
	unsigned char hash[32];         // 0x1C4
	unsigned char contentinfo[36*64]; // 0x204
} wup_tmd_body;

typedef struct
{
	unsigned char index[2];
	unsigned char commandcount[2];
	unsigned char hash[32];
} wup_tmd_contentinfo;


typedef struct
{
	unsigned char id[4];
	unsigned char index[2];
	unsigned char type[2];
	unsigned char size[8];
	unsigned char hash[32];
} wup_tmd_contentchunk;


typedef struct
{
	unsigned char signaturetype[4];
	unsigned char signature[0x100];
	unsigned char padding[0x3C];
} wup_tmd_header_2048;

typedef struct
{
	unsigned char signaturetype[4];
	unsigned char signature[0x200];
	unsigned char padding[0x3C];
} wup_tmd_header_4096;

typedef struct
{
	u32 size;
	u8* buffer;
	u8 content_hash_stat[64];
} tmd_context;



#ifdef __cplusplus
extern "C" {
#endif

void tmd_init(tmd_context* ctx);
void tmd_set_size(tmd_context* ctx, u32 size);
void tmd_set_usersettings(tmd_context* ctx);
void tmd_print(tmd_context* ctx);
void tmd_process(tmd_context* ctx, u32 actions);
wup_tmd_body *tmd_get_body(tmd_context *ctx);

#ifdef __cplusplus
}
#endif

#endif // _TMD_H_
