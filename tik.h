/*
 *  makefst - CDN FST packer and packager for Wii U homebrew
 *
 *  This code is licensed to you under the terms of the MIT License;
 *  see file LICENSE for details
 */

#ifndef __TIK_H__
#define __TIK_H__

#include "types.h"
#include "wup.h"

typedef struct 
{
	u8 enable_timelimit[4];
	u8 timelimit_seconds[4];
} timelimit_entry;

typedef enum
{
    SECT_PERMANENT = 1,
    SECT_SUBSCRIPTION = 2,
    SECT_CONTENT = 3,
    SECT_CONTENT_CONSUMPTION = 4,
    SECT_ACCESS_TITLE = 5,
    SECT_LIMITED_RESOURCE = 6,
    SECT_GENERIC = 7,
} section_type;

typedef struct {
    u8 ref_id[0x10];
    u8 ref_id_attribute[4];
} permanent_section;

typedef struct {
    u8 limit[4];
    u8 ref_id[0x10];
    u8 ref_id_attribute[4];
} subscription_section;

typedef struct {
    u8 offset[4];
    u8 access_mask[0x80];
} content_section;

typedef struct {
    u8 index[2];
    u8 code[2];
    u8 limit[4];
} content_consumption_section;

typedef struct {
    u8 access_title_id[8];
    u8 access_title_mask[8];
} title_section;

typedef struct {
    u8 limit[4];
    u8 ref_id[0x10];
    u8 ref_id_attribute[4];
} limited_resource_section;

typedef struct {
    u8 type[4];
    u8 data[0x1FC];
} generic_section;

typedef struct
{
    u8 section_offset[4];   // from beginning of ticket header
    u8 num_records[4];
    u8 record_size[4];
    u8 section_size[4];
    u8 section_type[2];
    u8 flags[2];
} section_header; // v1 tickets only!

typedef struct 
{
	u8 sig_type[4];                 // 0x0
	u8 signature[0x100];            // 0x4
	u8 padding1[0x3c];              // 0x104
	u8 issuer[0x40];                // 0x140
	u8 ecdsa_pubkey[0x3c];          // 0x180
	u8 version;                     // 0x1BC
	u8 ca_clr_version;              // 0x1BD
	u8 signer_crl_version;          // 0x1BE
	u8 encrypted_title_key[0x10];   // 0x1BF
	u8 reserved;                    // 0x1CF
	u8 ticket_id[8];                // 0x1D0
	u8 device_id[4];               // 0x1D8: setting will use "personalized" (ticketid+deviceid-based) titlekey encryption
	u8 title_id[8];                 // 0x1DC
	u8 sys_access[2];               // 0x1E4 - TODO: what's this actually?
	u8 ticket_version[2];           // 0x1E6
	u8 reserved3[8];                // 0x1E8
	u8 license_type;                // 0x1F0
	u8 ckey_index;                  // 0x1F1
    u8 property_mask[2];            // 0x1F2
	u8 hash_maybe[0x14];            // 0x1F4
    u8 reserved4[0x14];             // 0x208
	u8 account_id[4];               // 0x21C
	u8 reserved5;                   // 0x220
	u8 audit;                       // 0x221
	u8 reserved6[0x42];             // 0x222
	u8 limit_entries[0x40];         // 0x264 - 0x8 id, data pairs?
	u8 header_version[2];           // 0x2A4 - header starts here
    u8 header_size[2];              // 0x2A6
    u8 total_hdr_size[4];           // 0x2A8 - "ticket size", but it's not. hdr + sect size
    u8 sect_hdr_offset[4];          // 0x2AC - offset to sect headers from beginning of hdr
	u8 num_sect_headers[2];         // 0x2B0
    u8 num_sect_header_entry_size[2]; // 0x2B2
    u8 header_flags[4];             // 0x2B4
} eticket;

typedef struct
{
	FILE* file;
	u64 offset;
	u32 size;
	u8 titlekey[16];
	eticket tik;
	wup_aes_context aes;
} tik_context;

void tik_init(tik_context* ctx);
void tik_set_file(tik_context* ctx, FILE* file);
void tik_set_offset(tik_context* ctx, u64 offset);
void tik_set_size(tik_context* ctx, u32 size);
void tik_get_decrypted_titlekey(tik_context* ctx, u8 decryptedkey[0x10]);
void tik_get_titleid(tik_context* ctx, u8 titleid[8]);
void tik_get_iv(tik_context* ctx, u8 iv[0x10]);
void tik_decrypt_titlekey(tik_context* ctx, u8 decryptedkey[0x10]);
void tik_print(tik_context* ctx);
void tik_process(tik_context* ctx, u32 actions);

#endif
