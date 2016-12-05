/*
 *  makefst - CDN FST packer and packager for Wii U homebrew
 *
 *  This code is licensed to you under the terms of the MIT License;
 *  see file LICENSE for details
 */

#ifndef MAKEFST_FST_H
#define MAKEFST_FST_H

#include "lib.h"

#define FST_READ_OWNER  0x400
#define FST_WRITE_OWNER 0x200
#define FST_EXEC_OWNER  0x100

#define FST_READ_GROUP  0x040
#define FST_WRITE_GROUP 0x020
#define FST_EXEC_GROUP  0x010

#define FST_READ_OTHER  0x004
#define FST_WRITE_OTHER 0x002
#define FST_EXEC_OTHER  0x001

typedef struct fst_header
{
    char magic[3];
    u8 version;
    u8 header_size[4];
    u8 num_sections[4];
    u8 hash_disabled;
    u8 padding[0x13];
} fst_header;

typedef struct fst_section_entry
{
    u8 f_addr[4];
    u8 f_len[4];
    u8 owner_id[8];
    u8 group_id[4];
    u8 hash_mode;
    u8 padding[0xB];
} fst_section_entry;

typedef struct fst_node_entry
{
    u8 str_addr[4]; // first byte, 0 = file, 1 = dir entry, 0x80 = load from base content (updates)
    u8 f_off[4]; // Parent directory for dir entries
    u8 f_len[4]; // Next dir for alphabetically-in-order dirs, otherwise last file in dir before returning to placing entries in parent dir
    u8 perms[2];
    u8 content_id[2];
} fst_node_entry;

#endif //MAKEFST_FST_H
