/*
 *  makefst - CDN FST packer and packager for Wii U homebrew
 *
 *  This code is licensed to you under the terms of the MIT License;
 *  see file LICENSE for details
 */

#ifndef __TYPES_H__
#define __TYPES_H__

#include <stdint.h>
#include <inttypes.h>

typedef uint8_t			u8;
typedef uint16_t		u16;
typedef uint32_t		u32;
typedef uint64_t		u64;

typedef int8_t			s8;
typedef int16_t			s16;
typedef int32_t			s32;
typedef int64_t			s64;

typedef enum
{
	MEM_ERROR = -1,
	FAILED_TO_OPEN_FILE = -2,
	FAILED_TO_IMPORT_FILE = -3,
	FAILED_TO_CREATE_OUTFILE = -4,
} global_errors;

typedef enum
{
	BE = 0,
	LE = 1
} endianness_flag;

typedef enum
{
	KB = 1024,
	MB = 1048576,
	GB = 1073741824
} file_unit_size;

typedef enum
{
	MAX_U8 = 0xff,
	MAX_U16 = 0xffff,
	MAX_U32 = 0xffffffff,
	MAX_U64 = 0xffffffffffffffff,
} data_type_max;

enum flags
{
	ExtractFlag = (1<<0),
	InfoFlag = (1<<1),
	PlainFlag = (1<<2),
	VerboseFlag = (1<<3),
	VerifyFlag = (1<<4),
	RawFlag = (1<<5),
	ShowKeysFlag = (1<<6),
	DecompressCodeFlag = (1<<7),
	ShowSyscallsFlag = (1<<8),
};

enum validstate
{
	Unchecked = 0,
	Good = 1,
	Fail = 2,
};

enum sizeunits
{
	sizeKB = 0x400,
	sizeMB = 0x100000,
};

#endif
