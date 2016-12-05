/*
 *  makefst - CDN FST packer and packager for Wii U homebrew
 *
 *  This code is licensed to you under the terms of the MIT License;
 *  see file LICENSE for details
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include "lib.h"

#ifdef _WIN32
#define PATH_SEPERATOR '\\'
#else
#define PATH_SEPERATOR '/'
#endif

#ifndef MAX_PATH
	#define MAX_PATH 255
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	u64 size;
	u8 *buffer;
} buffer_struct;

// Memory
int CopyData(u8 **dest, const u8 *source, u64 size);
void rndset(void *ptr, u64 num);
void clrmem(void *ptr, u64 num);

// MISC
u64 roundup(u64 value, u64 alignment);
u64 min64(u64 a, u64 b);
u64 max64(u64 a, u64 b);

// Strings
void memdump(FILE* fout, const char* prefix, const u8* data, u32 size);
char* replace_filextention(const char *input, const char *extention);

// Base64
bool IsValidB64Char(char chr);
u32 b64_strlen(char *str);
void b64_strcpy(char *dst, char *src);
int b64_decode(u8 *dst, char *src, u32 dst_size);

// Pseudo-Random Number Generator
void initRand(void);
u8 u8GetRand(void);
u16 u16GetRand(void);
u32 u32GetRand(void);
u64 u64GetRand(void);

//Char IO
bool AssertFile(char *filename);
u64 GetFileSize64(char *filename);
int makedir(const char* dir);
int TruncateFile64(char *filename, u64 filelen);

//IO Misc
u8* ImportFile(char *file, u64 size);
void WriteBuffer(const void *buffer, u64 size, u64 offset, FILE *output);
void ReadFile64(void *outbuff, u64 size, u64 offset, FILE *file);
int fseek_64(FILE *fp, u64 file_pos);

//Data Size conversion
u16 u8_to_u16(const u8 *value, u8 endianness);
u32 u8_to_u32(const u8 *value, u8 endianness);
u64 u8_to_u64(const u8 *value, u8 endianness);
int u16_to_u8(u8 *out_value, u16 in_value, u8 endianness);
int u32_to_u8(u8 *out_value, u32 in_value, u8 endianness);
int u64_to_u8(u8 *out_value, u64 in_value, u8 endianness);

u32 align(u32 offset, u32 alignment);
u64 align64(u64 offset, u32 alignment);
u64 getle64(const u8* p);
u32 getle32(const u8* p);
u32 getle16(const u8* p);
u64 getbe64(const u8* p);
u32 getbe32(const u8* p);
u32 getbe16(const u8* p);
void putle16(u8* p, u16 n);
void putle32(u8* p, u32 n);
void putle64(u8* p, u64 n);
void putbe16(u8* p, u16 n);
void putbe32(u8* p, u32 n);
void putbe64(u8* p, u64 n);

void readkeyfile(u8* key, const char* keyfname);
void memdump(FILE* fout, const char* prefix, const u8* data, u32 size);
void hexdump(void *ptr, int buflen);
int key_load(char *name, u8 *out_buf);

int makedir(const char* dir);

u64 _fsize(const char *filename);

#ifdef _MSC_VER
inline int fseeko64(FILE *__stream, long long __off, int __whence)
{
	return _fseeki64(__stream, __off, __whence);
}
#elif __APPLE__
    #define fseeko64 fseek // OS X file I/O is 64bit
#elif __linux__
    extern int fseeko64 (FILE *__stream, __off64_t __off, int __whence);
#endif

#ifdef __cplusplus
}
#endif

#endif // _UTILS_H_
