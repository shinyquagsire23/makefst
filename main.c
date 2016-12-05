/*
 *  makefst - CDN FST packer and packager for Wii U homebrew
 *
 *  This code is licensed to you under the terms of the MIT License;
 *  see file LICENSE for details
 */

#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ezxml/ezxml.h"
#include "miniz.h"

#include "tmd.h"
#include "tik.h"
#include "fst.h"
#include "utils.h"
#include "certs.h"
#include "crypto.h"
#include "pki/test.h"
#include "pki/prod.h"

#define WIIU_BLOCK_SIZE 0x8000

void clear_dir(char *path);
int get_num_entries(char *dir, u8 filesOnly);
int get_entries(char *dir, char **out_dirs, u32 *out_sizes, u32 *out_parent_dir, int index, int base_parent_dir);
void print_fst(void *fst_buffer);

void help_show()
{
    printf("WUP makefst v0.5 \n(C)SALT 2016\n\n"
        "Usage: makefst [args] [folder]\n"
        "Option          Parameter           Explanation\n"
        "-help                               Display this text\n"
        "-verbose                            Verbose printout\n"
        "-rawout        \"out folder/\"        Specify output folder\n"
        "-raw                                Do not pack FST contents\n"
        "-noraw                              Remove FST contents when done\n"
        
        "\nWoomy options:\n"
        "-out           \"out name.woomy\"     Specify output filename\n"
        "-append                             Append additional data to existing woomy\n"
        "-icon          \"icon name.tga\"      Set metadata icon\n"
        "-name          \"display name\"       Set metadata display name\n"
        "-internal      \"internal name\"      Set metadata entry name\n"
        "-entry         \"entry path/\"        Set entry archive path\n");
}

int main(int argc, char *argv[])
{
    if(argc < 2)
    {
        help_show();
        return -1;
    }

    u64 target_os_version;
    u64 target_tid;
    u32 target_group_id;
    u32 target_version;
    u32 target_app_type;
    u32 fst_buffer_size;
    bool verbose_print = false;
    bool raw_fst = false;
    bool remove_fst = false;
    bool woomy_append = false;
    char fst_out_path[MAX_PATH] = {0};
    char woomy_out_path[MAX_PATH] = {0};
    char woomy_display_name[0x80] = {0};
    char woomy_internal_name[0x80] = {0};
    char woomy_entry_path[0x80] = {0};
    char woomy_icon_path[0x80] = {0};

    char* dir = NULL;
    for(int i = 1; i < argc; i++)
    {
        char *str_end;
        if(!strcmp(argv[i], "-verbose"))
        {
            verbose_print = true;
        }
        else if(!strcmp(argv[i], "-help"))
        {
            help_show();
            return -1;
        }
        else if(!strcmp(argv[i], "-rawout"))
        {
            strcpy(fst_out_path, argv[++i]);
        }
        else if(!strcmp(argv[i], "-raw"))
        {
            raw_fst = true;
        }
        else if(!strcmp(argv[i], "-noraw"))
        {
            remove_fst = true;
        }
        else if(!strcmp(argv[i], "-out"))
        {
            strcpy(woomy_out_path, argv[++i]);
        }
        else if(!strcmp(argv[i], "-append"))
        {
            woomy_append = true;
        }
        else if(!strcmp(argv[i], "-name"))
        {
            strncpy(woomy_display_name, argv[++i], 0x80);
        }
        else if(!strcmp(argv[i], "-internal"))
        {
            strncpy(woomy_internal_name, argv[++i], 0x80);
        }
        else if(!strcmp(argv[i], "-entry"))
        {
            strncpy(woomy_entry_path, argv[++i], 0x80);
        }
        else if(!strcmp(argv[i], "-icon"))
        {
            strncpy(woomy_icon_path, argv[++i], 0x80);
        }
        else
        {
            dir = argv[i];
            if(argv[i][strlen(argv[i])-1] == '/')
                argv[i][strlen(argv[i])-1] = 0;

            if(fst_out_path[strlen(fst_out_path)-1] == '/')
                fst_out_path[strlen(fst_out_path)-1] = 0;

            if(woomy_out_path[strlen(woomy_out_path)-1] == '/')
                woomy_out_path[strlen(woomy_out_path)-1] = 0;

            if(woomy_entry_path[strlen(woomy_entry_path)-1] == '/')
                woomy_entry_path[strlen(woomy_entry_path)-1] = 0;

            if(!fst_out_path[0])
                sprintf(fst_out_path, "%s_out", dir);

            if(!woomy_out_path[0])
                sprintf(woomy_out_path, "%s.woomy", dir);

            if(!woomy_display_name[0])
                sprintf(woomy_display_name, "%s", dir);

            if(!woomy_entry_path[0])
                sprintf(woomy_entry_path, "%s", dir);
        }
    }

    if(dir == NULL)
    {
        help_show();
        return -1;
    }

    if(remove_fst && raw_fst)
    {
        printf("Creating an FST and then removing it is pointless, exiting...\n");
        return -1;
    }

    //Read app.xml to retrieve target TID, Group ID
    char xml_path[PATH_MAX];

    sprintf(xml_path, "%s/code/app.xml", dir);
    printf("Reading '%s'...\n", xml_path);

    ezxml_t app_xml = ezxml_parse_file(xml_path);
    if(!app_xml)
    {
        printf("Could not find %s! Aborting...\n", xml_path);
        return -1;
    }
    else
    {
        target_os_version = strtoull(ezxml_get(app_xml, "os_version", -1)->txt, NULL, 16);
        target_tid = strtoull(ezxml_get(app_xml, "title_id", -1)->txt, NULL, 16);
        target_group_id = (u32)(strtoull(ezxml_get(app_xml, "group_id", -1)->txt, NULL, 16) & 0xFFFFFFFF);
        target_version = (u32)(strtoull(ezxml_get(app_xml, "title_version", -1)->txt, NULL, 16) & 0xFFFFFFFF);
        target_app_type = (u32)(strtoull(ezxml_get(app_xml, "app_type", -1)->txt, NULL, 16) & 0xFFFFFFFF);
    }

    ezxml_free(app_xml);
    
    // sanity-check meta.xml structure
    sprintf(xml_path, "%s/meta/meta.xml", dir);
    ezxml_t meta_xml = ezxml_parse_file(xml_path);
    if(!meta_xml)
    {
        printf("Could not find %s! Aborting...\n", xml_path);
        return -1;
    }
    u64 test_tid = strtoull(ezxml_get(meta_xml, "title_id", -1)->txt, NULL, 16);
    if(test_tid != target_tid)
    {
        printf("Error! Title ID in meta.xml and app.xml do not match.\n");
        return -1;
    }
    ezxml_free(meta_xml);

    printf("Compiling directory '%s' under TID %016LX, Group Id 0x%X, ver %u...\n", dir, target_tid, target_group_id, target_version);

    int num_entries = get_num_entries(dir, 0);
    int num_files =  get_num_entries(dir, 1);
    char **dir_entries = calloc((num_entries)*sizeof(char*)*2, 1);
    u32 *dir_entry_sizes = calloc((num_entries)*sizeof(u32)*2, 1);
    u32 *dir_entry_parents = calloc((num_entries)*sizeof(u32)*2, 1);
    u16 *node_to_index = calloc((num_entries)*sizeof(u16)*2, 1);
    u16 *index_to_node = calloc((num_entries)*sizeof(u16)*2, 1);
    if(!dir_entries || !dir_entry_sizes || !dir_entry_parents || !node_to_index || !index_to_node)
    {
        printf("Error! Failed to allocate memory for file metadata\n");
        return -1;
    }

    fst_buffer_size = sizeof(fst_header) + ((num_files+1)*sizeof(fst_section_entry)) + ((num_entries+1)*sizeof(fst_node_entry)) + ((num_entries+1)*MAX_PATH);
    fst_buffer_size = (fst_buffer_size+0x7FFF)&0xFFFF8000; //Round to 0x8000
    void *fst_buffer = calloc(fst_buffer_size, 1);
    if(!fst_buffer)
    {
        printf("Error! Failed to allocate memory for FST buffer\n");
        return -1;
    }

    printf("%u files, %u entries total\n", num_files, num_entries);
    get_entries(dir, dir_entries, dir_entry_sizes, dir_entry_parents, 0, 0);

    
    // begin building the actual fst file
    fst_header *f_header = fst_buffer;
    memcpy(f_header->magic, "FST", 3);
    f_header->version = 0;
    putbe32(f_header->header_size, 0x20);
    putbe32(f_header->num_sections, num_files+1);
    f_header->hash_disabled = true;

    int dir_entry_index = 0;
    u32 current_f_addr = 0x10000 / WIIU_BLOCK_SIZE;
    u32 non_content_addr = 0;
    for(int i = 1; i < getbe32(f_header->num_sections); i++)
    {
        fst_section_entry *f_entry = (fst_buffer+0x20) + (i*sizeof(fst_section_entry));

        int seed_dir_index = dir_entry_index;
        while(dir_entries[dir_entry_index][strlen(dir_entries[dir_entry_index])-1] == '/') 
        { 
            node_to_index[dir_entry_index] = 0xFFFF; 
            dir_entry_index++; 
        }

        index_to_node[i] = dir_entry_index;
        for(int j = seed_dir_index; j <= dir_entry_index; j++)
            node_to_index[j] = i;

        // set file offset and size entries, and update next offset
        u32 block_len = roundup(dir_entry_sizes[dir_entry_index], WIIU_BLOCK_SIZE) / WIIU_BLOCK_SIZE;
        putbe32(f_entry->f_len, block_len);
        putbe32(f_entry->f_addr, current_f_addr);
        current_f_addr += block_len;

        f_entry->hash_mode = 1;
        if(!strncmp(dir_entries[i], "code/", 5))
        {
            putbe32(f_entry->owner_id, 0);
            putbe32(f_entry->group_id, 0);
        }
        else if(!strncmp(dir_entries[i], "meta/", 5))
        {
            putbe32(f_entry->owner_id, 0);
            putbe32(f_entry->group_id, 0x400);
        }
        else if(!strncmp(dir_entries[i], "content/", 7))
        {
            putbe32(f_entry->owner_id, (u32)(target_tid & 0xFFFFFFFF));
            putbe32(f_entry->group_id, target_group_id);
        }
        dir_entry_index++;
    }

    fst_node_entry *f_root_entry = (fst_buffer+0x20) + (getbe32(f_header->num_sections)*sizeof(fst_section_entry));
    putbe32(f_root_entry->f_len, num_entries+1);
    putbe32(f_root_entry->f_off, 0);
    putbe32(f_root_entry->str_addr, 0x01000000);

    void *str_chunk = (fst_buffer+0x20) + (getbe32(f_header->num_sections)*sizeof(fst_section_entry)) + ((num_entries+1)*sizeof(fst_node_entry));
    u32 str_chunk_off = 1;
    for(int i = 1; i < num_entries+1; i++)
    {
        fst_node_entry *f_node_entry = (fst_buffer+0x20) + (getbe32(f_header->num_sections)*sizeof(fst_section_entry)) + (i*sizeof(fst_node_entry));
        bool is_folder = (dir_entries[i-1][strlen(dir_entries[i-1])-1] == '/');

        //Sift through the path and get our node string
        char *node_str = dir_entries[i-1];
        for(int j = strlen(dir_entries[i-1]) - (is_folder ? 2 : 0); j >= 0; j--)
        {
            if(!is_folder)
            {
                node_str = strrchr(dir_entries[i-1], '/')+1;
                break;
            }

            if(dir_entries[i][j] == '/')
            {
                node_str = dir_entries[i-1]+j+1;
                break;
            }
        }

        putbe32(f_node_entry->str_addr, str_chunk_off | (is_folder << 24));
        strncpy(str_chunk + str_chunk_off, node_str, strlen(node_str) - is_folder);
        str_chunk_off += strlen(node_str)+1;

        if(!is_folder)
        {
            putbe32(f_node_entry->f_off, 0);
            putbe32(f_node_entry->f_len, dir_entry_sizes[i - 1]);
            putbe16(f_node_entry->content_id, node_to_index[i-1]);
        }
        else
        {
            putbe32(f_node_entry->f_off, dir_entry_parents[i-1] != 0 ? dir_entry_parents[i-1]+1 : 0); //Folder's parents
            int j;
            for(j = i+1; j < num_entries+1; j++)
            {
                // Next folder with same parent
                if(dir_entry_parents[i-1] >= dir_entry_parents[j-1] && (dir_entries[j-1][strlen(dir_entries[j-1])-1] == '/'))
                    break;
                
                // more base dir entries
                if((dir_entry_parents[i-1] == dir_entry_parents[j-1]) && dir_entry_parents[i-1] != 0)
                    break;
                
            }
            putbe32(f_node_entry->f_len, j);
            putbe16(f_node_entry->content_id, node_to_index[i-1]);
        }
        
        // RW for all files
        putbe16(f_node_entry->perms, 0x666);
    }

    if(verbose_print)
        print_fst(fst_buffer);

    //Create the TMD for all of our .apps
    tmd_context *ctx = calloc(sizeof(tmd_context), 1);
    if(!ctx)
    {
        printf("Error! Failed to allocate memory for TMD\n");
        return -1;
    }
    tmd_init(ctx);
    ctx->buffer = calloc(0x400000, 1);
    if(!ctx->buffer)
    {
        printf("Error! Failed to allocate 4MB for TMD contents\n");
        return -1;
    }
    wup_tmd_header_2048* header2048 = (wup_tmd_header_2048*)ctx->buffer;
    putbe32(header2048->signaturetype, TMD_RSA_2048_SHA256);
    wup_tmd_body* body = tmd_get_body(ctx);
    wup_tmd_contentinfo* info = (wup_tmd_contentinfo*)(body->contentinfo);

    GenCertChildIssuer(body->issuer, cpB_tpki_cert);
    body->version =              1;
    body->ca_crl_version =       0;
    body->signer_crl_version =   0;
    putbe64(body->systemversion, target_os_version); //Wii U OS
    putbe64(body->titleid,       target_tid);
    putbe32(body->titletype,     0x00000100);
    putbe16(body->groupid,       (u16)target_group_id);
    putbe32(body->apptype,       target_app_type);
    putbe32(body->unknown,       0); //TODO?
    putbe32(body->unknown2,      0x019a0000); //TODO, mystery
    putbe32(body->accessrights,  0);
    putbe16(body->titleversion,  (u16)(target_version&0xFFFF));
    putbe16(body->contentcount,  (u16)getbe32(f_header->num_sections));
    putbe16(body->bootcontent,   0);

    putbe16(info->index, 0);
    putbe16(info->commandcount, (u16)getbe32(f_header->num_sections));

    char *path = malloc(PATH_MAX);
    if(!path)
    {
        printf("Error! Failed to allocate memory for .app path!\n");
        return -1;
    }

    //Write in FST content chunk
    wup_tmd_contentchunk* fst_chunk = (wup_tmd_contentchunk*)(body->contentinfo + 36*64);
    putbe32(fst_chunk->id, 0);
    putbe16(fst_chunk->index, 0);
    putbe16(fst_chunk->type, 0x2000);
    putbe64(fst_chunk->size, fst_buffer_size);
    ShaCalc(fst_buffer, fst_buffer_size, fst_chunk->hash, WUP_SHA_1);

    //Create output folder if it doesn't exist
    makedir(fst_out_path);

    sprintf(path, "%s/%08x.app", fst_out_path, 0);
    FILE* f_app = fopen(path, "wb");
    fwrite(fst_buffer, sizeof(u8), fst_buffer_size, f_app);
    fclose(f_app);

    for(int i = 1; i < getbe16(info->commandcount); i++)
    {
        u64 file_size = roundup(dir_entry_sizes[index_to_node[i]], WIIU_BLOCK_SIZE);
        
        // 2MB buffer
        const u32 file_block_size = 0x200000;
        void *file_alloc = malloc(file_block_size);
        if(!file_alloc)
        {
            printf("Error! Failed to allocate 2MB for file copy\n");
            return -1;
        }
        strcpy(path, dir);
        strcat(path, "/");
        strcat(path, dir_entries[index_to_node[i]]);
        printf("Content %-3x size %-10x actual size %-10x ", i, file_size, dir_entry_sizes[index_to_node[i]]);
	printf("%-10s\n", path);

        FILE* f_in = fopen(path, "rb");
        sprintf(path, "%s/%08x.app", fst_out_path, i);
        FILE* f_app = fopen(path, "wb");

        wup_tmd_contentchunk* chunk = (wup_tmd_contentchunk*)(body->contentinfo + 36*64 + i*48);
        putbe32(chunk->id, i);
        putbe16(chunk->index, i);
        putbe16(chunk->type, 0x2000);
        putbe64(chunk->size, file_size);

        sha1_context ctx;
        sha1_starts(&ctx);

        while(1)
        {
            size_t read = fread(file_alloc, 1, file_block_size, f_in);
            // round up to nearest 0x8000
            u32 write_size = (read + 0x7FFF) &~ 0x7FFF;
            
            // zeroed padding at end of file
            memset(file_alloc + read, 0, write_size - read);

            fwrite(file_alloc, 1, write_size, f_app);
            sha1_update(&ctx, file_alloc, write_size);

            if(read < file_block_size)
                break;
        }
        free(file_alloc);


        sha1_finish(&ctx, chunk->hash);
        memset(&ctx, 0, sizeof( sha1_context ));
        fclose(f_in);
        fclose(f_app);
    }

    // hash content chunk records, then contentinfo records
    ShaCalc(body->contentinfo + 36*64,sizeof(wup_tmd_contentchunk)*getbe16(body->contentcount), info->hash, WUP_SHA_256);
    ShaCalc(body->contentinfo,sizeof(wup_tmd_contentinfo)*64,body->hash,WUP_SHA_256);
    RsaSignVerify((u8*)body,sizeof(wup_tmd_body), header2048->signature, tpki_rsa.modulus, tpki_rsa.priv_exponent, RSA_2048_SHA256,WUP_RSA_SIGN);

    if(verbose_print)
        tmd_print(ctx);

    //Write TMD
    sprintf(path, "%s/title.tmd", fst_out_path);
    FILE* f_tmd = fopen(path, "wb");
    fwrite(ctx->buffer, sizeof(u8), (body->contentinfo + 36*64 + getbe16(info->commandcount)*48) - ctx->buffer, f_tmd);
    fclose(f_tmd);

    //Set up and write certchain buffer
    void *certchain_buffer = calloc(GetCertSize(ca3_ppki_cert)+GetCertSize(xsC_ppki_cert)+GetCertSize(cpB_ppki_cert),1);
    if(!certchain_buffer)
    {
        printf("Error! Failed to allocate memory for certchain buffer!\n");
        return -1;
    }

    memcpy(certchain_buffer,ca3_ppki_cert,GetCertSize(ca3_ppki_cert));
    memcpy((certchain_buffer+GetCertSize(ca3_ppki_cert)),xsC_ppki_cert,GetCertSize(xsC_ppki_cert));
    memcpy((certchain_buffer+GetCertSize(ca3_ppki_cert)+GetCertSize(xsC_ppki_cert)),cpB_ppki_cert,GetCertSize(cpB_ppki_cert));

    sprintf(path, "%s/title.cert", fst_out_path);
    FILE* f_cert = fopen(path, "wb");
    fwrite(certchain_buffer, sizeof(u8), GetCertSize(ca3_ppki_cert)+GetCertSize(xsC_ppki_cert)+GetCertSize(cpB_ppki_cert), f_cert);
    fclose(f_cert);

    free(certchain_buffer);

    tik_context *tik_ctx = calloc(sizeof(tik_context), 1);
    if(!tik_ctx)
    {
        printf("Error! Failed to allocate memory for ticket!\n");
        return -1;
    }
    tik_init(tik_ctx);

    putbe32(tik_ctx->tik.sig_type, TMD_RSA_2048_SHA256);
    GenCertChildIssuer(tik_ctx->tik.issuer, xsC_tpki_cert);
    tik_ctx->tik.version = 1;
    tik_ctx->tik.ca_clr_version = 0;
    tik_ctx->tik.signer_crl_version = 0;
    putbe64(tik_ctx->tik.ticket_id, 0x0005000000000000 | (u64GetRand() & 0x0000FFFFFFFFFFFF));
    putbe32(tik_ctx->tik.device_id, 0x0);
    putbe64(tik_ctx->tik.title_id, target_tid);
    putbe16(tik_ctx->tik.ticket_version, (u16)(target_version&0xFFFF));
    tik_ctx->tik.license_type = 0;
    tik_ctx->tik.ckey_index = 0;
    putbe32(tik_ctx->tik.account_id, 0x0);
    tik_ctx->tik.audit = 1;
    putbe16(tik_ctx->tik.property_mask, 6);
    // configure the header to use no sections
    putbe16(tik_ctx->tik.header_version, 1);
    putbe16(tik_ctx->tik.header_size, 0x14);
    putbe32(tik_ctx->tik.total_hdr_size, 0x14);
    putbe32(tik_ctx->tik.sect_hdr_offset, 0x14);
    putbe16(tik_ctx->tik.num_sect_headers, 0);
    putbe16(tik_ctx->tik.num_sect_header_entry_size, 0x14);
    putbe32(tik_ctx->tik.header_flags, 0);

    RsaSignVerify(tik_ctx->tik.padding1, 0x24C, tik_ctx->tik.signature, tpki_rsa.modulus, tpki_rsa.priv_exponent, RSA_2048_SHA256,WUP_RSA_SIGN);

    if(verbose_print)
        tik_print(tik_ctx);

    sprintf(path, "%s/title.tik", fst_out_path);
    FILE* f_tik = fopen(path, "wb");
    fwrite(&tik_ctx->tik, sizeof(u8), sizeof(eticket), f_tik);
    fwrite(cpB_ppki_cert, sizeof(u8), GetCertSize(cpB_ppki_cert), f_tik);
    fwrite(ca3_ppki_cert, sizeof(u8), GetCertSize(ca3_ppki_cert), f_tik);
    fclose(f_tik);

    //We're only creating a raw FST, exit
    if(raw_fst)
    {
        free(path);
        return -1;
    }

    // Pack .woomy
    char *archive_fst_folder = malloc(strlen(woomy_entry_path)+1);
    if(!archive_fst_folder)
    {
        printf("Error! Failed to allocate string for .woomy path!\n");
        return -1;
    }
    sprintf(archive_fst_folder, "%s/", woomy_entry_path);

    if(!woomy_append)
    {
        remove(woomy_out_path);
        printf("\nCreating archive '%s'\n", woomy_out_path);
    }
    else
    {
        printf("\nAdding entry to archive '%s'\n", woomy_out_path);
    }

    mz_zip_archive woomy_archive = {0};
    int status = mz_zip_reader_init_file(&woomy_archive, woomy_out_path, 0);
    if (status)
    {
        char tmp_filename[0x200];
        clear_dir("tmp_append/");
        makedir("tmp_append/");
        for (int i = 0; i < (int)mz_zip_reader_get_num_files(&woomy_archive); i++)
        {
            mz_zip_archive_file_stat file_stat;
            if (!mz_zip_reader_file_stat(&woomy_archive, i, &file_stat))
            {
                printf("mz_zip_reader_file_stat() failed!\n");
                continue;
            }

            snprintf(tmp_filename, 0x200, "tmp_append/%s", file_stat.m_filename);
            if(verbose_print)
                printf("Extracting '%s' to '%s' \n", file_stat.m_filename, tmp_filename);

            if(!mz_zip_reader_is_file_a_directory(&woomy_archive, i))
                mz_zip_reader_extract_file_to_file(&woomy_archive, file_stat.m_filename, tmp_filename, 0);
            else
                makedir(tmp_filename);
        }

        // Clear target FST directory if it exists
        status = mz_zip_reader_locate_file(&woomy_archive, archive_fst_folder, NULL, 0);
        if (status != -1)
        {
            snprintf(tmp_filename, 0x200, "tmp_append/%s", archive_fst_folder);
            clear_dir(tmp_filename);
        }

        mz_zip_reader_end(&woomy_archive);
    }

    status = mz_zip_writer_init_file(&woomy_archive, woomy_out_path, 0);
    if (!status)
    {
        printf("mz_zip_writer_init_file failed!\n");
        return -1;
    }


    //Create main folder for FST entries
    status = mz_zip_writer_add_mem(&woomy_archive, archive_fst_folder, NULL, 0, MZ_DEFAULT_LEVEL);
    if (!status)
    {
        printf("mz_zip_writer_add_mem failed!\n");
        return -1;
    }

    sprintf(path, "%s/", fst_out_path);
    int woomy_num_entries = get_num_entries(path, 0);
    char **woomy_dir_entries = calloc((woomy_num_entries)*sizeof(char*)*2, 1);
    u32 *woomy_dir_entry_sizes = calloc((woomy_num_entries)*sizeof(u32)*2, 1);
    u32 *woomy_dir_entry_parents = calloc((woomy_num_entries)*sizeof(u32)*2, 1);
    if(!woomy_dir_entries || !woomy_dir_entry_sizes || !woomy_dir_entry_parents)
    {
        printf("Error! Failed to allocate memory for woomy meta.\n");
        return -1;
    }

    printf("%u entries total\n", woomy_num_entries);
    get_entries(path, woomy_dir_entries, woomy_dir_entry_sizes, woomy_dir_entry_parents, 0, 0);

    char archive_filename[0x100];
    char original_filename[0x100];
    int woomy_total_contents = 0; //Used for metadata xml later
    for(int i = 0; i < woomy_num_entries; i++)
    {
        sprintf(archive_filename, "%s%s", archive_fst_folder, woomy_dir_entries[i]);
        sprintf(original_filename, "%s/%s", fst_out_path, woomy_dir_entries[i]);
        printf("Packing %s\n", archive_filename);

        char *ext = strchr(woomy_dir_entries[i], '.');
        if(ext && !strcmp(ext, ".app"))
            woomy_total_contents++;

        status = mz_zip_writer_add_file(&woomy_archive, archive_filename, original_filename, "FST File", (u16)strlen("FST File"), MZ_BEST_SPEED);

        if (!status)
        {
            printf("mz_zip_writer_add_file failed! %s->%s\n", original_filename, archive_filename);
            return -1;
        }

        //Remove packed file
        if(remove_fst)
            remove(original_filename);
    }
    free(woomy_dir_entry_sizes);
    free(woomy_dir_entry_parents);

    //Remove FST directory
    if(remove_fst)
        remove(fst_out_path);

    mz_zip_writer_finalize_archive(&woomy_archive);
    mz_zip_writer_end(&woomy_archive);
    mz_zip_reader_init_file(&woomy_archive, woomy_out_path, 0);

    ezxml_t woomy_xml;
    void *meta_buf = malloc(0x8000);
    if(!meta_buf)
    {
        printf("Error! Failed to allocate memory for .woomy meta buffer!\n");
        return -1;
    }
    if(!woomy_append)
    {
        printf("Creating metadata.xml...\n");
        woomy_xml = ezxml_new("woomy");
    }
    else
    {
        FILE *woomy_xml_file = fopen("tmp_append/metadata.xml", "rb");
        if(woomy_xml_file)
        {
            fread(meta_buf, 0x8000, 0x1, woomy_xml_file);
            fclose(woomy_xml_file);
            woomy_xml = ezxml_parse_str(meta_buf, strlen(meta_buf));

            remove("tmp_append/metadata.xml");
        }
        else
            woomy_xml = ezxml_new("woomy");
    }
    ezxml_t woomy_meta = ezxml_get(woomy_xml, "metadata", -1);
    if(!woomy_meta)
    {
        woomy_meta = ezxml_new("metadata");
        ezxml_insert(woomy_meta, woomy_xml, 0);
    }

    ezxml_t woomy_name = ezxml_get(woomy_xml, "metadata", 0, "name", -1);
    if(!woomy_name)
    {
        woomy_name = ezxml_add_child(woomy_meta, "name", 0);
        woomy_name->txt = dir;
    }

    if(woomy_display_name[0])
    {
        woomy_name->txt = woomy_display_name;
    }

    ezxml_t woomy_icon = ezxml_get(woomy_xml, "metadata", 0, "icon", -1);
    if(!woomy_icon)
    {
        woomy_icon = ezxml_add_child(woomy_meta, "icon", 0);
    }
    woomy_icon->txt = woomy_icon_path[0] != 0 || mz_zip_reader_locate_file(&woomy_archive, "icon.tga", NULL, 0) ? "1" : "0";

    ezxml_t woomy_entries = ezxml_get(woomy_xml, "entries", -1);
    ezxml_t woomy_entry = NULL;
    if(!woomy_entries)
    {
        woomy_entries = ezxml_new("entries");
        ezxml_insert(woomy_entries, woomy_xml, 0);
        woomy_entry = ezxml_add_child(woomy_entries, "entry", 0);
    }
    else
    {
        if(verbose_print)
            printf("Searching for existing entries...\n");
        ezxml_t woomy_entry_search = ezxml_get(woomy_xml, "entries", 0, "entry", -1);
        int entry_search_index = 0;
        while(1)
        {
            ezxml_t next_entry = ezxml_idx(woomy_entry_search, entry_search_index++);
            if(!next_entry)
                break;

            if(!ezxml_attr(next_entry, "folder"))
                break;

            if(verbose_print)
                printf("%s == %s?\n", ezxml_attr(next_entry, "folder"), archive_fst_folder);

            //If this already has an entry, cut it.
            if(!strcmp(ezxml_attr(next_entry, "folder"), archive_fst_folder))
                ezxml_cut(next_entry);
        }

        woomy_entry = ezxml_add_child(woomy_entries, "entry", 0);

        if(verbose_print)
            printf("Done.\n");
    }

    ezxml_set_attr(woomy_entry, "name", woomy_internal_name);
    ezxml_set_attr(woomy_entry, "folder", archive_fst_folder);

    char contents_numstr[0x100];
    snprintf(contents_numstr, 0x100, "%u", woomy_total_contents);
    ezxml_set_attr(woomy_entry, "entries", contents_numstr);

    //Init writer and add XML
    status = mz_zip_writer_init_from_reader(&woomy_archive, woomy_out_path);
    if (!status)
    {
        printf("mz_zip_writer_init_from_reader failed!\n");
        return -1;
    }

    char *xml_out = ezxml_toxml(woomy_xml);

    status = mz_zip_writer_add_mem(&woomy_archive, "metadata.xml", xml_out, strlen(xml_out), MZ_NO_COMPRESSION);
    if (!status)
    {
        printf("mz_zip_writer_add_mem failed!\n");
        return -1;
    }

    if(woomy_icon_path[0])
    {
        status = mz_zip_writer_add_file(&woomy_archive, "icon.tga", woomy_icon_path, "Woomy Icon", (u16) strlen("Woomy Icon"), MZ_NO_COMPRESSION);

        if (!status)
        {
            printf("mz_zip_writer_add_file failed! %s->%s\n", original_filename, archive_filename);
            return -1;
        }
        else
        {
            remove("tmp_append/icon.tga");
        }
    }

    //Repack unpacked contents leftover
    if(woomy_append)
    {
        sprintf(path, "%s/", "tmp_append");
        int woomy_append_num_entries = get_num_entries(path, 0);
        char **woomy_append_dir_entries = calloc((woomy_append_num_entries)*sizeof(char*)*2, 1);
        u32 *woomy_append_dir_entry_sizes = calloc((woomy_append_num_entries)*sizeof(u32)*2, 1);
        u32 *woomy_append_dir_entry_parents = calloc((woomy_append_num_entries)*sizeof(u32)*2, 1);
        if(!woomy_append_dir_entries || !woomy_append_dir_entry_sizes || !woomy_append_dir_entry_parents)
        {
            printf("Error! Failed to allocate memory for .woomy append meta!\n");
            return -1;
        }

        get_entries(path, woomy_append_dir_entries, woomy_append_dir_entry_sizes, woomy_append_dir_entry_parents, 0, 0);

        char archive_append_filename[0x100];
        char original_append_filename[0x100];
        for(int i = 0; i < woomy_append_num_entries; i++)
        {
            sprintf(archive_append_filename, "%s", woomy_append_dir_entries[i]);
            sprintf(original_append_filename, "%s%s", path, woomy_append_dir_entries[i]);
            printf("Packing %s\n", archive_append_filename);

            if(archive_append_filename[strlen(archive_append_filename)-1] == '/')
            {
                status = mz_zip_writer_add_mem(&woomy_archive, archive_fst_folder, NULL, 0, MZ_DEFAULT_LEVEL);
                if (!status)
                {
                    printf("mz_zip_writer_add_mem failed!\n");
                    return -1;
                }
            }
            else
            {
                status = mz_zip_writer_add_file(&woomy_archive, archive_append_filename, original_append_filename, "Repacked File", (u16)strlen("Repacked File"), MZ_BEST_SPEED);

                if (!status)
                {
                    printf("mz_zip_writer_add_file failed! %s->%s\n", original_filename, archive_filename);
                    return -1;
                }

                remove(original_append_filename);
            }
        }
        clear_dir("tmp_append/");
        free(woomy_append_dir_entry_sizes);
        free(woomy_append_dir_entry_parents);
    }

    mz_zip_writer_finalize_archive(&woomy_archive);
    mz_zip_writer_end(&woomy_archive);

    free(xml_out);
    ezxml_free(woomy_xml);

end:
    free(path);

    return 0;
}

void print_fst(void *fst_buffer)
{
    fst_header *f_header = fst_buffer;

    printf("Magic:\t%03s\nVersion:\t%x\nHeader Size:\t0x%x\nNumber of Sections:\t%u\nHash Disabled:\t%x\n\n", f_header->magic, f_header->version, getbe32(f_header->header_size), getbe32(f_header->num_sections), f_header->hash_disabled);
    for(int i = 0; i < getbe32(f_header->num_sections); i++)
    {
        fst_section_entry *f_entry = (fst_buffer+0x20) + (i*sizeof(fst_section_entry));
        printf("entry %x:\nf_addr:\t\t%x\nf_size:\t\t%x\nowner_id:\t%x\ngroup_id:\t%x\nhash mode:\t%x\n\n", i, getbe32(f_entry->f_addr), getbe32(f_entry->f_len), getbe64(f_entry->owner_id), getbe32(f_entry->group_id), f_entry->hash_mode);
    }

    fst_node_entry *f_root_entry = (fst_buffer+0x20) + (getbe32(f_header->num_sections)*sizeof(fst_section_entry));
    int num_nodes = getbe32(f_root_entry->f_len);
    void *str_chunk = (fst_buffer+0x20) + (getbe32(f_header->num_sections)*sizeof(fst_section_entry)) + (num_nodes*sizeof(fst_node_entry));
    printf("%u nodes total:\n", num_nodes);
    for(int i = 0; i < num_nodes; i++)
    {
        fst_node_entry *f_node_entry = (fst_buffer+0x20) + (getbe32(f_header->num_sections)*sizeof(fst_section_entry)) + (i*sizeof(fst_node_entry));
        printf("entry %x, %s:\ntype:\t\t%x\nstr_addr:\t%x\nf_addr:\t\t%x\nf_size:\t\t%x\nperms:\t\t%x\ncontent id:\t%x\n\n", i, str_chunk + (getbe32(f_node_entry->str_addr) & 0xFFFFFF), (getbe32(f_node_entry->str_addr) & 0xFF000000) >> 24, getbe32(f_node_entry->str_addr) & 0xFFFFFF, getbe32(f_node_entry->f_off), getbe32(f_node_entry->f_len), getbe16(f_node_entry->perms), getbe16(f_node_entry->content_id));
    }
}

void clear_dir(char *path)
{
    DIR *dir;
    struct dirent *ent;

    dir = opendir(path);
    if(dir == NULL)
        return;

    while (ent = readdir(dir))
    {
        char temp_buf[0x200];
        sprintf(temp_buf, "%s%s", path, ent->d_name);
        remove(temp_buf);
    }

    closedir(dir);

    remove(path);
}

int get_num_entries(char *dir, u8 filesOnly)
{
    DIR *dfd;
    struct dirent *dp;
    int num = 0;
    char *temp = malloc(0x200);

    if ((dfd = opendir(dir)) == NULL)
    {
        fprintf(stderr, "Can't open %s\n", dir);
        return 0;
    }

    while ((dp = readdir(dfd)) != NULL)
    {
        struct stat stbuf ;
        sprintf(temp, "%s/%s",dir,dp->d_name) ;
        if( stat(temp,&stbuf ) == -1 )
        {
            printf("Unable to stat file: %s\n", temp) ;
            continue ;
        }

        if ( ( stbuf.st_mode & S_IFMT ) == S_IFDIR )
        {
            if(strcmp(dp->d_name, ".") && strcmp(dp->d_name, ".."))
            {
                if(!filesOnly)
                    num++;
                num += get_num_entries(temp, filesOnly);
            }
        }
        else
        {
            num++;
        }
    }
    free(temp);

    return num;
}

int get_entries(char *dir, char **out_dirs, u32 *out_sizes, u32 *out_parent_dir, int index, int base_parent_dir)
{
    DIR *dfd;
    struct dirent *dp;
    int num = index;
    char *temp = malloc(0x200);

    if ((dfd = opendir(dir)) == NULL)
    {
        fprintf(stderr, "Can't open %s\n", dir);
        return 0;
    }

    while ((dp = readdir(dfd)) != NULL)
    {
        struct stat stbuf ;
        sprintf(temp, "%s/%s",dir,dp->d_name) ;
        if( stat(temp,&stbuf ) == -1 )
        {
            printf("Unable to stat file: %s\n", temp) ;
            continue ;
        }

        if ( ( stbuf.st_mode & S_IFMT ) == S_IFDIR )
        {
            if(strcmp(dp->d_name, ".") && strcmp(dp->d_name, ".."))
            {
                out_dirs[num] = calloc(strlen(temp)+2, 1);
                out_sizes[num] = stbuf.st_size;
                out_parent_dir[num] = base_parent_dir;
                strcpy(out_dirs[num], temp);

                // Folders get a trailing /
                if(out_dirs[num][strlen(out_dirs[num])-1] != '/')
                    strcat(out_dirs[num], "/");

                num++;
                num += get_entries(temp, out_dirs, out_sizes, out_parent_dir, num, base_parent_dir+1);
                
            }
        }
        else
        {
            out_dirs[num] = calloc(strlen(temp)+2, 1);
            out_sizes[num] = stbuf.st_size;
            out_parent_dir[num] = base_parent_dir;
            strcpy(out_dirs[num], temp);
            num++;
        }
    }
    free(temp);

    
    if(index == 0)
    {
        u32 *out_parent_dir_old = malloc(num*sizeof(u32));
        memcpy(out_parent_dir_old, out_parent_dir, num*sizeof(u32));

        for(int i = 0; i < num; i++)
        {
            //Strip path from contents
            strcpy(out_dirs[i], strstr(out_dirs[i], dir) + strlen(dir) + 1);

            //Convert levels to indexes
            int j;
            for(j = i; j > 0; j--)
            {
                if(out_parent_dir_old[j] == out_parent_dir_old[i]-1)
                    break;
            }
            out_parent_dir[i] = j;
        }

        free(out_parent_dir_old);
    }

    return num-index;
}
