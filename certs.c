/*
 *  makefst - CDN FST packer and packager for Wii U homebrew
 *
 *  This code is licensed to you under the terms of the MIT License;
 *  see file LICENSE for details
 */

#include "certs.h"

// Cert Sizes
void GetCertSigSectionSizes(u32 *sign_size, u32 *sign_padlen, const u8 *cert)
{
	u32 sig = u8_to_u32(cert,BE);
	switch(sig){
		case RSA_4096_SHA1 :
			*sign_size = 0x200;
			*sign_padlen = 0x3C;
			break;
		case RSA_2048_SHA1 :
			*sign_size = 0x100;
			*sign_padlen = 0x3C;
			break;
		case ECC_SHA1 :
			*sign_size = 0x3C;
			*sign_padlen = 0x40;
			break;
		case RSA_4096_SHA256 :
			*sign_size = 0x200;
			*sign_padlen = 0x3C;
			break;
		case RSA_2048_SHA256 :
			*sign_size = 0x100;
			*sign_padlen = 0x3C;
			break;
		case ECC_SHA256 :
			*sign_size = 0x3C;
			*sign_padlen = 0x40;
			break;
		default :
			*sign_size = 0;
			*sign_padlen = 0;
			break;
	}
	return;
}

u32 GetCertSize(const u8 *cert)
{
	u32 sign_size = 0;
	u32 sign_padlen = 0;
	GetCertSigSectionSizes(&sign_size,&sign_padlen,cert);
	if(!sign_size || !sign_padlen)
		return 0;

	return sizeof(u32) + sign_size + sign_padlen + sizeof(cert_hdr) + GetCertPubkSectionSize(GetCertPubkType(cert));
}


cert_hdr* GetCertHdr(const u8 *cert)
{
	u32 sign_size = 0;
	u32 sign_padlen = 0;
	GetCertSigSectionSizes(&sign_size,&sign_padlen,cert);
	if(!sign_size || !sign_padlen) return NULL;

	return (cert_hdr*)(cert+4+sign_size+sign_padlen);
}

u32 GetCertPubkSectionSize(pubk_types type)
{
	switch(type){
		case RSA_4096_PUBK : return sizeof(rsa_4096_pubk_struct);
		case RSA_2048_PUBK : return sizeof(rsa_2048_pubk_struct);
		case ECC_PUBK : return sizeof(ecc_pubk_struct);
		default : return 0;
	}
}

// Issuer/Name Functions
u8 *GetCertIssuer(const u8 *cert)
{
	cert_hdr *hdr = GetCertHdr(cert);
	return hdr->issuer;
}
u8 *GetCertName(const u8 *cert)
{
	cert_hdr *hdr = GetCertHdr(cert);
	return hdr->name;
}

void GenCertChildIssuer(u8 *dest, const u8 *cert)
{
	snprintf((char*)dest,0x40,"%s-%s",GetCertIssuer(cert),GetCertName(cert));
}

// Pubk
pubk_types GetCertPubkType(const u8 *cert)
{
	cert_hdr *hdr = GetCertHdr(cert);

	return (pubk_types)u8_to_u32(hdr->keyType,BE);
}
u8 *GetCertPubk(const u8 *cert)
{
	if(!GetCertHdr(cert)) 
		return NULL;
	return ((u8*)GetCertHdr(cert)) + sizeof(cert_hdr);
}

bool VerifyCert(u8 *cert, const u8 *pubk)
{
	if(!GetCertHdr(cert)) 
		return false;
	u8 *signature = (cert+sizeof(u32));
	u8 *data = (u8*)GetCertHdr(cert);
	u32 datasize = sizeof(cert_hdr) + GetCertPubkSectionSize(GetCertPubkType(cert));

	return RsaSignVerify(data,datasize,signature,pubk,NULL,u8_to_u32(cert,BE),WUP_RSA_VERIFY);
}
