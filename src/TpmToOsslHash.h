/********************************************************************************/
/*										*/
/*		Used to splice the OpenSSL() hash code into the TPM code  	*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: TpmToOsslHash.h 1311 2018-08-23 21:39:29Z kgoldman $		*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2016 - 2018				*/
/*										*/
/********************************************************************************/

#ifndef TPMTOOSSLHASH_H
#define TPMTOOSSLHASH_H

/* B.2.2.1. TpmToOsslHash.h */
/* B.2.2.1.1. Introduction */
/* This header file is used to splice the OpenSSL() hash code into the TPM
 * code. */
#ifndef _TPM_TO_OSSL_HASH_H_
#define _TPM_TO_OSSL_HASH_H_
#if HASH_LIB == OSSL
#include <openssl/evp.h>
/* B.2.2.1.2. Links to the OpenSSL HASH code */
/* Redefine the internal name used for each of the hash state structures to the
 * name used by the library. These defines need to be known in all parts of the
 * TPM so that the structure sizes can be properly computed when needed. */
#define tpmHashStateSHA1_t        EVP_MD_CTX*
#define tpmHashStateSHA256_t      EVP_MD_CTX*
#define tpmHashStateSHA384_t      EVP_MD_CTX*
#define tpmHashStateSHA512_t      EVP_MD_CTX*
#define tpmHashStateSHA3_256_t    EVP_MD_CTX*
#define tpmHashStateSHA3_384_t    EVP_MD_CTX*
#define tpmHashStateSHA3_512_t    EVP_MD_CTX*
#define tpmHashStateSHAKE128_t    EVP_MD_CTX*
#define tpmHashStateSHAKE256_t    EVP_MD_CTX*
#if ALG_SM3_256
#   error "The version of OpenSSL used by this code does not support SM3"
#endif
/*     The defines below are only needed when compiling CryptHash.c or
 *     CryptSmac.c. This isolation is primarily to avoid name space collision.
 *     However, if there is a real collision, it will likely show up when the
 *     linker tries to put things together. */
#ifdef _CRYPT_HASH_C_
typedef BYTE          *PBYTE;
typedef const BYTE    *PCBYTE;
/* Define the interface between CryptHash.c to the functions provided by the
 * library. For each method, define the calling parameters of the method and
 * then define how the method is invoked in CryptHash.c. */
/* All hashes are required to have the same calling sequence. If they don't,
 * create a simple adaptation function that converts from the standard form of
 * the call to the form used by the specific hash (and then send a nasty letter
 * to the person who wrote the hash function for the library). */
/* The macro that calls the method also defines how the parameters get swizzled
 * between the default form (in CryptHash.c)and the library form. */
/* Initialize the hash context */
#define HASH_START_METHOD_DEF   void (HASH_START_METHOD)(EVP_MD_CTX *state, \
        const EVP_MD *md, ENGINE *impl)
#define HASH_START(hashState)						\
    switch((hashState)->hashAlg) { \
        case TPM_ALG_SHA1: \
            (hashState)->state.Sha1 = EVP_MD_CTX_new(); \
            ((hashState)->def->method.start)((hashState)->state.Sha1, \
                (hashState)->def->method.type, NULL); \
           break;\
        case TPM_ALG_SHA256: \
            (hashState)->state.Sha256 = EVP_MD_CTX_new(); \
            ((hashState)->def->method.start)((hashState)->state.Sha256, \
                (hashState)->def->method.type, NULL); \
           break;\
        case TPM_ALG_SHA384: \
            (hashState)->state.Sha384 = EVP_MD_CTX_new(); \
            ((hashState)->def->method.start)((hashState)->state.Sha384, \
                (hashState)->def->method.type, NULL); \
           break;\
        case TPM_ALG_SHA512:  \
            (hashState)->state.Sha512 = EVP_MD_CTX_new(); \
            ((hashState)->def->method.start)((hashState)->state.Sha512, \
                (hashState)->def->method.type, NULL); \
           break;\
        case TPM_ALG_SHA3_256:  \
            (hashState)->state.Sha3_256 = EVP_MD_CTX_new(); \
            ((hashState)->def->method.start)((hashState)->state.Sha3_256, \
                (hashState)->def->method.type, NULL); \
           break;\
        case TPM_ALG_SHA3_384:  \
            (hashState)->state.Sha3_384 = EVP_MD_CTX_new(); \
            ((hashState)->def->method.start)((hashState)->state.Sha3_384, \
                (hashState)->def->method.type, NULL); \
           break;\
        case TPM_ALG_SHA3_512:  \
            (hashState)->state.Sha3_512 = EVP_MD_CTX_new(); \
            ((hashState)->def->method.start)((hashState)->state.Sha3_512, \
                (hashState)->def->method.type, NULL); \
           break;\
        case TPM_ALG_SHAKE128:  \
            (hashState)->state.Shake128 = EVP_MD_CTX_new(); \
            ((hashState)->def->method.start)((hashState)->state.Shake128, \
                (hashState)->def->method.type, NULL); \
           break;\
        case TPM_ALG_SHAKE256:  \
            (hashState)->state.Shake256 = EVP_MD_CTX_new(); \
            ((hashState)->def->method.start)((hashState)->state.Shake256, \
                (hashState)->def->method.type, NULL); \
           break;\
        default: \
            printf("Start hash with unexpected hash alg: %d\n", (hashState)->hashAlg); \
            break;\
    }\
/* Add data to the hash */
#define HASH_DATA_METHOD_DEF						\
    void (HASH_DATA_METHOD)(EVP_MD_CTX *state,			\
			    PCBYTE buffer,				\
			    size_t size)
#define HASH_DATA(hashState, dInSize, dIn)				\
    switch((hashState)->hashAlg) { \
        case TPM_ALG_SHA1:  \
            ((hashState)->def->method.data)((hashState)->state.Sha1, dIn, dInSize); \
           break;\
        case TPM_ALG_SHA256:  \
            ((hashState)->def->method.data)((hashState)->state.Sha256, dIn, dInSize); \
           break;\
        case TPM_ALG_SHA384:  \
            ((hashState)->def->method.data)((hashState)->state.Sha384, dIn, dInSize); \
           break;\
        case TPM_ALG_SHA512:  \
            ((hashState)->def->method.data)((hashState)->state.Sha512, dIn, dInSize); \
           break;\
        case TPM_ALG_SHA3_256:  \
            ((hashState)->def->method.data)((hashState)->state.Sha3_256, dIn, dInSize); \
           break;\
        case TPM_ALG_SHA3_384:  \
            ((hashState)->def->method.data)((hashState)->state.Sha3_384, dIn, dInSize); \
           break;\
        case TPM_ALG_SHA3_512:  \
            ((hashState)->def->method.data)((hashState)->state.Sha3_512, dIn, dInSize); \
           break;\
        case TPM_ALG_SHAKE128:  \
            ((hashState)->def->method.data)((hashState)->state.Shake128, dIn, dInSize); \
           break;\
        case TPM_ALG_SHAKE256:  \
            ((hashState)->def->method.data)((hashState)->state.Shake256, dIn, dInSize); \
           break;\
        default: \
            printf("Process hash with unexpected hash alg: %d\n", (hashState)->hashAlg); \
            break;\
    }\
/* Finalize the hash and get the digest */
#define HASH_END_METHOD_DEF						\
    void (HASH_END_METHOD)(EVP_MD_CTX *state, BYTE *buffer, size_t len)
#define HASH_END(hashState, buffer, dOutSize)					\
    switch((hashState)->hashAlg) { \
        case TPM_ALG_SHA1:  \
           ((hashState)->def->method.end)((hashState)->state.Sha1, buffer, 0); \
           EVP_MD_CTX_free((hashState)->state.Sha1); \
           break;\
        case TPM_ALG_SHA256:  \
           ((hashState)->def->method.end)((hashState)->state.Sha256, buffer, 0); \
           EVP_MD_CTX_free((hashState)->state.Sha256); \
           break;\
        case TPM_ALG_SHA384:  \
           ((hashState)->def->method.end)((hashState)->state.Sha384, buffer, 0); \
           EVP_MD_CTX_free((hashState)->state.Sha384); \
           break;\
        case TPM_ALG_SHA512:  \
           ((hashState)->def->method.end)((hashState)->state.Sha512, buffer, 0); \
           EVP_MD_CTX_free((hashState)->state.Sha512); \
           break;\
        case TPM_ALG_SHA3_256:  \
           ((hashState)->def->method.end)((hashState)->state.Sha3_256, buffer, 0); \
           EVP_MD_CTX_free((hashState)->state.Sha3_256); \
           break;\
        case TPM_ALG_SHA3_384:  \
           ((hashState)->def->method.end)((hashState)->state.Sha3_384, buffer, 0); \
           EVP_MD_CTX_free((hashState)->state.Sha3_384); \
           break;\
        case TPM_ALG_SHA3_512:  \
           ((hashState)->def->method.end)((hashState)->state.Sha3_512, buffer, 0); \
           EVP_MD_CTX_free((hashState)->state.Sha3_512); \
           break;\
        case TPM_ALG_SHAKE128:  \
           ((hashState)->def->method.end)((hashState)->state.Shake128, buffer, dOutSize); \
           EVP_MD_CTX_free((hashState)->state.Shake128); \
           break;\
        case TPM_ALG_SHAKE256:  \
           ((hashState)->def->method.end)((hashState)->state.Shake256, buffer, dOutSize); \
           EVP_MD_CTX_free((hashState)->state.Shake256); \
           break;\
        default: \
            printf("Ended hash with unexpected hash alg: %d\n", (hashState)->hashAlg); \
            break;\
    }\
/* Copy the hash context */
/* NOTE: For import, export, and copy, memcpy() is used since there is no
 * reformatting necessary between the internal and external forms. */
#define HASH_STATE_COPY_METHOD_DEF					\
    void (HASH_STATE_COPY_METHOD)(PANY_HASH_STATE to,			\
				  PCANY_HASH_STATE from,		\
				  size_t size)
#define HASH_STATE_COPY(hashStateOut, hashStateIn)			\
    ((hashStateIn)->def->method.copy)(&(hashStateOut)->state,		\
				      &(hashStateIn)->state,		\
				      (hashStateIn)->def->contextSize)
/* Copy (with reformatting when necessary) an internal hash structure to an external blob */
#define  HASH_STATE_EXPORT_METHOD_DEF					\
    void (HASH_STATE_EXPORT_METHOD)(BYTE *to,				\
				    PCANY_HASH_STATE from,		\
				    size_t size)
#define  HASH_STATE_EXPORT(to, hashStateFrom)				\
    ((hashStateFrom)->def->method.copyOut)				\
    (&(((BYTE *)(to))[offsetof(HASH_STATE, state)]),			\
     &(hashStateFrom)->state,						\
     (hashStateFrom)->def->contextSize)
/* Copy from an external blob to an internal formate (with reformatting when necessary */
#define  HASH_STATE_IMPORT_METHOD_DEF					\
    void (HASH_STATE_IMPORT_METHOD)(PANY_HASH_STATE to,			\
				    const BYTE *from,			\
				    size_t size)
#define  HASH_STATE_IMPORT(hashStateTo, from)				\
    ((hashStateTo)->def->method.copyIn)					\
    (&(hashStateTo)->state,						\
     &(((const BYTE *)(from))[offsetof(HASH_STATE, state)]),		\
     (hashStateTo)->def->contextSize)

/* Function aliases. The code in CryptHash.c uses the internal designation for
 * the functions. These need to be translated to the function names of the
 * library. */
//      Internal Designation        External Designation
#define tpmHashStart_SHA1           EVP_DigestInit_ex                 // external name of the initialization method
#define tpmHashData_SHA1            EVP_DigestUpdate
#define tpmHashEnd_SHA1             EVP_DigestFinal_ex
#define tpmHashStateCopy_SHA1       memcpy
#define tpmHashStateExport_SHA1     memcpy
#define tpmHashStateImport_SHA1     memcpy

#define tpmHashStart_SHA256         EVP_DigestInit_ex
#define tpmHashData_SHA256          EVP_DigestUpdate
#define tpmHashEnd_SHA256           EVP_DigestFinal_ex
#define tpmHashStateCopy_SHA256     memcpy
#define tpmHashStateExport_SHA256   memcpy
#define tpmHashStateImport_SHA256   memcpy

#define tpmHashStart_SHA384         EVP_DigestInit_ex
#define tpmHashData_SHA384          EVP_DigestUpdate
#define tpmHashEnd_SHA384           EVP_DigestFinal_ex
#define tpmHashStateCopy_SHA384     memcpy
#define tpmHashStateExport_SHA384   memcpy
#define tpmHashStateImport_SHA384   memcpy

#define tpmHashStart_SHA512         EVP_DigestInit_ex
#define tpmHashData_SHA512          EVP_DigestUpdate
#define tpmHashEnd_SHA512           EVP_DigestFinal_ex
#define tpmHashStateCopy_SHA512     memcpy
#define tpmHashStateExport_SHA512   memcpy
#define tpmHashStateImport_SHA512   memcpy

#define tpmHashStart_SHA3_256       EVP_DigestInit_ex
#define tpmHashData_SHA3_256        EVP_DigestUpdate
#define tpmHashEnd_SHA3_256         EVP_DigestFinal_ex
#define tpmHashStateCopy_SHA3_256   memcpy
#define tpmHashStateExport_SHA3_256 memcpy
#define tpmHashStateImport_SHA3_256 memcpy

#define tpmHashStart_SHA3_384       EVP_DigestInit_ex
#define tpmHashData_SHA3_384        EVP_DigestUpdate
#define tpmHashEnd_SHA3_384         EVP_DigestFinal_ex
#define tpmHashStateCopy_SHA3_384   memcpy
#define tpmHashStateExport_SHA3_384 memcpy
#define tpmHashStateImport_SHA3_384 memcpy

#define tpmHashStart_SHA3_512       EVP_DigestInit_ex
#define tpmHashData_SHA3_512        EVP_DigestUpdate
#define tpmHashEnd_SHA3_512         EVP_DigestFinal_ex
#define tpmHashStateCopy_SHA3_512   memcpy
#define tpmHashStateExport_SHA3_512 memcpy
#define tpmHashStateImport_SHA3_512 memcpy

#define tpmHashStart_SHAKE128       EVP_DigestInit_ex
#define tpmHashData_SHAKE128        EVP_DigestUpdate
#define tpmHashEnd_SHAKE128         EVP_DigestFinalXOF
#define tpmHashStateCopy_SHAKE128   memcpy
#define tpmHashStateExport_SHAKE128 memcpy
#define tpmHashStateImport_SHAKE128 memcpy

#define tpmHashStart_SHAKE256       EVP_DigestInit_ex
#define tpmHashData_SHAKE256        EVP_DigestUpdate
#define tpmHashEnd_SHAKE256         EVP_DigestFinalXOF
#define tpmHashStateCopy_SHAKE256   memcpy
#define tpmHashStateExport_SHAKE256 memcpy
#define tpmHashStateImport_SHAKE256 memcpy

#endif // _CRYPT_HASH_C_
#define LibHashInit() \
    SHA1_Def.method.type     = EVP_sha1(); \
    SHA256_Def.method.type   = EVP_sha256(); \
    SHA384_Def.method.type   = EVP_sha384(); \
    SHA512_Def.method.type   = EVP_sha512(); \
    SHA3_256_Def.method.type = EVP_sha3_256(); \
    SHA3_384_Def.method.type = EVP_sha3_384(); \
    SHA3_512_Def.method.type = EVP_sha3_512(); \
    SHAKE128_Def.method.type = EVP_shake128(); \
    SHAKE256_Def.method.type = EVP_shake256();

/* This definition would change if there were something to report */
#define HashLibSimulationEnd()
#endif // HASH_LIB == OSSL
#endif //

#endif
