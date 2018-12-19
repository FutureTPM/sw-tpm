/********************************************************************************/
/*										*/
/*			  Asymmetric Commands   				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: AsymmetricCommands.c 1262 2018-07-11 21:03:43Z kgoldman $	*/
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

#include "Tpm.h"
#include "RSA_Encrypt_fp.h"
#if CC_RSA_Encrypt  // Conditional expansion of this file
#if ALG_RSA
TPM_RC
TPM2_RSA_Encrypt(
		 RSA_Encrypt_In      *in,            // IN: input parameter list
		 RSA_Encrypt_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC                  result;
    OBJECT                  *rsaKey;
    TPMT_RSA_DECRYPT        *scheme;
    // Input Validation
    rsaKey = HandleToObject(in->keyHandle);
    // selected key must be an RSA key
    if(rsaKey->publicArea.type != TPM_ALG_RSA)
	return TPM_RCS_KEY + RC_RSA_Encrypt_keyHandle;
    // selected key must have the decryption attribute
    if(!IS_ATTRIBUTE(rsaKey->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
	return TPM_RCS_ATTRIBUTES + RC_RSA_Encrypt_keyHandle;
    // Is there a label?
    if(!IsLabelProperlyFormatted(&in->label.b))
	return TPM_RCS_VALUE + RC_RSA_Encrypt_label;
    // Command Output
    // Select a scheme for encryption
    scheme = CryptRsaSelectScheme(in->keyHandle, &in->inScheme);
    if(scheme == NULL)
	return TPM_RCS_SCHEME + RC_RSA_Encrypt_inScheme;
    // Encryption.  TPM_RC_VALUE, or TPM_RC_SCHEME errors my be returned buy
    // CryptEncyptRSA.
    out->outData.t.size = sizeof(out->outData.t.buffer);
    result = CryptRsaEncrypt(&out->outData, &in->message.b, rsaKey, scheme,
			     &in->label.b, NULL);
    return result;
}
#endif
#endif // CC_RSA_Encrypt
#include "Tpm.h"
#include "RSA_Decrypt_fp.h"
#if CC_RSA_Decrypt  // Conditional expansion of this file
#if ALG_RSA
TPM_RC
TPM2_RSA_Decrypt(
		 RSA_Decrypt_In      *in,            // IN: input parameter list
		 RSA_Decrypt_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC                       result;
    OBJECT                      *rsaKey;
    TPMT_RSA_DECRYPT            *scheme;
    // Input Validation
    rsaKey = HandleToObject(in->keyHandle);
    // The selected key must be an RSA key
    if(rsaKey->publicArea.type != TPM_ALG_RSA)
	return TPM_RCS_KEY + RC_RSA_Decrypt_keyHandle;
    // The selected key must be an unrestricted decryption key
    if(IS_ATTRIBUTE(rsaKey->publicArea.objectAttributes, TPMA_OBJECT, restricted)
       || !IS_ATTRIBUTE(rsaKey->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
	return TPM_RCS_ATTRIBUTES + RC_RSA_Decrypt_keyHandle;
    // NOTE: Proper operation of this command requires that the sensitive area
    // of the key is loaded. This is assured because authorization is required
    // to use the sensitive area of the key. In order to check the authorization,
    // the sensitive area has to be loaded, even if authorization is with policy.
    // If label is present, make sure that it is a NULL-terminated string
    if(!IsLabelProperlyFormatted(&in->label.b))
	return TPM_RCS_VALUE + RC_RSA_Decrypt_label;
    // Command Output
    // Select a scheme for decrypt.
    scheme = CryptRsaSelectScheme(in->keyHandle, &in->inScheme);
    if(scheme == NULL)
	return TPM_RCS_SCHEME + RC_RSA_Decrypt_inScheme;
    // Decryption.  TPM_RC_VALUE, TPM_RC_SIZE, and TPM_RC_KEY error may be
    // returned by CryptRsaDecrypt.
    // NOTE: CryptRsaDecrypt can also return TPM_RC_ATTRIBUTES or TPM_RC_BINDING
    // when the key is not a decryption key but that was checked above.
    out->message.t.size = sizeof(out->message.t.buffer);
    result = CryptRsaDecrypt(&out->message.b, &in->cipherText.b, rsaKey,
			     scheme, &in->label.b);
    return result;
}
#endif
#endif // CC_RSA_Decrypt
#include "Tpm.h"
#include "ECDH_KeyGen_fp.h"
#if CC_ECDH_KeyGen  // Conditional expansion of this file
#if ALG_ECC
TPM_RC
TPM2_ECDH_KeyGen(
		 ECDH_KeyGen_In      *in,            // IN: input parameter list
		 ECDH_KeyGen_Out     *out            // OUT: output parameter list
		 )
{
    OBJECT                  *eccKey;
    TPM2B_ECC_PARAMETER      sensitive;
    TPM_RC                   result;
    // Input Validation
    eccKey = HandleToObject(in->keyHandle);
    // Referenced key must be an ECC key
    if(eccKey->publicArea.type != TPM_ALG_ECC)
	return TPM_RCS_KEY + RC_ECDH_KeyGen_keyHandle;
    // Command Output
    do
	{
	    TPMT_PUBLIC         *keyPublic = &eccKey->publicArea;
	    // Create ephemeral ECC key
	    result = CryptEccNewKeyPair(&out->pubPoint.point, &sensitive,
					keyPublic->parameters.eccDetail.curveID);
	    if(result == TPM_RC_SUCCESS)
	        {
	            // Compute Z
	            result = CryptEccPointMultiply(&out->zPoint.point,
	                                           keyPublic->parameters.eccDetail.curveID,
	                                           &keyPublic->unique.ecc,
	                                           &sensitive,
	                                           NULL, NULL);
		    // The point in the key is not on the curve. Indicate
		    // that the key is bad.
	            if(result == TPM_RC_ECC_POINT)
	                return TPM_RCS_KEY + RC_ECDH_KeyGen_keyHandle;
		    // The other possible error from CryptEccPointMultiply is
		    // TPM_RC_NO_RESULT indicating that the multiplication resulted in
		    // the point at infinity, so get a new random key and start over
		    // BTW, this never happens.
	        }
	} while(result == TPM_RC_NO_RESULT);
    return result;
}
#endif // ALG_ECC
#endif // CC_ECDH_KeyGen
#include "Tpm.h"
#include "ECDH_ZGen_fp.h"
#if CC_ECDH_ZGen  // Conditional expansion of this file
#if ALG_ECC
TPM_RC
TPM2_ECDH_ZGen(
	       ECDH_ZGen_In    *in,            // IN: input parameter list
	       ECDH_ZGen_Out   *out            // OUT: output parameter list
	       )
{
    TPM_RC                   result;
    OBJECT                  *eccKey;
    // Input Validation
    eccKey = HandleToObject(in->keyHandle);
    // Selected key must be a non-restricted, decrypt ECC key
    if(eccKey->publicArea.type != TPM_ALG_ECC)
	return TPM_RCS_KEY + RC_ECDH_ZGen_keyHandle;
    // Selected key needs to be unrestricted with the 'decrypt' attribute
    if(IS_ATTRIBUTE(eccKey->publicArea.objectAttributes, TPMA_OBJECT, restricted)
       || !IS_ATTRIBUTE(eccKey->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
	return TPM_RCS_ATTRIBUTES + RC_ECDH_ZGen_keyHandle;
    // Make sure the scheme allows this use
    if(eccKey->publicArea.parameters.eccDetail.scheme.scheme != TPM_ALG_ECDH
       &&  eccKey->publicArea.parameters.eccDetail.scheme.scheme != TPM_ALG_NULL)
	return TPM_RCS_SCHEME + RC_ECDH_ZGen_keyHandle;
    // Command Output
    // Compute Z. TPM_RC_ECC_POINT or TPM_RC_NO_RESULT may be returned here.
    result = CryptEccPointMultiply(&out->outPoint.point,
				   eccKey->publicArea.parameters.eccDetail.curveID,
				   &in->inPoint.point,
				   &eccKey->sensitive.sensitive.ecc,
				   NULL, NULL);
    if(result != TPM_RC_SUCCESS)
	return RcSafeAddToResult(result, RC_ECDH_ZGen_inPoint);
    return result;
}
#endif
#endif // CC_ECDH_ZGen
#include "Tpm.h"
#include "ECC_Parameters_fp.h"
#if CC_ECC_Parameters  // Conditional expansion of this file
#if ALG_ECC
TPM_RC
TPM2_ECC_Parameters(
		    ECC_Parameters_In   *in,            // IN: input parameter list
		    ECC_Parameters_Out  *out            // OUT: output parameter list
		    )
{
    // Command Output
    // Get ECC curve parameters
    if(CryptEccGetParameters(in->curveID, &out->parameters))
	return TPM_RC_SUCCESS;
    else
	return TPM_RCS_VALUE + RC_ECC_Parameters_curveID;
}
#endif
#endif // CC_ECC_Parameters
#include "Tpm.h"
#include "ZGen_2Phase_fp.h"
#if CC_ZGen_2Phase  // Conditional expansion of this file
TPM_RC
TPM2_ZGen_2Phase(
		 ZGen_2Phase_In      *in,            // IN: input parameter list
		 ZGen_2Phase_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC                   result;
    OBJECT                  *eccKey;
    TPM2B_ECC_PARAMETER      r;
    TPM_ALG_ID               scheme;
    // Input Validation
    eccKey = HandleToObject(in->keyA);
    // keyA must be an ECC key
    if(eccKey->publicArea.type != TPM_ALG_ECC)
	return TPM_RCS_KEY + RC_ZGen_2Phase_keyA;
    // keyA must not be restricted and must be a decrypt key
    if(IS_ATTRIBUTE(eccKey->publicArea.objectAttributes, TPMA_OBJECT, restricted)
       || !IS_ATTRIBUTE(eccKey->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
	return TPM_RCS_ATTRIBUTES + RC_ZGen_2Phase_keyA;
    // if the scheme of keyA is TPM_ALG_NULL, then use the input scheme; otherwise
    // the input scheme must be the same as the scheme of keyA
    scheme = eccKey->publicArea.parameters.asymDetail.scheme.scheme;
    if(scheme != TPM_ALG_NULL)
	{
	    if(scheme != in->inScheme)
		return TPM_RCS_SCHEME + RC_ZGen_2Phase_inScheme;
	}
    else
	scheme = in->inScheme;
    if(scheme == TPM_ALG_NULL)
	return TPM_RCS_SCHEME + RC_ZGen_2Phase_inScheme;
    // Input points must be on the curve of keyA
    if(!CryptEccIsPointOnCurve(eccKey->publicArea.parameters.eccDetail.curveID,
			       &in->inQsB.point))
	return TPM_RCS_ECC_POINT + RC_ZGen_2Phase_inQsB;
    if(!CryptEccIsPointOnCurve(eccKey->publicArea.parameters.eccDetail.curveID,
			       &in->inQeB.point))
	return TPM_RCS_ECC_POINT + RC_ZGen_2Phase_inQeB;
    if(!CryptGenerateR(&r, &in->counter,
		       eccKey->publicArea.parameters.eccDetail.curveID,
		       NULL))
	return TPM_RCS_VALUE + RC_ZGen_2Phase_counter;
    // Command Output
    result = CryptEcc2PhaseKeyExchange(&out->outZ1.point,
				       &out->outZ2.point,
				       eccKey->publicArea.parameters.eccDetail.curveID,
				       scheme,
				       &eccKey->sensitive.sensitive.ecc,
				       &r,
				       &in->inQsB.point,
				       &in->inQeB.point);
    if(result == TPM_RC_SCHEME)
	return TPM_RCS_SCHEME + RC_ZGen_2Phase_inScheme;
    if(result == TPM_RC_SUCCESS)
	CryptEndCommit(in->counter);
    return result;
}
#endif

/*****************************************************************************/
/*                                Kyber Mods                                 */
/*****************************************************************************/
#if ALG_KYBER
#include "kyber-params.h"

typedef struct {
    uint64_t k;
    uint64_t eta;
    uint64_t publickeybytes;
    uint64_t secretkeybytes;
    uint64_t polyveccompressedbytes;
    uint64_t indcpa_secretkeybytes;
    uint64_t indcpa_publickeybytes;
    uint64_t ciphertextbytes;
} KyberParams;

static KyberParams generate_kyber_params(BYTE kyber_k) {
    KyberParams params;
    uint64_t kyber_polyvecbytes           = 0;

    params.k = kyber_k;
    kyber_polyvecbytes           = kyber_k * KYBER_POLYBYTES;
    params.polyveccompressedbytes = kyber_k * 352;

    params.indcpa_publickeybytes = params.polyveccompressedbytes + KYBER_SYMBYTES;
    params.indcpa_secretkeybytes = kyber_polyvecbytes;

    params.publickeybytes =  params.indcpa_publickeybytes;
    params.secretkeybytes =  params.indcpa_secretkeybytes + params.indcpa_publickeybytes + 2*KYBER_SYMBYTES;
    params.ciphertextbytes = params.polyveccompressedbytes + KYBER_POLYCOMPRESSEDBYTES;

    if (kyber_k == 2) {
        params.eta = 5; /* Kyber512 */
    } else if (kyber_k == 3) {
        params.eta = 4; /* Kyber768 */
    } else {
        params.eta = 3; /* Kyber1024 */
    }

    return params;
}
#endif

#if CC_KYBER_KeyGen  // Conditional expansion of this file
#include "Tpm.h"
#include "KYBER_KeyGen_fp.h"
#include "kyber-params.h"
#include "kyber-indcpa.h"
#include "fips202.h"
#if ALG_KYBER
TPM_RC
TPM2_KYBER_KeyGen(
		 KYBER_KeyGen_In      *in,            // In: input parameter list
		 KYBER_KeyGen_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   result = TPM_RC_SUCCESS;
    KyberParams params;

    // Parameter check
    if (in->sec_sel >= 2 && in->sec_sel <= 4) {
        params = generate_kyber_params(in->sec_sel);
    } else {
        // TODO: Proper Error codes
        return result + 2;
    }

    // Command Output
    indcpa_keypair((unsigned char *)&out->public_key.b.buffer,
            (unsigned char *)&out->secret_key.b.buffer,
            params.k, params.polyveccompressedbytes, params.eta);
    for (size_t i = 0; i < params.indcpa_publickeybytes; i++) {
      out->secret_key.b.buffer[i+params.indcpa_secretkeybytes] = out->public_key.b.buffer[i];
    }
    sha3_256((unsigned char *)out->secret_key.b.buffer+params.secretkeybytes-2*KYBER_SYMBYTES,
            out->public_key.b.buffer,
            params.publickeybytes);
    /* Value z for pseudo-random output on reject */
    CryptRandomGenerate(KYBER_SYMBYTES, out->secret_key.b.buffer+params.secretkeybytes-KYBER_SYMBYTES);

    out->public_key.b.size = params.publickeybytes;
    out->secret_key.b.size = params.secretkeybytes;

    return result;
}
#endif // ALG_KYBER
#endif // CC_KYBER_KeyGen

#if CC_KYBER_Enc  // Conditional expansion of this file
#include "Tpm.h"
#include "KYBER_Enc_fp.h"
#include "kyber-params.h"
#include "kyber-indcpa.h"
#include "fips202.h"
#if ALG_KYBER
TPM_RC
TPM2_KYBER_Enc(
		 KYBER_Enc_In      *in,            // In: input parameter list
		 KYBER_Enc_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   result = TPM_RC_SUCCESS;
    KyberParams params;

    // Input check
    if (in->sec_sel >= 2 && in->sec_sel <= 4) {
        // TODO: Check if public key belongs to the security level stated
        params = generate_kyber_params(in->sec_sel);
    } else {
        // TODO: Proper Error codes
        return result + 2;
    }

    /* Will contain key, coins */
    unsigned char  kr[2*KYBER_SYMBYTES];
    unsigned char buf[2*KYBER_SYMBYTES];

    CryptRandomGenerate(KYBER_SYMBYTES, buf);
    /* Don't release system RNG output */
    sha3_256(buf,buf,KYBER_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    sha3_256(buf+KYBER_SYMBYTES, (unsigned char *)&in->public_key.b.buffer,
            params.publickeybytes);
    sha3_512(kr, buf, 2*KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc((unsigned char *)&out->cipher_text.b.buffer, buf,
            (unsigned char *)&in->public_key.b.buffer, kr+KYBER_SYMBYTES,
            params.k,
            params.polyveccompressedbytes,
            params.eta);

    /* overwrite coins in kr with H(c) */
    sha3_256(kr+KYBER_SYMBYTES, (unsigned char *)&out->cipher_text.b.buffer, params.ciphertextbytes);
    /* hash concatenation of pre-k and H(c) to k */
    sha3_256((unsigned char *)&out->shared_key.b.buffer, kr, 2*KYBER_SYMBYTES);

    out->shared_key.b.size = 32;
    out->cipher_text.b.size = params.ciphertextbytes;

    return result;
}
#endif // ALG_KYBER
#endif // CC_KYBER_Enc

#if CC_KYBER_Dec  // Conditional expansion of this file
#include "Tpm.h"
#include "KYBER_Dec_fp.h"
#include "kyber-verify.h"
#include "kyber-params.h"
#include "kyber-indcpa.h"
#include "fips202.h"
#if ALG_KYBER
TPM_RC
TPM2_KYBER_Dec(
		 KYBER_Dec_In      *in,            // In: input parameter list
		 KYBER_Dec_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   result = TPM_RC_SUCCESS;
    KyberParams params;

    // Input check
    if (in->sec_sel >= 2 && in->sec_sel <= 4) {
        // TODO: Check if public key belongs to the security level stated
        params = generate_kyber_params(in->sec_sel);
    } else {
        printf("Bad Parameter: %d\n", in->sec_sel);
        // TODO: Proper Error codes
        return result + 2;
    }

    size_t i;
    int fail;
    unsigned char cmp[params.ciphertextbytes];
    unsigned char buf[2*KYBER_SYMBYTES];
    /* Will contain key, coins, qrom-hash */
    unsigned char kr[2*KYBER_SYMBYTES];
    const unsigned char *pk = in->secret_key.b.buffer+params.indcpa_secretkeybytes;

    indcpa_dec(buf, in->cipher_text.b.buffer, in->secret_key.b.buffer, params.k,
            params.polyveccompressedbytes, params.eta);

    /* Multitarget countermeasure for coins + contributory KEM */
    for(i=0;i<KYBER_SYMBYTES;i++) {
      /* Save hash by storing H(pk) in sk */
      buf[KYBER_SYMBYTES+i] = in->secret_key.b.buffer[params.secretkeybytes-2*KYBER_SYMBYTES+i];
    }
    sha3_512(kr, buf, 2*KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES, params.k,
            params.polyveccompressedbytes, params.eta);

    fail = kyber_verify(in->cipher_text.b.buffer, cmp, params.ciphertextbytes);

    /* overwrite coins in kr with H(c)  */
    sha3_256(kr+KYBER_SYMBYTES, in->cipher_text.b.buffer, params.ciphertextbytes);

    /* Overwrite pre-k with z on re-encryption failure */
    kyber_cmov(kr, in->secret_key.b.buffer+params.secretkeybytes-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

    /* hash concatenation of pre-k and H(c) to k */
    sha3_256(out->shared_key.b.buffer, kr, 2*KYBER_SYMBYTES);

    out->shared_key.b.size = 32;

    return result;
}
#endif // ALG_KYBER
#endif // CC_KYBER_Dec
/*****************************************************************************/
/*                                Kyber Mods                                 */
/*****************************************************************************/

/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/
#if ALG_DILITHIUM
#include "dilithium-params.h"

typedef struct {
    uint64_t k;
    uint64_t l;
    uint64_t eta;
    uint64_t setabits;
    uint64_t beta;
    uint64_t omega;
    uint64_t polt0_size_packed;
    uint64_t polt1_size_packed;
    uint64_t poleta_size_packed;
    uint64_t polz_size_packed;
    uint64_t crypto_publickeybytes;
    uint64_t crypto_secretkeybytes;
    uint64_t crypto_bytes;
    uint64_t pol_size_packed;
    uint64_t polw1_size_packed;
    uint64_t polveck_size_packed;
    uint64_t polvecl_size_packed;
} DilithiumParams;

static DilithiumParams generate_dilithium_params(BYTE mode) {
    DilithiumParams params;

    switch(mode) {
        case 0:
            params.k = 3;
            params.l = 2;
            params.eta = 7;
            params.setabits = 4;
            params.beta = 375;
            params.omega = 64;
            break;
        case 1:
            params.k = 4;
            params.l = 3;
            params.eta = 6;
            params.setabits = 4;
            params.beta = 325;
            params.omega = 96;
            break;
        case 2:
            params.k = 5;
            params.l = 4;
            params.eta = 5;
            params.setabits = 4;
            params.beta = 275;
            params.omega = 120;
            break;
        case 3:
            params.k = 6;
            params.l = 5;
            params.eta = 3;
            params.setabits = 3;
            params.beta = 175;
            params.omega = 120;
            break;
    }

    params.pol_size_packed     = ((DILITHIUM_N * DILITHIUM_QBITS) / 8);
    params.polt1_size_packed   = ((DILITHIUM_N * (DILITHIUM_QBITS - DILITHIUM_D)) / 8);
    params.polt0_size_packed   = ((DILITHIUM_N * DILITHIUM_D) / 8);
    params.poleta_size_packed  = ((DILITHIUM_N * params.setabits) / 8);
    params.polz_size_packed    = ((DILITHIUM_N * (DILITHIUM_QBITS - 3)) / 8);
    params.polw1_size_packed   = ((DILITHIUM_N * 4) / 8);
    params.polveck_size_packed = (params.k * params.pol_size_packed);
    params.polvecl_size_packed = (params.l * params.pol_size_packed);

    params.crypto_publickeybytes = (DILITHIUM_SEEDBYTES + params.k*params.polt1_size_packed);
    params.crypto_secretkeybytes = (2*DILITHIUM_SEEDBYTES + (params.l + params.k)*params.poleta_size_packed + DILITHIUM_CRHBYTES + params.k*params.polt0_size_packed);
    params.crypto_bytes = (params.l * params.polz_size_packed + (params.omega + params.k) + (DILITHIUM_N/8 + 8));


    return params;
}
#endif

#if CC_DILITHIUM_KeyGen  // Conditional expansion of this file
#include "Tpm.h"
#include "DILITHIUM_KeyGen_fp.h"
#include "dilithium-params.h"
#include "dilithium-sign.h"
#include "fips202.h"
#include "dilithium-polyvec.h"
#include "dilithium-sign.h"
#include "dilithium-packing.h"
#if ALG_DILITHIUM

TPM_RC
TPM2_DILITHIUM_KeyGen(
		 DILITHIUM_KeyGen_In      *in,            // In: input parameter list
		 DILITHIUM_KeyGen_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   result = TPM_RC_SUCCESS;
    unsigned int i;
    unsigned char seedbuf[3*DILITHIUM_SEEDBYTES];
    unsigned char tr[DILITHIUM_CRHBYTES];
    unsigned char *rho, *rhoprime, *key;
    uint16_t nonce = 0;
    dilithium_polyvecl mat[6]; // MAX K in Dilithium
    dilithium_polyvecl s1, s1hat;
    dilithium_polyveck s2, t, t1, t0;
    DilithiumParams params;

    if (in->mode >= 0 && in->mode <= 3) {
        params = generate_dilithium_params(in->mode);
    } else {
        return TPM_RC_SUCCESS + 2;
    }

    /* Expand 32 bytes of randomness into rho, rhoprime and key */
    CryptRandomGenerate(DILITHIUM_SEEDBYTES, seedbuf);
    shake256(seedbuf, 3*DILITHIUM_SEEDBYTES, seedbuf, DILITHIUM_SEEDBYTES);
    rho = seedbuf;
    rhoprime = rho + DILITHIUM_SEEDBYTES;
    key = rho + 2*DILITHIUM_SEEDBYTES;

    /* Expand matrix */
    dilithium_expand_mat(mat, rho, params.k, params.l);

    /* Sample short vectors s1 and s2 */
    for(i = 0; i < params.l; ++i)
      dilithium_poly_uniform_eta(s1.vec+i, rhoprime, nonce++, params.eta);
    for(i = 0; i < params.k; ++i)
      dilithium_poly_uniform_eta(s2.vec+i, rhoprime, nonce++, params.eta);

    /* Matrix-vector multiplication */
    s1hat = s1;
    dilithium_polyvecl_ntt(&s1hat, params.l);
    for(i = 0; i < params.k; ++i) {
      dilithium_polyvecl_pointwise_acc_invmontgomery(t.vec+i, mat+i, &s1hat, params.l);
      dilithium_poly_reduce(t.vec+i);
      dilithium_poly_invntt_montgomery(t.vec+i);
    }

    /* Add noise vector s2 */
    dilithium_polyveck_add(&t, &t, &s2, params.k);

    /* Extract t1 and write public key */
    dilithium_polyveck_freeze(&t, params.k);
    dilithium_polyveck_power2round(&t1, &t0, &t, params.k);
    dilithium_pack_pk((unsigned char *)&out->public_key.b.buffer, rho, &t1, params.k,
            params.polt1_size_packed);

    /* Compute CRH(rho, t1) and write secret key */
    shake256(tr, DILITHIUM_CRHBYTES, (unsigned char *)&out->public_key.b.buffer,
            params.crypto_publickeybytes);
    dilithium_pack_sk((unsigned char *)&out->secret_key.b.buffer, rho, key, tr, &s1, &s2, &t0,
            params.k, params.l, params.poleta_size_packed,
            params.polt0_size_packed, params.eta);

    out->public_key.b.size = params.crypto_publickeybytes;
    out->secret_key.b.size = params.crypto_secretkeybytes;

    return result;
}
#endif // ALG_DILITHIUM
#endif // CC_DILITHIUM_KeyGen

#if CC_DILITHIUM_Sign  // Conditional expansion of this file
#include "Tpm.h"
#include "DILITHIUM_Sign_fp.h"
#include "dilithium-params.h"
#include "dilithium-sign.h"
#include "fips202.h"
#include "dilithium-polyvec.h"
#include "dilithium-sign.h"
#include "dilithium-packing.h"
#if ALG_DILITHIUM

TPM_RC
TPM2_DILITHIUM_Sign(
		 DILITHIUM_Sign_In      *in,            // In: input parameter list
		 DILITHIUM_Sign_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   result = TPM_RC_SUCCESS;
    DilithiumParams params;
    unsigned long long i, j;
    unsigned int n;
    unsigned char seedbuf[2*DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES];
    unsigned char tr[DILITHIUM_CRHBYTES];
    unsigned char *rho, *key, *mu;
    uint16_t nonce = 0;
    dilithium_poly c, chat;
    dilithium_polyvecl mat[6], s1, y, yhat, z; // Max K in Dilithium
    dilithium_polyveck s2, t0, w, w1;
    dilithium_polyveck h, wcs2, wcs20, ct0, tmp;

    if (in->mode >= 0 && in->mode <= 3) {
        params = generate_dilithium_params(in->mode);
    } else {
        return TPM_RC_SUCCESS + 2;
    }

    rho = seedbuf;
    key = seedbuf + DILITHIUM_SEEDBYTES;
    mu = seedbuf + 2*DILITHIUM_SEEDBYTES;
    dilithium_unpack_sk(rho, key, tr, &s1, &s2, &t0,
            (unsigned char *)&in->secret_key.b.buffer, params.k,
            params.l, params.poleta_size_packed, params.polt0_size_packed,
            params.eta);

    /* Copy tr and message into the sm buffer,
     * backwards since m and sm can be equal in SUPERCOP API */
    for(i = 1; i <= in->message.b.size; ++i)
      out->signed_message.b.buffer[params.crypto_bytes + in->message.b.size - i] = in->message.b.buffer[in->message.b.size - i];
    for(i = 0; i < DILITHIUM_CRHBYTES; ++i)
      out->signed_message.b.buffer[params.crypto_bytes - DILITHIUM_CRHBYTES + i] = tr[i];

    /* Compute CRH(tr, msg) */
    shake256(mu, DILITHIUM_CRHBYTES, out->signed_message.b.buffer + params.crypto_bytes - DILITHIUM_CRHBYTES,
            DILITHIUM_CRHBYTES + in->message.b.size);

    /* Expand matrix and transform vectors */
    dilithium_expand_mat(mat, rho, params.k, params.l);
    dilithium_polyvecl_ntt(&s1, params.l);
    dilithium_polyveck_ntt(&s2, params.k);
    dilithium_polyveck_ntt(&t0, params.k);

    rej:
    /* Sample intermediate vector y */
    for(i = 0; i < params.l; ++i)
      dilithium_poly_uniform_gamma1m1(y.vec+i, key, nonce++);

    /* Matrix-vector multiplication */
    yhat = y;
    dilithium_polyvecl_ntt(&yhat, params.l);
    for(i = 0; i < params.k; ++i) {
      dilithium_polyvecl_pointwise_acc_invmontgomery(w.vec+i, mat+i, &yhat,
              params.l);
      dilithium_poly_reduce(w.vec+i);
      dilithium_poly_invntt_montgomery(w.vec+i);
    }

    /* Decompose w and call the random oracle */
    dilithium_polyveck_csubq(&w, params.k);
    dilithium_polyveck_decompose(&w1, &tmp, &w, params.k);
    dilithium_challenge(&c, mu, &w1, params.k, params.polw1_size_packed);

    /* Compute z, reject if it reveals secret */
    chat = c;
    dilithium_poly_ntt(&chat);
    for(i = 0; i < params.l; ++i) {
      dilithium_poly_pointwise_invmontgomery(z.vec+i, &chat, s1.vec+i);
      dilithium_poly_invntt_montgomery(z.vec+i);
    }
    dilithium_polyvecl_add(&z, &z, &y, params.l);
    dilithium_polyvecl_freeze(&z, params.l);
    if(dilithium_polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - params.beta, params.l))
      goto rej;

    /* Compute w - cs2, reject if w1 can not be computed from it */
    for(i = 0; i < params.k; ++i) {
      dilithium_poly_pointwise_invmontgomery(wcs2.vec+i, &chat, s2.vec+i);
      dilithium_poly_invntt_montgomery(wcs2.vec+i);
    }
    dilithium_polyveck_sub(&wcs2, &w, &wcs2, params.k);
    dilithium_polyveck_freeze(&wcs2, params.k);
    dilithium_polyveck_decompose(&tmp, &wcs20, &wcs2, params.k);
    dilithium_polyveck_csubq(&wcs20, params.k);
    if(dilithium_polyveck_chknorm(&wcs20, DILITHIUM_GAMMA2 - params.beta, params.k))
      goto rej;

    for(i = 0; i < params.k; ++i)
      for(j = 0; j < DILITHIUM_N; ++j)
        if(tmp.vec[i].coeffs[j] != w1.vec[i].coeffs[j])
          goto rej;

    /* Compute hints for w1 */
    for(i = 0; i < params.k; ++i) {
      dilithium_poly_pointwise_invmontgomery(ct0.vec+i, &chat, t0.vec+i);
      dilithium_poly_invntt_montgomery(ct0.vec+i);
    }

    dilithium_polyveck_csubq(&ct0, params.k);
    if(dilithium_polyveck_chknorm(&ct0, DILITHIUM_GAMMA2, params.k))
      goto rej;

    dilithium_polyveck_add(&tmp, &wcs2, &ct0, params.k);
    dilithium_polyveck_csubq(&tmp, params.k);
    n = dilithium_polyveck_make_hint(&h, &wcs2, &tmp, params.k);
    if(n > params.omega)
      goto rej;

    /* Write signature */
    dilithium_pack_sig((unsigned char *)&out->signed_message.b.buffer, &z, &h,
            &c, params.k, params.l, params.polz_size_packed, params.omega);

    out->signed_message.b.size = in->message.b.size + params.crypto_bytes;

    return result;
}
#endif // ALG_DILITHIUM
#endif // CC_DILITHIUM_Sign

#if CC_DILITHIUM_Verify  // Conditional expansion of this file
#include "Tpm.h"
#include "DILITHIUM_Verify_fp.h"
#include "dilithium-params.h"
#include "dilithium-sign.h"
#include "fips202.h"
#include "dilithium-polyvec.h"
#include "dilithium-sign.h"
#include "dilithium-packing.h"
#if ALG_DILITHIUM

TPM_RC
TPM2_DILITHIUM_Verify(
		 DILITHIUM_Verify_In      *in,            // In: input parameter list
		 DILITHIUM_Verify_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   result = TPM_RC_SUCCESS;
    DilithiumParams params;
    unsigned long long i;
    unsigned char rho[DILITHIUM_SEEDBYTES];
    unsigned char mu[DILITHIUM_CRHBYTES];
    dilithium_poly c, chat, cp;
    dilithium_polyvecl mat[6], z; // Max K for Dilithium
    dilithium_polyveck t1, w1, h, tmp1, tmp2;

    if (in->mode >= 0 && in->mode <= 3) {
        params = generate_dilithium_params(in->mode);
    } else {
        return TPM_RC_SUCCESS + 2;
    }

    if(in->signed_message.b.size < params.crypto_bytes)
      goto badsig;

    out->message.b.size = in->signed_message.b.size - params.crypto_bytes;

    dilithium_unpack_pk(rho, &t1, in->public_key.b.buffer, params.k, params.polt1_size_packed);
    if(dilithium_unpack_sig(&z, &h, &c, in->signed_message.b.buffer, params.k, params.l, params.polz_size_packed, params.omega))
      goto badsig;
    if(dilithium_polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - params.beta, params.l))
      goto badsig;

    /* Compute CRH(CRH(rho, t1), msg) using m as "playground" buffer */
    if(in->signed_message.b.buffer != out->message.b.buffer)
      for(i = 0; i < out->message.b.size; ++i)
        out->message.b.buffer[params.crypto_bytes + i] = in->signed_message.b.buffer[params.crypto_bytes + i];

    shake256(out->message.b.buffer + params.crypto_bytes - DILITHIUM_CRHBYTES,
            DILITHIUM_CRHBYTES,
            in->public_key.b.buffer, params.crypto_publickeybytes);
    shake256(mu, DILITHIUM_CRHBYTES,
            out->message.b.buffer + params.crypto_bytes - DILITHIUM_CRHBYTES,
            DILITHIUM_CRHBYTES + out->message.b.size);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    dilithium_expand_mat(mat, rho, params.k, params.l);
    dilithium_polyvecl_ntt(&z, params.l);
    for(i = 0; i < params.k; ++i)
      dilithium_polyvecl_pointwise_acc_invmontgomery(tmp1.vec+i, mat+i, &z, params.l);

    chat = c;
    dilithium_poly_ntt(&chat);
    dilithium_polyveck_shiftl(&t1, DILITHIUM_D, params.k);
    dilithium_polyveck_ntt(&t1, params.k);
    for(i = 0; i < params.k; ++i)
      dilithium_poly_pointwise_invmontgomery(tmp2.vec+i, &chat, t1.vec+i);

    dilithium_polyveck_sub(&tmp1, &tmp1, &tmp2, params.k);
    dilithium_polyveck_reduce(&tmp1, params.k);
    dilithium_polyveck_invntt_montgomery(&tmp1, params.k);

    /* Reconstruct w1 */
    dilithium_polyveck_csubq(&tmp1, params.k);
    dilithium_polyveck_use_hint(&w1, &tmp1, &h, params.k);

    /* Call random oracle and verify challenge */
    dilithium_challenge(&cp, mu, &w1, params.k, params.polw1_size_packed);
    for(i = 0; i < DILITHIUM_N; ++i)
      if(c.coeffs[i] != cp.coeffs[i])
        goto badsig;

    /* All good, copy msg, return 0 */
    for(i = 0; i < out->message.b.size; ++i)
      out->message.b.buffer[i] = in->signed_message.b.buffer[params.crypto_bytes + i];

    return result;

    /* Signature verification failed */
    badsig:
    out->message.b.size = (UINT16) -1;
    for(i = 0; i < in->signed_message.b.size; ++i)
      out->message.b.buffer[i] = 0;

    return result-1;
}
#endif // ALG_DILITHIUM
#endif // CC_DILITHIUM_Verify
/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/
