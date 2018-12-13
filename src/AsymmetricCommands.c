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

/* Kyber Mods */
#include "Tpm.h"
#include "KYBER_KeyGen_fp.h"
#include "kyber_params.h"
#include "indcpa.h"
#include "fips202.h"
#if CC_KYBER_KeyGen  // Conditional expansion of this file
#if ALG_KYBER
TPM_RC
TPM2_KYBER_KeyGen(
		 KYBER_KeyGen_In      *in,            // In: input parameter list
		 KYBER_KeyGen_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   result = TPM_RC_SUCCESS;
    uint64_t kyber_polyvecbytes           = 0;
    uint64_t kyber_polyveccompressedbytes = 0;
    uint64_t kyber_indcpa_publickeybytes = 0;
    uint64_t kyber_indcpa_secretkeybytes = 0;
    uint64_t kyber_k = 0;
    uint64_t kyber_eta = 0;
    uint64_t kyber_publickeybytes = 0;
    uint64_t kyber_secretkeybytes = 0;

    // Parameter check
    if (in->sec_sel >= 2 && in->sec_sel <= 4) {
        printf("Good security parameter given\n");
        printf("KYBER K received is %u\n", in->sec_sel);

        kyber_k = in->sec_sel;
        kyber_polyvecbytes           = kyber_k * KYBER_POLYBYTES;
        kyber_polyveccompressedbytes = kyber_k * 352;

        kyber_indcpa_publickeybytes = kyber_polyveccompressedbytes + KYBER_SYMBYTES;
        kyber_indcpa_secretkeybytes = kyber_polyvecbytes;

        kyber_publickeybytes =  kyber_indcpa_publickeybytes;
        kyber_secretkeybytes =  kyber_indcpa_secretkeybytes + kyber_indcpa_publickeybytes + 2*KYBER_SYMBYTES;

        if (in->sec_sel == 2) {
            kyber_eta = 5; /* Kyber512 */
        } else if (in->sec_sel == 3) {
            kyber_eta = 4; /* Kyber768 */
        } else {
            kyber_eta = 3; /* Kyber1024 */
        }

        printf("Public Key size is %lu\n", kyber_publickeybytes);
        printf("Secret Key size is %lu\n", kyber_secretkeybytes);
        printf("Kyber ETA is %lu\n", kyber_eta);
    } else {
        printf("Bad security parameter given\n");
        // TODO: Proper Error codes
        return result + 2;
    }

    // Command Output
    indcpa_keypair((unsigned char *)&out->public_key.b.buffer,
            (unsigned char *)&out->secret_key.b.buffer,
            kyber_k, kyber_polyveccompressedbytes, kyber_eta);
    for (size_t i = 0; i < kyber_indcpa_publickeybytes; i++) {
      out->secret_key.b.buffer[i+kyber_indcpa_secretkeybytes] = out->public_key.b.buffer[i];
    }
    sha3_256((unsigned char *)out->secret_key.b.buffer+kyber_secretkeybytes-2*KYBER_SYMBYTES,
            out->public_key.b.buffer,
            kyber_publickeybytes);
    /* Value z for pseudo-random output on reject */
    CryptRandomGenerate(KYBER_SYMBYTES, out->secret_key.b.buffer+kyber_secretkeybytes-KYBER_SYMBYTES);

    out->public_key.b.size = kyber_publickeybytes;
    out->secret_key.b.size = kyber_secretkeybytes;

    return result;
}
#endif // ALG_KYBER
#endif // CC_KYBER_KeyGen

#include "KYBER_Enc_fp.h"
#if CC_KYBER_Enc  // Conditional expansion of this file
#if ALG_KYBER

static void print_array(unsigned char * buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02X", buffer[i]);

        if (i != (size - 1)) {
            printf(", ");
        }
    }
}

TPM_RC
TPM2_KYBER_Enc(
		 KYBER_Enc_In      *in,            // In: input parameter list
		 KYBER_Enc_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   result = TPM_RC_SUCCESS;
    uint64_t kyber_polyvecbytes           = 0;
    uint64_t kyber_polyveccompressedbytes = 0;
    uint64_t kyber_indcpa_publickeybytes = 0;
    uint64_t kyber_indcpa_secretkeybytes = 0;
    uint64_t kyber_k = 0;
    uint64_t kyber_eta = 0;
    uint64_t kyber_publickeybytes = 0;
    uint64_t kyber_secretkeybytes = 0;
    uint64_t kyber_indcpa_bytes = 0;
    uint64_t kyber_ciphertextbytes = 0;

    // Input check
    if (in->sec_sel >= 2 && in->sec_sel <= 4) {
        // TODO: Check if public key belongs to the security level stated
        printf("Starting Encryption\n");
        printf("KYBER K received is %u\n", in->sec_sel);

        kyber_k = in->sec_sel;
        kyber_polyvecbytes           = kyber_k * KYBER_POLYBYTES;
        kyber_polyveccompressedbytes = kyber_k * 352;

        kyber_indcpa_publickeybytes = kyber_polyveccompressedbytes + KYBER_SYMBYTES;
        kyber_indcpa_secretkeybytes = kyber_polyvecbytes;

        kyber_publickeybytes =  kyber_indcpa_publickeybytes;
        kyber_secretkeybytes =  kyber_indcpa_secretkeybytes + kyber_indcpa_publickeybytes + 2*KYBER_SYMBYTES;

        kyber_indcpa_bytes = (kyber_polyveccompressedbytes + KYBER_POLYCOMPRESSEDBYTES);
        kyber_ciphertextbytes = kyber_indcpa_bytes;

        if (in->sec_sel == 2) {
            kyber_eta = 5; /* Kyber512 */
        } else if (in->sec_sel == 3) {
            kyber_eta = 4; /* Kyber768 */
        } else {
            kyber_eta = 3; /* Kyber1024 */
        }

        printf("Public Key size is %lu\n", kyber_publickeybytes);
        printf("Secret Key size is %lu\n", kyber_secretkeybytes);
        printf("Cipher Text size is %lu\n", kyber_ciphertextbytes);
        printf("Kyber ETA is %lu\n", kyber_eta);
    } else {
        printf("Bad security parameter given\n");
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
            kyber_publickeybytes);
    sha3_512(kr, buf, 2*KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc((unsigned char *)&out->cipher_text.b.buffer, buf,
            (unsigned char *)&in->public_key.b.buffer, kr+KYBER_SYMBYTES,
            kyber_k,
            kyber_polyveccompressedbytes,
            kyber_eta);

    /* overwrite coins in kr with H(c) */
    sha3_256(kr+KYBER_SYMBYTES, (unsigned char *)&out->cipher_text.b.buffer, kyber_ciphertextbytes);
    /* hash concatenation of pre-k and H(c) to k */
    sha3_256((unsigned char *)&out->shared_key.b.buffer, kr, 2*KYBER_SYMBYTES);

    out->shared_key.b.size = 32;
    out->cipher_text.b.size = kyber_ciphertextbytes;

    printf("Kyber Shared Key: [");
    print_array(out->shared_key.b.buffer, out->shared_key.b.size);
    printf("]\n");

    printf("Kyber Cipher Text: [");
    print_array(out->cipher_text.b.buffer, out->cipher_text.b.size);
    printf("]\n");


    return result;
}
#endif // ALG_KYBER
#endif // CC_KYBER_Enc

#include "KYBER_Dec_fp.h"
#include "verify.h"
#if CC_KYBER_Dec  // Conditional expansion of this file
#if ALG_KYBER

TPM_RC
TPM2_KYBER_Dec(
		 KYBER_Dec_In      *in,            // In: input parameter list
		 KYBER_Dec_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   result = TPM_RC_SUCCESS;
    uint64_t kyber_polyvecbytes           = 0;
    uint64_t kyber_polyveccompressedbytes = 0;
    uint64_t kyber_indcpa_publickeybytes = 0;
    uint64_t kyber_indcpa_secretkeybytes = 0;
    uint64_t kyber_k = 0;
    uint64_t kyber_eta = 0;
    uint64_t kyber_publickeybytes = 0;
    uint64_t kyber_secretkeybytes = 0;
    uint64_t kyber_indcpa_bytes = 0;
    uint64_t kyber_ciphertextbytes = 0;

    // Input check
    if (in->sec_sel >= 2 && in->sec_sel <= 4) {
        // TODO: Check if public key belongs to the security level stated
        printf("Starting Decryption\n");
        printf("KYBER K received is %u\n", in->sec_sel);

        kyber_k = in->sec_sel;
        kyber_polyvecbytes           = kyber_k * KYBER_POLYBYTES;
        kyber_polyveccompressedbytes = kyber_k * 352;

        kyber_indcpa_publickeybytes = kyber_polyveccompressedbytes + KYBER_SYMBYTES;
        kyber_indcpa_secretkeybytes = kyber_polyvecbytes;

        kyber_publickeybytes =  kyber_indcpa_publickeybytes;
        kyber_secretkeybytes =  kyber_indcpa_secretkeybytes + kyber_indcpa_publickeybytes + 2*KYBER_SYMBYTES;

        kyber_indcpa_bytes = (kyber_polyveccompressedbytes + KYBER_POLYCOMPRESSEDBYTES);
        kyber_ciphertextbytes = kyber_indcpa_bytes;

        if (in->sec_sel == 2) {
            kyber_eta = 5; /* Kyber512 */
        } else if (in->sec_sel == 3) {
            kyber_eta = 4; /* Kyber768 */
        } else {
            kyber_eta = 3; /* Kyber1024 */
        }

        printf("Public Key size is %lu\n", kyber_publickeybytes);
        printf("Secret Key size is %lu\n", kyber_secretkeybytes);
        printf("Cipher Text size is %lu\n", kyber_ciphertextbytes);
        printf("Kyber ETA is %lu\n", kyber_eta);
    } else {
        printf("Bad security parameter given\n");
        // TODO: Proper Error codes
        return result + 2;
    }

    size_t i;
    int fail;
    unsigned char cmp[kyber_ciphertextbytes];
    unsigned char buf[2*KYBER_SYMBYTES];
    /* Will contain key, coins, qrom-hash */
    unsigned char kr[2*KYBER_SYMBYTES];
    const unsigned char *pk = in->secret_key.b.buffer+kyber_indcpa_secretkeybytes;

    indcpa_dec(buf, in->cipher_text.b.buffer, in->secret_key.b.buffer, kyber_k,
            kyber_polyveccompressedbytes, kyber_eta);

    /* Multitarget countermeasure for coins + contributory KEM */
    for(i=0;i<KYBER_SYMBYTES;i++) {
      /* Save hash by storing H(pk) in sk */
      buf[KYBER_SYMBYTES+i] = in->secret_key.b.buffer[kyber_secretkeybytes-2*KYBER_SYMBYTES+i];
    }
    sha3_512(kr, buf, 2*KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES, kyber_k,
            kyber_polyveccompressedbytes, kyber_eta);

    fail = verify(in->cipher_text.b.buffer, cmp, kyber_ciphertextbytes);

    /* overwrite coins in kr with H(c)  */
    sha3_256(kr+KYBER_SYMBYTES, in->cipher_text.b.buffer, kyber_ciphertextbytes);

    /* Overwrite pre-k with z on re-encryption failure */
    cmov(kr, in->secret_key.b.buffer+kyber_secretkeybytes-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

    /* hash concatenation of pre-k and H(c) to k */
    sha3_256(out->shared_key.b.buffer, kr, 2*KYBER_SYMBYTES);

    out->shared_key.b.size = 32;

    printf("Kyber Shared Key: [");
    print_array(out->shared_key.b.buffer, out->shared_key.b.size);
    printf("]\n");

    return result;
}
#endif // ALG_KYBER
#endif // CC_KYBER_Dec
/* Kyber Mods */
