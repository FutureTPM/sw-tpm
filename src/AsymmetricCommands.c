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
#if CC_KYBER_Enc  // Conditional expansion of this file
#include "Tpm.h"
#include "Kyber_Enc_fp.h"
#if ALG_KYBER
TPM_RC
TPM2_Kyber_Enc(
		 Kyber_Encapsulate_In      *in, // In: input parameter list
		 Kyber_Encapsulate_Out     *out // OUT: output parameter list
		 )
{
    TPM_RC retVal = TPM_RC_SUCCESS;
    OBJECT *kyberKey;

    // Input Validation
    kyberKey = HandleToObject(in->key_handle);
    // selected key must be a Kyber key
    if(kyberKey->publicArea.type != TPM_ALG_KYBER)
        return TPM_RCS_KEY + RC_Kyber_Encapsulate_key_handle;
    // selected key must have the decryption attribute
    if(!IS_ATTRIBUTE(kyberKey->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_ATTRIBUTES + RC_Kyber_Encapsulate_key_handle;
    // Kyber is only used for encryption/decryption, no signing
    if (IS_ATTRIBUTE(kyberKey->publicArea.objectAttributes, TPMA_OBJECT, sign))
        return TPM_RC_NO_RESULT;
    // Validate security parameter
    if (!CryptKyberIsModeValid(kyberKey->publicArea.parameters.kyberDetail.security))
        return TPM_RCS_KEY + RC_Kyber_Encapsulate_key_handle;

    // Check key validity
    if (CryptValidateKeys(&kyberKey->publicArea,
                NULL, 0, 0) != TPM_RC_SUCCESS)
        return TPM_RCS_KEY + RC_Kyber_Encapsulate_key_handle;

    retVal = CryptKyberEncapsulate(&kyberKey->publicArea, &out->shared_key,
            &out->cipher_text);

    return retVal;
}
#endif // ALG_KYBER
#endif // CC_KYBER_Enc

#if CC_KYBER_Dec  // Conditional expansion of this file
#include "Tpm.h"
#include "Kyber_Dec_fp.h"
#if ALG_KYBER
TPM_RC
TPM2_Kyber_Dec(
		 Kyber_Decapsulate_In      *in,            // In: input parameter list
		 Kyber_Decapsulate_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    OBJECT *kyberKey;

    // Input Validation
    kyberKey = HandleToObject(in->key_handle);
    // selected key must be a Kyber key
    if(kyberKey->publicArea.type != TPM_ALG_KYBER)
        return TPM_RCS_KEY + RC_Kyber_Decapsulate_key_handle;
    // selected key must have the decryption attribute
    if(!IS_ATTRIBUTE(kyberKey->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_ATTRIBUTES + RC_Kyber_Decapsulate_key_handle;
    // Kyber is only used for encryption/decryption, no signing
    if (IS_ATTRIBUTE(kyberKey->publicArea.objectAttributes, TPMA_OBJECT, sign))
        return TPM_RC_NO_RESULT;
    // Validate security parameter
    if (!CryptKyberIsModeValid(kyberKey->publicArea.parameters.kyberDetail.security))
        return TPM_RCS_KEY + RC_Kyber_Decapsulate_key_handle;
    // Check key validity
    if (CryptValidateKeys(&kyberKey->publicArea,
                &kyberKey->sensitive, 0, 0) != TPM_RC_SUCCESS)
        return TPM_RCS_KEY + RC_Kyber_Decapsulate_key_handle;
    // Validate Cipher Text size for static key
    if (CryptKyberValidateCipherTextSize(
                &in->cipher_text,
                kyberKey->publicArea.parameters.kyberDetail.security
                ) != TPM_RC_SUCCESS)
        return TPM_RC_VALUE + RC_Kyber_Decapsulate_cipher_text;

    retVal = CryptKyberDecapsulate(&kyberKey->sensitive,
            kyberKey->publicArea.parameters.kyberDetail.security,
            &in->cipher_text, &out->shared_key);

    return retVal;
}
#endif // ALG_KYBER
#endif // CC_KYBER_Dec

#if CC_KYBER_Encrypt  // Conditional expansion of this file
#include "Tpm.h"
#include "Kyber_Encrypt_fp.h"
#include "kyber-params.h"
#if ALG_KYBER
TPM_RC
TPM2_Kyber_Encrypt(
		 Kyber_Encrypt_In      *in,            // In: input parameter list
		 Kyber_Encrypt_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    OBJECT *key_handle;

    // Input Validation
    key_handle = HandleToObject(in->keyHandle);

    // selected key must be a Kyber key
    if(key_handle->publicArea.type != TPM_ALG_KYBER)
        return TPM_RCS_KEY + RC_Kyber_Encrypt_key_handle;
    // selected key must have the decryption attribute
    if(IS_ATTRIBUTE(key_handle->publicArea.objectAttributes, TPMA_OBJECT, restricted)
       || !IS_ATTRIBUTE(key_handle->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_KEY + RC_Kyber_Encrypt_key_handle;
    // Kyber is only used for encryption/decryption, no signing
    if (IS_ATTRIBUTE(key_handle->publicArea.objectAttributes, TPMA_OBJECT, sign))
        return TPM_RC_NO_RESULT;
    // Validate security parameter
    if (!CryptKyberIsModeValid(key_handle->publicArea.parameters.kyberDetail.security))
        return TPM_RCS_KEY + RC_Kyber_Encrypt_key_handle;
    // Check static key validity
    if (CryptValidateKeys(&key_handle->publicArea,
                NULL, 0, 0) != TPM_RC_SUCCESS)
        return TPM_RCS_KEY + RC_Kyber_Encrypt_key_handle;

    retVal = CryptKyberEncrypt(&out->outData, key_handle, &in->message.b);

    return retVal;
}
#endif // ALG_KYBER
#endif // CC_KYBER_Encrypt

#if CC_KYBER_Decrypt  // Conditional expansion of this file
#include "Tpm.h"
#include "Kyber_Decrypt_fp.h"
#include "kyber-params.h"
#if ALG_KYBER
TPM_RC
TPM2_Kyber_Decrypt(
		 Kyber_Decrypt_In      *in,            // In: input parameter list
		 Kyber_Decrypt_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    OBJECT *key_handle;

    // Input Validation
    key_handle = HandleToObject(in->keyHandle);

    // selected key must be a Kyber key
    if(key_handle->publicArea.type != TPM_ALG_KYBER)
        return TPM_RCS_KEY + RC_Kyber_Decrypt_key_handle;
    // selected key must have the decryption attribute
    if(IS_ATTRIBUTE(key_handle->publicArea.objectAttributes, TPMA_OBJECT, restricted)
       || !IS_ATTRIBUTE(key_handle->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_KEY + RC_Kyber_Decrypt_key_handle;
    // Kyber is only used for encryption/decryption, no signing
    if (IS_ATTRIBUTE(key_handle->publicArea.objectAttributes, TPMA_OBJECT, sign))
        return TPM_RC_NO_RESULT;
    // Validate security parameter
    if (!CryptKyberIsModeValid(key_handle->publicArea.parameters.kyberDetail.security))
        return TPM_RCS_KEY + RC_Kyber_Decrypt_key_handle;
    // Check static key validity
    if (CryptValidateKeys(&key_handle->publicArea,
                &key_handle->sensitive, 0, 0) != TPM_RC_SUCCESS)
        return TPM_RCS_KEY;

    retVal = CryptKyberDecrypt(&out->outData.b, key_handle, &in->message);

    return retVal;
}
#endif // ALG_KYBER
#endif // CC_KYBER_Decrypt
/*****************************************************************************/
/*                                Kyber Mods                                 */
/*****************************************************************************/

/*****************************************************************************/
/*                                 LDAA Mods                                 */
/*****************************************************************************/
#if CC_LDAA_Join  // Conditional expansion of this file
#include "Tpm.h"
#include "LDaa_Join_fp.h"
#if ALG_LDAA
TPM_RC
TPM2_LDAA_Join(
		 LDAA_Join_In      *in,            // In: input parameter list
		 LDAA_Join_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    OBJECT  *ldaa_key;

    // Input Validation
    ldaa_key = HandleToObject(in->key_handle);

    // Input key must be an LDAA key
    if(ldaa_key->publicArea.type != TPM_ALG_LDAA)
        return TPM_RCS_KEY + RC_LDAA_Join_key_handle;
    if(!CryptIsSchemeAnonymous(ldaa_key->publicArea.parameters.ldaaDetail.scheme.scheme))
        return TPM_RCS_SCHEME + RC_LDAA_Join_key_handle;
    if(!CryptLDaaIsModeValid(ldaa_key->publicArea.parameters.ldaaDetail.security))
        return TPM_RCS_SCHEME + RC_LDAA_Join_key_handle;

    // The specification requires the TPM to be able to take part in more than
    // one LDAA session simultaneously. The current implementation
    // _doesn't_do_that_. In this implementation only the SID is checked as a
    // means to differentiate between sessions, and only one session is
    // supported at a time. Furthermore, the implementation doesn't
    // diferentiate between different users in the same machine, or different
    // hosts.
    //
    // Check if the received entry exists in storage, if not then proceed
    // and create entry (set SID and tie private key to the session). If there
    // is an entry present reset the protocol status and fail.
    if (gr.ldaa_commitCounter != 0) {
        // Clear current state of the protocol
        CryptLDaaClearProtocolState();
        return TPM_RC_NO_RESULT;
    } else {
        // Store protocol SID
        gr.ldaa_sid = in->sid;
        // Store Key Security Mode
        gr.ldaa_security = ldaa_key->publicArea.parameters.ldaaDetail.security;
        // Hash private key to tie it to the current LDAA session
        CryptHashBlock(ALG_SHA256_VALUE,
                ldaa_key->sensitive.sensitive.ldaa.t.size,
                ldaa_key->sensitive.sensitive.ldaa.t.buffer,
                SHA256_DIGEST_SIZE,
                gr.ldaa_hash_private_key);
    }

    // Perform Join operation
    retVal = CryptLDaaJoin(
            // Outputs
            &out->public_key, &out->nym,
            // Inputs
            &ldaa_key->publicArea, &in->bsn_I, &ldaa_key->sensitive);

    // Run Commit command
    if (retVal == TPM_RC_SUCCESS)
        retVal = CryptLDaaCommit();

    return retVal;
}
#endif // ALG_LDAA
#endif // CC_LDAA_Join

#if CC_LDAA_SignCommit1  // Conditional expansion of this file
#include "Tpm.h"
#include "LDaa_SignCommit1_fp.h"
#if ALG_LDAA
TPM_RC
TPM2_LDAA_SignCommit1(
		 LDAA_SignCommit1_In      *in,            // In: input parameter list
		 LDAA_SignCommit1_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    OBJECT  *ldaa_key;
    BYTE     digest[SHA256_DIGEST_SIZE];

    // Input Validation
    ldaa_key = HandleToObject(in->key_handle);

    // Input key must be an LDAA key
    if(ldaa_key->publicArea.type != TPM_ALG_LDAA)
        return TPM_RCS_KEY + RC_LDAA_SignCommit1_key_handle;
    if(!CryptIsSchemeAnonymous(ldaa_key->publicArea.parameters.ldaaDetail.scheme.scheme))
        return TPM_RCS_SCHEME + RC_LDAA_SignCommit1_key_handle;
    if(!CryptLDaaIsModeValid(ldaa_key->publicArea.parameters.ldaaDetail.security))
        return TPM_RCS_SCHEME + RC_LDAA_SignCommit1_key_handle;

    // Hash private key
    CryptHashBlock(ALG_SHA256_VALUE,
            ldaa_key->sensitive.sensitive.ldaa.t.size,
            ldaa_key->sensitive.sensitive.ldaa.t.buffer,
            SHA256_DIGEST_SIZE,
            digest);

    uint8_t lower_limit, higher_limit;
    if (ldaa_key->publicArea.parameters.ldaaDetail.security == TPM_LDAA_SECURITY_MODE_WEAK) {
        lower_limit = 3;
        higher_limit = 14;
    } else if (ldaa_key->publicArea.parameters.ldaaDetail.security == TPM_LDAA_SECURITY_MODE_MEDIUM) {
        lower_limit = 3;
        higher_limit = 26;
    } else if (ldaa_key->publicArea.parameters.ldaaDetail.security == TPM_LDAA_SECURITY_MODE_HIGH) {
        lower_limit = 3;
        higher_limit = 26;
    } else {
        return TPM_RCS_SCHEME + RC_LDAA_SignCommit1_key_handle;
    }

    // Fail if the private key passed is different than the tied key to
    // the LDAA session, if the SID stored and passed are different, or
    // if commit counter isn't in the correct state.
    if (gr.ldaa_commitCounter < lower_limit || gr.ldaa_commitCounter > higher_limit ||
            in->sid != gr.ldaa_sid ||
            !MemoryEqual(digest, gr.ldaa_hash_private_key, SHA256_DIGEST_SIZE) ||
            ldaa_key->publicArea.parameters.ldaaDetail.security != gr.ldaa_security) {
        // Clear current state of the protocol
        CryptLDaaClearProtocolState();
        return TPM_RC_NO_RESULT;
    }

    UINT8 commit_sel = 1;

    retVal = CryptLDaaSignCommit(
            // Outputs
            &out->commit,
            // Inputs
            &ldaa_key->sensitive,
            &commit_sel, &in->sign_state_sel,
            &in->pbsn, &in->pe,
            &in->issuer_at_ntt,
            &in->bsn, &in->seed,
            ldaa_key->publicArea.parameters.ldaaDetail.security);

    // Run Commit command
    if (retVal == TPM_RC_SUCCESS)
        retVal = CryptLDaaCommit();

    return retVal;
}
#endif // ALG_LDAA
#endif // CC_LDAA_SignCommit1

#if CC_LDAA_SignCommit2  // Conditional expansion of this file
#include "Tpm.h"
#include "LDaa_SignCommit2_fp.h"
#if ALG_LDAA
TPM_RC
TPM2_LDAA_SignCommit2(
		 LDAA_SignCommit2_In      *in,            // In: input parameter list
		 LDAA_SignCommit2_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    OBJECT  *ldaa_key;
    BYTE     digest[SHA256_DIGEST_SIZE];

    // Input Validation
    ldaa_key = HandleToObject(in->key_handle);

    // Input key must be an LDAA key
    if(ldaa_key->publicArea.type != TPM_ALG_LDAA)
        return TPM_RCS_KEY + RC_LDAA_SignCommit2_key_handle;
    if(!CryptIsSchemeAnonymous(ldaa_key->publicArea.parameters.ldaaDetail.scheme.scheme))
        return TPM_RCS_SCHEME + RC_LDAA_SignCommit2_key_handle;
    if(!CryptLDaaIsModeValid(ldaa_key->publicArea.parameters.ldaaDetail.security))
        return TPM_RCS_SCHEME + RC_LDAA_SignCommit2_key_handle;

    // Hash private key
    CryptHashBlock(ALG_SHA256_VALUE,
            ldaa_key->sensitive.sensitive.ldaa.t.size,
            ldaa_key->sensitive.sensitive.ldaa.t.buffer,
            SHA256_DIGEST_SIZE,
            digest);

    uint8_t lower_limit, higher_limit;
    if (ldaa_key->publicArea.parameters.ldaaDetail.security == TPM_LDAA_SECURITY_MODE_WEAK) {
        lower_limit = 3;
        higher_limit = 14;
    } else if (ldaa_key->publicArea.parameters.ldaaDetail.security == TPM_LDAA_SECURITY_MODE_MEDIUM) {
        lower_limit = 3;
        higher_limit = 26;
    } else if (ldaa_key->publicArea.parameters.ldaaDetail.security == TPM_LDAA_SECURITY_MODE_HIGH) {
        lower_limit = 3;
        higher_limit = 26;
    } else {
        return TPM_RCS_SCHEME + RC_LDAA_SignCommit2_key_handle;
    }

    // Fail if the private key passed is different than the tied key to
    // the LDAA session, if the SID stored and passed are different, or
    // if commit counter isn't in the correct state.
    if (gr.ldaa_commitCounter < lower_limit || gr.ldaa_commitCounter > higher_limit ||
            in->sid != gr.ldaa_sid ||
            !MemoryEqual(digest, gr.ldaa_hash_private_key, SHA256_DIGEST_SIZE) ||
            ldaa_key->publicArea.parameters.ldaaDetail.security != gr.ldaa_security) {
        // Clear current state of the protocol
        CryptLDaaClearProtocolState();
        return TPM_RC_NO_RESULT;
    }

    UINT8 commit_sel = 2;

    retVal = CryptLDaaSignCommit(
            // Outputs
            &out->commit,
            // Inputs
            &ldaa_key->sensitive,
            &commit_sel, &in->sign_state_sel,
            &in->pbsn, &in->pe,
            NULL, &in->bsn, &in->seed,
            ldaa_key->publicArea.parameters.ldaaDetail.security);

    // Run Commit command
    if (retVal == TPM_RC_SUCCESS)
        retVal = CryptLDaaCommit();

    return retVal;
}
#endif // ALG_LDAA
#endif // CC_LDAA_SignCommit2

#if CC_LDAA_SignCommit3  // Conditional expansion of this file
#include "Tpm.h"
#include "LDaa_SignCommit3_fp.h"
#if ALG_LDAA
TPM_RC
TPM2_LDAA_SignCommit3(
		 LDAA_SignCommit3_In      *in,            // In: input parameter list
		 LDAA_SignCommit3_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    OBJECT  *ldaa_key;
    BYTE     digest[SHA256_DIGEST_SIZE];

    // Input Validation
    ldaa_key = HandleToObject(in->key_handle);

    // Input key must be an LDAA key
    if(ldaa_key->publicArea.type != TPM_ALG_LDAA)
        return TPM_RCS_KEY + RC_LDAA_SignCommit3_key_handle;
    if(!CryptIsSchemeAnonymous(ldaa_key->publicArea.parameters.ldaaDetail.scheme.scheme))
        return TPM_RCS_SCHEME + RC_LDAA_SignCommit3_key_handle;
    if(!CryptLDaaIsModeValid(ldaa_key->publicArea.parameters.ldaaDetail.security))
        return TPM_RCS_SCHEME + RC_LDAA_SignCommit3_key_handle;

    // Hash private key
    CryptHashBlock(ALG_SHA256_VALUE,
            ldaa_key->sensitive.sensitive.ldaa.t.size,
            ldaa_key->sensitive.sensitive.ldaa.t.buffer,
            SHA256_DIGEST_SIZE,
            digest);

    uint8_t lower_limit, higher_limit;
    if (ldaa_key->publicArea.parameters.ldaaDetail.security == TPM_LDAA_SECURITY_MODE_WEAK) {
        lower_limit = 3;
        higher_limit = 14;
    } else if (ldaa_key->publicArea.parameters.ldaaDetail.security == TPM_LDAA_SECURITY_MODE_MEDIUM) {
        lower_limit = 3;
        higher_limit = 26;
    } else if (ldaa_key->publicArea.parameters.ldaaDetail.security == TPM_LDAA_SECURITY_MODE_HIGH) {
        lower_limit = 3;
        higher_limit = 26;
    } else {
        return TPM_RCS_SCHEME + RC_LDAA_SignCommit3_key_handle;
    }

    // Fail if the private key passed is different than the tied key to
    // the LDAA session, if the SID stored and passed are different, or
    // if commit counter isn't in the correct state.
    if (gr.ldaa_commitCounter < lower_limit || gr.ldaa_commitCounter > higher_limit ||
            in->sid != gr.ldaa_sid ||
            !MemoryEqual(digest, gr.ldaa_hash_private_key, SHA256_DIGEST_SIZE) ||
            ldaa_key->publicArea.parameters.ldaaDetail.security != gr.ldaa_security) {
        // Clear current state of the protocol
        CryptLDaaClearProtocolState();
        return TPM_RC_NO_RESULT;
    }

    UINT8 commit_sel = 3;

    retVal = CryptLDaaSignCommit(
            // Outputs
            &out->commit,
            // Inputs
            &ldaa_key->sensitive,
            &commit_sel, &in->sign_state_sel,
            &in->pbsn, &in->pe,
            NULL, &in->bsn, &in->seed,
            ldaa_key->publicArea.parameters.ldaaDetail.security);

    // Run Commit command
    if (retVal == TPM_RC_SUCCESS)
        retVal = CryptLDaaCommit();

    return retVal;
}
#endif // ALG_LDAA
#endif // CC_LDAA_SignCommit3

#if CC_LDAA_CommitTokenLink  // Conditional expansion of this file
#include "Tpm.h"
#include "LDaa_CommitTokenLink_fp.h"
#if ALG_LDAA
TPM_RC
TPM2_LDAA_CommitTokenLink(
		 LDAA_CommitTokenLink_In      *in,            // In: input parameter list
		 LDAA_CommitTokenLink_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    OBJECT  *ldaa_key;
    BYTE     digest[SHA256_DIGEST_SIZE];

    // Input Validation
    ldaa_key = HandleToObject(in->key_handle);

    // Input key must be an LDAA key
    if(ldaa_key->publicArea.type != TPM_ALG_LDAA)
        return TPM_RCS_KEY + RC_LDAA_CommitTokenLink_key_handle;
    if(!CryptIsSchemeAnonymous(ldaa_key->publicArea.parameters.ldaaDetail.scheme.scheme))
        return TPM_RCS_SCHEME + RC_LDAA_CommitTokenLink_key_handle;
    if(!CryptLDaaIsModeValid(ldaa_key->publicArea.parameters.ldaaDetail.security))
        return TPM_RCS_SCHEME + RC_LDAA_CommitTokenLink_key_handle;

    // Hash private key
    CryptHashBlock(ALG_SHA256_VALUE,
            ldaa_key->sensitive.sensitive.ldaa.t.size,
            ldaa_key->sensitive.sensitive.ldaa.t.buffer,
            SHA256_DIGEST_SIZE,
            digest);

    // Fail if the private key passed is different than the tied key to
    // the LDAA session, if the SID stored and passed are different, or
    // if commit counter isn't in the correct state.
    if (gr.ldaa_commitCounter != 2 ||
            in->sid != gr.ldaa_sid ||
            !MemoryEqual(digest, gr.ldaa_hash_private_key, SHA256_DIGEST_SIZE) ||
            ldaa_key->publicArea.parameters.ldaaDetail.security != gr.ldaa_security) {
        // Clear current state of the protocol
        CryptLDaaClearProtocolState();
        return TPM_RC_NO_RESULT;
    }

    retVal = CryptLDaaCommitTokenLink(
            // Outputs
            &out->nym, &out->pbsn, &out->pe,
            // Inputs
            &ldaa_key->sensitive, &in->bsn,
            ldaa_key->publicArea.parameters.ldaaDetail.security);

    // Run Commit command
    if (retVal == TPM_RC_SUCCESS)
        retVal = CryptLDaaCommit();

    return retVal;
}
#endif // ALG_LDAA
#endif // CC_LDAA_CommitTokenLink

#if CC_LDAA_SignProof  // Conditional expansion of this file
#include "Tpm.h"
#include "LDaa_SignProof_fp.h"
#if ALG_LDAA
TPM_RC
TPM2_LDAA_SignProof(
		 LDAA_SignProof_In      *in,            // In: input parameter list
		 LDAA_SignProof_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    OBJECT  *ldaa_key;
    BYTE     digest[SHA256_DIGEST_SIZE];

    // Input Validation
    ldaa_key = HandleToObject(in->key_handle);

    // Input key must be an LDAA key
    if(ldaa_key->publicArea.type != TPM_ALG_LDAA)
        return TPM_RCS_KEY + RC_LDAA_SignProof_key_handle;
    if(!CryptIsSchemeAnonymous(ldaa_key->publicArea.parameters.ldaaDetail.scheme.scheme))
        return TPM_RCS_SCHEME + RC_LDAA_SignProof_key_handle;
    if(!CryptLDaaIsModeValid(ldaa_key->publicArea.parameters.ldaaDetail.security))
        return TPM_RCS_SCHEME + RC_LDAA_SignProof_key_handle;

    // Hash private key
    CryptHashBlock(ALG_SHA256_VALUE,
            ldaa_key->sensitive.sensitive.ldaa.t.size,
            ldaa_key->sensitive.sensitive.ldaa.t.buffer,
            SHA256_DIGEST_SIZE,
            digest);

    uint8_t lower_limit, higher_limit;
    if (ldaa_key->publicArea.parameters.ldaaDetail.security == TPM_LDAA_SECURITY_MODE_WEAK) {
        lower_limit = 15;
        higher_limit = 18;
    } else if (ldaa_key->publicArea.parameters.ldaaDetail.security == TPM_LDAA_SECURITY_MODE_MEDIUM) {
        lower_limit = 27;
        higher_limit = 34;
    } else if (ldaa_key->publicArea.parameters.ldaaDetail.security == TPM_LDAA_SECURITY_MODE_HIGH) {
        lower_limit = 27;
        higher_limit = 34;
    } else {
        return TPM_RCS_SCHEME + RC_LDAA_SignProof_key_handle;
    }

    // Fail if the private key passed is different than the tied key to
    // the LDAA session, if the SID stored and passed are different, or
    // if commit counter isn't in the correct state.
    if (gr.ldaa_commitCounter < lower_limit || gr.ldaa_commitCounter > higher_limit ||
            in->sid != gr.ldaa_sid ||
            !MemoryEqual(digest, gr.ldaa_hash_private_key, SHA256_DIGEST_SIZE) ||
            ldaa_key->publicArea.parameters.ldaaDetail.security != gr.ldaa_security) {
        // Clear current state of the protocol
        CryptLDaaClearProtocolState();
        return TPM_RC_NO_RESULT;
    }

    retVal = CryptLDaaSignProof(
            // Outputs
            &out->R1,
            &out->R2,
            &out->sign_group,
            // Inputs
            &in->R1,
            &in->R2,
            &in->sign_state_sel,
            &in->sign_state_type,
            ldaa_key->publicArea.parameters.ldaaDetail.security);

    // Run Commit command
    if (retVal == TPM_RC_SUCCESS && gr.ldaa_commitCounter != higher_limit)
        retVal = CryptLDaaCommit();
    else
        retVal = CryptLDaaClearProtocolState();

    return retVal;
}
#endif // ALG_LDAA
#endif // CC_LDAA_SignProof

#if CC_LDAA_SignProceed  // Conditional expansion of this file
#include "Tpm.h"
#include "LDaa_SignProceed_fp.h"
#if ALG_LDAA
TPM_RC
TPM2_LDAA_SignProceed(
		 LDAA_SignProceed_In      *in            // In: input parameter list
		 )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    OBJECT  *ldaa_key;
    BYTE     digest[SHA256_DIGEST_SIZE];

    // Input Validation
    ldaa_key = HandleToObject(in->key_handle);

    // Input key must be an LDAA key
    if(ldaa_key->publicArea.type != TPM_ALG_LDAA)
        return TPM_RCS_KEY + RC_LDAA_SignProceed_key_handle;
    if(!CryptIsSchemeAnonymous(ldaa_key->publicArea.parameters.ldaaDetail.scheme.scheme))
        return TPM_RCS_SCHEME + RC_LDAA_SignProceed_key_handle;
    if(!CryptLDaaIsModeValid(ldaa_key->publicArea.parameters.ldaaDetail.security))
        return TPM_RCS_SCHEME + RC_LDAA_SignProceed_key_handle;

    // Hash private key
    CryptHashBlock(ALG_SHA256_VALUE,
            ldaa_key->sensitive.sensitive.ldaa.t.size,
            ldaa_key->sensitive.sensitive.ldaa.t.buffer,
            SHA256_DIGEST_SIZE,
            digest);

    // Fail if the private key passed is different than the tied key to
    // the LDAA session, if the SID stored and passed are different, or
    // if commit counter isn't in the correct state.
    if (gr.ldaa_commitCounter != 1 ||
            in->sid != gr.ldaa_sid ||
            !MemoryEqual(digest, gr.ldaa_hash_private_key, SHA256_DIGEST_SIZE) ||
            ldaa_key->publicArea.parameters.ldaaDetail.security != gr.ldaa_security) {
        // Clear current state of the protocol
        CryptLDaaClearProtocolState();
        return TPM_RC_NO_RESULT;
    }

    retVal = CryptLDaaCommit();

    return retVal;
}
#endif // ALG_LDAA
#endif // CC_LDAA_SignProof
/*****************************************************************************/
/*                                 LDAA Mods                                 */
/*****************************************************************************/

/*****************************************************************************/
/*                                NTTRU Mods                                 */
/*****************************************************************************/
#if CC_NTTRU_Enc  // Conditional expansion of this file
#include "Tpm.h"
#include "NTTRU_Enc_fp.h"
#if ALG_NTTRU
TPM_RC
TPM2_NTTRU_Enc(
		 NTTRU_Encapsulate_In      *in, // In: input parameter list
		 NTTRU_Encapsulate_Out     *out // OUT: output parameter list
		 )
{
    TPM_RC retVal = TPM_RC_SUCCESS;
    OBJECT *nttruKey;

    // Input Validation
    nttruKey = HandleToObject(in->key_handle);
    // selected key must be a NTTRU key
    if(nttruKey->publicArea.type != TPM_ALG_NTTRU)
        return TPM_RCS_KEY + RC_NTTRU_Encapsulate_key_handle;
    // selected key must have the decryption attribute
    if(!IS_ATTRIBUTE(nttruKey->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_ATTRIBUTES + RC_NTTRU_Encapsulate_key_handle;
    // NTTRU is only used for encryption/decryption, no signing
    if (IS_ATTRIBUTE(nttruKey->publicArea.objectAttributes, TPMA_OBJECT, sign))
        return TPM_RC_NO_RESULT;

    // Check key validity
    if (CryptValidateKeys(&nttruKey->publicArea,
                NULL, 0, 0) != TPM_RC_SUCCESS)
        return TPM_RCS_KEY + RC_NTTRU_Encapsulate_key_handle;

    retVal = CryptNTTRUEncapsulate(&nttruKey->publicArea, &out->shared_key,
            &out->cipher_text);

    return retVal;
}
#endif // ALG_NTTRU
#endif // CC_NTTRU_Enc

#if CC_NTTRU_Dec  // Conditional expansion of this file
#include "Tpm.h"
#include "NTTRU_Dec_fp.h"
#if ALG_NTTRU
TPM_RC
TPM2_NTTRU_Dec(
		 NTTRU_Decapsulate_In      *in,            // In: input parameter list
		 NTTRU_Decapsulate_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    OBJECT *nttruKey;

    // Input Validation
    nttruKey = HandleToObject(in->key_handle);
    // selected key must be a NTTRU key
    if(nttruKey->publicArea.type != TPM_ALG_NTTRU)
        return TPM_RCS_KEY + RC_NTTRU_Decapsulate_key_handle;
    // selected key must have the decryption attribute
    if(!IS_ATTRIBUTE(nttruKey->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_ATTRIBUTES + RC_NTTRU_Decapsulate_key_handle;
    // NTTRU is only used for encryption/decryption, no signing
    if (IS_ATTRIBUTE(nttruKey->publicArea.objectAttributes, TPMA_OBJECT, sign))
        return TPM_RC_NO_RESULT;
    // Check key validity
    if (CryptValidateKeys(&nttruKey->publicArea,
                &nttruKey->sensitive, 0, 0) != TPM_RC_SUCCESS)
        return TPM_RCS_KEY + RC_NTTRU_Decapsulate_key_handle;
    // Validate Cipher Text size for static key
    if (CryptNTTRUValidateCipherTextSize(&in->cipher_text) != TPM_RC_SUCCESS)
        return TPM_RC_VALUE + RC_NTTRU_Decapsulate_cipher_text;

    retVal = CryptNTTRUDecapsulate(&nttruKey->sensitive,
            &in->cipher_text, &out->shared_key);

    return retVal;
}
#endif // ALG_NTTRU
#endif // CC_NTTRU_Dec

#if CC_NTTRU_Encrypt  // Conditional expansion of this file
#include "Tpm.h"
#include "NTTRU_Encrypt_fp.h"
#if ALG_NTTRU
TPM_RC
TPM2_NTTRU_Encrypt(
		 NTTRU_Encrypt_In      *in,            // In: input parameter list
		 NTTRU_Encrypt_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC retVal = TPM_RC_SUCCESS;
    OBJECT *key_handle;

    // Input Validation
    key_handle = HandleToObject(in->keyHandle);

    // selected key must be a NTTRU key
    if(key_handle->publicArea.type != TPM_ALG_NTTRU)
        return TPM_RCS_KEY + RC_NTTRU_Encrypt_key_handle;
    // selected key must have the decryption attribute
    if(IS_ATTRIBUTE(key_handle->publicArea.objectAttributes, TPMA_OBJECT, restricted)
       || !IS_ATTRIBUTE(key_handle->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_KEY + RC_NTTRU_Encrypt_key_handle;
    // NTTRU is only used for encryption/decryption, no signing
    if (IS_ATTRIBUTE(key_handle->publicArea.objectAttributes, TPMA_OBJECT, sign))
        return TPM_RC_NO_RESULT;

    // Validate security parameter
    /* if (!CryptNTTRUIsModeValid(key_handle->publicArea.parameters.kyberDetail.security)) */
    /*     return TPM_RCS_KEY + RC_NTTRU_Encrypt_key_handle; */

    // Check static key validity
    if (CryptValidateKeys(&key_handle->publicArea,
                NULL, 0, 0) != TPM_RC_SUCCESS)
        return TPM_RCS_KEY + RC_NTTRU_Encrypt_key_handle;

    retVal = CryptNTTRUEncrypt(&out->outData, key_handle, &in->message.b);

    return retVal;
}
#endif // ALG_NTTRU
#endif // CC_NTTRU_Encrypt

#if CC_NTTRU_Decrypt  // Conditional expansion of this file
#include "Tpm.h"
#include "NTTRU_Decrypt_fp.h"
#if ALG_NTTRU
TPM_RC
TPM2_NTTRU_Decrypt(
		 NTTRU_Decrypt_In      *in,            // In: input parameter list
		 NTTRU_Decrypt_Out     *out            // OUT: output parameter list
		 )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    OBJECT *key_handle;

    // Input Validation
    key_handle = HandleToObject(in->keyHandle);

    // selected key must be a NTTRU key
    if(key_handle->publicArea.type != TPM_ALG_NTTRU)
        return TPM_RCS_KEY + RC_NTTRU_Decrypt_key_handle;
    // selected key must have the decryption attribute
    if(IS_ATTRIBUTE(key_handle->publicArea.objectAttributes, TPMA_OBJECT, restricted)
       || !IS_ATTRIBUTE(key_handle->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_KEY + RC_NTTRU_Decrypt_key_handle;
    // NTTRU is only used for encryption/decryption, no signing
    if (IS_ATTRIBUTE(key_handle->publicArea.objectAttributes, TPMA_OBJECT, sign))
        return TPM_RC_NO_RESULT;

    /* // Validate security parameter */
    /* if (!CryptNTTRUIsModeValid(key_handle->publicArea.parameters.kyberDetail.security)) */
    /*     return TPM_RCS_KEY + RC_NTTRU_Decrypt_key_handle; */

    // Check static key validity
    if (CryptValidateKeys(&key_handle->publicArea,
                &key_handle->sensitive, 0, 0) != TPM_RC_SUCCESS)
        return TPM_RCS_KEY;

    retVal = CryptNTTRUDecrypt(&out->outData.b, key_handle, &in->message);

    return retVal;
}
#endif // ALG_NTTRU
#endif // CC_NTTRU_Decrypt

/*****************************************************************************/
/*                                NTTRU Mods                                 */
/*****************************************************************************/
