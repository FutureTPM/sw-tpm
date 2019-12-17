/*
 * MIT License
 *
 * Copyright (c) 2019 Luís Fiolhais, Paulo Martins, Leonel Sousa (INESC-ID)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "Tpm.h"
#include "CryptNTTRU_fp.h"
#include "nttru-params.h"
#include "nttru-kem.h"
#include "nttru-ntt.h"

BOOL CryptNTTRUInit(void) {
    nttru_init_ntt();
    return TRUE;
}

BOOL CryptNTTRUStartup(void) {
    return TRUE;
}

LIB_EXPORT TPM_RC
CryptNTTRUValidateCipherTextSize(
            // IN: the cipher text
            TPM2B_NTTRU_CIPHER_TEXT *ct
		 ) {
    if (ct->t.size != NTTRU_CIPHERTEXTBYTES) return TPM_RC_VALUE;

    return TPM_RC_SUCCESS;
}

LIB_EXPORT TPM_RC
CryptNTTRUGenerateKey(
            // IN/OUT: The object structure in which the key is created.
		    OBJECT              *nttruKey,
            // IN: if not NULL, the deterministic RNG state
		    RAND_STATE          *rand
		 )
{
    TPMT_PUBLIC         *publicArea = &nttruKey->publicArea;
    TPMT_SENSITIVE      *sensitive  = &nttruKey->sensitive;
    TPM_RC               retVal     = TPM_RC_NO_RESULT;

    pAssert(nttruKey != NULL);

    // NTTRU is only used for encryption/decryption, no signing
    if (IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
        ERROR_RETURN(TPM_RC_NO_RESULT);

    // Command Output
    nttru_crypto_kem_keypair(publicArea->unique.nttru.t.buffer,
            sensitive->sensitive.nttru.t.buffer, rand);

    publicArea->unique.nttru.t.size = NTTRU_PUBLICKEYBYTES;
    sensitive->sensitive.nttru.t.size = NTTRU_SECRETKEYBYTES;

    retVal = TPM_RC_SUCCESS;

Exit:
    return retVal;
}

LIB_EXPORT TPM_RC
CryptNTTRUEncapsulate(
            // IN: The object structure which contains the public key used in
            // the encapsulation.
		    TPMT_PUBLIC             *publicArea,
            // OUT: the shared key
            TPM2B_NTTRU_SHARED_KEY  *ss,
            // OUT: the cipher text
            TPM2B_NTTRU_CIPHER_TEXT *ct
		 )
{
    TPM_RC               retVal     = TPM_RC_SUCCESS;

    pAssert(publicArea != NULL && ss != NULL && ct != NULL);

    nttru_crypto_kem_enc(ct->t.buffer,
            ss->t.buffer,
            publicArea->unique.nttru.t.buffer, NULL);

    ss->t.size = NTTRU_SHAREDKEYBYTES;
    ct->t.size = NTTRU_CIPHERTEXTBYTES;

    return retVal;
}

LIB_EXPORT TPM_RC
CryptNTTRUDecapsulate(
            // IN: The object structure which contains the secret key used in
            // the decapsulation.
		    TPMT_SENSITIVE          *sensitive,
            // IN: the cipher text
            TPM2B_NTTRU_CIPHER_TEXT *ct,
            // OUT: the shared key
            TPM2B_NTTRU_SHARED_KEY  *ss
		 )
{
    TPM_RC               retVal     = TPM_RC_SUCCESS;

    pAssert(sensitive != NULL && ss != NULL && ct != NULL);

    int fail = nttru_crypto_kem_dec(ss->t.buffer,
            ct->t.buffer,
            sensitive->sensitive.nttru.t.buffer);

    ss->t.size = NTTRU_SHAREDKEYBYTES;

    if (fail != 0) {
        retVal = TPM_RC_VALUE;
    }

    return retVal;
}
