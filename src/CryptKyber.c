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
#include "CryptKyber_fp.h"
#include "kyber-params.h"
#include "kyber-indcpa.h"
#include "kyber-verify.h"

BOOL CryptKyberInit(void) {
    return TRUE;
}

BOOL CryptKyberStartup(void) {
    return TRUE;
}

BOOL CryptKyberIsModeValid(
            // IN: the security mode
            TPM_KYBER_SECURITY  k
        ) {
    switch (k) {
        case TPM_KYBER_SECURITY_2:
            return TRUE;
        case TPM_KYBER_SECURITY_3:
            return TRUE;
        case TPM_KYBER_SECURITY_4:
            return TRUE;
        default:
            return FALSE;
    }
}

LIB_EXPORT TPM_RC
CryptKyberValidateCipherTextSize(
            // IN: the cipher text
            TPM2B_KYBER_CIPHER_TEXT *ct,
            // IN: the security mode being used to decapsulate the cipher text
            TPM_KYBER_SECURITY  k
		 ) {
    TPM_RC   retVal             = TPM_RC_SUCCESS;

    switch (k) {
        case TPM_KYBER_SECURITY_2:
            if (ct->t.size != 800) return TPM_RC_VALUE;
            break;
        case TPM_KYBER_SECURITY_3:
            if (ct->t.size != 1152) return TPM_RC_VALUE;
            break;
        case TPM_KYBER_SECURITY_4:
            if (ct->t.size != 1504) return TPM_RC_VALUE;
            break;
        default:
            /* This should not be possible. The caller should have already
             * checked for the validity of the security parameter. */
            break;
    }

    return retVal;
}

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

static KyberParams generate_kyber_params(TPM_KYBER_SECURITY kyber_k) {
    KyberParams params;
    uint64_t kyber_polyvecbytes = 0;

    params.k = kyber_k;
    kyber_polyvecbytes            = kyber_k * KYBER_POLYBYTES;
    params.polyveccompressedbytes = kyber_k * 352;

    params.indcpa_publickeybytes = params.polyveccompressedbytes +
        KYBER_SYMBYTES;
    params.indcpa_secretkeybytes = kyber_polyvecbytes;

    params.publickeybytes =  params.indcpa_publickeybytes;
    params.secretkeybytes =  params.indcpa_secretkeybytes +
        params.indcpa_publickeybytes + 2*KYBER_SYMBYTES;
    params.ciphertextbytes = params.polyveccompressedbytes +
        KYBER_POLYCOMPRESSEDBYTES;

    switch (kyber_k) {
        case TPM_KYBER_SECURITY_2:
            params.eta = 5; /* Kyber512 */
            break;
        case TPM_KYBER_SECURITY_3:
            params.eta = 4; /* Kyber768 */
            break;
        case TPM_KYBER_SECURITY_4:
            params.eta = 3; /* Kyber1024 */
            break;
        default:
            break;
    }

    return params;
}

LIB_EXPORT TPM_RC
CryptKyberEncrypt(
            // OUT: The encrypted data
            TPM2B_KYBER_ENCRYPT *cOut,
            // IN: The object structure in which the key is created.
		    OBJECT              *kyberKey,
            // IN: the data to encrypt
            TPM2B               *dIn
		 )
{
    TPM_RC result = TPM_RC_SUCCESS;
    TPM2B_KYBER_SHARED_KEY ss;
    TPM2B_KYBER_CIPHER_TEXT ct;

    if (result == TPM_RC_SUCCESS) {
        result = CryptKyberEncapsulate(&kyberKey->publicArea, &ss, &ct);

        MemoryCopy(cOut->t.buffer, ct.t.buffer, ct.t.size);
        cOut->t.size = ct.t.size;
    }

    if (result == TPM_RC_SUCCESS) {
        result = CryptSymmetricEncrypt(
                      cOut->b.buffer + ct.t.size,
                      TPM_ALG_AES, ss.t.size * 8, ss.t.buffer, NULL,
                      TPM_ALG_CFB, dIn->size, dIn->buffer);

        cOut->t.size += dIn->size;
    }

    return result;
}

LIB_EXPORT TPM_RC
CryptKyberDecrypt(
            // OUT: The decrypted data
            TPM2B               *cOut,
            // IN: The object structure in which the key is created.
		    OBJECT              *kyberKey,
            // IN: the data to decrypt
            TPM2B_KYBER_ENCRYPT *dIn
            )
{
    TPM_RC result = TPM_RC_SUCCESS;
    TPM2B_KYBER_SHARED_KEY ss;
    TPM2B_KYBER_CIPHER_TEXT ct;
    KyberParams params;

    // Parameter generation
    params = generate_kyber_params(kyberKey->publicArea.parameters.kyberDetail.security);

    MemoryCopy(ct.t.buffer, dIn->t.buffer, params.ciphertextbytes);
    ct.t.size = params.ciphertextbytes;

    if (result == TPM_RC_SUCCESS) {
        result = CryptKyberDecapsulate(&kyberKey->sensitive,
                kyberKey->publicArea.parameters.kyberDetail.security,
                &ct, &ss);
    }

    // cOut is the result of AES
    if (result == TPM_RC_SUCCESS) {
        result = CryptSymmetricDecrypt(cOut->buffer, TPM_ALG_AES, ss.t.size * 8,
                  ss.t.buffer, NULL, TPM_ALG_CFB,
                  dIn->t.size - params.ciphertextbytes,
                  dIn->b.buffer + params.ciphertextbytes);
        cOut->size = dIn->t.size - params.ciphertextbytes;
    }

    return result;
}

LIB_EXPORT TPM_RC
CryptKyberGenerateKey(
            // IN/OUT: The object structure in which the key is created.
		    OBJECT              *kyberKey,
            // IN: if not NULL, the deterministic RNG state
		    RAND_STATE          *rand
		 )
{
    TPMT_PUBLIC         *publicArea = &kyberKey->publicArea;
    TPMT_SENSITIVE      *sensitive  = &kyberKey->sensitive;
    TPM_RC               retVal     = TPM_RC_NO_RESULT;
    KyberParams params;

    pAssert(kyberKey != NULL);

    // Kyber is only used for encryption/decryption, no signing
    if (IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
        ERROR_RETURN(TPM_RC_NO_RESULT);

    // Parameter generation
    params = generate_kyber_params(publicArea->parameters.kyberDetail.security);

    // Command Output
    indcpa_keypair(publicArea->unique.kyber.t.buffer,
            sensitive->sensitive.kyber.t.buffer,
            params.k, params.polyveccompressedbytes, params.eta, rand);
    for (size_t i = 0; i < params.indcpa_publickeybytes; i++) {
      sensitive->sensitive.kyber.t.buffer[i+params.indcpa_secretkeybytes] = publicArea->unique.kyber.t.buffer[i];
    }

    CryptHashBlock(TPM_ALG_SHA3_256,
            params.publickeybytes, publicArea->unique.kyber.t.buffer,
            KYBER_SYMBYTES, sensitive->sensitive.kyber.t.buffer+params.secretkeybytes-2*KYBER_SYMBYTES);
    /* Value z for pseudo-random output on reject */
    //CryptRandomGenerate(KYBER_SYMBYTES, sensitive->sensitive.kyber.t.buffer+params.secretkeybytes-KYBER_SYMBYTES);
    DRBG_Generate(rand,
            sensitive->sensitive.kyber.t.buffer+params.secretkeybytes-KYBER_SYMBYTES,
            KYBER_SYMBYTES);

    publicArea->unique.kyber.t.size = params.publickeybytes;
    sensitive->sensitive.kyber.t.size = params.secretkeybytes;

    retVal = TPM_RC_SUCCESS;

Exit:
    return retVal;
}

// Caller must validate sizes of public key, and the security mode.
LIB_EXPORT TPM_RC
CryptKyberEncapsulate(
            // IN: The object structure which contains the public key used in
            // the encapsulation.
		    TPMT_PUBLIC             *publicArea,
            // OUT: the shared key
            TPM2B_KYBER_SHARED_KEY  *ss,
            // OUT: the cipher text
            TPM2B_KYBER_CIPHER_TEXT *ct
		 )
{
    TPM_RC               retVal     = TPM_RC_SUCCESS;
    KyberParams params;
    /* Will contain key, coins */
    unsigned char  kr[2*KYBER_SYMBYTES];
    unsigned char buf[2*KYBER_SYMBYTES];

    pAssert(publicArea != NULL && ss != NULL && ct != NULL);

    // Parameter Generation
    params = generate_kyber_params(publicArea->parameters.kyberDetail.security);

    // Create secret data from RNG
    CryptRandomGenerate(KYBER_SYMBYTES, buf);
    /* Don't release system RNG output */
    CryptHashBlock(TPM_ALG_SHA3_256,
            KYBER_SYMBYTES, buf,
            KYBER_SYMBYTES, buf);

    /* Multitarget countermeasure for coins + contributory KEM */
    CryptHashBlock(TPM_ALG_SHA3_256,
            params.publickeybytes, publicArea->unique.kyber.t.buffer,
            KYBER_SYMBYTES, buf+KYBER_SYMBYTES);
    CryptHashBlock(TPM_ALG_SHA3_512,
            2*KYBER_SYMBYTES, buf,
            2*KYBER_SYMBYTES, kr);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(ct->t.buffer, buf,
            publicArea->unique.kyber.t.buffer,
            kr+KYBER_SYMBYTES, params.k,
            params.polyveccompressedbytes, params.eta);

    /* overwrite coins in kr with H(c) */
    CryptHashBlock(TPM_ALG_SHA3_256,
            params.ciphertextbytes, ct->t.buffer,
            KYBER_SYMBYTES, kr+KYBER_SYMBYTES);
    /* hash concatenation of pre-k and H(c) to k */
    CryptHashBlock(TPM_ALG_SHA3_256,
            2*KYBER_SYMBYTES, kr,
            KYBER_SYMBYTES, ss->t.buffer);

    ss->t.size = 32;
    ct->t.size = params.ciphertextbytes;

    return retVal;
}

// Caller must validate sizes of cipher text, secret key, and the security mode
LIB_EXPORT TPM_RC
CryptKyberDecapsulate(
            // IN: The object structure which contains the secret key used in
            // the decapsulation.
		    TPMT_SENSITIVE          *sensitive,
            // IN: Kyber security mode
            TPM_KYBER_SECURITY      k,
            // IN: the cipher text
            TPM2B_KYBER_CIPHER_TEXT *ct,
            // OUT: the shared key
            TPM2B_KYBER_SHARED_KEY  *ss
		 )
{
    TPM_RC               retVal     = TPM_RC_SUCCESS;
    KyberParams params;
    size_t i;
    int fail;
    unsigned char buf[2*KYBER_SYMBYTES];
    /* Will contain key, coins, qrom-hash */
    unsigned char kr[2*KYBER_SYMBYTES];

    pAssert(sensitive != NULL && ss != NULL && ct != NULL);

    // Parameter Generation
    params = generate_kyber_params(k);

    {
        const unsigned char *pk = sensitive->sensitive.kyber.t.buffer+params.indcpa_secretkeybytes;
        unsigned char cmp[params.ciphertextbytes];

        indcpa_dec(buf, ct->t.buffer, sensitive->sensitive.kyber.t.buffer, params.k,
                params.polyveccompressedbytes, params.eta);

        /* Multitarget countermeasure for coins + contributory KEM */
        for(i=0;i<KYBER_SYMBYTES;i++) {
          /* Save hash by storing H(pk) in sk */
          buf[KYBER_SYMBYTES+i] = sensitive->sensitive.kyber.t.buffer[params.secretkeybytes-2*KYBER_SYMBYTES+i];
        }
        CryptHashBlock(TPM_ALG_SHA3_512,
                2*KYBER_SYMBYTES, buf,
                2*KYBER_SYMBYTES, kr);

        /* coins are in kr+KYBER_SYMBYTES */
        indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES, params.k,
                params.polyveccompressedbytes, params.eta);

        fail = kyber_verify(ct->t.buffer, cmp, params.ciphertextbytes);

        /* overwrite coins in kr with H(c)  */
        CryptHashBlock(TPM_ALG_SHA3_256,
                params.ciphertextbytes, ct->t.buffer,
                KYBER_SYMBYTES, kr+KYBER_SYMBYTES);

        /* Overwrite pre-k with z on re-encryption failure */
        kyber_cmov(kr, sensitive->sensitive.kyber.t.buffer+params.secretkeybytes-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

        /* hash concatenation of pre-k and H(c) to k */
        CryptHashBlock(TPM_ALG_SHA3_256,
                2*KYBER_SYMBYTES, kr,
                KYBER_SYMBYTES, ss->t.buffer);

        ss->t.size = 32;

        retVal = TPM_RC_SUCCESS;
    }

    return retVal;
}
