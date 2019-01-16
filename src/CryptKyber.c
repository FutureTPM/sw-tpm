#include "Tpm.h"
#include "CryptKyber_fp.h"
#include "kyber-params.h"
#include "kyber-indcpa.h"
#include "fips202.h"

BOOL CryptKyberInit(void) {
    return TRUE;
}

BOOL CryptKyberStartup(void) {
    return TRUE;
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

static TPM_RC generate_kyber_params(TPM_KYBER_SECURITY kyber_k, KyberParams *params) {
    TPM_RC   retVal             = TPM_RC_NO_RESULT;
    uint64_t kyber_polyvecbytes = 0;

    params->k = kyber_k;
    kyber_polyvecbytes           = kyber_k * KYBER_POLYBYTES;
    params->polyveccompressedbytes = kyber_k * 352;

    params->indcpa_publickeybytes = params->polyveccompressedbytes +
        KYBER_SYMBYTES;
    params->indcpa_secretkeybytes = kyber_polyvecbytes;

    params->publickeybytes =  params->indcpa_publickeybytes;
    params->secretkeybytes =  params->indcpa_secretkeybytes +
        params->indcpa_publickeybytes + 2*KYBER_SYMBYTES;
    params->ciphertextbytes = params->polyveccompressedbytes +
        KYBER_POLYCOMPRESSEDBYTES;

    switch (kyber_k) {
        case TPM_KYBER_SECURITY_2:
            params->eta = 5; /* Kyber512 */
            retVal = TPM_RC_SUCCESS;
            break;
        case TPM_KYBER_SECURITY_3:
            params->eta = 4; /* Kyber768 */
            retVal = TPM_RC_SUCCESS;
            break;
        case TPM_KYBER_SECURITY_4:
            params->eta = 3; /* Kyber1024 */
            retVal = TPM_RC_SUCCESS;
            break;
        default:
            retVal = TPM_RC_VALUE;
            break;
    }

    return retVal;
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

    // Parameter check
    if (generate_kyber_params(publicArea->parameters.kyberDetail.security,
                &params) != TPM_RC_SUCCESS) {
        return TPM_RC_VALUE;
    }

    // Command Output
    indcpa_keypair((unsigned char *)&publicArea->unique.kyber.t.buffer,
            (unsigned char *)&sensitive->sensitive.kyber.t.buffer,
            params.k, params.polyveccompressedbytes, params.eta);
    for (size_t i = 0; i < params.indcpa_publickeybytes; i++) {
      sensitive->sensitive.kyber.t.buffer[i+params.indcpa_secretkeybytes] = publicArea->unique.kyber.t.buffer[i];
    }
    sha3_256((unsigned char *)sensitive->sensitive.kyber.t.buffer+params.secretkeybytes-2*KYBER_SYMBYTES,
            publicArea->unique.kyber.t.buffer,
            params.publickeybytes);
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
