#include "Tpm.h"
#include "CryptLDaa_fp.h"
#include "ldaa-params.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial.h"

BOOL CryptLDaaInit(void) {
    return TRUE;
}

BOOL CryptLDaaStartup(void) {
    return TRUE;
}

/* Serialize coefficient to Little Endian */
static inline void Coeff2Bytes(BYTE *out, UINT32 in) {
    for (size_t i = 0; i < 4; i++) {
        out[i] = (BYTE) (0xff & (in >> (i * 8)));
    }
}

/* Deserialize bytes in Little Endian to coefficients */
static inline UINT32 Bytes2Coeff(BYTE *in) {
    UINT32 out = 0;

    for (size_t i = 0; i < 4; i++) {
        out |= ((UINT32) in[i]) << (i * 8);
    }

    return out;
}

static void CryptLDaaDeserializeIssuerAT(
        // OUT: at polynomial matrix matrix
        ldaa_poly_matrix_xt_t *at,
        // IN: The public area parameter which contains the serialized at from
        // the issuer
        TPM2B_LDAA_ISSUER_AT *issuer_at
        ) {
    // Loop polynomial matrix (Mx1)
    for (size_t i = 0; i < LDAA_M; i++) {
        // Loop coefficients of each polynomial
        for (size_t j = 0; j < LDAA_N; j++) {
           at->coeffs[i].coeffs[j] =
               Bytes2Coeff((BYTE*) &issuer_at->t.buffer+((i*LDAA_N+j)*4));
        }
    }
}

static void CryptLDaaSerializePublicKey(
        // OUT: serialized secret key
        TPM2B_LDAA_PUBLIC_KEY *ut,
        // IN: The public key in polynomial form
        ldaa_poly_t *public_key
        ) {
    for (size_t i = 0; i < LDAA_N; i++) {
        Coeff2Bytes((BYTE *)&ut->t.buffer+(i*4), public_key->coeffs[i]);
    }

    ut->t.size = MAX_LDAA_PUBLIC_KEY_SIZE;
}

static void CryptLDaaSerializeSecretKey(
        // OUT: serialized secret key
        TPM2B_LDAA_SECRET_KEY *xt,
        // IN: The secret key in matrix polynomial form
        ldaa_poly_matrix_xt_t *secret_key
        ) {
    // Loop polynomial matrix (Mx1)
    for (size_t i = 0; i < LDAA_M; i++) {
        // Loop coefficients of each polynomial
        for (size_t j = 0; j < LDAA_N; j++) {
            Coeff2Bytes((BYTE*)&xt->t.buffer+((i*LDAA_N+j)*4),
                    secret_key->coeffs[i].coeffs[j]);
        }
    }

    xt->t.size = MAX_LDAA_SECRET_KEY_SIZE;
}

LIB_EXPORT TPM_RC
CryptLDaaGenerateKey(
            // IN/OUT: The object structure in which the key is created.
		    OBJECT              *ldaaKey,
            // IN: if not NULL, the deterministic RNG state
		    RAND_STATE          *rand
		 )
{
    TPMT_PUBLIC                *publicArea = &ldaaKey->publicArea;
    TPMT_SENSITIVE             *sensitive  = &ldaaKey->sensitive;
    TPM_RC                      retVal     = TPM_RC_NO_RESULT;
    ldaa_poly_matrix_xt_t      xt;
    ldaa_poly_matrix_xt_t      at;
    ldaa_poly_matrix_ut_t      prod;
    ldaa_poly_t                ut;

    pAssert(ldaaKey != NULL);

    // DAA is only used for signing
    if (!IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
        ERROR_RETURN(TPM_RC_NO_RESULT);

    // TODO: Pass rand state to the sample_z function
    // Private key generation
    ldaa_poly_matrix_sample_z_xt(&xt);

    // Public Key generation
    CryptLDaaDeserializeIssuerAT(&at,
            &publicArea->parameters.ldaaDetail.issuer_at);

    // Set prod coefficients to zero
    for (size_t i = 0; i < LDAA_N; i++) {
        prod.coeffs[0].coeffs[i] = 0;
    }
    ldaa_poly_matrix_product(&prod, &at, &xt);
    MemoryCopy(&ut.coeffs, &prod.coeffs[0].coeffs, LDAA_N);

    // Serialization is simply splitting each coefficient into 4 bytes and
    // inserting into the buffer.
    CryptLDaaSerializePublicKey(&publicArea->unique.ldaa, &ut);
    CryptLDaaSerializeSecretKey(&sensitive->sensitive.ldaa, &xt);

    retVal = TPM_RC_SUCCESS;
Exit:
    return retVal;
}

