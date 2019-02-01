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

static void CryptLDaaDeserializePublicKey(
        // OUT: The public key in polynomial form
        ldaa_poly_t *public_key,
        // IN: serialized secret key
        TPM2B_LDAA_PUBLIC_KEY *ut
        ) {
    for (size_t i = 0; i < LDAA_N; i++) {
        public_key->coeffs[i] = Bytes2Coeff((BYTE *)&ut->t.buffer+(i*4));
    }
}

static void CryptLDaaDeserializeSecretKey(
        // OUT: The secret key in matrix polynomial form
        ldaa_poly_matrix_xt_t *secret_key,
        // IN: serialized secret key
        TPM2B_LDAA_SECRET_KEY *xt
        ) {
    // Loop polynomial matrix (Mx1)
    for (size_t i = 0; i < LDAA_M; i++) {
        // Loop coefficients of each polynomial
        for (size_t j = 0; j < LDAA_N; j++) {
            secret_key->coeffs[i].coeffs[j] =
                Bytes2Coeff((BYTE*)&xt->t.buffer+((i*LDAA_N+j)*4));
        }
    }
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

LIB_EXPORT TPM_RC
CryptLDaaJoin(
        // OUT: returned public Key
        TPM2B_LDAA_PUBLIC_KEY *public_key_serial,
        // OUT: return link token
        TPM2B_LDAA_NYM *nym_serial,
        // IN: public area to fetch the public key
        TPMT_PUBLIC *publicArea,
        // IN: Issuer basename
        TPM2B_LDAA_BASENAME_ISSUER   *bsn_I,
        // IN: secret area to fetch the secret key
        TPMT_SENSITIVE *sensitive
        ) {
    ldaa_poly_t            ut;
    ldaa_poly_t            pe;
    ldaa_poly_t            nym;
    ldaa_poly_matrix_xt_t  xt;
    ldaa_poly_t            pbsn;
    HASH_STATE             hash_state;
    BYTE                   digest[SHA256_BLOCK_SIZE];

    /* Deserialize keys */
    CryptLDaaDeserializePublicKey(&ut, &publicArea->unique.ldaa);
    CryptLDaaDeserializeSecretKey(&xt, &sensitive->sensitive.ldaa);

    /* ********************************************************************* */
    /* Token Link Calculation                                                */
    /* vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv */
    CryptHashStart(&hash_state, ALG_SHA256_VALUE);
    CryptDigestUpdate(&hash_state, bsn_I->t.size, bsn_I->t.buffer);
    CryptHashEnd(&hash_state, SHA256_BLOCK_SIZE, digest);
    ldaa_poly_from_hash(&pbsn, digest);

    ldaa_poly_sample_z(&pe);

    ldaa_poly_mul(&nym, &xt.coeffs[0], &pbsn);
    ldaa_poly_add(&nym, &nym, &pe);
    /* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */
    /* Token Link Calculation                                                */
    /* ********************************************************************* */

    /* TODO: Need to implement proof of signature of the nonce to */
    /* send to the issuer (pi)                                    */

    // Return already serialized Public Key
    MemoryCopy2B(&public_key_serial->b,
            &publicArea->unique.ldaa.b, publicArea->unique.ldaa.t.size);
    // Serialize Token link
    CryptLDaaSerializePublicKey(nym_serial, &nym);

    return TPM_RC_SUCCESS;
}

LIB_EXPORT TPM_RC
CryptLDaaClearProtocolState(void) {
    gr.ldaa_sid = 0;
    gr.ldaa_commitCounter = 0;
    return TPM_RC_SUCCESS;
}

LIB_EXPORT TPM_RC
CryptLDaaCommit(void) {
    gr.ldaa_commitCounter++;
    return TPM_RC_SUCCESS;
}
