#include "Tpm.h"
#include "CryptLDaa_fp.h"
#include "ldaa-params.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-matrix-ntt.h"
#include "ldaa-polynomial.h"
#include "ldaa-sign-state.h"
#include "ldaa-commitment.h"

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

static void CryptLDaaDeserializeIssuerATNTT(
        // OUT: Issuer NTT A matrix
        ldaa_poly_matrix_ntt_issuer_at_t *at_ntt,
        // IN: The public area parameter which contains the serialized
        // NTT matrix of A from the issuer
        TPM2B_LDAA_ISSUER_ATNTT *issuer_atntt) {
    // Loop polynomial matrix (1xM)
    for (size_t i = 0; i < LDAA_M; i++) {
        // Loop coefficients of each polynomial
        for (size_t j = 0; j < LDAA_N; j++) {
           at_ntt->coeffs[i].coeffs[j] =
               Bytes2Coeff((BYTE*) &issuer_atntt->t.buffer+((i*LDAA_N+j)*4));
        }
    }
}


static void CryptLDaaDeserializeIssuerBNTT1(
        // OUT: Issuer NTT B matrix
        ldaa_poly_matrix_ntt_B_t *b_ntt,
        // IN: The public area parameter which contains the serialized
        // NTT matrix of B from the issuer
        TPM2B_LDAA_ISSUER_BNTT *issuer_bntt) {
    // Loop polynomial matrix
    // (4 + 4 * (2 * (1 << LDAA_LOG_W) - 1) * LDAA_LOG_BETA) x LDAA_K_COMM
    // Loop rows
    for (size_t i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        // Loop columns
        for (size_t j = 0; j < LDAA_K_COMM; j++) {
            // Loop coefficients of each polynomial
            for (size_t k = 0; k < LDAA_N; k++) {
               b_ntt->coeffs[i * LDAA_K_COMM + j].coeffs[k] =
                   Bytes2Coeff((BYTE*) &issuer_bntt->t.buffer+(((i*LDAA_K_COMM+j*LDAA_N)+k)*4));
            }
        }
    }
}

static void CryptLDaaDeserializeIssuerBNTT2(
        // OUT: Issuer NTT B matrix
        ldaa_poly_matrix_ntt_B2_t *b_ntt,
        // IN: The public area parameter which contains the serialized
        // NTT matrix of B from the issuer
        TPM2B_LDAA_ISSUER_BNTT2 *issuer_bntt) {
    // Loop polynomial matrix
    // (4 + 4 * (2 * (1 << LDAA_LOG_W) - 1) * LDAA_LOG_BETA) x LDAA_K_COMM
    // Loop rows
    for (size_t i = 0; i < LDAA_COMMIT2_LENGTH; i++) {
        // Loop columns
        for (size_t j = 0; j < LDAA_K_COMM; j++) {
            // Loop coefficients of each polynomial
            for (size_t k = 0; k < LDAA_N; k++) {
               b_ntt->coeffs[i * LDAA_K_COMM + j].coeffs[k] =
                   Bytes2Coeff((BYTE*) &issuer_bntt->t.buffer+(((i*LDAA_K_COMM+j*LDAA_N)+k)*4));
            }
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

    for (size_t i = 0; i < LDAA_N; i++) {
        nym.coeffs[i] = 0;
    }
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

LIB_EXPORT TPM_RC
CryptLDaaSignCommit(
        // OUT: Result of commit 1
        TPM2B_LDAA_C1 *c1_out,
        // OUT: Result of commit 2
        TPM2B_LDAA_C2 *c2_out,
        // OUT: Result of commit 3
        TPM2B_LDAA_C3 *c3_out,
        // IN: Serialized private key
        TPMT_SENSITIVE *sensitive,
        // IN: Serialized key
        TPM2B_LDAA_ISSUER_ATNTT *issuer_atntt_serial,
        // IN: Serialized key
        TPM2B_LDAA_ISSUER_BNTT  *issuer_bntt1_serial,
        // IN: Serialized key
        TPM2B_LDAA_ISSUER_BNTT2 *issuer_bntt2_serial,
        // IN: Serialized key
        TPM2B_LDAA_ISSUER_BNTT3 *issuer_bntt3_serial,
        // IN: Basename to be used in the commit
        TPM2B_LDAA_BASENAME *bsn
        ) {
    size_t i, j, k;
    ldaa_poly_t                      pe;
    ldaa_poly_t                      nym;
    ldaa_poly_matrix_xt_t            xt;
    ldaa_poly_t                      pbsn;
    HASH_STATE                       hash_state;
    BYTE                             digest[SHA256_BLOCK_SIZE];
    ldaa_poly_matrix_ntt_issuer_at_t issuer_at_ntt;
    ldaa_poly_matrix_ntt_B_t         issuer_b_ntt_1;
    ldaa_poly_matrix_ntt_B2_t        issuer_b_ntt_2;
    ldaa_poly_matrix_ntt_B3_t        issuer_b_ntt_3;
    /* TODO: sign state needs to be stored in the TPM. Find some way to do so
    without blowing up the memory */
    ldaa_sign_state_i_t              sign_states_tpm[LDAA_C];

    ldaa_poly_matrix_commit1_t       C1[LDAA_C];
    ldaa_poly_matrix_commit2_t       C2[LDAA_C];
    ldaa_poly_matrix_commit3_t       C3[LDAA_C];

    /* Deserialize keys */
    CryptLDaaDeserializeSecretKey(&xt, &sensitive->sensitive.ldaa);
    CryptLDaaDeserializeIssuerATNTT(&issuer_at_ntt, issuer_atntt_serial);
    CryptLDaaDeserializeIssuerBNTT1(&issuer_b_ntt_1, issuer_bntt1_serial);
    CryptLDaaDeserializeIssuerBNTT2(&issuer_b_ntt_2, issuer_bntt2_serial);
    CryptLDaaDeserializeIssuerBNTT2(&issuer_b_ntt_3, issuer_bntt3_serial);

    /* ********************************************************************* */
    /* Token Link Calculation                                                */
    /* vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv */
    CryptHashStart(&hash_state, ALG_SHA256_VALUE);
    CryptDigestUpdate(&hash_state, bsn->t.size, bsn->t.buffer);
    CryptHashEnd(&hash_state, SHA256_BLOCK_SIZE, digest);
    ldaa_poly_from_hash(&pbsn, digest);

    ldaa_poly_sample_z(&pe);

    for (size_t i = 0; i < LDAA_N; i++) {
        nym.coeffs[i] = 0;
    }
    ldaa_poly_mul(&nym, &xt.coeffs[0], &pbsn);
    ldaa_poly_add(&nym, &nym, &pe);
    /* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */
    /* Token Link Calculation                                                */
    /* ********************************************************************* */

    /* ********************************************************************* */
    /*                            Pi calculations                            */
    /* vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv */
    for (i = 0; i < LDAA_C; i++) {
        ldaa_sign_state_i_t *ssi = &sign_states_tpm[i];
        ldaa_commitment1_t commited1;
        ldaa_commitment2_t commited2;
        ldaa_commitment3_t commited3;

        ldaa_fill_sign_state_tpm(ssi, &xt, &pe);
        ldaa_tpm_comm_1(ssi, &pbsn, &issuer_at_ntt, &commited1, &issuer_b_ntt_1);
        ldaa_tpm_comm_2(ssi, &commited2, &issuer_b_ntt_2);
        ldaa_tpm_comm_3(ssi, &commited3, &issuer_b_ntt_3);

        ldaa_poly_matrix_commit1_t *c1 = &C1[i];
        ldaa_poly_matrix_commit2_t *c2 = &C2[i];
        ldaa_poly_matrix_commit2_t *c3 = &C3[i];
        for (j = 0; j < LDAA_COMMIT1_LENGTH; j++) {
            for (k = 0; k < LDAA_N; k++) {
                c1->coeffs[j].coeffs[k] = commited1.C.coeffs[j].coeffs[k];
            }
        }
        for (j = 0; j < LDAA_COMMIT2_LENGTH; j++) {
            for (k = 0; k < LDAA_N; k++) {
                c2->coeffs[j].coeffs[k] = commited2.C.coeffs[j].coeffs[k];
                c3->coeffs[j].coeffs[k] = commited3.C.coeffs[j].coeffs[k];
            }
        }
    }
    /* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */
    /*                            Pi calculations                            */
    /* ********************************************************************* */

    return TPM_RC_SUCCESS;
}
