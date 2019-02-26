#include "Tpm.h"
#include "CryptLDaa_fp.h"
#include "ldaa-params.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-matrix-ntt.h"
#include "ldaa-polynomial.h"
#include "ldaa-sign-state.h"
#include "ldaa-commitment.h"

#define RES0 0
#define RES1 1
#define RES2 2

// TODO: All of these variables don't fit in the stack. Better yet, the
// largest one doesn't fit the stack. This is a temporary solution.
static ldaa_commitment1_t               commited1;      // 102.4KB + 65KB
static ldaa_commitment2_t               commited2;      // 39.5MB + 65KB
static ldaa_commitment3_t               commited3;      // 39.5MB + 65KB
static ldaa_poly_matrix_ntt_B_t         issuer_b_ntt_1; // 25.6KB
static ldaa_poly_matrix_ntt_B2_t        issuer_b_ntt_2; // 10MB
static ldaa_poly_matrix_ntt_B3_t        issuer_b_ntt_3; // 10MB

BOOL CryptLDaaInit(void) {
    return TRUE;
}

BOOL CryptLDaaStartup(void) {
    return TRUE;
}

/* Serialize coefficient to Big Endian */
static inline void Coeff2Bytes(BYTE *out, UINT32 in) {
    for (size_t i = 0; i < 4; i++) {
        out[i] = (BYTE) (0xff & (in >> (24 - i * 8)));
    }
}

/* Deserialize bytes in Big Endian to coefficients */
static inline UINT32 Bytes2Coeff(BYTE *in) {
    UINT32 out = 0;

    for (size_t i = 0; i < 4; i++) {
        out |= ((UINT32) in[i]) << (24 - i * 8);
    }

    return out;
}

static void CryptLDaaSerializeSignGroup(
        // OUT: The serialized sign state
        TPM2B_LDAA_SIGN_GROUP *sign_group_serial,
        // IN: sign group
        TPMU_LDAA_SIGN_GROUP  *sign_group,
        // IN: type of sign group
        UINT8                 *sign_state_type
        ) {

    switch (*sign_state_type) {
        case RES0:
            ///////////////////////////
            // Serialize phi_x
            ///////////////////////////
            for (size_t i = 0; i < LDAA_M * LDAA_LOG_BETA; i++) {
                for (size_t j = 0; j < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; j++) {
                    Coeff2Bytes((BYTE *)&sign_group_serial->t.buffer+((i * LDAA_N + j)*4),
                            sign_group->res_1.phi_x[i].coeffs[j]);
                }
            }
            ///////////////////////////
            // Serialize varphi_e
            ///////////////////////////
            for (size_t i = 0; i < LDAA_LOG_BETA; i++) {
                for (size_t j = 0; j < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; j++) {
                    Coeff2Bytes((BYTE *)&sign_group_serial->t.buffer+((i * LDAA_N + j)*4),
                            sign_group->res_1.varphi_e[i].coeffs[j]);
                }
            }
            ///////////////////////////
            // Serialize varphi_r_e
            ///////////////////////////
            for (size_t i = 0; i < LDAA_LOG_BETA; i++) {
                for (size_t j = 0; j < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; j++) {
                    Coeff2Bytes((BYTE *)&sign_group_serial->t.buffer+((i * LDAA_N + j)*4),
                            sign_group->res_1.varphi_r_e[i].coeffs[j]);
                }
            }
            ///////////////////////////
            // Serialize phi_r
            ///////////////////////////
            for (size_t i = 0; i < LDAA_M * LDAA_LOG_BETA; i++) {
                for (size_t j = 0; j < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; j++) {
                    Coeff2Bytes((BYTE *)&sign_group_serial->t.buffer+((i * LDAA_N + j)*4),
                            sign_group->res_1.phi_r[i].coeffs[j]);
                }
            }
            break;
        case RES1:
            ///////////////////////////
            // Serialize phi
            ///////////////////////////
            for (size_t i = 0; i < LDAA_LOG_BETA; i++) {
                for (size_t j = 0; j < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; j++) {
                    Coeff2Bytes((BYTE *)&sign_group_serial->t.buffer+((i * LDAA_N + j)*4),
                            sign_group->res_2.phi[i].v[j]);
                }
            }
            ///////////////////////////
            // Serialize varphi
            ///////////////////////////
            for (size_t i = 0; i < LDAA_LOG_BETA; i++) {
                for (size_t j = 0; j < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; j++) {
                    Coeff2Bytes((BYTE *)&sign_group_serial->t.buffer+((i * LDAA_N + j)*4),
                            sign_group->res_2.varphi[i].v[j]);
                }
            }
            ///////////////////////////
            // Serialize v_e
            ///////////////////////////
            for (size_t i = 0; i < LDAA_LOG_BETA; i++) {
                for (size_t j = 0; j < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; j++) {
                    Coeff2Bytes((BYTE *)&sign_group_serial->t.buffer+((i * LDAA_N + j)*4),
                            sign_group->res_2.v_e[i].coeffs[j]);
                }
            }
            ///////////////////////////
            // Serialize v
            ///////////////////////////
            for (size_t i = 0; i < LDAA_M * LDAA_LOG_BETA; i++) {
                for (size_t j = 0; j < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; j++) {
                    Coeff2Bytes((BYTE *)&sign_group_serial->t.buffer+((i * LDAA_N + j)*4),
                            sign_group->res_2.v[i].coeffs[j]);
                }
            }
            break;
        case RES2:
            ///////////////////////////
            // Serialize phi
            ///////////////////////////
            for (size_t i = 0; i < LDAA_LOG_BETA; i++) {
                for (size_t j = 0; j < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; j++) {
                    Coeff2Bytes((BYTE *)&sign_group_serial->t.buffer+((i * LDAA_N + j)*4),
                            sign_group->res_3.phi[i].v[j]);
                }
            }
            ///////////////////////////
            // Serialize varphi
            ///////////////////////////
            for (size_t i = 0; i < LDAA_LOG_BETA; i++) {
                for (size_t j = 0; j < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; j++) {
                    Coeff2Bytes((BYTE *)&sign_group_serial->t.buffer+((i * LDAA_N + j)*4),
                            sign_group->res_3.varphi[i].v[j]);
                }
            }
            ///////////////////////////
            // Serialize r_e
            ///////////////////////////
            for (size_t i = 0; i < LDAA_LOG_BETA; i++) {
                for (size_t j = 0; j < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; j++) {
                    Coeff2Bytes((BYTE *)&sign_group_serial->t.buffer+((i * LDAA_N + j)*4),
                            sign_group->res_3.r_e[i].coeffs[j]);
                }
            }
            ///////////////////////////
            // Serialize r
            ///////////////////////////
            for (size_t i = 0; i < LDAA_M * LDAA_LOG_BETA; i++) {
                for (size_t j = 0; j < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; j++) {
                    Coeff2Bytes((BYTE *)&sign_group_serial->t.buffer+((i * LDAA_N + j)*4),
                            sign_group->res_3.r[i].coeffs[j]);
                }
            }
            break;
        default:
            return;
    }
}

static void CryptLDaaSerializeSignState(
        // OUT: The serialized sign state
        TPM2B_LDAA_SIGN_STATE *R_serial,
        // In: sign state
        ldaa_poly_matrix_R_t *R
        ) {
    // Loop polynomial matrix
    for (size_t i = 0; i < LDAA_K_COMM; i++) {
        // Loop coefficients of each polynomial
        for (size_t j = 0; j < LDAA_N; j++) {
            Coeff2Bytes((BYTE *)&R_serial->t.buffer+((i * LDAA_N + j)*4),
                    R->coeffs[i].coeffs[j]);
        }
    }
}

static void CryptLDaaDeserializeSignState(
        // OUT: deserialized sign state
        ldaa_poly_matrix_R_t *R,
        // IN: The serialized sign state
        TPM2B_LDAA_SIGN_STATE *R_serial
        ) {
    // Loop polynomial matrix
    for (size_t i = 0; i < LDAA_K_COMM; i++) {
        // Loop coefficients of each polynomial
        for (size_t j = 0; j < LDAA_N; j++) {
           R->coeffs[i].coeffs[j] =
               Bytes2Coeff((BYTE*) &R_serial->t.buffer+((i*LDAA_N+j)*4));
        }
    }
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
           b_ntt->coeffs[i * LDAA_K_COMM + j] =
               Bytes2Coeff((BYTE*) &issuer_bntt->t.buffer+((i*LDAA_K_COMM+j)*4));
        }
    }
}

static void CryptLDaaDeserializeIssuerBNTT2(
        // OUT: Issuer NTT B matrix
        ldaa_poly_matrix_ntt_B2_t *b_ntt,
        // IN: The public area parameter which contains the serialized
        // NTT matrix of B from the issuer
        TPM2B_LDAA_ISSUER_BNTT *issuer_bntt) {
    // Loop polynomial matrix
    // (4 + 4 * (2 * (1 << LDAA_LOG_W) - 1) * LDAA_LOG_BETA) x LDAA_K_COMM
    // Loop rows
    for (size_t i = 0; i < LDAA_COMMIT2_LENGTH; i++) {
        // Loop columns
        for (size_t j = 0; j < LDAA_K_COMM; j++) {
           b_ntt->coeffs[i * LDAA_K_COMM + j] =
               Bytes2Coeff((BYTE*) &issuer_bntt->t.buffer+((i*LDAA_K_COMM+j)*4));
        }
    }
}

static void CryptLDaaSerializeCommit1(
        // OUT: serialized commit
        TPM2B_LDAA_COMMIT *commit_serial,
        // IN: The public key in polynomial form
        ldaa_poly_matrix_commit1_t *commit
        ) {
    for (size_t i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        for (size_t j = 0; j < LDAA_N; j++) {
            Coeff2Bytes((BYTE *)&commit_serial->t.buffer+((i * LDAA_N + j)*4),
                    commit->coeffs[i].coeffs[j]);
        }
    }

    commit_serial->t.size = LDAA_C1_LENGTH;
}

static void CryptLDaaSerializeCommit2(
        // OUT: serialized commit
        TPM2B_LDAA_COMMIT *commit_serial,
        // IN: The public key in polynomial form
        ldaa_poly_matrix_commit2_t *commit
        ) {
    for (size_t i = 0; i < LDAA_COMMIT2_LENGTH; i++) {
        for (size_t j = 0; j < LDAA_N; j++) {
            Coeff2Bytes((BYTE *)&commit_serial->t.buffer+((i * LDAA_N + j)*4),
                    commit->coeffs[i].coeffs[j]);
        }
    }

    commit_serial->t.size = LDAA_C2_LENGTH;
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

    // Serialization is simply splitting each coefficient into 4 bytes and
    // inserting into the buffer.
    CryptLDaaSerializePublicKey(&publicArea->unique.ldaa, &prod.coeffs[0]);
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
    gr.ldaa_commit_sign_state = 0;
    return TPM_RC_SUCCESS;
}

LIB_EXPORT TPM_RC
CryptLDaaCommit(void) {
    gr.ldaa_commitCounter++;
    return TPM_RC_SUCCESS;
}

LIB_EXPORT TPM_RC
CryptLDaaCommitTokenLink(
        // OUT: Serialized token link
        TPM2B_LDAA_NYM *nym_serial,
        // OUT: Serialized polynomial of the hash of the basename
        TPM2B_LDAA_PBSN *pbsn_serial,
        // OUT: Serialized error polynomial
        TPM2B_LDAA_PE   *pe_serial,
        // IN: Serialized private key
        TPMT_SENSITIVE *sensitive,
        // IN: Basename to be used in the commit
        TPM2B_LDAA_BASENAME *bsn
        ) {
    ldaa_poly_t           pe;
    ldaa_poly_t           nym;
    ldaa_poly_matrix_xt_t xt;
    ldaa_poly_t           pbsn;
    HASH_STATE            hash_state;
    BYTE                  digest[SHA256_BLOCK_SIZE];

    CryptLDaaDeserializeSecretKey(&xt, &sensitive->sensitive.ldaa);

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

    // Serialize All outputs
    CryptLDaaSerializePublicKey(nym_serial, &nym);
    CryptLDaaSerializePublicKey(pe_serial, &pe);
    CryptLDaaSerializePublicKey(pbsn_serial, &pbsn);

    return TPM_RC_SUCCESS;
}

LIB_EXPORT TPM_RC
CryptLDaaSignCommit(
        // OUT: Result of commit
        TPM2B_LDAA_COMMIT *c_out,
        // IN: Serialized private key
        TPMT_SENSITIVE    *sensitive,
        // IN: commit selection
        BYTE              *commit_sel,
        // IN: sign state selection
        BYTE              *sign_state_sel,
        // IN: Serialized polynomial of the hash of the basename
        TPM2B_LDAA_PBSN   *pbsn_serial,
        // IN: Serialized error polynomial
        TPM2B_LDAA_PE     *pe_serial,
        // IN: Serialized key
        TPM2B_LDAA_ISSUER_ATNTT *issuer_atntt_serial,
        // IN: Serialized key
        TPM2B_LDAA_ISSUER_BNTT  *issuer_bntt_serial,
        // IN: Basename to be used in the commit
        TPM2B_LDAA_BASENAME *bsn
        ) {
    ldaa_poly_t                      pe;   // 1KB
    ldaa_poly_t                      pbsn; // 1KB
    ldaa_poly_matrix_xt_t            xt;   // 24.5KB
    ldaa_poly_matrix_ntt_issuer_at_t issuer_at_ntt;  // 24.5KB

    /* Deserialize keys */
    CryptLDaaDeserializeSecretKey(&xt, &sensitive->sensitive.ldaa);
    CryptLDaaDeserializePublicKey(&pbsn, pbsn_serial);
    CryptLDaaDeserializePublicKey(&pe, pe_serial);

    switch(*commit_sel) {
        case 1:
            CryptLDaaDeserializeIssuerATNTT(&issuer_at_ntt, issuer_atntt_serial);
            CryptLDaaDeserializeIssuerBNTT1(&issuer_b_ntt_1, issuer_bntt_serial);
            break;
        case 2:
            CryptLDaaDeserializeIssuerBNTT2(&issuer_b_ntt_2, issuer_bntt_serial);
            break;
        case 3:
            CryptLDaaDeserializeIssuerBNTT2(&issuer_b_ntt_3, issuer_bntt_serial);
            break;
        default:
            // This should never happen. The caller should verify the validity
            // of the commit_sel variable.
            return TPM_RC_FAILURE;
    }

    /* ********************************************************************* */
    /*                          Theta T calculations                         */
    /* vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv */
    ldaa_sign_state_i_t *ssi = &gr.sign_states_tpm[*sign_state_sel];
    if (((gr.ldaa_commit_sign_state >> (*sign_state_sel)) & 0x0001) == 0) {
        ldaa_fill_sign_state_tpm(ssi, &xt, &pe);
        gr.ldaa_commit_sign_state |= 1 << (*sign_state_sel);
    }

    switch (*commit_sel) {
        case 1:
            ldaa_tpm_comm_1(ssi, &pbsn, &issuer_at_ntt, &commited1, &issuer_b_ntt_1);
            CryptLDaaSerializeCommit1(c_out, &commited1.C);
            break;
        case 2:
            ldaa_tpm_comm_2(ssi, &commited2, &issuer_b_ntt_2);
            CryptLDaaSerializeCommit2(c_out, &commited2.C);
            break;
        case 3:
            ldaa_tpm_comm_3(ssi, &commited3, &issuer_b_ntt_3);
            CryptLDaaSerializeCommit2(c_out, &commited3.C);
            break;
        default:
            // This should never happen. The caller should verify the validity
            // of the commit_sel variable.
            return TPM_RC_FAILURE;
    }
    /* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */
    /*                           Theta T calculations                        */
    /* ********************************************************************* */

    return TPM_RC_SUCCESS;
}

LIB_EXPORT TPM_RC
CryptLDaaSignProof(
        // OUT: sign state R1
        TPM2B_LDAA_SIGN_STATE   *R1_out_serial,
        // OUT: sign state R2
        TPM2B_LDAA_SIGN_STATE   *R2_out_serial,
        // OUT: Sign Group
        TPM2B_LDAA_SIGN_GROUP   *sign_group_serial,
        // IN:  sign state R1
        TPM2B_LDAA_SIGN_STATE   *R1_in_serial,
        // IN:  sign state R2
        TPM2B_LDAA_SIGN_STATE   *R2_in_serial,
        // IN: sign state selection
        BYTE                    *sign_state_sel,
        // IN: Sign State type
        BYTE                    *sign_state_type
        ) {
    ldaa_poly_matrix_R_t   R1, R2;     // 64kB each
    TPMU_LDAA_SIGN_GROUP   sign_group; // 1.2MB
    size_t                 j, jj;

    /* Deserialize objects */
    CryptLDaaDeserializeSignState(&R1, R1_in_serial);
    CryptLDaaDeserializeSignState(&R2, R2_in_serial);

    ldaa_sign_state_i_t *ssi = &gr.sign_states_tpm[*sign_state_sel];

    switch (*sign_state_type) {
        case RES0:
            for (j = 0; j < LDAA_LOG_BETA; j++) {
                for (jj = 0; jj < LDAA_M; jj++) {
                    ldaa_integer_matrix_t phi_xij;
                    ldaa_integer_matrix_copy(&ssi->x[jj * LDAA_LOG_BETA + j], &phi_xij);
                    ldaa_integer_matrix_permute(&phi_xij, &ssi->phi[j]);

                    ldaa_integer_matrix_copy(&phi_xij,
                            &sign_group.res_1.phi_x[j * LDAA_M + jj]);
                }
            }

            for (j = 0; j < LDAA_LOG_BETA; j++) {
                ldaa_integer_matrix_t varphi_ej;
                ldaa_integer_matrix_copy(&ssi->e[j], &varphi_ej);
                ldaa_integer_matrix_permute(&varphi_ej, &ssi->varphi[j]);

                ldaa_integer_matrix_copy(&varphi_ej,
                        &sign_group.res_1.varphi_e[j]);
            }

            for (j = 0; j < LDAA_LOG_BETA; j++) {
                ldaa_integer_matrix_t varphi_rej;
                ldaa_integer_matrix_copy(&ssi->re[j], &varphi_rej);
                ldaa_integer_matrix_permute(&varphi_rej, &ssi->varphi[j]);

                ldaa_integer_matrix_copy(&varphi_rej,
                        &sign_group.res_1.varphi_r_e[j]);
            }

            for (j = 0; j < LDAA_LOG_BETA; j++) {
                for (jj = 0; jj < LDAA_M; jj++) {
                    ldaa_integer_matrix_t phi_rij;
                    ldaa_integer_matrix_copy(&ssi->r[jj * LDAA_LOG_BETA + j], &phi_rij);
                    ldaa_integer_matrix_permute(&phi_rij, &ssi->phi[j]);

                    ldaa_integer_matrix_copy(&phi_rij,
                            &sign_group.res_1.phi_r[j * LDAA_M + jj]);
                }
            }

            // R1 = R2 from Host
            // R2 = R3 from Host
            ldaa_poly_matrix_R_add(&R1, &R1, &ssi->R2);
            ldaa_poly_matrix_R_add(&R2, &R2, &ssi->R3);
            break;

        case RES1:
            for (j = 0; j < LDAA_LOG_BETA; j++) {
                ldaa_permutation_copy(&ssi->phi[j], &sign_group.res_2.phi[j]);
            }

            for (j = 0; j < LDAA_LOG_BETA; j++) {
                ldaa_permutation_copy(&ssi->varphi[j], &sign_group.res_2.varphi[j]);
            }

            for (j = 0; j < LDAA_LOG_BETA; j++) {
                ldaa_integer_matrix_copy(&ssi->ve[j], &sign_group.res_2.v_e[j]);
            }

            for (j = 0; j < LDAA_M * LDAA_LOG_BETA; j++) {
                ldaa_integer_matrix_copy(&ssi->v[j], &sign_group.res_2.v[j]);
            }

            // R1 = R1 from Host
            // R2 = R3 from Host
            ldaa_poly_matrix_R_add(&R1, &R1, &ssi->R1);
            ldaa_poly_matrix_R_add(&R2, &R2, &ssi->R3);
            break;

        case RES2:
            for (j = 0; j < LDAA_LOG_BETA; j++) {
                ldaa_permutation_copy(&ssi->phi[j], &sign_group.res_3.phi[j]);
            }

            for (j = 0; j < LDAA_LOG_BETA; j++) {
                ldaa_permutation_copy(&ssi->varphi[j], &sign_group.res_3.varphi[j]);
            }

            for (j = 0; j < LDAA_LOG_BETA; j++) {
                ldaa_integer_matrix_copy(&ssi->re[j], &sign_group.res_3.r_e[j]);
            }

            for (j = 0; j < LDAA_M * LDAA_LOG_BETA; j++) {
                ldaa_integer_matrix_copy(&ssi->r[j], &sign_group.res_3.r[j]);
            }

            // R1 = R1 from Host
            // R2 = R2 from Host
            ldaa_poly_matrix_R_add(&R1, &R1, &ssi->R1);
            ldaa_poly_matrix_R_add(&R2, &R2, &ssi->R2);
            break;

        default:
            return TPM_RC_FAILURE;
    }

    /* Serialize objects */
    CryptLDaaSerializeSignState(R1_out_serial, &R1);
    CryptLDaaSerializeSignState(R2_out_serial, &R2);
    CryptLDaaSerializeSignGroup(sign_group_serial, &sign_group,
            sign_state_type);

    return TPM_RC_SUCCESS;
}
