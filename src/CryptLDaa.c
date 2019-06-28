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
#include "CryptLDaa_fp.h"
#include "ldaa-params.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-matrix-ntt.h"
#include "ldaa-polynomial.h"
#include "ldaa-sign-state.h"
#include "ldaa-commitment.h"

typedef union {
    ldaa_commitment1_t         commited1;      // 102.4KB + 65KB
    ldaa_commitment2_t         commited2;      // 80MB + 65KB
    ldaa_commitment3_t         commited3;      // 80MB + 65KB
} LDAA_LOCAL_COMMITS;

#define RES0 0
#define RES1 1
#define RES2 2

BOOL CryptLDaaInit(void) {
    return TRUE;
}

BOOL CryptLDaaStartup(void) {
    return TRUE;
}

BOOL CryptLDaaIsModeValid(
            // IN: the security mode
            TPM_LDAA_SECURITY_MODE  security
        ) {
    switch (security) {
        case TPM_LDAA_SECURITY_MODE_WEAK:
        case TPM_LDAA_SECURITY_MODE_MEDIUM:
        case TPM_LDAA_SECURITY_MODE_HIGH:
            return TRUE;
        default:
            return FALSE;
    }
}

typedef struct {
    uint64_t m;
    uint64_t n;
    uint64_t q;
    uint64_t s;
    uint64_t l;
    uint64_t c;
    uint64_t log_beta;
    uint64_t log_w;
    uint64_t k_comm;
    uint64_t alpha2;
    uint64_t commit1_len;
    uint64_t commit2_len;
} LDaaParams;

static LDaaParams generate_ldaa_params(BYTE security_mode) {
    LDaaParams params;

    switch (security_mode) {
        case TPM_LDAA_SECURITY_MODE_WEAK:
            params.m =           LDAA_WEAK_M;
            params.n =           LDAA_WEAK_N;
            params.q =           LDAA_WEAK_Q;
            params.s =           LDAA_WEAK_S;
            params.l =           LDAA_WEAK_L;
            params.c =           LDAA_WEAK_C;
            params.log_beta =    LDAA_WEAK_LOG_BETA;
            params.log_w =       LDAA_WEAK_LOG_W;
            params.k_comm =      LDAA_WEAK_K_COMM;
            params.alpha2 =      LDAA_WEAK_ALPHA2;
            params.commit1_len = LDAA_WEAK_COMMIT1_LENGTH;
            params.commit2_len = LDAA_WEAK_COMMIT2_LENGTH;
            break;
        case TPM_LDAA_SECURITY_MODE_MEDIUM:
            params.m =           LDAA_MEDIUM_M;
            params.n =           LDAA_MEDIUM_N;
            params.q =           LDAA_MEDIUM_Q;
            params.s =           LDAA_MEDIUM_S;
            params.l =           LDAA_MEDIUM_L;
            params.c =           LDAA_MEDIUM_C;
            params.log_beta =    LDAA_MEDIUM_LOG_BETA;
            params.log_w =       LDAA_MEDIUM_LOG_W;
            params.k_comm =      LDAA_MEDIUM_K_COMM;
            params.alpha2 =      LDAA_MEDIUM_ALPHA2;
            params.commit1_len = LDAA_MEDIUM_COMMIT1_LENGTH;
            params.commit2_len = LDAA_MEDIUM_COMMIT2_LENGTH;
            break;
        case TPM_LDAA_SECURITY_MODE_HIGH:
            params.m =           LDAA_HIGH_M;
            params.n =           LDAA_HIGH_N;
            params.q =           LDAA_HIGH_Q;
            params.s =           LDAA_HIGH_S;
            params.l =           LDAA_HIGH_L;
            params.c =           LDAA_HIGH_C;
            params.log_beta =    LDAA_HIGH_LOG_BETA;
            params.log_w =       LDAA_HIGH_LOG_W;
            params.k_comm =      LDAA_HIGH_K_COMM;
            params.alpha2 =      LDAA_HIGH_ALPHA2;
            params.commit1_len = LDAA_HIGH_COMMIT1_LENGTH;
            params.commit2_len = LDAA_HIGH_COMMIT2_LENGTH;
            break;
        default:
            break;
    }

    return params;
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
        UINT8                 *sign_state_type,
        LDaaParams params
        ) {

    switch (*sign_state_type) {
        case RES0:
            ///////////////////////////
            // Serialize phi_x
            ///////////////////////////
            for (size_t i = 0; i < params.m * params.log_beta; i++) {
                for (size_t j = 0; j < (2*(1<<params.log_w)-1)*params.n; j++) {
                    Coeff2Bytes(
                            (BYTE *)&sign_group_serial->t.buffer +
                            ((i * (2*(1<<params.log_w)-1)*params.n + j)*4),
                            sign_group->res_1.phi_x[i].coeffs[j]);
                }
            }
            sign_group_serial->t.size = params.m * params.log_beta * (2*(1<<params.log_w)-1)*params.n * 4;
            ///////////////////////////
            // Serialize varphi_e
            ///////////////////////////
            for (size_t i = 0; i < params.log_beta; i++) {
                for (size_t j = 0; j < (2*(1<<params.log_w)-1)*params.n; j++) {
                    Coeff2Bytes(
                            (BYTE *)&sign_group_serial->t.buffer +
                            sign_group_serial->t.size +
                            ((i * (2*(1<<params.log_w)-1)*params.n + j)*4),
                            sign_group->res_1.varphi_e[i].coeffs[j]);
                }
            }
            sign_group_serial->t.size += params.log_beta * (2*(1<<params.log_w)-1)*params.n * 4;
            ///////////////////////////
            // Serialize varphi_r_e
            ///////////////////////////
            for (size_t i = 0; i < params.log_beta; i++) {
                for (size_t j = 0; j < (2*(1<<params.log_w)-1)*params.n; j++) {
                    Coeff2Bytes(
                            (BYTE *)&sign_group_serial->t.buffer +
                            sign_group_serial->t.size +
                            ((i * (2*(1<<params.log_w)-1)*params.n + j)*4),
                            sign_group->res_1.varphi_r_e[i].coeffs[j]);
                }
            }
            sign_group_serial->t.size += params.log_beta * (2*(1<<params.log_w)-1)*params.n * 4;
            ///////////////////////////
            // Serialize phi_r
            ///////////////////////////
            for (size_t i = 0; i < params.m * params.log_beta; i++) {
                for (size_t j = 0; j < (2*(1<<params.log_w)-1)*params.n; j++) {
                    Coeff2Bytes(
                            (BYTE *)&sign_group_serial->t.buffer +
                            sign_group_serial->t.size +
                            ((i * (2*(1<<params.log_w)-1)*params.n + j)*4),
                            sign_group->res_1.phi_r[i].coeffs[j]);
                }
            }
            sign_group_serial->t.size += params.m * params.log_beta * (2*(1<<params.log_w)-1)*params.n * 4;
            break;
        case RES1:
            ///////////////////////////
            // Serialize phi
            ///////////////////////////
            for (size_t i = 0; i < params.log_beta; i++) {
                for (size_t j = 0; j < (2*(1<<params.log_w)-1)*params.n; j++) {
                    Coeff2Bytes(
                            (BYTE *)&sign_group_serial->t.buffer +
                            ((i * (2*(1<<params.log_w)-1)*params.n + j)*4),
                            sign_group->res_2.phi[i].v[j]);
                }
            }
            sign_group_serial->t.size = params.log_beta * (2*(1<<params.log_w)-1)*params.n * 4;
            ///////////////////////////
            // Serialize varphi
            ///////////////////////////
            for (size_t i = 0; i < params.log_beta; i++) {
                for (size_t j = 0; j < (2*(1<<params.log_w)-1)*params.n; j++) {
                    Coeff2Bytes(
                            (BYTE *)&sign_group_serial->t.buffer +
                            sign_group_serial->t.size +
                            ((i * (2*(1<<params.log_w)-1)*params.n + j)*4),
                            sign_group->res_2.varphi[i].v[j]);
                }
            }
            sign_group_serial->t.size += params.log_beta * (2*(1<<params.log_w)-1)*params.n * 4;
            ///////////////////////////
            // Serialize v_e
            ///////////////////////////
            for (size_t i = 0; i < params.log_beta; i++) {
                for (size_t j = 0; j < (2*(1<<params.log_w)-1)*params.n; j++) {
                    Coeff2Bytes(
                            (BYTE *)&sign_group_serial->t.buffer +
                            sign_group_serial->t.size +
                            ((i * (2*(1<<params.log_w)-1)*params.n + j)*4),
                            sign_group->res_2.v_e[i].coeffs[j]);
                }
            }
            sign_group_serial->t.size += params.log_beta * (2*(1<<params.log_w)-1)*params.n * 4;
            ///////////////////////////
            // Serialize v
            ///////////////////////////
            for (size_t i = 0; i < params.m * params.log_beta; i++) {
                for (size_t j = 0; j < (2*(1<<params.log_w)-1)*params.n; j++) {
                    Coeff2Bytes(
                            (BYTE *)&sign_group_serial->t.buffer +
                            sign_group_serial->t.size +
                            ((i * (2*(1<<params.log_w)-1)*params.n + j)*4),
                            sign_group->res_2.v[i].coeffs[j]);
                }
            }
            sign_group_serial->t.size += params.m * params.log_beta * (2*(1<<params.log_w)-1)*params.n * 4;
            break;
        case RES2:
            ///////////////////////////
            // Serialize phi
            ///////////////////////////
            for (size_t i = 0; i < params.log_beta; i++) {
                for (size_t j = 0; j < (2*(1<<params.log_w)-1)*params.n; j++) {
                    Coeff2Bytes(
                            (BYTE *)&sign_group_serial->t.buffer +
                            ((i * (2*(1<<params.log_w)-1)*params.n + j)*4),
                            sign_group->res_3.phi[i].v[j]);
                }
            }
            sign_group_serial->t.size = params.log_beta * (2*(1<<params.log_w)-1)*params.n * 4;
            ///////////////////////////
            // Serialize varphi
            ///////////////////////////
            for (size_t i = 0; i < params.log_beta; i++) {
                for (size_t j = 0; j < (2*(1<<params.log_w)-1)*params.n; j++) {
                    Coeff2Bytes(
                            (BYTE *)&sign_group_serial->t.buffer+
                            sign_group_serial->t.size +
                            ((i * (2*(1<<params.log_w)-1)*params.n + j)*4),
                            sign_group->res_3.varphi[i].v[j]);
                }
            }
            sign_group_serial->t.size += params.log_beta * (2*(1<<params.log_w)-1)*params.n * 4;
            ///////////////////////////
            // Serialize r_e
            ///////////////////////////
            for (size_t i = 0; i < params.log_beta; i++) {
                for (size_t j = 0; j < (2*(1<<params.log_w)-1)*params.n; j++) {
                    Coeff2Bytes(
                            (BYTE *)&sign_group_serial->t.buffer+
                            sign_group_serial->t.size +
                            ((i * (2*(1<<params.log_w)-1)*params.n + j)*4),
                            sign_group->res_3.r_e[i].coeffs[j]);
                }
            }
            sign_group_serial->t.size += params.log_beta * (2*(1<<params.log_w)-1)*params.n * 4;
            ///////////////////////////
            // Serialize r
            ///////////////////////////
            for (size_t i = 0; i < params.m * params.log_beta; i++) {
                for (size_t j = 0; j < (2*(1<<params.log_w)-1)*params.n; j++) {
                    Coeff2Bytes(
                            (BYTE *)&sign_group_serial->t.buffer +
                            sign_group_serial->t.size +
                            ((i * (2*(1<<params.log_w)-1)*params.n + j)*4),
                            sign_group->res_3.r[i].coeffs[j]);
                }
            }
            sign_group_serial->t.size += params.m * params.log_beta * (2*(1<<params.log_w)-1)*params.n * 4;
            break;
        default:
            return;
    }
}

static void CryptLDaaSerializeSignState(
        // OUT: The serialized sign state
        TPM2B_LDAA_SIGN_STATE *R_serial,
        // In: sign state
        ldaa_poly_matrix_R_t *R,
        uint64_t k_comm,
        uint64_t n
        ) {
    // Loop polynomial matrix
    for (size_t i = 0; i < k_comm; i++) {
        // Loop coefficients of each polynomial
        for (size_t j = 0; j < n; j++) {
            Coeff2Bytes((BYTE *)&R_serial->t.buffer+((i * n + j)*4),
                    R->coeffs[i].coeffs[j]);
        }
    }

    R_serial->t.size = k_comm * n * 4;
}

static void CryptLDaaDeserializeSignState(
        // OUT: deserialized sign state
        ldaa_poly_matrix_R_t *R,
        // IN: The serialized sign state
        TPM2B_LDAA_SIGN_STATE *R_serial,
        uint64_t k_comm,
        uint64_t n
        ) {
    // Loop polynomial matrix
    for (size_t i = 0; i < k_comm; i++) {
        // Loop coefficients of each polynomial
        for (size_t j = 0; j < n; j++) {
           R->coeffs[i].coeffs[j] =
               Bytes2Coeff((BYTE*) &R_serial->t.buffer+((i*n+j)*4));
        }
    }
}

static void CryptLDaaDeserializeIssuerAT(
        // OUT: at polynomial matrix matrix
        ldaa_poly_matrix_xt_t *at,
        // IN: The public area parameter which contains the serialized at from
        // the issuer
        TPM2B_LDAA_ISSUER_AT *issuer_at,
        uint64_t m,
        uint64_t n
        ) {
    // Loop polynomial matrix (Mx1)
    for (size_t i = 0; i < m; i++) {
        // Loop coefficients of each polynomial
        for (size_t j = 0; j < n; j++) {
           at->coeffs[i].coeffs[j] =
               Bytes2Coeff((BYTE*) &issuer_at->t.buffer+((i*n+j)*4));
        }
    }
}

static void CryptLDaaDeserializeIssuerATNTT(
        // OUT: Issuer NTT A matrix
        ldaa_poly_matrix_ntt_issuer_at_t *at_ntt,
        // IN: The public area parameter which contains the serialized
        // NTT matrix of A from the issuer
        TPM2B_LDAA_ISSUER_ATNTT *issuer_atntt,
        uint64_t m,
        uint64_t n) {
    // Loop polynomial matrix (1xM)
    for (size_t i = 0; i < m; i++) {
        // Loop coefficients of each polynomial
        for (size_t j = 0; j < n; j++) {
           at_ntt->coeffs[i].coeffs[j] =
               Bytes2Coeff((BYTE*) &issuer_atntt->t.buffer+((i*n+j)*4));
        }
    }
}

static void CryptLDaaSerializeCommit1(
        // OUT: serialized commit
        TPM2B_LDAA_COMMIT *commit_serial,
        // IN: The public key in polynomial form
        ldaa_poly_matrix_commit1_t *commit,
        uint64_t commit1_len,
        uint64_t n
        ) {
    for (size_t i = 0; i < commit1_len; i++) {
        for (size_t j = 0; j < n; j++) {
            Coeff2Bytes((BYTE *)&commit_serial->t.buffer+((i * n + j)*4),
                    commit->coeffs[i].coeffs[j]);
        }
    }

    commit_serial->t.size = commit1_len * n * 4;
}

static void CryptLDaaSerializeCommit2(
        // OUT: serialized commit
        TPM2B_LDAA_COMMIT *commit_serial,
        // IN: The public key in polynomial form
        ldaa_poly_matrix_commit2_t *commit,
        uint64_t commit2_len,
        uint64_t n
        ) {
    for (size_t i = 0; i < commit2_len; i++) {
        for (size_t j = 0; j < n; j++) {
            Coeff2Bytes((BYTE *)&commit_serial->t.buffer+((i * n + j)*4),
                    commit->coeffs[i].coeffs[j]);
        }
    }

    commit_serial->t.size = commit2_len * n * 4;
}

static void CryptLDaaSerializePublicKey(
        // OUT: serialized secret key
        TPM2B_LDAA_PUBLIC_KEY *ut,
        // IN: The public key in polynomial form
        ldaa_poly_t *public_key,
        uint64_t n
        ) {
    for (size_t i = 0; i < n; i++) {
        Coeff2Bytes((BYTE *)&ut->t.buffer+(i*4), public_key->coeffs[i]);
    }

    ut->t.size = n * 4;
}

static void CryptLDaaSerializeSecretKey(
        // OUT: serialized secret key
        TPM2B_LDAA_SECRET_KEY *xt,
        // IN: The secret key in matrix polynomial form
        ldaa_poly_matrix_xt_t *secret_key,
        uint64_t m,
        uint64_t n
        ) {
    // Loop polynomial matrix (Mx1)
    for (size_t i = 0; i < m; i++) {
        // Loop coefficients of each polynomial
        for (size_t j = 0; j < n; j++) {
            Coeff2Bytes((BYTE*)&xt->t.buffer+((i*n+j)*4),
                    secret_key->coeffs[i].coeffs[j]);
        }
    }

    xt->t.size = m * n * 4;
}

static void CryptLDaaDeserializePublicKey(
        // OUT: The public key in polynomial form
        ldaa_poly_t *public_key,
        // IN: serialized secret key
        TPM2B_LDAA_PUBLIC_KEY *ut,
        uint64_t n
        ) {
    for (size_t i = 0; i < n; i++) {
        public_key->coeffs[i] = Bytes2Coeff((BYTE *)&ut->t.buffer+(i*4));
    }
}

static void CryptLDaaDeserializeSecretKey(
        // OUT: The secret key in matrix polynomial form
        ldaa_poly_matrix_xt_t *secret_key,
        // IN: serialized secret key
        TPM2B_LDAA_SECRET_KEY *xt,
        uint64_t m,
        uint64_t n
        ) {
    // Loop polynomial matrix (Mx1)
    for (size_t i = 0; i < m; i++) {
        // Loop coefficients of each polynomial
        for (size_t j = 0; j < n; j++) {
            secret_key->coeffs[i].coeffs[j] =
                Bytes2Coeff((BYTE*)&xt->t.buffer+((i*n+j)*4));
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

    LDaaParams params = generate_ldaa_params(publicArea->parameters.ldaaDetail.security);

    // TODO: Pass rand state to the sample_z function
    // Private key generation
    ldaa_poly_matrix_sample_z_xt(&xt, params.m, params.n, params.s, params.q);

    // Public Key generation
    CryptLDaaDeserializeIssuerAT(&at,
            &publicArea->parameters.ldaaDetail.issuer_at, params.m, params.n);

    // Set prod coefficients to zero
    for (size_t i = 0; i < params.n; i++) {
        prod.coeffs[0].coeffs[i] = 0;
    }
    ldaa_poly_matrix_product(&prod, &at, &xt, params.m, params.n, params.q);

    // Serialization is simply splitting each coefficient into 4 bytes and
    // inserting into the buffer.
    CryptLDaaSerializePublicKey(&publicArea->unique.ldaa, &prod.coeffs[0],
            params.n);
    CryptLDaaSerializeSecretKey(&sensitive->sensitive.ldaa, &xt,
            params.m, params.n);

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
    ldaa_poly_t            pe;
    ldaa_poly_t            nym;
    ldaa_poly_matrix_xt_t  xt;
    ldaa_poly_t            pbsn;
    HASH_STATE             hash_state;
    BYTE                   digest[SHA256_DIGEST_SIZE];

    LDaaParams params = generate_ldaa_params(publicArea->parameters.ldaaDetail.security);

    MemorySet(&pbsn.coeffs, 0, params.n * sizeof(UINT32));

    /* Deserialize keys */
    CryptLDaaDeserializeSecretKey(&xt, &sensitive->sensitive.ldaa,
            params.m, params.n);

    /* ********************************************************************* */
    /* Token Link Calculation                                                */
    /* vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv */
    CryptHashStart(&hash_state, ALG_SHA256_VALUE);
    CryptDigestUpdate(&hash_state, bsn_I->t.size, bsn_I->t.buffer);
    CryptHashEnd(&hash_state, SHA256_DIGEST_SIZE, digest);
    ldaa_poly_from_hash(&pbsn, digest, params.n, params.q);

    ldaa_poly_sample_z(&pe, params.n, params.s, params.q);

    ldaa_poly_mul(&nym, &xt.coeffs[0], &pbsn, params.n, params.q);
    ldaa_poly_add(&nym, &nym, &pe, params.n, params.q);
    /* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */
    /* Token Link Calculation                                                */
    /* ********************************************************************* */

    /* TODO: Need to implement proof of signature of the nonce to */
    /* send to the issuer (pi)                                    */

    // Return already serialized Public Key
    MemoryCopy2B(&public_key_serial->b,
            &publicArea->unique.ldaa.b, publicArea->unique.ldaa.t.size);
    // Serialize Token link
    CryptLDaaSerializePublicKey(nym_serial, &nym, params.n);

    return TPM_RC_SUCCESS;
}

//static void print_ldaa_state(void) {
//    printf("LDAA state:\n");
//    printf("\tcommit counter = %hd\n", gr.ldaa_commitCounter);
//    printf("\tsid = %hhd\n", gr.ldaa_sid);
//    printf("\tcommit sign state = %08x\n", gr.ldaa_commit_sign_state);
//    printf("\tHash Private Key = \n\t\t");
//    for (size_t i = 0; i < 32; i++) {
//        printf("%02x", gr.ldaa_hash_private_key[i]);
//    }
//    printf("\n");
//}


LIB_EXPORT TPM_RC
CryptLDaaClearProtocolState(void) {
    gr.ldaa_commitCounter = 0;
    gr.ldaa_sid = 0;
    gr.ldaa_commit_sign_state = 0;
    gr.ldaa_security = TPM_LDAA_SECURITY_MODE_NONE;
    MemorySet(gr.sign_states_tpm, 0, sizeof(gr.sign_states_tpm));
    MemorySet(gr.ldaa_hash_private_key, 0, sizeof(gr.ldaa_hash_private_key));
    //print_ldaa_state();
    return TPM_RC_SUCCESS;
}

LIB_EXPORT TPM_RC
CryptLDaaCommit(void) {
    gr.ldaa_commitCounter++;
    //print_ldaa_state();

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
        TPM2B_LDAA_BASENAME *bsn,
        // IN: Security Mode used in the LDAA key
        BYTE security
        ) {
    ldaa_poly_t           pe;
    ldaa_poly_t           nym;
    ldaa_poly_matrix_xt_t xt;
    ldaa_poly_t           pbsn;
    HASH_STATE            hash_state;
    BYTE                  digest[SHA256_DIGEST_SIZE];

    LDaaParams params = generate_ldaa_params(security);

    MemorySet(&pbsn.coeffs, 0, params.n * sizeof(UINT32));

    CryptLDaaDeserializeSecretKey(&xt, &sensitive->sensitive.ldaa,
            params.m, params.n);

    CryptHashStart(&hash_state, ALG_SHA256_VALUE);
    CryptDigestUpdate(&hash_state, bsn->t.size, bsn->t.buffer);
    CryptHashEnd(&hash_state, SHA256_DIGEST_SIZE, digest);
    ldaa_poly_from_hash(&pbsn, digest, params.n, params.q);

    ldaa_poly_sample_z(&pe, params.n, params.s, params.q);

    for (size_t i = 0; i < params.n; i++) {
        nym.coeffs[i] = 0;
    }
    ldaa_poly_mul(&nym, &xt.coeffs[0], &pbsn, params.n, params.q);
    ldaa_poly_add(&nym, &nym, &pe, params.n, params.q);

    // Serialize All outputs
    CryptLDaaSerializePublicKey(nym_serial, &nym, params.n);
    CryptLDaaSerializePublicKey(pe_serial, &pe, params.n);
    CryptLDaaSerializePublicKey(pbsn_serial, &pbsn, params.n);

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
        // IN: Basename to be used in the commit
        TPM2B_LDAA_BASENAME *bsn,
        // IN: Seed to generate the B NTT matrices
        UINT32              *in_seed,
        // IN: Security Mode used in the LDAA key
        BYTE security
        ) {
    ldaa_poly_t                      pe;   // 1KB
    ldaa_poly_t                      pbsn; // 1KB
    ldaa_poly_matrix_xt_t            xt;   // 24.5KB
    ldaa_poly_matrix_ntt_issuer_at_t issuer_at_ntt;  // 24.5KB
    static LDAA_LOCAL_COMMITS        ldaa_commits; // 80MB + 65KB
    memset(&ldaa_commits, 0, sizeof(ldaa_commits));

    LDaaParams params = generate_ldaa_params(security);

    /* Deserialize keys */
    CryptLDaaDeserializeSecretKey(&xt, &sensitive->sensitive.ldaa,
            params.m, params.n);
    CryptLDaaDeserializePublicKey(&pbsn, pbsn_serial, params.n);
    CryptLDaaDeserializePublicKey(&pe, pe_serial, params.n);

    switch(*commit_sel) {
        case 1:
            CryptLDaaDeserializeIssuerATNTT(&issuer_at_ntt, issuer_atntt_serial,
                    params.m, params.n);
            break;
        case 2:
        case 3:
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
    if (((gr.ldaa_commit_sign_state >> (*sign_state_sel)) & 0x00000001) == 0) {
        // printf("Updating LDAA state\n");
        // print_ldaa_state();
        ldaa_fill_sign_state_tpm(ssi, &xt, &pe, params.m, params.log_beta,
                params.log_w, params.n, params.q);
    //ldaa_fill_sign_state_tpm_fixed(ssi);
        gr.ldaa_commit_sign_state |= 1 << (*sign_state_sel);
    }
    //print_ldaa_state();

    size_t seed = (size_t) *in_seed;
    switch (*commit_sel) {
        case 1:
            ldaa_tpm_comm_1(ssi, &pbsn, &issuer_at_ntt,
                    &ldaa_commits.commited1, seed, params.m, params.log_beta,
                params.log_w, params.n, params.q, params.commit1_len,
                params.k_comm, params.alpha2);
            CryptLDaaSerializeCommit1(c_out, &ldaa_commits.commited1.C,
                    params.commit1_len + 1, params.n);
            break;
        case 2:
            ldaa_tpm_comm_2(ssi, &ldaa_commits.commited2, seed, params.m,
                    params.log_beta, params.log_w, params.n, params.q,
                    params.commit2_len, params.k_comm, params.l, params.alpha2);
            CryptLDaaSerializeCommit2(c_out, &ldaa_commits.commited2.C,
                    params.commit2_len + 1, params.n);
            break;
        case 3:
            ldaa_tpm_comm_3(ssi, &ldaa_commits.commited3, seed, params.m,
                    params.log_beta, params.log_w, params.n, params.q,
                    params.commit2_len, params.k_comm, params.l, params.alpha2);
            CryptLDaaSerializeCommit2(c_out, &ldaa_commits.commited3.C,
                    params.commit2_len + 1, params.n);
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
        BYTE                    *sign_state_type,
        // IN: Security Mode used in the LDAA key
        BYTE security
        ) {
    ldaa_poly_matrix_R_t   R1, R2;     // 64kB each
    TPMU_LDAA_SIGN_GROUP   sign_group; // 1.2MB
    size_t                 j, jj;
    LDaaParams params = generate_ldaa_params(security);

    /* Deserialize objects */
    CryptLDaaDeserializeSignState(&R1, R1_in_serial, params.k_comm, params.n);
    CryptLDaaDeserializeSignState(&R2, R2_in_serial, params.k_comm, params.n);

    ldaa_sign_state_i_t *ssi = &gr.sign_states_tpm[*sign_state_sel];

    switch (*sign_state_type) {
        case RES0:
            for (j = 0; j < params.log_beta; j++) {
                for (jj = 0; jj < params.m; jj++) {
                    ldaa_integer_matrix_t phi_xij;
                    ldaa_integer_matrix_copy(&ssi->x[jj * params.log_beta + j],
                            &phi_xij, params.log_w, params.n);
                    ldaa_integer_matrix_permute(&phi_xij, &ssi->phi[j],
                            params.log_w, params.n);

                    ldaa_integer_matrix_copy(&phi_xij,
                            &sign_group.res_1.phi_x[j * params.m + jj],
                            params.log_w, params.n);
                }
            }

            for (j = 0; j < params.log_beta; j++) {
                ldaa_integer_matrix_t varphi_ej;
                ldaa_integer_matrix_copy(&ssi->e[j], &varphi_ej,
                            params.log_w, params.n);
                ldaa_integer_matrix_permute(&varphi_ej, &ssi->varphi[j],
                            params.log_w, params.n);

                ldaa_integer_matrix_copy(&varphi_ej,
                        &sign_group.res_1.varphi_e[j],
                        params.log_w, params.n);
            }

            for (j = 0; j < params.log_beta; j++) {
                ldaa_integer_matrix_t varphi_rej;
                ldaa_integer_matrix_copy(&ssi->re[j], &varphi_rej,
                        params.log_w, params.n);
                ldaa_integer_matrix_permute(&varphi_rej, &ssi->varphi[j],
                        params.log_w, params.n);

                ldaa_integer_matrix_copy(&varphi_rej,
                        &sign_group.res_1.varphi_r_e[j],
                        params.log_w, params.n);
            }

            for (j = 0; j < params.log_beta; j++) {
                for (jj = 0; jj < params.m; jj++) {
                    ldaa_integer_matrix_t phi_rij;
                    ldaa_integer_matrix_copy(&ssi->r[jj * params.log_beta + j], &phi_rij,
                            params.log_w, params.n);
                    ldaa_integer_matrix_permute(&phi_rij, &ssi->phi[j],
                            params.log_w, params.n);

                    ldaa_integer_matrix_copy(&phi_rij,
                            &sign_group.res_1.phi_r[j * params.m + jj],
                            params.log_w, params.n);
                }
            }

            // R1 = R2 from Host
            // R2 = R3 from Host
            ldaa_poly_matrix_R_add(&R1, &R1, &ssi->R2,
                    params.k_comm, params.n, params.q);
            ldaa_poly_matrix_R_add(&R2, &R2, &ssi->R3,
                    params.k_comm, params.n, params.q);
            break;

        case RES1:
            for (j = 0; j < params.log_beta; j++) {
                ldaa_permutation_copy(&ssi->phi[j], &sign_group.res_2.phi[j],
                        params.log_w, params.n);
            }

            for (j = 0; j < params.log_beta; j++) {
                ldaa_permutation_copy(&ssi->varphi[j], &sign_group.res_2.varphi[j],
                        params.log_w, params.n);
            }

            for (j = 0; j < params.log_beta; j++) {
                ldaa_integer_matrix_copy(&ssi->ve[j], &sign_group.res_2.v_e[j],
                        params.log_w, params.n);
            }

            for (j = 0; j < params.m * params.log_beta; j++) {
                ldaa_integer_matrix_copy(&ssi->v[j], &sign_group.res_2.v[j],
                        params.log_w, params.n);
            }

            // R1 = R1 from Host
            // R2 = R3 from Host
            ldaa_poly_matrix_R_add(&R1, &R1, &ssi->R1,
                    params.k_comm, params.n, params.q);
            ldaa_poly_matrix_R_add(&R2, &R2, &ssi->R3,
                    params.k_comm, params.n, params.q);
            break;

        case RES2:
            for (j = 0; j < params.log_beta; j++) {
                ldaa_permutation_copy(&ssi->phi[j], &sign_group.res_3.phi[j],
                        params.log_w, params.n);
            }

            for (j = 0; j < params.log_beta; j++) {
                ldaa_permutation_copy(&ssi->varphi[j], &sign_group.res_3.varphi[j],
                        params.log_w, params.n);
            }

            for (j = 0; j < params.log_beta; j++) {
                ldaa_integer_matrix_copy(&ssi->re[j], &sign_group.res_3.r_e[j],
                        params.log_w, params.n);
            }

            for (j = 0; j < params.m * params.log_beta; j++) {
                ldaa_integer_matrix_copy(&ssi->r[j], &sign_group.res_3.r[j],
                        params.log_w, params.n);
            }

            // R1 = R1 from Host
            // R2 = R2 from Host
            ldaa_poly_matrix_R_add(&R1, &R1, &ssi->R1,
                    params.k_comm, params.n, params.q);
            ldaa_poly_matrix_R_add(&R2, &R2, &ssi->R2,
                    params.k_comm, params.n, params.q);
            break;

        default:
            return TPM_RC_FAILURE;
    }

    /* Serialize objects */
    CryptLDaaSerializeSignState(R1_out_serial, &R1, params.k_comm, params.n);
    CryptLDaaSerializeSignState(R2_out_serial, &R2, params.k_comm, params.n);
    CryptLDaaSerializeSignGroup(sign_group_serial, &sign_group,
            sign_state_type, params);

    return TPM_RC_SUCCESS;
}
