#include "ldaa-params.h"
#include "ldaa-sign-state.h"
#include "ldaa-conversions.h"
#include "ldaa-permutation.h"
#include "ldaa-polynomial-mix.h"
#include "ldaa-commitment-scheme.h"

void ldaa_fill_sign_state_tpm(ldaa_sign_state_i_t *sign_state,
		    ldaa_poly_matrix_xt_t *xt,
		    ldaa_poly_t *pe)
{
    size_t i, j;

    /* x */
    for (i = 0; i < LDAA_M; i++) {
        ldaa_poly_t *pxi = &xt->coeffs[i];
        decompose_extend_w(pxi, &sign_state->x[i * LDAA_LOG_BETA]);
    }

    /* e */
    decompose_extend_w(pe, sign_state->e);

    /* r */
    for (i = 0; i < LDAA_M; i++) {
        for (j = 0; j < LDAA_LOG_BETA; j++) {
            ldaa_integer_matrix_sample_u(&sign_state->r[i * LDAA_LOG_BETA + j]);
        }
    }

    /* re */
    for (i = 0; i < LDAA_LOG_BETA; i++) {
        ldaa_integer_matrix_sample_u(&sign_state->re[i]);
    }

    /* phi */
    for (i = 0; i < LDAA_LOG_BETA; i++) {
        ldaa_permutation_sample_u(&sign_state->phi[i]);
    }

    /* varphi */
    for (i = 0; i < LDAA_LOG_BETA; i++) {
        ldaa_permutation_sample_u(&sign_state->varphi[i]);
    }

    /* v */
    for (i = 0; i < LDAA_M; i++) {
        for (j = 0; j < LDAA_LOG_BETA; j++) {
            ldaa_integer_matrix_add(&sign_state->v[i * LDAA_LOG_BETA + j],
                                    &sign_state->x[i * LDAA_LOG_BETA + j],
                                    &sign_state->r[i * LDAA_LOG_BETA + j]);
        }
    }

    /* ve */
    for (i = 0; i < LDAA_LOG_BETA; i++) {
        ldaa_integer_matrix_add(&sign_state->ve[i],
                                &sign_state->e[i],
                                &sign_state->re[i]);
    }
}

void ldaa_tpm_comm_1(ldaa_sign_state_i_t *s,
	   ldaa_poly_t *pbsn,
       ldaa_poly_matrix_ntt_issuer_at_t *atNTT,
       ldaa_commitment1_t *commited,
       ldaa_poly_matrix_ntt_B_t *BNTT)
{
    size_t i, j;
    size_t w = (1<<LDAA_LOG_W);
    size_t m = (2*(1<<LDAA_LOG_W)-1)*LDAA_N;
    size_t numpols = (m + ((LDAA_N - (m % LDAA_N)) % LDAA_N)) / LDAA_N;

    ldaa_poly_matrix_comm1_t comm;

    // Zero commit matrix
    for (i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        for (j = 0; j < LDAA_N; j++) {
            comm.coeffs[i].coeffs[j] = 0;
        }
    }

    /* entry 0 & part of 1*/
    ldaa_poly_ntt_t rotat[LDAA_M];

    for (i = 0; i < LDAA_M; i++) {
        for (j = 0; j < LDAA_N; j++) {
            rotat[i].coeffs[j] = atNTT->coeffs[i].coeffs[j];
        }
    }

    ldaa_poly_t fst;
    ldaa_poly_t snd;

    // Zero fst
    for (j = 0; j < LDAA_N; j++) {
        fst.coeffs[j] = 0;
    }

    for (i = 0; i < LDAA_M; i++) {
        ldaa_poly_t v;
        fold_embed(&s->r[i * LDAA_LOG_BETA], &v);
        if (i == 0)
            ldaa_poly_mul(&snd, pbsn, &v);
        ldaa_poly_mul_ntt_1(&v, &rotat[i], &v);
        ldaa_poly_add(&fst, &fst, &v);
    }
    for (i = 0; i < LDAA_N; i++) {
        comm.coeffs[0].coeffs[i] = fst.coeffs[i];
    }

    /* entry 1 */
    ldaa_poly_t v2;
    fold_embed(&s->re[0], &v2);
    ldaa_poly_add(&snd, &snd, &v2);
    for (i = 0; i < LDAA_N; i++) {
        comm.coeffs[1].coeffs[i] = snd.coeffs[i];
    }

    /* entry 2 filled by host */
    /* entries 3..3+3*LDAA_LOG_BETA-1 */

    for (i = 0; i < LDAA_LOG_BETA; i++) {
        ldaa_poly_t ps[numpols];
        ldaa_permutation_embed(&s->phi[i], ps);
        ldaa_poly_matrix_comm1_set_v_entries(&comm, 3 + i*(2*w-1), 0, ps, 2*w-1);
    }

    /* entries 3+3*LDAA_LOG_BETA..3+6*LDAA_LOG_BETA-1 filled by host */
    /* entries 3+6*LDAA_LOG_BETA..3+9*LDAA_LOG_BETA-1 filled by host */

    /* entries 3+9*LDAA_LOG_BETA..3+12*LDAA_LOG_BETA-1 */
    for (i = 0; i < LDAA_LOG_BETA; i++) {
        ldaa_poly_t ps[numpols];
        ldaa_permutation_embed(&s->varphi[i], ps);
        ldaa_poly_matrix_comm1_set_v_entries(&comm,
                3 + 3*(2*w-1)*LDAA_LOG_BETA + i*(2*w-1),
                0, ps, 2*w-1);
    }

    ldaa_commit_scheme_commit_1(&comm, commited, BNTT);

    for (size_t i = 0; i < LDAA_K_COMM; i++) {
        for (size_t j = 0; j < LDAA_N; j++) {
            s->R1.coeffs[i].coeffs[j] = commited->R.coeffs[i].coeffs[j];
        }
    }
}

void ldaa_tpm_comm_2(ldaa_sign_state_i_t *s,
        ldaa_commitment2_t *commited,
        ldaa_poly_matrix_ntt_B2_t *BNTT)
{
    size_t i, j;
    size_t w = (1<<LDAA_LOG_W);

    ldaa_poly_matrix_comm2_t comm;
    // Zero commit matrix
    for (i = 0; i < LDAA_COMMIT2_LENGTH; i++) {
        for (j = 0; j < LDAA_N; j++) {
            comm.coeffs[i].coeffs[j] = 0;
        }
    }

    size_t m = (2*(1<<LDAA_LOG_W)-1)*LDAA_N;
    size_t numpols = (m + ((LDAA_N - (m % LDAA_N)) % LDAA_N)) / LDAA_N;
    size_t row_size = (2*w-1)*(3*LDAA_M + 2*LDAA_M*LDAA_L);
    for (i = 0; i < LDAA_LOG_BETA; i++) {
        /* entries row_size * i..row_size * i + 3*LDAA_M-1 */
        for (j = 0; j < LDAA_M; j++) {
            ldaa_integer_matrix_t rji;
            ldaa_integer_matrix_copy(&s->r[j * LDAA_LOG_BETA + i], &rji);
            ldaa_integer_matrix_permute(&rji, &s->phi[i]);

            ldaa_poly_t prji[numpols];
            embed_1(&rji, prji);
            ldaa_poly_matrix_comm2_set_v_entries(&comm,
                    i*row_size + j*(2*w-1), 0, prji, 2*w-1);
        }
        /* entries row_size * i + 3*LDAA_M..row_size * i + 6*LDAA_M-1 set by host */
        /* entries row_size * i + 6*LDAA_M..row_size * i + 9*LDAA_M-1 set by host */
        /* entries row_size * i + 9*LDAA_M..row_size * i + 9*LDAA_M + 2*LDAA_L*LDAA_M*3 -1 set by host */
    }

    /* entries row_size * LDAA_LOG_BETA..row_size * LDAA_LOG_BETA + 3*LDAA_LOG_BETA-1 */
    for (i = 0; i < LDAA_LOG_BETA; i++) {
        ldaa_integer_matrix_t rei;
        ldaa_integer_matrix_copy(&s->re[i], &rei);
        ldaa_integer_matrix_permute(&rei, &s->varphi[i]);

        ldaa_poly_t prei[numpols];
        embed_1(&rei, prei);
        ldaa_poly_matrix_comm2_set_v_entries(&comm,
                row_size * LDAA_LOG_BETA + i*(2*w-1), 0, prei, 2*w-1);
    }
    /* entry row_size *LDAA_LOG_BETA + 3*LDAA_LOG_BETA filled by host */

    ldaa_commit_scheme_commit_2(&comm, commited, BNTT);

    for (size_t i = 0; i < LDAA_K_COMM; i++) {
        for (size_t j = 0; j < LDAA_N; j++) {
            s->R2.coeffs[i].coeffs[j] = commited->R.coeffs[i].coeffs[j];
        }
    }
}

void ldaa_tpm_comm_3(ldaa_sign_state_i_t *s,
        ldaa_commitment3_t *commited,
        ldaa_poly_matrix_ntt_B3_t *BNTT)
{
    size_t i, j;
    size_t w = (1ULL<<LDAA_LOG_W);

    ldaa_poly_matrix_comm3_t comm;
    // Zero commit matrix
    for (i = 0; i < LDAA_COMMIT3_LENGTH; i++) {
        for (j = 0; j < LDAA_N; j++) {
            comm.coeffs[i].coeffs[j] = 0;
        }
    }

    size_t m = (2*(1<<LDAA_LOG_W)-1)*LDAA_N;
    size_t numpols = (m + ((LDAA_N - (m % LDAA_N)) % LDAA_N)) / LDAA_N;
    size_t row_size = (2*w-1)*(3*LDAA_M + 2*LDAA_M*LDAA_L);
    for (i = 0; i < LDAA_LOG_BETA; i++) {
        /* entries row_size * i..row_size * i + 3*LDAA_M-1 */
        for (j = 0; j < LDAA_M; j++) {
            ldaa_integer_matrix_t vji;
            ldaa_integer_matrix_copy(&s->v[j * LDAA_LOG_BETA + i], &vji);
            ldaa_integer_matrix_permute(&vji, &s->phi[i]);

            ldaa_poly_t pvji[numpols];
            embed_1(&vji, pvji);
            ldaa_poly_matrix_comm2_set_v_entries(&comm,
                    i*row_size + j*(2*w-1), 0, pvji, 2*w-1);
        }
        /* entries row_size * i + 3*LDAA_M..row_size * i + 6*LDAA_M-1 set by host */
        /* entries row_size * i + 6*LDAA_M..row_size * i + 9*LDAA_M-1 set by host */
        /* entries row_size * i + 9*LDAA_M..row_size * i + 9*LDAA_M + 2*LDAA_L*LDAA_M*3 -1 set by host */
    }

    /* entries row_size * LDAA_LOG_BETA..row_size * LDAA_LOG_BETA + 3*LDAA_LOG_BETA-1 */
    for (i = 0; i < LDAA_LOG_BETA; i++) {
        ldaa_integer_matrix_t vei;
        ldaa_integer_matrix_copy(&s->ve[i], &vei);
        ldaa_integer_matrix_permute(&vei, &s->varphi[i]);

        ldaa_poly_t pvei[numpols];
        embed_1(&vei, pvei);
        ldaa_poly_matrix_comm2_set_v_entries(&comm,
                row_size * LDAA_LOG_BETA + i*(2*w-1), 0, pvei, 2*w-1);
    }
    /* entry row_size * LDAA_LOG_BETA + 3 * LDAA_LOG_BETA filled by host */

    ldaa_commit_scheme_commit_2(&comm, commited, BNTT);

    for (size_t i = 0; i < LDAA_K_COMM; i++) {
        for (size_t j = 0; j < LDAA_N; j++) {
            s->R3.coeffs[i].coeffs[j] = commited->R.coeffs[i].coeffs[j];
        }
    }
}
