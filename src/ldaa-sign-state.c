#include "ldaa-params.h"
#include "ldaa-sign-state.h"
#include "ldaa-conversions.h"
#include "ldaa-permutation.h"
#include "ldaa-polynomial-mix.h"
#include "ldaa-commitment-scheme.h"

void ldaa_fill_sign_state_tpm(ldaa_sign_state_i_t *sign_state,
		    ldaa_poly_matrix_xt_t *xt,
		    ldaa_poly_t *pe, uint64_t m, uint64_t log_beta, uint64_t log_w,
            uint64_t n, uint64_t q)
{
    size_t i, j;

    /* x */
    for (i = 0; i < m; i++) {
        ldaa_poly_t *pxi = &xt->coeffs[i];
        decompose_extend_w(pxi, &sign_state->x[i * log_beta],
                log_w, log_beta, n, q);
    }

    /* e */
    decompose_extend_w(pe, sign_state->e, log_w, log_beta, n, q);

    /* r */
    for (i = 0; i < m; i++) {
        for (j = 0; j < log_beta; j++) {
            ldaa_integer_matrix_sample_u(&sign_state->r[i * log_beta + j],
                    log_w, n, q);
        }
    }

    /* re */
    for (i = 0; i < log_beta; i++) {
        ldaa_integer_matrix_sample_u(&sign_state->re[i], log_w, n, q);
    }

    /* phi */
    for (i = 0; i < log_beta; i++) {
        ldaa_permutation_sample_u(&sign_state->phi[i], log_w, n);
    }

    /* varphi */
    for (i = 0; i < log_beta; i++) {
        ldaa_permutation_sample_u(&sign_state->varphi[i], log_w, n);
    }

    /* v */
    for (i = 0; i < m; i++) {
        for (j = 0; j < log_beta; j++) {
            ldaa_integer_matrix_add(&sign_state->v[i * log_beta + j],
                                    &sign_state->x[i * log_beta + j],
                                    &sign_state->r[i * log_beta + j],
                                    log_w, n, q);
        }
    }

    /* ve */
    for (i = 0; i < log_beta; i++) {
        ldaa_integer_matrix_add(&sign_state->ve[i],
                                &sign_state->e[i],
                                &sign_state->re[i],
                                log_w, n, q);
    }
}

void ldaa_tpm_comm_1(ldaa_sign_state_i_t *s,
	   ldaa_poly_t *pbsn,
       ldaa_poly_matrix_ntt_issuer_at_t *atNTT,
       ldaa_commitment1_t *commited,
       size_t seed, uint64_t m, uint64_t log_beta, uint64_t log_w,
       uint64_t n, uint64_t q, uint64_t commit1_len, uint64_t k_comm,
       uint64_t alpha2)
{
    size_t i, j;
    const size_t w = (1<<log_w);
    const size_t m_loop = (2*(1<<log_w)-1)*n;
    const size_t numpols = (m_loop + ((n - (m_loop % n)) % n)) / n;
    ldaa_poly_t ps[numpols];

    ldaa_poly_matrix_comm1_t comm;
    memset(comm.coeffs, 0, sizeof(ldaa_poly_matrix_comm1_t));

    // Zero commit matrix
    for (i = 0; i < commit1_len; i++) {
        for (j = 0; j < n; j++) {
            comm.coeffs[i].coeffs[j] = 0;
        }
    }

    /* entry 0 & part of 1*/
    ldaa_poly_ntt_t rotat[m];

    for (i = 0; i < m; i++) {
        for (j = 0; j < n; j++) {
            rotat[i].coeffs[j] = atNTT->coeffs[i].coeffs[j];
        }
    }

    ldaa_poly_t fst;
    ldaa_poly_t snd;

    // Zero fst
    for (j = 0; j < n; j++) {
        fst.coeffs[j] = 0;
    }

    for (i = 0; i < m; i++) {
        ldaa_poly_t v;
        fold_embed(&s->r[i * log_beta], &v, log_beta, log_w, n);
        if (i == 0) {
            // Checked pbsn, v and snd
            ldaa_poly_mul(&snd, pbsn, &v, n, q);
        }
        ldaa_poly_mul_ntt_1(&v, &rotat[i], &v, n, q);
        ldaa_poly_add(&fst, &fst, &v, n, q);
    }

    for (i = 0; i < n; i++) {
        comm.coeffs[0].coeffs[i] = fst.coeffs[i];
    }

    /* entry 1 */
    ldaa_poly_t v2;
    // Checked s->re, and v2
    fold_embed(&s->re[0], &v2, log_beta, log_w, n);
    ldaa_poly_add(&snd, &snd, &v2, n, q);

    for (i = 0; i < n; i++) {
        comm.coeffs[1].coeffs[i] = snd.coeffs[i];
    }

    /* entry 2 filled by host */
    /* entries 3..3+3*log_beta-1 */

    // Checked
    for (i = 0; i < log_beta; i++) {
        ldaa_permutation_embed(&s->phi[i], ps, log_w, n);
        ldaa_poly_matrix_comm1_set_v_entries(&comm,
                3 + i*(2*w-1),
                0, ps, 2*w-1, n);
    }

    /* entries 3+3*log_beta..3+6*log_beta-1 filled by host */
    /* entries 3+6*log_beta..3+9*log_beta-1 filled by host */

    /* entries 3+9*log_beta..3+12*log_beta-1 */
    // Checked
    for (i = 0; i < log_beta; i++) {
        ldaa_permutation_embed(&s->varphi[i], ps, log_w, n);
        ldaa_poly_matrix_comm1_set_v_entries(&comm,
                3 + 3*(2*w-1)*log_beta + i*(2*w-1),
                0, ps, 2*w-1, n);

    }

    ldaa_commit_scheme_commit_1(&comm, commited, seed, commit1_len,
            n, q, k_comm, alpha2);

    for (size_t i = 0; i < k_comm; i++) {
        for (size_t j = 0; j < n; j++) {
            s->R1.coeffs[i].coeffs[j] = commited->R.coeffs[i].coeffs[j];
        }
    }
}

void ldaa_tpm_comm_2(ldaa_sign_state_i_t *s,
        ldaa_commitment2_t *commited, size_t seed,
        uint64_t m, uint64_t log_beta, uint64_t log_w,
        uint64_t n, uint64_t q, uint64_t commit2_len, uint64_t k_comm,
        uint64_t l, uint64_t alpha2)
{
    size_t i, j;
    const size_t w = (1<<log_w);

    static ldaa_poly_matrix_comm2_t comm;
    memset(comm.coeffs, 0, sizeof(ldaa_poly_matrix_comm2_t));

    const size_t m_loop = (2*(1<<log_w)-1)*n;
    const size_t numpols = (m_loop + ((n - (m_loop % n)) % n)) / n;
    const size_t row_size = (2*w-1)*(3*m + 2*m*l);
    ldaa_integer_matrix_t r;
    ldaa_poly_t pr[numpols];
    for (i = 0; i < log_beta; i++) {
        /* entries row_size * i..row_size * i + 3*m-1 */
        for (j = 0; j < m; j++) {
            ldaa_integer_matrix_copy(&s->r[j * log_beta + i], &r, log_w, n);
            ldaa_integer_matrix_permute(&r, &s->phi[i], log_w, n);

            embed_1(&r, pr, log_w, n);
            ldaa_poly_matrix_comm2_set_v_entries(&comm,
                    i*row_size + j*(2*w-1), 0, pr, 2*w-1, n);
        }
        /* entries row_size * i + 3*m..row_size * i + 6*m-1 set by host */
        /* entries row_size * i + 6*m..row_size * i + 9*m-1 set by host */
        /* entries row_size * i + 9*m..row_size * i + 9*m + 2*l*m*3 -1 set by host */
    }

    /* entries row_size * log_beta..row_size * log_beta + 3*log_beta-1 */
    for (i = 0; i < log_beta; i++) {
        ldaa_integer_matrix_copy(&s->re[i], &r, log_w, n);
        ldaa_integer_matrix_permute(&r, &s->varphi[i], log_w, n);

        embed_1(&r, pr, log_w, n);
        ldaa_poly_matrix_comm2_set_v_entries(&comm,
                row_size * log_beta + i*(2*w-1), 0, pr, 2*w-1, n);
    }
    /* entry row_size *log_beta + 3*log_beta filled by host */

    ldaa_commit_scheme_commit_2(&comm, commited, seed, commit2_len, n, q,
            k_comm, alpha2);

    for (size_t i = 0; i < k_comm; i++) {
        for (size_t j = 0; j < n; j++) {
            s->R2.coeffs[i].coeffs[j] = commited->R.coeffs[i].coeffs[j];
        }
    }
}

void ldaa_tpm_comm_3(ldaa_sign_state_i_t *s,
        ldaa_commitment3_t *commited, size_t seed,
        uint64_t m, uint64_t log_beta, uint64_t log_w,
        uint64_t n, uint64_t q, uint64_t commit3_len, uint64_t k_comm,
        uint64_t l, uint64_t alpha2)
{
    size_t i, j;
    const size_t w = (1ULL<<log_w);

    static ldaa_poly_matrix_comm3_t comm;
    memset(comm.coeffs, 0, sizeof(ldaa_poly_matrix_comm2_t));

    const size_t m_loop = (2*(1<<log_w)-1)*n;
    const size_t numpols = (m_loop + ((n - (m_loop % n)) % n)) / n;
    const size_t row_size = (2*w-1)*(3*m + 2*m*l);
    for (i = 0; i < log_beta; i++) {
        /* entries row_size * i..row_size * i + 3*LDAA_M-1 */
        for (j = 0; j < m; j++) {
            ldaa_integer_matrix_t vji;
            ldaa_integer_matrix_copy(&s->v[j * log_beta + i], &vji, log_w, n);
            ldaa_integer_matrix_permute(&vji, &s->phi[i], log_w, n);

            ldaa_poly_t pvji[numpols];
            embed_1(&vji, pvji, log_w, n);
            ldaa_poly_matrix_comm2_set_v_entries(&comm,
                    i*row_size + j*(2*w-1), 0, pvji, 2*w-1, n);
        }
        /* entries row_size * i + 3*LDAA_M..row_size * i + 6*LDAA_M-1 set by host */
        /* entries row_size * i + 6*LDAA_M..row_size * i + 9*LDAA_M-1 set by host */
        /* entries row_size * i + 9*LDAA_M..row_size * i + 9*LDAA_M + 2*LDAA_L*LDAA_M*3 -1 set by host */
    }

    /* entries row_size * log_beta..row_size * log_beta + 3*log_beta-1 */
    for (i = 0; i < log_beta; i++) {
        ldaa_integer_matrix_t vei;
        ldaa_integer_matrix_copy(&s->ve[i], &vei, log_w, n);
        ldaa_integer_matrix_permute(&vei, &s->varphi[i], log_w, n);

        ldaa_poly_t pvei[numpols];
        embed_1(&vei, pvei, log_w, n);
        ldaa_poly_matrix_comm2_set_v_entries(&comm,
                row_size * log_beta + i*(2*w-1), 0, pvei, 2*w-1, n);
    }
    /* entry row_size * log_beta + 3 * log_beta filled by host */

    ldaa_commit_scheme_commit_2(&comm, commited, seed, commit3_len, n, q,
            k_comm, alpha2);

    for (size_t i = 0; i < k_comm; i++) {
        for (size_t j = 0; j < n; j++) {
            s->R3.coeffs[i].coeffs[j] = commited->R.coeffs[i].coeffs[j];
        }
    }
}
