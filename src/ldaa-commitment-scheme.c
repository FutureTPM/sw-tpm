#include "Tpm.h"
#include "ldaa-params.h"
#include "ldaa-commitment-scheme.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-matrix-ntt.h"
#include "ldaa-polynomial-matrix-mix.h"
#include "ldaa-uniform-int.h"

static void compute_commitment_1(ldaa_poly_matrix_R_commit_t *R,
		   ldaa_poly_matrix_comm1_t *S,
           ldaa_commitment1_t *commited, size_t seed, uint64_t commit1_len,
           uint64_t n, uint64_t q, uint64_t k_comm)
{
    ldaa_poly_matrix_commit1_t prod;
    ldaa_poly_matrix_commit1_product_ntt_1(&prod, R, seed, commit1_len,
            n, q, k_comm);

    ldaa_poly_matrix_commit1_t S2;
    // Append S rows to S2
    for (size_t i = 0; i < commit1_len; i++) {
        if (i == 0) {
            for (size_t j = 0; j < n; j++) {
                S2.coeffs[i].coeffs[j] = 0;
            }
        } else {
            for (size_t j = 0; j < n; j++) {
                S2.coeffs[i].coeffs[j] = S->coeffs[i - 1].coeffs[j];
            }
        }
    }
    ldaa_poly_matrix_commit1_add(&S2, &S2, &prod, commit1_len, n, q);

    // Copy results to output struct
    for (size_t i = 0; i < commit1_len; i++) {
        for (size_t j = 0; j < n; j++) {
            commited->C.coeffs[i].coeffs[j] = S2.coeffs[i].coeffs[j];
        }
    }

    for (size_t i = 0; i < k_comm; i++) {
        commited->R.coeffs[i].coeffs[0] = R->coeffs[i];
    }
}

void ldaa_commit_scheme_commit_1(ldaa_poly_matrix_comm1_t *S,
        ldaa_commitment1_t *commited, size_t seed, uint64_t commit1_len,
           uint64_t n, uint64_t q, uint64_t k_comm, uint64_t alpha2)
{
    ldaa_poly_matrix_R_commit_t R;
    size_t i;

    for (i = 0; i < k_comm; i++) {
        R.coeffs[i] = ldaa_uniform_int_sample(0, alpha2, NULL);
    }

    compute_commitment_1(&R, S, commited, seed, commit1_len, n, q, k_comm);
}

static void compute_commitment_2(ldaa_poly_matrix_R_commit_t *R,
		   ldaa_poly_matrix_comm2_t *S,
           ldaa_commitment2_t *commited, size_t seed, uint64_t commit2_len,
           uint64_t n, uint64_t q, uint64_t k_comm)
{
    static ldaa_poly_matrix_commit2_t prod;
    ldaa_poly_matrix_commit2_product_ntt_1(&prod, R, seed, commit2_len,
            n, q, k_comm);

    static ldaa_poly_matrix_commit2_t S2;
    // Append S rows to S2
    for (size_t i = 0; i < commit2_len; i++) {
        if (i == 0) {
            for (size_t j = 0; j < n; j++) {
                S2.coeffs[i].coeffs[j] = 0;
            }
        } else {
            for (size_t j = 0; j < n; j++) {
                S2.coeffs[i].coeffs[j] = S->coeffs[i - 1].coeffs[j];
            }
        }
    }
    ldaa_poly_matrix_commit2_add(&S2, &S2, &prod, commit2_len, n, q);

    // Copy results to output struct
    for (size_t i = 0; i < commit2_len; i++) {
        for (size_t j = 0; j < n; j++) {
            commited->C.coeffs[i].coeffs[j] = S2.coeffs[i].coeffs[j];
        }
    }

    for (size_t i = 0; i < k_comm; i++) {
        commited->R.coeffs[i].coeffs[0] = R->coeffs[i];
    }
}

void ldaa_commit_scheme_commit_2(ldaa_poly_matrix_comm2_t *S,
        ldaa_commitment2_t *commited, size_t seed, uint64_t commit2_len,
           uint64_t n, uint64_t q, uint64_t k_comm, uint64_t alpha2)
{
    ldaa_poly_matrix_R_commit_t R;
    size_t i;

    for (i = 0; i < k_comm; i++) {
        R.coeffs[i] = ldaa_uniform_int_sample(0, alpha2, NULL);
    }

    compute_commitment_2(&R, S, commited, seed, commit2_len, n, q, k_comm);
}
