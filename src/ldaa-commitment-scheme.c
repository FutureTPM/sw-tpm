#include "BaseTypes.h"
#include "ldaa-params.h"
#include "ldaa-commitment-scheme.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-matrix-ntt.h"
#include "ldaa-polynomial-matrix-mix.h"
#include "ldaa-uniform-int.h"

static void compute_commitment_1(ldaa_poly_matrix_ntt_B_t *B,
		   ldaa_poly_matrix_R_commit_t *R,
		   ldaa_poly_matrix_comm1_t *S,
           ldaa_commitment1_t *commited)
{
    ldaa_poly_matrix_commit1_t prod;
    ldaa_poly_matrix_commit1_product_ntt_1(&prod, B, R);

    ldaa_poly_matrix_commit1_t S2;
    // Append S rows to S2
    for (size_t i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        if (i == 0) {
            for (size_t j = 0; j < LDAA_N; j++) {
                S2.coeffs[i].coeffs[j] = 0;
            }
        } else {
            for (size_t j = 0; j < LDAA_N; j++) {
                S2.coeffs[i].coeffs[j] = S->coeffs[i - 1].coeffs[j];
            }
        }
    }
    ldaa_poly_matrix_commit1_add(&S2, &S2, &prod);

    // Copy results to output struct
    for (size_t i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        for (size_t j = 0; j < LDAA_N; j++) {
            commited->C.coeffs[i].coeffs[j] = S2.coeffs[i].coeffs[j];
        }
    }

    for (size_t i = 0; i < LDAA_K_COMM; i++) {
        commited->R.coeffs[i].coeffs[0] = R->coeffs[i];
    }
}

void ldaa_commit_scheme_commit_1(ldaa_poly_matrix_comm1_t *S,
        ldaa_commitment1_t *commited, ldaa_poly_matrix_ntt_B_t *BNTT)
{
    ldaa_poly_matrix_R_commit_t R;
    size_t i;

    for (i = 0; i < LDAA_K_COMM; i++) {
        R.coeffs[i] = ldaa_uniform_int_sample(0, LDAA_ALPHA2);
    }

    compute_commitment_1(BNTT, &R, S, commited);
}

static void compute_commitment_2(ldaa_poly_matrix_ntt_B2_t *B,
		   ldaa_poly_matrix_R_commit_t *R,
		   ldaa_poly_matrix_comm2_t *S,
           ldaa_commitment2_t *commited, size_t n_lines)
{
    static ldaa_poly_matrix_commit2_t prod;
    ldaa_poly_matrix_commit2_product_ntt_1(&prod, B, R, n_lines);

    static ldaa_poly_matrix_commit2_t S2;
    // Append S rows to S2
    for (size_t i = 0; i < n_lines; i++) {
        if (i == 0) {
            for (size_t j = 0; j < LDAA_N; j++) {
                S2.coeffs[i].coeffs[j] = 0;
            }
        } else {
            for (size_t j = 0; j < LDAA_N; j++) {
                S2.coeffs[i].coeffs[j] = S->coeffs[i - 1].coeffs[j];
            }
        }
    }
    ldaa_poly_matrix_commit2_add(&S2, &S2, &prod, n_lines);

    // Copy results to output struct
    for (size_t i = 0; i < n_lines; i++) {
        for (size_t j = 0; j < LDAA_N; j++) {
            commited->C.coeffs[i].coeffs[j] = S2.coeffs[i].coeffs[j];
        }
    }

    for (size_t i = 0; i < LDAA_K_COMM; i++) {
        commited->R.coeffs[i].coeffs[0] = R->coeffs[i];
    }
}

void ldaa_commit_scheme_commit_2(ldaa_poly_matrix_comm2_t *S,
        ldaa_commitment2_t *commited, ldaa_poly_matrix_ntt_B2_t *BNTT,
        ldaa_poly_matrix_R_t *already_processed_R,
        BOOL r_already_processed, size_t n_lines)
{
    ldaa_poly_matrix_R_commit_t R;
    size_t i;

    if (!r_already_processed) {
        for (i = 0; i < LDAA_K_COMM; i++) {
            //R.coeffs[i] = ldaa_uniform_int_sample(0, LDAA_ALPHA2);
            R.coeffs[i] = 1;
        }
    } else {
        for (i = 0; i < LDAA_K_COMM; i++) {
            R.coeffs[i] = already_processed_R->coeffs[i].coeffs[0];
        }
    }

    compute_commitment_2(BNTT, &R, S, commited, n_lines);
}
