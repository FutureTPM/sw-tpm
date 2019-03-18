#include "ldaa-polynomial-matrix-ntt.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-ntt.h"
#include "ldaa-params.h"

void ldaa_poly_matrix_ntt_commit1_product(ldaa_poly_matrix_ntt_commit1_prod_t *this,
		    ldaa_poly_matrix_ntt_B_t *a,
		    ldaa_poly_matrix_ntt_R_t *b)
{
    size_t i, j, k, l;
    UINT32 prod;

    for (i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        for (j = 0; j < 1; j++) {
            for (k = 0; k < LDAA_K_COMM; k++) {
                for (l = 0; l < LDAA_N; l++) {
                    prod = ldaa_reduce((UINT64)a->coeffs[i * LDAA_K_COMM + k].coeffs[l] * b->coeffs[k * 1 + j].coeffs[l]);
                    this->coeffs[i * 1 + j].coeffs[l] = this->coeffs[i * 1 + j].coeffs[l] + prod;
                    if (this->coeffs[i * 1 + j].coeffs[l] >= LDAA_Q) {
                        this->coeffs[i * 1 + j].coeffs[l] -= LDAA_Q;
                    }
                }
            }
        }
    }
}

void ldaa_poly_matrix_ntt_commit2_product(ldaa_poly_matrix_ntt_commit2_prod_t *this,
		    ldaa_poly_matrix_ntt_B2_t *a,
		    ldaa_poly_matrix_ntt_R_t *b,
            size_t n_lines)
{
    size_t i, j, k, l;
    UINT32 prod;

    for (i = 0; i < n_lines; i++) {
        for (j = 0; j < 1; j++) {
            for (k = 0; k < LDAA_K_COMM; k++) {
                for (l = 0; l < LDAA_N; l++) {
                    prod = ldaa_reduce((UINT64)a->coeffs[i * LDAA_K_COMM + k].coeffs[l] * b->coeffs[k * 1 + j].coeffs[l]);
                    this->coeffs[i * 1 + j].coeffs[l] = this->coeffs[i * 1 + j].coeffs[l] + prod;
                    if (this->coeffs[i * 1 + j].coeffs[l] >= LDAA_Q) {
                        this->coeffs[i * 1 + j].coeffs[l] -= LDAA_Q;
                    }
                }
            }
        }
    }
}

void ldaa_poly_matrix_ntt_R_commit_from_canonical(ldaa_poly_matrix_ntt_R_t *this,
			   ldaa_poly_matrix_R_commit_t *a)
{
    size_t i, j;
    for (i = 0; i < LDAA_K_COMM; i++) {
        for (j = 0; j < LDAA_N; j++) {
            if (j == 0) {
                this->coeffs[i].coeffs[j] = a->coeffs[i];
            } else {
                this->coeffs[i].coeffs[j] = 0;
            }
        }
        ldaa_poly_ntt(this->coeffs[i].coeffs);
    }

}
