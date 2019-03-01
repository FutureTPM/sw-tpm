#include "Tpm.h"
#include "ldaa-polynomial-matrix-ntt.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-ntt.h"
#include "ldaa-params.h"

void ldaa_poly_matrix_ntt_commit1_product(ldaa_poly_matrix_ntt_commit1_prod_t *this,
		    ldaa_poly_matrix_ntt_B_t *a,
		    ldaa_poly_matrix_ntt_R_commit_t *b)
{
    size_t i, k;
    UINT32 prod;

    for (i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        for (k = 0; k < LDAA_K_COMM; k++) {
            prod = ldaa_reduce((UINT64)a->coeffs[i * LDAA_K_COMM + k] * b->coeffs[k]);
            this->coeffs[i] = this->coeffs[i] + prod;
            if (this->coeffs[i] >= LDAA_Q) {
                this->coeffs[i] -= LDAA_Q;
            }
        }
    }
}

void ldaa_poly_matrix_ntt_commit2_product(ldaa_poly_matrix_ntt_commit2_prod_t *this,
		    ldaa_poly_matrix_ntt_B2_t *a,
		    ldaa_poly_matrix_ntt_R_commit_t *b)
{
    size_t i, k;
    UINT32 prod;

    for (i = 0; i < LDAA_COMMIT2_LENGTH; i++) {
        for (k = 0; k < LDAA_K_COMM; k++) {
            prod = ldaa_reduce((UINT64)a->coeffs[i * LDAA_K_COMM + k] * b->coeffs[k]);
            this->coeffs[i] = this->coeffs[i] + prod;
            if (this->coeffs[i] >= LDAA_Q) {
                this->coeffs[i] -= LDAA_Q;
            }
        }
    }
}

void ldaa_poly_matrix_ntt_R_commit_from_canonical(ldaa_poly_matrix_ntt_R_commit_t *this,
			   ldaa_poly_matrix_R_commit_t *a)
{
    size_t i;
    for (i = 0; i < LDAA_K_COMM; i++) {
        this->coeffs[i] = a->coeffs[i];
    }
}
