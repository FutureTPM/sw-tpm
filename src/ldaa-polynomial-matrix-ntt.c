#include "Tpm.h"
#include "ldaa-polynomial-matrix-ntt.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-ntt.h"
#include "ldaa-params.h"

void ldaa_poly_matrix_ntt_commit1_product(ldaa_poly_matrix_ntt_commit1_prod_t *this,
		    ldaa_poly_matrix_ntt_B_t *a,
		    ldaa_poly_matrix_ntt_R_t *b)
{
    size_t i, j, k;
    ldaa_poly_ntt_t prod;

    for (i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        for (j = 0; j < 1; j++) {
            for (k = 0; k < LDAA_K_COMM; k++) {
                ldaa_poly_ntt_mul(&prod,
                        &a->coeffs[i * LDAA_K_COMM + k], &b->coeffs[k + j]);
                ldaa_poly_ntt_add(&this->coeffs[i + j],
                        &this->coeffs[i + j], &prod);
            }
        }
    }
}

void ldaa_poly_matrix_ntt_commit2_product(ldaa_poly_matrix_ntt_commit2_prod_t *this,
		    ldaa_poly_matrix_ntt_B2_t *a,
		    ldaa_poly_matrix_ntt_R_t *b)
{
    size_t i, j, k;
    ldaa_poly_ntt_t prod;

    for (i = 0; i < LDAA_COMMIT2_LENGTH; i++) {
        for (j = 0; j < 1; j++) {
            for (k = 0; k < LDAA_K_COMM; k++) {
                ldaa_poly_ntt_mul(&prod,
                        &a->coeffs[i * LDAA_K_COMM + k], &b->coeffs[k + j]);
                ldaa_poly_ntt_add(&this->coeffs[i + j],
                        &this->coeffs[i + j], &prod);
            }
        }
    }
}

void ldaa_poly_matrix_ntt_R_from_canonical(ldaa_poly_matrix_ntt_R_t *this,
			   ldaa_poly_matrix_R_t *a)
{
    size_t i, j, k;
    for (i = 0; i < LDAA_LOG_BETA; i++) {
        for (j = 0; j < 1; j++) {
            ldaa_poly_t *aij = &a->coeffs[i];
            for (k = 0; k < LDAA_N; k++) {
                this->coeffs[i + j].coeffs[k] = aij->coeffs[k];
            }
        }
    }
}
