#include "ldaa-polynomial-matrix-mix.h"

void ldaa_poly_matrix_commit1_prod_from_ntt(ldaa_poly_matrix_commit1_t *this,
	 ldaa_poly_matrix_ntt_commit1_prod_t *a)
{
    size_t i, j, k;

    for (i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        for (j = 0; j < 1; j++) {
            ldaa_poly_ntt_t *aij = &a->coeffs[i + j];
            for (k = 0; k < LDAA_N; k++) {
                this->coeffs[i + j].coeffs[k] = aij->coeffs[k];
            }
        }
    }
}

void ldaa_poly_matrix_commit1_product_ntt_1(ldaa_poly_matrix_commit1_t *this,
			  ldaa_poly_matrix_ntt_B_t *a,
			  ldaa_poly_matrix_R_t *ba)
{
    ldaa_poly_matrix_ntt_R_t b;
    ldaa_poly_matrix_ntt_R_from_canonical(&b, ba);
    ldaa_poly_matrix_ntt_commit1_prod_t prod;
    // Zero prod
    for (size_t i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        for (size_t j = 0; j < LDAA_N; j++) {
            prod.coeffs[i].coeffs[j] = 0;
        }
    }
    ldaa_poly_matrix_ntt_commit1_product(&prod, a, &b);

    ldaa_poly_matrix_commit1_prod_from_ntt(this, &prod);
}

void ldaa_poly_matrix_commit2_prod_from_ntt(ldaa_poly_matrix_commit2_t *this,
	 ldaa_poly_matrix_ntt_commit2_prod_t *a)
{
    size_t i, j, k;

    for (i = 0; i < LDAA_COMMIT2_LENGTH; i++) {
        for (j = 0; j < 1; j++) {
            ldaa_poly_ntt_t *aij = &a->coeffs[i + j];
            for (k = 0; k < LDAA_N; k++) {
                this->coeffs[i + j].coeffs[k] = aij->coeffs[k];
            }
        }
    }
}

void ldaa_poly_matrix_commit2_product_ntt_1(ldaa_poly_matrix_commit2_t *this,
			  ldaa_poly_matrix_ntt_B2_t *a,
			  ldaa_poly_matrix_R_t *ba)
{
    ldaa_poly_matrix_ntt_R_t b;
    ldaa_poly_matrix_ntt_R_from_canonical(&b, ba);
    ldaa_poly_matrix_ntt_commit2_prod_t prod;
    // Zero prod
    for (size_t i = 0; i < LDAA_COMMIT2_LENGTH; i++) {
        for (size_t j = 0; j < LDAA_N; j++) {
            prod.coeffs[i].coeffs[j] = 0;
        }
    }
    ldaa_poly_matrix_ntt_commit2_product(&prod, a, &b);

    ldaa_poly_matrix_commit2_prod_from_ntt(this, &prod);
}
