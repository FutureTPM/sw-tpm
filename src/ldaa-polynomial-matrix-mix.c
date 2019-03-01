#include "ldaa-polynomial-matrix-mix.h"

void ldaa_poly_matrix_commit1_prod_from_ntt(ldaa_poly_matrix_commit1_t *this,
	 ldaa_poly_matrix_ntt_commit1_prod_t *a)
{
    size_t i, k;

    for (i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        this->coeffs[i].coeffs[0] = a->coeffs[i];
        for (k = 1; k < LDAA_N; k++) {
            this->coeffs[i].coeffs[k] = 0;
        }
    }
}

void ldaa_poly_matrix_commit1_product_ntt_1(ldaa_poly_matrix_commit1_t *this,
			  ldaa_poly_matrix_ntt_B_t *a,
			  ldaa_poly_matrix_R_commit_t *ba)
{
    ldaa_poly_matrix_ntt_R_commit_t b;
    ldaa_poly_matrix_ntt_R_commit_from_canonical(&b, ba);
    ldaa_poly_matrix_ntt_commit1_prod_t prod;
    // Zero prod
    MemorySet(&prod.coeffs, 0, LDAA_COMMIT1_LENGTH * sizeof(UINT32));
    ldaa_poly_matrix_ntt_commit1_product(&prod, a, &b);

    ldaa_poly_matrix_commit1_prod_from_ntt(this, &prod);
}

void ldaa_poly_matrix_commit2_prod_from_ntt(ldaa_poly_matrix_commit2_t *this,
	 ldaa_poly_matrix_ntt_commit2_prod_t *a)
{
    size_t i, k;

    for (i = 0; i < LDAA_COMMIT2_LENGTH; i++) {
        this->coeffs[i].coeffs[0] = a->coeffs[i];
        for (k = 1; k < LDAA_N; k++) {
            this->coeffs[i].coeffs[k] = 0;
        }
    }
}

void ldaa_poly_matrix_commit2_product_ntt_1(ldaa_poly_matrix_commit2_t *this,
			  ldaa_poly_matrix_ntt_B2_t *a,
			  ldaa_poly_matrix_R_commit_t *ba)
{
    ldaa_poly_matrix_ntt_R_commit_t b;
    ldaa_poly_matrix_ntt_R_commit_from_canonical(&b, ba);
    ldaa_poly_matrix_ntt_commit2_prod_t prod;
    // Zero prod
    for (size_t i = 0; i < LDAA_COMMIT2_LENGTH; i++) {
        prod.coeffs[i] = 0;
    }
    ldaa_poly_matrix_ntt_commit2_product(&prod, a, &b);

    ldaa_poly_matrix_commit2_prod_from_ntt(this, &prod);
}
