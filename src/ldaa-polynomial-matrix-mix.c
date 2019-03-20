#include "ldaa-polynomial-matrix-mix.h"
#include "BaseTypes.h"
#include "Memory_fp.h"

void ldaa_poly_matrix_commit1_prod_from_ntt(ldaa_poly_matrix_commit1_t *this,
	 ldaa_poly_matrix_ntt_commit1_prod_t *a)
{
    size_t i, k;

    for (i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        for (k = 0; k < LDAA_N; k++) {
            this->coeffs[i].coeffs[k] = a->coeffs[i].coeffs[k];
        }
        ldaa_poly_invntt(this->coeffs[i].coeffs);
    }
}

void ldaa_poly_matrix_commit1_product_ntt_1(ldaa_poly_matrix_commit1_t *this,
			  ldaa_poly_matrix_R_commit_t *ba, size_t seed)
{
    ldaa_poly_matrix_ntt_R_t b;
    ldaa_poly_matrix_ntt_R_commit_from_canonical(&b, ba);
    static ldaa_poly_matrix_ntt_commit1_prod_t prod;
    // Zero prod
    MemorySet(prod.coeffs, 0, LDAA_COMMIT1_LENGTH * LDAA_N * sizeof(UINT32));
    ldaa_poly_matrix_ntt_commit1_product(&prod, &b, seed);

    ldaa_poly_matrix_commit1_prod_from_ntt(this, &prod);
}

void ldaa_poly_matrix_commit2_prod_from_ntt(ldaa_poly_matrix_commit2_t *this,
	 ldaa_poly_matrix_ntt_commit2_prod_t *a)
{
    size_t i, k;

    for (i = 0; i < LDAA_COMMIT2_LENGTH; i++) {
        for (k = 0; k < LDAA_N; k++) {
            this->coeffs[i].coeffs[k] = a->coeffs[i].coeffs[k];
        }
        ldaa_poly_invntt(this->coeffs[i].coeffs);
    }
}

void ldaa_poly_matrix_commit2_product_ntt_1(ldaa_poly_matrix_commit2_t *this,
			  ldaa_poly_matrix_R_commit_t *ba, size_t seed)
{
    // ldaa_poly_matrix_ntt_B2_t *a,
    ldaa_poly_matrix_ntt_R_t b;
    ldaa_poly_matrix_ntt_R_commit_from_canonical(&b, ba);
    static ldaa_poly_matrix_ntt_commit2_prod_t prod;
    // Zero prod
    MemorySet(prod.coeffs, 0, LDAA_COMMIT2_LENGTH * LDAA_N * sizeof(UINT32));
    ldaa_poly_matrix_ntt_commit2_product(&prod, &b, seed);

    ldaa_poly_matrix_commit2_prod_from_ntt(this, &prod);
}
