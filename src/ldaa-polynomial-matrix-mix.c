#include "ldaa-polynomial-matrix-mix.h"

void ldaa_poly_matrix_commit1_prod_from_ntt(ldaa_poly_matrix_commit1_t *this,
	 ldaa_poly_matrix_ntt_prod_t *a)
{
  size_t i, j, k;

  for (i = 0; i < (4 + 4 * (2 * (1<<LDAA_LOG_W) - 1) * LDAA_LOG_BETA); i++) {
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
    ldaa_poly_matrix_ntt_prod_t prod;
    ldaa_poly_matrix_ntt_product(&prod, a, &b);

    ldaa_poly_matrix_commit1_prod_from_ntt(this, &prod);
}

