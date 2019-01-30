#include "ldaa-params.h"
#include "ldaa-polynomial-matrix.h"

void ldaa_poly_matrix_sample_z_xt(ldaa_poly_matrix_xt_t *this)
{
  for (size_t i = 0; i < LDAA_M; i++) {
      ldaa_poly_sample_z(&this->coeffs[i]);
  }
}

void ldaa_poly_matrix_product(ldaa_poly_matrix_ut_t *out,
		    ldaa_poly_matrix_xt_t *a,
		    ldaa_poly_matrix_xt_t *b)
{
  size_t k;

  ldaa_poly_t prod;
  for (k = 0; k < LDAA_N; k++) {
    ldaa_poly_mul(&prod, &a->coeffs[k], &b->coeffs[k]);
    ldaa_poly_add(&out->coeffs[0], &out->coeffs[0], &prod);
  }

  //clean_matrix(this->coeffs, this->m, this->n);
}
