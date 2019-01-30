#ifndef LDAA_POLYNOMIAL_MATRIX_H
#define LDAA_POLYNOMIAL_MATRIX_H

#include "ldaa-polynomial.h"

typedef struct {
  ldaa_poly_t coeffs[LDAA_M*1];
} ldaa_poly_matrix_xt_t;

void ldaa_poly_matrix_sample_z_xt(ldaa_poly_matrix_xt_t *this);

typedef struct {
  ldaa_poly_t coeffs[1*1];
} ldaa_poly_matrix_ut_t;

void ldaa_poly_matrix_product(ldaa_poly_matrix_ut_t *out,
		    ldaa_poly_matrix_xt_t *a,
		    ldaa_poly_matrix_xt_t *b);
#endif
