#ifndef LDAA_POLYNOMIAL_MATRIX_H
#define LDAA_POLYNOMIAL_MATRIX_H

#include "Tpm.h"
#include "ldaa-params.h"
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

typedef struct {
  ldaa_poly_t coeffs[(3 + 4*(2*(1<<LDAA_LOG_W)-1)*LDAA_LOG_BETA)*1];
} ldaa_poly_matrix_comm_t;

typedef struct {
  ldaa_poly_t coeffs[LDAA_COMMIT1_LENGTH];
} ldaa_poly_matrix_commit1_t;

void ldaa_poly_matrix_comm_set_v_entries(
        ldaa_poly_matrix_comm_t *this,
        size_t i0, size_t j0,
        ldaa_poly_t *as, size_t numpols);

void ldaa_poly_matrix_commit1_add(ldaa_poly_matrix_commit1_t *out,
		    ldaa_poly_matrix_commit1_t *a,
		    ldaa_poly_matrix_commit1_t *b);

typedef struct {
  ldaa_poly_t coeffs[LDAA_K_COMM * 1];
} ldaa_poly_matrix_R_t;

#endif
