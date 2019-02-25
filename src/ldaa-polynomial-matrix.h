#ifndef LDAA_POLYNOMIAL_MATRIX_H
#define LDAA_POLYNOMIAL_MATRIX_H

#include "BaseTypes.h"
#include "ldaa-params.h"
#include "ldaa-polynomial.h"
#include <stddef.h>

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
  ldaa_poly_t coeffs[(LDAA_COMMIT1_LENGTH - 1)*1];
} ldaa_poly_matrix_comm1_t;

void ldaa_poly_matrix_comm1_set_v_entries(
        ldaa_poly_matrix_comm1_t *this,
        size_t i0, size_t j0,
        ldaa_poly_t *as, size_t numpols);

typedef struct {
  ldaa_poly_t coeffs[LDAA_COMMIT1_LENGTH];
} ldaa_poly_matrix_commit1_t;

void ldaa_poly_matrix_commit1_add(ldaa_poly_matrix_commit1_t *out,
		    ldaa_poly_matrix_commit1_t *a,
		    ldaa_poly_matrix_commit1_t *b);

typedef struct {
  ldaa_poly_t coeffs[(LDAA_COMMIT2_LENGTH - 1)*1];
} ldaa_poly_matrix_comm2_t;

typedef ldaa_poly_matrix_comm2_t ldaa_poly_matrix_comm3_t;

void ldaa_poly_matrix_comm2_set_v_entries(
        ldaa_poly_matrix_comm2_t *this,
        size_t i0, size_t j0,
        ldaa_poly_t *as, size_t numpols);

typedef struct {
  ldaa_poly_t coeffs[LDAA_COMMIT2_LENGTH];
} ldaa_poly_matrix_commit2_t;

typedef ldaa_poly_matrix_commit2_t ldaa_poly_matrix_commit3_t;

void ldaa_poly_matrix_commit2_add(ldaa_poly_matrix_commit2_t *out,
		    ldaa_poly_matrix_commit2_t *a,
		    ldaa_poly_matrix_commit2_t *b);

typedef struct {
  UINT32 coeffs[LDAA_K_COMM * 1];
} ldaa_poly_matrix_R_commit_t;

typedef struct {
  ldaa_poly_t coeffs[LDAA_K_COMM * 1];
} ldaa_poly_matrix_R_t;

void ldaa_poly_matrix_R_add(ldaa_poly_matrix_R_t *out,
		    ldaa_poly_matrix_R_t *a,
		    ldaa_poly_matrix_R_t *b);

#endif
