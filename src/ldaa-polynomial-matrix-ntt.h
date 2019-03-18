#ifndef LDAA_POLYNOMIAL_MATRIX_NTT_H
#define LDAA_POLYNOMIAL_MATRIX_NTT_H
#include "BaseTypes.h"
#include "TpmTypes.h"
#include "ldaa-params.h"
#include "ldaa-polynomial-ntt.h"
#include "ldaa-polynomial-matrix.h"
#include <stddef.h>

typedef struct {
  ldaa_poly_ntt_t coeffs[LDAA_M];
} ldaa_poly_matrix_ntt_issuer_at_t;

typedef struct {
  ldaa_poly_t coeffs[LDAA_ISSUER_BNTT_LENGTH];
} ldaa_poly_matrix_ntt_B_t;

typedef struct {
  ldaa_poly_t coeffs[LDAA_COMMIT2_LENGTH * LDAA_K_COMM];
} ldaa_poly_matrix_ntt_B2_t;

typedef ldaa_poly_matrix_ntt_B2_t ldaa_poly_matrix_ntt_B3_t;

typedef struct {
  ldaa_poly_ntt_t coeffs[LDAA_K_COMM * 1];
} ldaa_poly_matrix_ntt_R_t;

// The R polynomial matrix only needs the first order coefficient when
// processing the commit.
typedef struct {
  UINT32 coeffs[LDAA_K_COMM * 1];
} ldaa_poly_matrix_ntt_R_commit_t;

typedef struct {
  ldaa_poly_t coeffs[LDAA_COMMIT1_LENGTH * 1];
} ldaa_poly_matrix_ntt_commit1_prod_t;

typedef struct {
  ldaa_poly_t coeffs[LDAA_COMMIT2_LENGTH * 1];
} ldaa_poly_matrix_ntt_commit2_prod_t;

void ldaa_poly_matrix_ntt_R_commit_from_canonical(ldaa_poly_matrix_ntt_R_t *this,
			   ldaa_poly_matrix_R_commit_t *a);

void ldaa_poly_matrix_ntt_commit1_product(ldaa_poly_matrix_ntt_commit1_prod_t *this,
		    ldaa_poly_matrix_ntt_B_t *a,
		    ldaa_poly_matrix_ntt_R_t *b);

void ldaa_poly_matrix_ntt_commit2_product(ldaa_poly_matrix_ntt_commit2_prod_t *this,
		    ldaa_poly_matrix_ntt_B2_t *a,
		    ldaa_poly_matrix_ntt_R_t *b,
            size_t n_lines);
#endif
