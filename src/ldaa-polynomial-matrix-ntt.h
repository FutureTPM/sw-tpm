#ifndef LDAA_POLYNOMIAL_MATRIX_NTT_H
#define LDAA_POLYNOMIAL_MATRIX_NTT_H
#include "Tpm.h"
#include "ldaa-params.h"
#include "ldaa-polynomial-ntt.h"
#include "ldaa-polynomial-matrix.h"

typedef struct {
  ldaa_poly_ntt_t coeffs[LDAA_M];
} ldaa_poly_matrix_ntt_issuer_at_t;

typedef struct {
  ldaa_poly_ntt_t coeffs[LDAA_ISSUER_BNTT_LENGTH];
} ldaa_poly_matrix_ntt_B_t;

typedef struct {
  ldaa_poly_ntt_t coeffs[LDAA_K_COMM * 1];
} ldaa_poly_matrix_ntt_R_t;

typedef struct {
  ldaa_poly_ntt_t coeffs[(4 + 4 * (2 * (1<<LDAA_LOG_W) - 1) * LDAA_LOG_BETA) * 1];
} ldaa_poly_matrix_ntt_prod_t;

typedef struct {
  ldaa_poly_ntt_t coeffs[(4 + 4 * (2 * (1<<LDAA_LOG_W) - 1) * LDAA_LOG_BETA) * 1];
} ldaa_poly_matrix_ntt_comm2_t;

void ldaa_poly_matrix_ntt_R_from_canonical(ldaa_poly_matrix_ntt_R_t *this,
			   ldaa_poly_matrix_R_t *a);

void ldaa_poly_matrix_ntt_product(ldaa_poly_matrix_ntt_prod_t *this,
		    ldaa_poly_matrix_ntt_B_t *a,
		    ldaa_poly_matrix_ntt_R_t *b);
#endif
