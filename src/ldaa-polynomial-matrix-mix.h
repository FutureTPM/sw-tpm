#ifndef LDAA_POLYNOMIAL_MATRIX_MIX_H
#define LDAA_POLYNOMIAL_MATRIX_MIX_H

#include "Tpm.h"
#include "ldaa-params.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-matrix-ntt.h"

void ldaa_poly_matrix_commit1_prod_from_ntt(ldaa_poly_matrix_commit1_t *this,
	 ldaa_poly_matrix_ntt_commit1_prod_t *a);

void ldaa_poly_matrix_commit1_product_ntt_1(ldaa_poly_matrix_commit1_t *this,
			  ldaa_poly_matrix_ntt_B_t *a,
			  ldaa_poly_matrix_R_commit_t *ba);

void ldaa_poly_matrix_commit2_prod_from_ntt(ldaa_poly_matrix_commit2_t *this,
	 ldaa_poly_matrix_ntt_commit2_prod_t *a);

void ldaa_poly_matrix_commit2_product_ntt_1(ldaa_poly_matrix_commit2_t *this,
			  ldaa_poly_matrix_ntt_B2_t *a,
			  ldaa_poly_matrix_R_commit_t *ba);

#endif
