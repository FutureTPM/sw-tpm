#ifndef LDAA_POLYNOMIAL_MATRIX_MIX_H
#define LDAA_POLYNOMIAL_MATRIX_MIX_H
#include <stddef.h>
#include "ldaa-params.h"
#include "TpmTypes.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-matrix-ntt.h"

void ldaa_poly_matrix_commit1_prod_from_ntt(ldaa_poly_matrix_commit1_t *this,
	 ldaa_poly_matrix_ntt_commit1_prod_t *a,
     uint64_t commit1_len, uint64_t n, uint64_t q);

void ldaa_poly_matrix_commit1_product_ntt_1(ldaa_poly_matrix_commit1_t *this,
			  ldaa_poly_matrix_R_commit_t *ba, size_t seed,
              uint64_t commit1_len, uint64_t n, uint64_t q, uint64_t k_comm);

void ldaa_poly_matrix_commit2_prod_from_ntt(ldaa_poly_matrix_commit2_t *this,
	 ldaa_poly_matrix_ntt_commit2_prod_t *a, uint64_t commit2_len,
     uint64_t n, uint64_t q);

void ldaa_poly_matrix_commit2_product_ntt_1(ldaa_poly_matrix_commit2_t *this,
			  ldaa_poly_matrix_R_commit_t *ba, size_t seed,
              uint64_t commit2_len, uint64_t n, uint64_t q, uint64_t k_comm);

#endif
