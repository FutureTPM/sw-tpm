#ifndef LDAA_POLYNOMIAL_MATRIX_NTT_H
#define LDAA_POLYNOMIAL_MATRIX_NTT_H
#include "BaseTypes.h"
#include "TpmTypes.h"
#include "ldaa-params.h"
#include "ldaa-polynomial-ntt.h"
#include "ldaa-polynomial-matrix.h"
#include <stddef.h>

void ldaa_poly_matrix_ntt_R_commit_from_canonical(ldaa_poly_matrix_ntt_R_t *this,
			   ldaa_poly_matrix_R_commit_t *a, uint64_t n, uint64_t k_comm,
               uint64_t q);

void ldaa_poly_matrix_ntt_commit1_product(ldaa_poly_matrix_ntt_commit1_prod_t *this,
		    ldaa_poly_matrix_ntt_R_t *b, size_t seed, uint64_t commit1_len,
            uint64_t n, uint64_t k_comm, uint64_t q);

void ldaa_poly_matrix_ntt_commit2_product(ldaa_poly_matrix_ntt_commit2_prod_t *this,
		    ldaa_poly_matrix_ntt_R_t *b, size_t seed, uint64_t commit2_len,
            uint64_t n, uint64_t k_comm, uint64_t q);
#endif
