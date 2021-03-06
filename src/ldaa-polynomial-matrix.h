#ifndef LDAA_POLYNOMIAL_MATRIX_H
#define LDAA_POLYNOMIAL_MATRIX_H

#include "Tpm.h"
#include "ldaa-params.h"
#include "ldaa-polynomial.h"
#include <stddef.h>

void ldaa_poly_matrix_sample_z_xt(ldaa_poly_matrix_xt_t *this, uint64_t m,
        uint64_t n, uint64_t s, uint64_t q);

void ldaa_poly_matrix_product(ldaa_poly_matrix_ut_t *out,
		    ldaa_poly_matrix_xt_t *a,
		    ldaa_poly_matrix_xt_t *b,
            uint64_t m,
            uint64_t n,
            uint64_t q);

void ldaa_poly_matrix_comm1_set_v_entries(
        ldaa_poly_matrix_comm1_t *this,
        size_t i0, size_t j0,
        ldaa_poly_t *as, size_t numpols, uint64_t n);

void ldaa_poly_matrix_commit1_add(ldaa_poly_matrix_commit1_t *out,
		    ldaa_poly_matrix_commit1_t *a,
		    ldaa_poly_matrix_commit1_t *b,
            uint64_t commit1_len, uint64_t n, uint64_t q);

void ldaa_poly_matrix_comm2_set_v_entries(
        ldaa_poly_matrix_comm2_t *this,
        size_t i0, size_t j0,
        ldaa_poly_t *as, size_t numpols, uint64_t n);

void ldaa_poly_matrix_commit2_add(ldaa_poly_matrix_commit2_t *out,
		    ldaa_poly_matrix_commit2_t *a,
		    ldaa_poly_matrix_commit2_t *b,
            uint64_t commit2_len,
            uint64_t n,
            uint64_t q);

void ldaa_poly_matrix_R_add(ldaa_poly_matrix_R_t *out,
		    ldaa_poly_matrix_R_t *a,
		    ldaa_poly_matrix_R_t *b,
            uint64_t k_comm,
            uint64_t n,
            uint64_t q);

#endif
