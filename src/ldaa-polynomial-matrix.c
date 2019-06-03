#include "ldaa-params.h"
#include "ldaa-polynomial-matrix.h"
#include <stddef.h>
#include <stdio.h>

void ldaa_poly_matrix_sample_z_xt(ldaa_poly_matrix_xt_t *this, uint64_t m,
        uint64_t n, uint64_t s, uint64_t q)
{
    for (size_t i = 0; i < m; i++) {
        ldaa_poly_sample_z(&this->coeffs[i], n, s, q);
    }
}

void ldaa_poly_matrix_commit1_add(ldaa_poly_matrix_commit1_t *out,
		    ldaa_poly_matrix_commit1_t *a,
		    ldaa_poly_matrix_commit1_t *b,
            uint64_t commit1_len, uint64_t n, uint64_t q)
{
    size_t i;
    for (i = 0; i < commit1_len * 1; i++) {
        ldaa_poly_add(&out->coeffs[i], &a->coeffs[i], &b->coeffs[i], n, q);
    }
}

void ldaa_poly_matrix_product(ldaa_poly_matrix_ut_t *out,
		    ldaa_poly_matrix_xt_t *a,
		    ldaa_poly_matrix_xt_t *b,
            uint64_t m,
            uint64_t n,
            uint64_t q)
{
    size_t k;

    ldaa_poly_t prod;
    for (k = 0; k < m; k++) {
        ldaa_poly_mul(&prod, &a->coeffs[k], &b->coeffs[k], n, q);
        ldaa_poly_add(&out->coeffs[0], &out->coeffs[0], &prod, n, q);
    }
}

void ldaa_poly_matrix_comm1_set_v_entries(
        ldaa_poly_matrix_comm1_t *this,
        size_t i0, size_t j0,
        ldaa_poly_t *as, size_t numpols, uint64_t n)
{
    size_t i, j;

    for (i = 0; i < numpols; i++) {
        for (j = 0; j < n; j++) {
            this->coeffs[(i0 + i) + j0].coeffs[j] = as[i].coeffs[j];
        }
    }
}

void ldaa_poly_matrix_comm2_set_v_entries(
        ldaa_poly_matrix_comm2_t *this,
        size_t i0, size_t j0,
        ldaa_poly_t *as, size_t numpols, uint64_t n)
{
    size_t i, j;

    for (i = 0; i < numpols; i++) {
        for (j = 0; j < n; j++) {
            this->coeffs[(i0 + i) + j0].coeffs[j] = as[i].coeffs[j];
        }
    }
}

void ldaa_poly_matrix_commit2_add(ldaa_poly_matrix_commit2_t *out,
		    ldaa_poly_matrix_commit2_t *a,
		    ldaa_poly_matrix_commit2_t *b,
            uint64_t commit2_len,
            uint64_t n,
            uint64_t q)
{
    size_t i;
    for (i = 0; i < commit2_len; i++) {
        ldaa_poly_add(&out->coeffs[i], &a->coeffs[i], &b->coeffs[i], n, q);
    }
}

void ldaa_poly_matrix_R_add(ldaa_poly_matrix_R_t *out,
		    ldaa_poly_matrix_R_t *a,
		    ldaa_poly_matrix_R_t *b,
            uint64_t k_comm,
            uint64_t n,
            uint64_t q)
{
    size_t i;
    for (i = 0; i < k_comm * 1; i++) {
        ldaa_poly_add(&out->coeffs[i], &a->coeffs[i], &b->coeffs[i], n, q);
    }
}
