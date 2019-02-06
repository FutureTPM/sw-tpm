#include "ldaa-params.h"
#include "ldaa-polynomial-matrix.h"

void ldaa_poly_matrix_sample_z_xt(ldaa_poly_matrix_xt_t *this)
{
    for (size_t i = 0; i < LDAA_M; i++) {
        ldaa_poly_sample_z(&this->coeffs[i]);
    }
}

void ldaa_poly_matrix_commit1_add(ldaa_poly_matrix_commit1_t *out,
		    ldaa_poly_matrix_commit1_t *a,
		    ldaa_poly_matrix_commit1_t *b)
{
    size_t i;
    for (i = 0; i < (4 + 4 * (2 * (1<<LDAA_LOG_W) - 1) * LDAA_LOG_BETA) * 1; i++) {
            ldaa_poly_add(&out->coeffs[i], &a->coeffs[i], &b->coeffs[i]);
    }
}

void ldaa_poly_matrix_product(ldaa_poly_matrix_ut_t *out,
		    ldaa_poly_matrix_xt_t *a,
		    ldaa_poly_matrix_xt_t *b)
{
    size_t k;

    ldaa_poly_t prod;
    for (k = 0; k < LDAA_N; k++) {
        ldaa_poly_mul(&prod, &a->coeffs[k], &b->coeffs[k]);
        ldaa_poly_add(&out->coeffs[0], &out->coeffs[0], &prod);
    }
}

void ldaa_poly_matrix_comm_set_v_entries(
        ldaa_poly_matrix_comm_t *this,
        size_t i0, size_t j0,
        ldaa_poly_t *as, size_t numpols)
{
    size_t i, j;

    for (i = 0; i < numpols; i++) {
        for (j = 0; j < LDAA_N; j++) {
            this->coeffs[(i0 + i) + j0].coeffs[j] = as[i].coeffs[j];
        }
    }
}

