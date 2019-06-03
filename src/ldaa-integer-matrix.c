#include "ldaa-integer-matrix.h"
#include "ldaa-permutation.h"
#include "ldaa-params.h"
#include "ldaa-uniform-int.h"
#include <stddef.h>

void ldaa_integer_matrix_pext_permute(ldaa_integer_matrix_pext_t *this,
		    ldaa_permutation_perm_t *p, uint64_t log_w, uint64_t n)
{
    size_t i;

    UINT32 *v = p->v;
    UINT32 coeffs[(2*(1<<log_w)-2)*n];
    for (i = 0; i < (2*(1<<log_w)-2)*n; i++) {
        coeffs[v[i]] = this->coeffs[i];
    }

    for (i = 0; i < (2*(1<<log_w)-2)*n; i++) {
        this->coeffs[i] = coeffs[i];
    }
}

void ldaa_integer_matrix_append_rows_pext(ldaa_integer_matrix_t *this,
			ldaa_integer_matrix_pext_t *a, uint64_t log_w, uint64_t n)
{
    size_t i, j;

    for (i = n; i < (n + ((2*(1<<log_w)-2)*n)); i++) {
        for (j = 0; j < 1; j++) {
            this->coeffs[i + j] = a->coeffs[(i - n) + j];
        }
    }
}

void ldaa_integer_matrix_sample_u(ldaa_integer_matrix_t *this,
        uint64_t log_w, uint64_t n, uint64_t q)
{
    size_t i, j;

    for (i = 0; i < (2*(1<<log_w)-1)*n; i++) {
        for (j = 0; j < 1; j++) {
            this->coeffs[i + j] = ldaa_uniform_int_sample(0, q, NULL);
        }
    }
}

void ldaa_integer_matrix_add(ldaa_integer_matrix_t *this,
		ldaa_integer_matrix_t *a,
		ldaa_integer_matrix_t *b,
        uint64_t log_w, uint64_t n, uint64_t q)
{
    size_t i;

    for (i = 0; i < (2*(1<<log_w)-1)*n; i++) {
        this->coeffs[i] = a->coeffs[i] + b->coeffs[i];
        if (this->coeffs[i] >= q)
            this->coeffs[i] -= q;
    }
}

void ldaa_integer_matrix_copy(ldaa_integer_matrix_t *this,
        ldaa_integer_matrix_t *other,
        uint64_t log_w, uint64_t n) {
    for (size_t i = 0; i < (2*(1<<log_w)-1)*n; i++) {
        other->coeffs[i] = this->coeffs[i];
    }
}

void ldaa_integer_matrix_permute(ldaa_integer_matrix_t *this,
		    ldaa_permutation_t *p, uint64_t log_w, uint64_t n)
{
    size_t i;
    UINT32 coeffs[(2*(1<<log_w)-1)*n];

    // Permute data
    for (i = 0; i < (2*(1<<log_w)-1)*n; i++) {
        coeffs[p->v[i]] = this->coeffs[i];
    }

    // Copy data back
    for (i = 0; i < (2*(1<<log_w)-1)*n; i++) {
        this->coeffs[i] = coeffs[i];
    }
}
