#ifndef LDAA_INTEGER_MATRIX_H
#define LDAA_INTEGER_MATRIX_H

#include "Tpm.h"
#include "ldaa-params.h"
#include "ldaa-permutation.h"

void ldaa_integer_matrix_sample_u(ldaa_integer_matrix_t *this,
        uint64_t log_w, uint64_t n, uint64_t q);
void ldaa_integer_matrix_add(ldaa_integer_matrix_t *this,
		ldaa_integer_matrix_t *a,
		ldaa_integer_matrix_t *b,
        uint64_t log_w, uint64_t n, uint64_t q);
void ldaa_integer_matrix_copy(ldaa_integer_matrix_t *this,
        ldaa_integer_matrix_t *other,
        uint64_t log_w, uint64_t n);
void ldaa_integer_matrix_permute(ldaa_integer_matrix_t *this,
		    ldaa_permutation_t *p, uint64_t log_w, uint64_t n);

typedef struct {
    UINT32 coeffs[(2*(1<<MAX_LDAA_LOG_W)-2)*MAX_LDAA_N];
} ldaa_integer_matrix_pext_t;

void ldaa_integer_matrix_pext_permute(ldaa_integer_matrix_pext_t *this,
		    ldaa_permutation_perm_t *p, uint64_t log_w, uint64_t n);
void ldaa_integer_matrix_append_rows_pext(ldaa_integer_matrix_t *this,
			ldaa_integer_matrix_pext_t *a, uint64_t log_w, uint64_t n);

#endif
