#ifndef LDAA_INTEGER_MATRIX_H
#define LDAA_INTEGER_MATRIX_H

#include "Tpm.h"
#include "ldaa-params.h"
#include "ldaa-permutation.h"

typedef struct {
    UINT32 coeffs[(2*(1<<LDAA_LOG_W)-1)*LDAA_N];
} ldaa_integer_matrix_t;

void ldaa_integer_matrix_sample_u(ldaa_integer_matrix_t *this);
void ldaa_integer_matrix_add(ldaa_integer_matrix_t *this,
		ldaa_integer_matrix_t *a,
		ldaa_integer_matrix_t *b);
void ldaa_integer_matrix_copy(ldaa_integer_matrix_t *this,
        ldaa_integer_matrix_t *other);
void ldaa_integer_matrix_permute(ldaa_integer_matrix_t *this,
		    ldaa_permutation_t *p);

typedef struct {
    UINT32 coeffs[(2*(1<<LDAA_LOG_W)-2)*LDAA_N];
} ldaa_integer_matrix_pext_t;

void ldaa_integer_matrix_pext_permute(ldaa_integer_matrix_pext_t *this,
		    ldaa_permutation_perm_t *p);
void ldaa_integer_matrix_append_rows_pext(ldaa_integer_matrix_t *this,
			ldaa_integer_matrix_pext_t *a);

#endif
