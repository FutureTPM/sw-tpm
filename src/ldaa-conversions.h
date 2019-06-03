#ifndef LDAA_CONVERSIONS_H
#define LDAA_CONVERSIONS_H

#include "ldaa-polynomial.h"
#include "ldaa-integer-matrix.h"

void decompose_extend_w(ldaa_poly_t *p, ldaa_integer_matrix_t *pdecomp,
        uint64_t log_w, uint64_t log_beta, uint64_t n, uint64_t q);
void fold_embed(ldaa_integer_matrix_t *vs, ldaa_poly_t *res,
        uint64_t log_beta, uint64_t log_w, uint64_t n);
void embed_1(ldaa_integer_matrix_t *v, ldaa_poly_t *ps,
        uint64_t log_w, uint64_t n);

#endif
