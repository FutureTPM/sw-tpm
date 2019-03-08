#ifndef LDAA_CONVERSIONS_H
#define LDAA_CONVERSIONS_H

#include "ldaa-polynomial.h"
#include "ldaa-integer-matrix.h"

void decompose_extend_w(ldaa_poly_t *p, ldaa_integer_matrix_t *pdecomp);
void fold_embed(ldaa_integer_matrix_t *vs, ldaa_poly_t *res);
void embed_1(ldaa_integer_matrix_t *v, ldaa_poly_t *ps);

#endif
