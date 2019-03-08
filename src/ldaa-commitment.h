#ifndef LDAA_COMMITMENT_H
#define LDAA_COMMITMENT_H
#include "ldaa-params.h"
#include "ldaa-polynomial-matrix.h"

typedef struct {
  /** Public part */
  ldaa_poly_matrix_commit1_t C;
  /** Secret randomness. Only used when opening a commitment*/
  ldaa_poly_matrix_R_t R;
} ldaa_commitment1_t;

typedef struct {
  /** Public part */
  ldaa_poly_matrix_commit2_t C;
  /** Secret randomness. Only used when opening a commitment*/
  ldaa_poly_matrix_R_t R;
} ldaa_commitment2_t;

typedef ldaa_commitment2_t ldaa_commitment3_t;

#endif
