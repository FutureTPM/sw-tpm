#ifndef LDAA_COMMITMENT_SCHEME_H
#define LDAA_COMMITMENT_SCHEME_H
#include "ldaa-params.h"
#include "ldaa-commitment.h"
#include "ldaa-polynomial-matrix-ntt.h"
#include "Tpm.h"

void ldaa_commit_scheme_commit_1(ldaa_poly_matrix_comm1_t *S,
        ldaa_commitment1_t *commited, size_t seed);
void ldaa_commit_scheme_commit_2(ldaa_poly_matrix_comm2_t *S,
        ldaa_commitment2_t *commited, size_t seed);

#endif
