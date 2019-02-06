#ifndef LDAA_COMMITMENT_SCHEME_H
#define LDAA_COMMITMENT_SCHEME_H

#include "Tpm.h"
#include "ldaa-params.h"
#include "ldaa-commitment.h"
#include "ldaa-polynomial-matrix-ntt.h"

void ldaa_commit_scheme_commit_1(ldaa_poly_matrix_comm_t *S,
        ldaa_commitment1_t *commited, ldaa_poly_matrix_ntt_B_t *BNTT);
#endif
