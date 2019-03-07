#ifndef LDAA_COMMITMENT_SCHEME_H
#define LDAA_COMMITMENT_SCHEME_H

#include "ldaa-params.h"
#include "ldaa-commitment.h"
#include "ldaa-polynomial-matrix-ntt.h"

void ldaa_commit_scheme_commit_1(ldaa_poly_matrix_comm1_t *S,
        ldaa_commitment1_t *commited, ldaa_poly_matrix_ntt_B_t *BNTT);
void ldaa_commit_scheme_commit_2(ldaa_poly_matrix_comm2_t *S,
        ldaa_commitment2_t *commited, ldaa_poly_matrix_ntt_B2_t *BNTT,
        ldaa_poly_matrix_R_t *already_processed_R,
        BOOL r_already_processed, size_t n_lines);

#endif
