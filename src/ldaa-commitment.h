#ifndef LDAA_COMMITMENT_H
#define LDAA_COMMITMENT_H
#include "Tpm.h"
#include "ldaa-params.h"
#include "ldaa-polynomial-matrix.h"

/** Includes both the secret randomness and the public commitment to a vector
 * of polynomials.
 *
 * Implemented according to ``Efficient Commitments and Zero-Knowledge
 * Protocols from Ring-SIS with Applications to Lattice-based Threshold
 * Cryptosystems'' by Baum, Damgard, Oechsner and Peikert
**/
typedef struct {
  /** Public part */
  ldaa_poly_matrix_commit1_t C;
  /** Secret randomness. Only used when opening a commitment*/
  ldaa_poly_matrix_R_t R;
} ldaa_commitment1_t;

//typedef struct {
//  vector_t *Chash;
//  polynomial_matrix_t *R;
//} ldaa_commitment_hash_t;

#endif
