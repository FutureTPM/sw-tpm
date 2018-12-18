#include "fips202.h"
#include "dilithium-params.h"
#include "dilithium-sign.h"

/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|i|j).
*
* Arguments:   - polyvecl mat[K]: output matrix
*              - const unsigned char rho[]: byte array containing seed rho
**************************************************/
void dilithium_expand_mat(dilithium_polyvecl *mat,
        const unsigned char rho[DILITHIUM_SEEDBYTES],
        uint64_t dilithium_k, uint64_t dilithium_l) {
  unsigned int i, j;
  unsigned char inbuf[DILITHIUM_SEEDBYTES + 1];
  /* Don't change this to smaller values,
   * sampling later assumes sufficient SHAKE output!
   * Probability that we need more than 5 blocks: < 2^{-132}.
   * Probability that we need more than 6 blocks: < 2^{-546}. */
  unsigned char outbuf[5*SHAKE128_RATE];

  for(i = 0; i < DILITHIUM_SEEDBYTES; ++i)
    inbuf[i] = rho[i];

  for(i = 0; i < dilithium_k; ++i) {
    for(j = 0; j < dilithium_l; ++j) {
      inbuf[DILITHIUM_SEEDBYTES] = i + (j << 4);
      shake128(outbuf, sizeof(outbuf), inbuf, DILITHIUM_SEEDBYTES + 1);
      dilithium_poly_uniform(mat[i].vec+j, outbuf);
    }
  }
}
