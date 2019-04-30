#include "dilithium-params.h"
#include "dilithium-sign.h"
#include "fips202.h"
#include "Tpm.h"

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

  for(i = 0; i < dilithium_k; ++i) {
    for(j = 0; j < dilithium_l; ++j) {
      dilithium_poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
    }
  }
}

/*************************************************
* Name:        challenge
*
* Description: Implementation of H. Samples polynomial with 60 nonzero
*              coefficients in {-1,1} using the output stream of
*              SHAKE256(mu|w1).
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const unsigned char mu[]: byte array containing mu
*              - const polyveck *w1: pointer to vector w1
**************************************************/
void dilithium_challenge(dilithium_poly *c,
               const unsigned char mu[DILITHIUM_CRHBYTES],
               const dilithium_polyveck *w1,
               uint64_t dilithium_k,
               uint64_t dilithium_polw1_size_packed)
{
  unsigned int i, b, pos;
  unsigned char inbuf[DILITHIUM_CRHBYTES + dilithium_k*dilithium_polw1_size_packed];
  unsigned char outbuf[SHAKE256_RATE];
  uint64_t signs;
  keccak_state state;

  for(i = 0; i < DILITHIUM_CRHBYTES; ++i)
    inbuf[i] = mu[i];
  for(i = 0; i < dilithium_k; ++i)
    dilithium_polyw1_pack(inbuf + DILITHIUM_CRHBYTES + i*dilithium_polw1_size_packed, &w1->vec[i]);

  shake256_absorb(&state, inbuf, sizeof(inbuf));
  shake256_squeezeblocks(outbuf, 1, &state);

  signs = 0;
  for(i = 0; i < 8; ++i)
    signs |= (uint64_t)outbuf[i] << 8*i;

  pos = 8;

  for(i = 0; i < DILITHIUM_N; ++i)
    c->coeffs[i] = 0;

  for(i = 196; i < 256; ++i) {
    do {
      if(pos >= SHAKE256_RATE) {
        shake256_squeezeblocks(outbuf, 1, &state);
        pos = 0;
      }

      b = outbuf[pos++];
    } while(b > i);

    c->coeffs[i] = c->coeffs[b];
    c->coeffs[b] = 1;
    c->coeffs[b] ^= -(signs & 1) & (1 ^ (DILITHIUM_Q-1));
    signs >>= 1;
  }
}
