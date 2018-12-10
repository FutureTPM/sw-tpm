#include "inttypes.h"
#include "ntt.h"
#include "reduce.h"

#include "Tpm.h"
#include "KYBER_KeyGen_fp.h"

extern const uint16_t omegas_inv_bitrev_montgomery[];
extern const uint16_t psis_inv_montgomery[];
extern const uint16_t zetas[];

/*************************************************
* Name:        ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial (vector of 256 coefficients) in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *p: pointer to in/output polynomial
**************************************************/
void ntt(uint16_t *p) {
  int j;
  uint16_t zeta, t;

  size_t k = 1;
  for(int level = 7; level >= 0; level--) {
    for(int start = 0; start < KYBER_N; start = j + (1<<level)) {
      zeta = zetas[k++];
      for(j = start; j < start + (1<<level); ++j) {
        t = montgomery_reduce((uint32_t)zeta * p[j + (1<<level)]);

        p[j + (1<<level)] = barrett_reduce(p[j] + 4*KYBER_Q - t);

        if(level & 1) /* odd level */
          p[j] = p[j] + t; /* Omit reduction (be lazy) */
        else
          p[j] = barrett_reduce(p[j] + t);
      }
    }
  }
}

/*************************************************
* Name:        invntt
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT) of
*              a polynomial (vector of 256 coefficients) in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void invntt(uint16_t * a) {
  uint16_t temp, W;
  uint32_t t;

  for(int level = 0; level < 8; level++) {
    for(int start = 0; start < (1<<level); start++) {
      int jTwiddle = 0;
      for(int j = start; j < KYBER_N-1; j += 2*(1<<level)) {
        W = omegas_inv_bitrev_montgomery[jTwiddle++];
        temp = a[j];

        if(level & 1) /* odd level */
          a[j] = barrett_reduce((temp + a[j + (1<<level)]));
        else
          a[j] = (temp + a[j + (1<<level)]); /* Omit reduction (be lazy) */

        t = (W * ((uint32_t)temp + 4*KYBER_Q - a[j + (1<<level)]));

        a[j + (1<<level)] = montgomery_reduce(t);
      }
    }
  }

  for(size_t j = 0; j < KYBER_N; j++)
    a[j] = montgomery_reduce((a[j] * psis_inv_montgomery[j]));
}
