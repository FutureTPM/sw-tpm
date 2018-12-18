#include "kyber-reduce.h"
#include "kyber-params.h"


static const uint32_t kyber_qinv = 7679; // -inverse_mod(q,2^18)
static const uint32_t kyber_rlog = 18;

/*************************************************
* Name:        montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q,
*              where R=2^18 (see value of rlog)
*
* Arguments:   - uint32_t a: input unsigned integer to be reduced; has to be in {0,...,2281446912}
*
* Returns:     unsigned integer in {0,...,2^13-1} congruent to a * R^-1 modulo q.
**************************************************/
uint16_t kyber_montgomery_reduce(uint32_t a) {
  uint32_t u;

  u = (a * kyber_qinv);
  u &= ((1<<kyber_rlog)-1);
  u *= KYBER_Q;
  a = a + u;
  return a >> kyber_rlog;
}


/*************************************************
* Name:        barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              16-bit integer congruent to a mod q in {0,...,11768}
*
* Arguments:   - uint16_t a: input unsigned integer to be reduced
*
* Returns:     unsigned integer in {0,...,11768} congruent to a modulo q.
**************************************************/
uint16_t kyber_barrett_reduce(uint16_t a) {
  uint32_t u;

  u = a >> 13;//((uint32_t) a * sinv) >> 16;
  u *= KYBER_Q;
  a -= u;
  return a;
}

/*************************************************
* Name:        freeze
*
* Description: Full reduction; given a 16-bit integer a, computes
*              unsigned integer a mod q.
*
* Arguments:   - uint16_t x: input unsigned integer to be reduced
*
* Returns:     unsigned integer in {0,...,q-1} congruent to a modulo q.
**************************************************/
uint16_t kyber_freeze(uint16_t x) {
  uint16_t m,r;
  int16_t c;
  r = kyber_barrett_reduce(x);

  m = r - KYBER_Q;
  c = m;
  c >>= 15;
  r = m ^ ((r^m)&c);

  return r;
}
