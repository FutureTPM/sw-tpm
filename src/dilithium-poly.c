#include <stdint.h>
#include "fips202.h"
#include "dilithium-params.h"
#include "dilithium-reduce.h"
#include "dilithium-rounding.h"
#include "dilithium-ntt.h"
#include "dilithium-poly.h"

/*************************************************
* Name:        poly_reduce
*
* Description: Reduce all coefficients of input polynomial to representative
*              in [0,2*Q[.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void dilithium_poly_reduce(dilithium_poly *a) {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N; ++i)
    a->coeffs[i] = dilithium_reduce32(a->coeffs[i]);

}

/*************************************************
* Name:        poly_csubq
*
* Description: For all coefficients of input polynomial subtract Q if
*              coefficient is bigger than Q.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void dilithium_poly_csubq(dilithium_poly *a) {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N; ++i)
    a->coeffs[i] = dilithium_csubq(a->coeffs[i]);

}

/*************************************************
* Name:        poly_freeze
*
* Description: Reduce all coefficients of the polynomial to standard
*              representatives.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void dilithium_poly_freeze(dilithium_poly *a) {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N; ++i)
    a->coeffs[i] = dilithium_freeze(a->coeffs[i]);

}

/*************************************************
* Name:        poly_add
*
* Description: Add polynomials. No modular reduction is performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first summand
*              - const poly *b: pointer to second summand
**************************************************/
void dilithium_poly_add(dilithium_poly *c, const dilithium_poly *a, const dilithium_poly *b)  {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N; ++i)
    c->coeffs[i] = a->coeffs[i] + b->coeffs[i];

}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract polynomials. Assumes coefficients of second input
*              polynomial to be less than 2*Q. No modular reduction is
*              performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial to be
*                               subtraced from first input polynomial
**************************************************/
void dilithium_poly_sub(dilithium_poly *c, const dilithium_poly *a, const dilithium_poly *b) {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N; ++i)
    c->coeffs[i] = a->coeffs[i] + 2*DILITHIUM_Q - b->coeffs[i];

}

/*************************************************
* Name:        poly_neg
*
* Description: Negate polynomial. Assumes input coefficients to be standard
*              representatives.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void dilithium_poly_neg(dilithium_poly *a) {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N; ++i)
    a->coeffs[i] = DILITHIUM_Q - a->coeffs[i];

}

/*************************************************
* Name:        poly_shiftl
*
* Description: Multiply polynomial by 2^D without modular reduction. Assumes
*              input coefficients to be less than 2^{32-D}.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void dilithium_poly_shiftl(dilithium_poly *a) {
    unsigned int i;

    for(i = 0; i < DILITHIUM_N; ++i)
        a->coeffs[i] <<= DILITHIUM_D;
}

/*************************************************
* Name:        poly_ntt
*
* Description: Forward NTT. Output coefficients can be up to 16*Q larger than
*              input coefficients.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void dilithium_poly_ntt(dilithium_poly *a) {
  dilithium_ntt(a->coeffs);
}

/*************************************************
* Name:        poly_invntt_montgomery
*
* Description: Inverse NTT and multiplication with 2^{32}. Input coefficients
*              need to be less than 2*Q. Output coefficients are less than 2*Q.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void dilithium_poly_invntt_montgomery(dilithium_poly *a) {
  dilithium_invntt_frominvmont(a->coeffs);
}

/*************************************************
* Name:        poly_pointwise_invmontgomery
*
* Description: Pointwise multiplication of polynomials in NTT domain
*              representation and multiplication of resulting polynomial
*              with 2^{-32}. Output coefficients are less than 2*Q if input
*              coefficient are less than 22*Q.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void dilithium_poly_pointwise_invmontgomery(dilithium_poly *c, const dilithium_poly *a, const dilithium_poly *b) {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N; ++i)
    c->coeffs[i] = dilithium_montgomery_reduce((uint64_t)a->coeffs[i] * b->coeffs[i]);

}

/*************************************************
* Name:        poly_power2round
*
* Description: For all coefficients c of the input polynomial,
*              compute c0, c1 such that c mod Q = c1*2^D + c0
*              with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients Q + a0
*              - const poly *v: pointer to input polynomial
**************************************************/
void dilithium_poly_power2round(dilithium_poly *a1, dilithium_poly *a0, const dilithium_poly *a) {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N; ++i)
    a1->coeffs[i] = dilithium_power2round(a->coeffs[i], &a0->coeffs[i]);

}

/*************************************************
* Name:        poly_decompose
*
* Description: For all coefficients c of the input polynomial,
*              compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0
*              with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we
*              set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients Q + a0
*              - const poly *c: pointer to input polynomial
**************************************************/
void dilithium_poly_decompose(dilithium_poly *a1, dilithium_poly *a0, const dilithium_poly *a) {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N; ++i)
    a1->coeffs[i] = dilithium_decompose(a->coeffs[i], &a0->coeffs[i]);

}

/*************************************************
* Name:        poly_make_hint
*
* Description: Compute hint polynomial. The coefficients of which indicate
*              whether the high bits of the corresponding coefficients
*              of the first input polynomial and of the sum of the input
*              polynomials differ.
*
* Arguments:   - poly *h: pointer to output hint polynomial
*              - const poly *a0: pointer to low part of input polynomial
*              - const poly *a1: pointer to high part of input polynomial
*
* Returns number of 1 bits.
**************************************************/
unsigned int dilithium_poly_make_hint(dilithium_poly *h,
        const dilithium_poly *a0, const dilithium_poly *a1) {
  unsigned int i, s = 0;

  for(i = 0; i < DILITHIUM_N; ++i) {
    h->coeffs[i] = dilithium_make_hint(a0->coeffs[i], a1->coeffs[i]);
    s += h->coeffs[i];
  }

  return s;
}

/*************************************************
* Name:        poly_use_hint
*
* Description: Use hint polynomial to correct the high bits of a polynomial.
*
* Arguments:   - poly *a: pointer to output polynomial with corrected high bits
*              - const poly *b: pointer to input polynomial
*              - const poly *h: pointer to input hint polynomial
**************************************************/
void dilithium_poly_use_hint(dilithium_poly *a, const dilithium_poly *b, const dilithium_poly *h) {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N; ++i)
    a->coeffs[i] = dilithium_use_hint(b->coeffs[i], h->coeffs[i]);

}

/*************************************************
* Name:        poly_chknorm
*
* Description: Check infinity norm of polynomial against given bound.
*              Assumes input coefficients to be standard representatives.
*
* Arguments:   - const poly *a: pointer to polynomial
*              - uint32_t B: norm bound
*
* Returns 0 if norm is strictly smaller than B and 1 otherwise.
**************************************************/
int dilithium_poly_chknorm(const dilithium_poly *a, uint32_t B) {
  unsigned int i;
  int32_t t;

  /* It is ok to leak which coefficient violates the bound since
     the probability for each coefficient is independent of secret
     data but we must not leak the sign of the centralized representative. */
  for(i = 0; i < DILITHIUM_N; ++i) {
    /* Absolute value of centralized representative */
    t = (DILITHIUM_Q-1)/2 - a->coeffs[i];
    t ^= (t >> 31);
    t = (DILITHIUM_Q-1)/2 - t;

    if((uint32_t)t >= B) {
      return 1;
    }
  }

  return 0;
}

/*************************************************
 * Name:        rej_uniform
 *
 * Description: Sample uniformly random coefficients in [0, Q-1] by
 *              performing rejection sampling using array of random bytes.
 *
 * Arguments:   - uint32_t *a: pointer to output array (allocated)
 *              - unsigned int len: number of coefficients to be sampled
 *              - const unsigned char *buf: array of random bytes
 *              - unsigned int buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/
static unsigned int rej_uniform(uint32_t *a, unsigned int len,
        const unsigned char *buf, unsigned int buflen) {
    unsigned int ctr, pos;
    uint32_t t;

    ctr = pos = 0;
    while(ctr < len && pos + 3 <= buflen) {
        t  = buf[pos++];
        t |= (uint32_t)buf[pos++] << 8;
        t |= (uint32_t)buf[pos++] << 16;
        t &= 0x7FFFFF;

        if(t < DILITHIUM_Q)
            a[ctr++] = t;
    }

    return ctr;
}

/*************************************************
* Name:        poly_uniform
*
* Description: Sample polynomial with uniformly random coefficients
*              in [0,Q-1] by performing rejection sampling using the
*              output stream from SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char seed[]: byte array with seed of length
*                                            SEEDBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
void dilithium_poly_uniform(dilithium_poly *a,
                  const unsigned char seed[DILITHIUM_SEEDBYTES],
                  uint16_t nonce)
{
    unsigned int i, ctr, off;
    unsigned int nblocks = (769 + STREAM128_BLOCKBYTES)/STREAM128_BLOCKBYTES;
    unsigned int buflen = nblocks*STREAM128_BLOCKBYTES;
    unsigned char buf[buflen + 2];
    stream128_state state;

    shake128_stream_init(&state, seed, nonce);
    shake128_squeezeblocks(buf, nblocks, &state);

    ctr = rej_uniform(a->coeffs, DILITHIUM_N, buf, buflen);

    while(ctr < DILITHIUM_N) {
        off = buflen % 3;
        for(i = 0; i < off; ++i)
            buf[i] = buf[buflen - off + i];

        buflen = STREAM128_BLOCKBYTES + off;
        shake128_squeezeblocks(buf + off, 1, &state);
        ctr += rej_uniform(a->coeffs + ctr, DILITHIUM_N - ctr, buf, buflen);
    }
}

/*************************************************
* Name:        rej_eta
*
* Description: Sample uniformly random coefficients in [-ETA, ETA] by
*              performing rejection sampling using array of random bytes.
*
* Arguments:   - uint32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const unsigned char *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_eta(uint32_t *a,
                            unsigned int len,
                            const unsigned char *buf,
                            unsigned int buflen,
                            uint64_t dilithium_eta)
{
  unsigned int ctr, pos;
  uint32_t t0, t1;

  ctr = pos = 0;
  while(ctr < len && pos < buflen) {
      if (dilithium_eta <= 3) {
        t0 = buf[pos] & 0x07;
        t1 = buf[pos++] >> 5;
      } else {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos++] >> 4;
      }

    if (t0 <= 2 * dilithium_eta)
      a[ctr++] = DILITHIUM_Q + dilithium_eta - t0;
    if (t1 <= 2 * dilithium_eta && ctr < len)
      a[ctr++] = DILITHIUM_Q + dilithium_eta - t1;
  }

  return ctr;
}

/*************************************************
* Name:        poly_uniform_eta
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-ETA,ETA] by performing rejection sampling using the
*              output stream from SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char seed[]: byte array with seed of length
*                                            SEEDBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
void dilithium_poly_uniform_eta(dilithium_poly *a,
                      const unsigned char seed[DILITHIUM_SEEDBYTES],
                      uint16_t nonce, uint64_t dilithium_eta,
                      uint64_t dilithium_setabits)
{
    unsigned int ctr;
    unsigned int nblocks = ((DILITHIUM_N/2 * (1U << dilithium_setabits)) / (2*dilithium_eta + 1)
                          + STREAM128_BLOCKBYTES) / STREAM128_BLOCKBYTES;
    unsigned int buflen = nblocks*STREAM128_BLOCKBYTES;
    unsigned char buf[buflen];
    stream128_state state;

    shake128_stream_init(&state, seed, nonce);
    shake128_squeezeblocks(buf, nblocks, &state);

    ctr = rej_eta(a->coeffs, DILITHIUM_N, buf, buflen, dilithium_eta);

    while(ctr < DILITHIUM_N) {
        shake128_squeezeblocks(buf, 1, &state);
        ctr += rej_eta(a->coeffs + ctr, DILITHIUM_N - ctr, buf, STREAM128_BLOCKBYTES, dilithium_eta);
    }
}

/*************************************************
* Name:        rej_gamma1m1
*
* Description: Sample uniformly random coefficients
*              in [-(GAMMA1 - 1), GAMMA1 - 1] by performing rejection sampling
*              using array of random bytes.
*
* Arguments:   - uint32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const unsigned char *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_gamma1m1(uint32_t *a,
                                 unsigned int len,
                                 const unsigned char *buf,
                                 unsigned int buflen)
{
#if DILITHIUM_GAMMA1 > (1 << 19)
#error "rej_gamma1m1() assumes GAMMA1 - 1 fits in 19 bits"
#endif
  unsigned int ctr, pos;
  uint32_t t0, t1;

  ctr = pos = 0;
  while(ctr < len && pos + 5 <= buflen) {
    t0  = buf[pos];
    t0 |= (uint32_t)buf[pos + 1] << 8;
    t0 |= (uint32_t)buf[pos + 2] << 16;
    t0 &= 0xFFFFF;

    t1  = buf[pos + 2] >> 4;
    t1 |= (uint32_t)buf[pos + 3] << 4;
    t1 |= (uint32_t)buf[pos + 4] << 12;

    pos += 5;

    if(t0 <= 2*DILITHIUM_GAMMA1 - 2)
      a[ctr++] = DILITHIUM_Q + DILITHIUM_GAMMA1 - 1 - t0;
    if(t1 <= 2*DILITHIUM_GAMMA1 - 2 && ctr < len)
      a[ctr++] = DILITHIUM_Q + DILITHIUM_GAMMA1 - 1 - t1;
  }

  return ctr;
}

/*************************************************
* Name:        poly_uniform_gamma1m1
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-(GAMMA1 - 1), GAMMA1 - 1] by performing rejection
*              sampling on output stream of SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char seed[]: byte array with seed of length
*                                            CRHBYTES
*              - uint16_t nonce: 16-bit nonce
**************************************************/
void dilithium_poly_uniform_gamma1m1(dilithium_poly *a,
                           const unsigned char seed[DILITHIUM_CRHBYTES],
                           uint16_t nonce)
{
    unsigned int i, ctr, off;
    unsigned int nblocks = (641 + STREAM256_BLOCKBYTES) / STREAM256_BLOCKBYTES;
    unsigned int buflen = nblocks * STREAM256_BLOCKBYTES;
    unsigned char buf[buflen + 4];
    stream256_state state;

    shake256_stream_init(&state, seed, nonce);
    shake256_squeezeblocks(buf, nblocks, &state);

    ctr = rej_gamma1m1(a->coeffs, DILITHIUM_N, buf, buflen);

    while(ctr < DILITHIUM_N) {
        off = buflen % 5;
        for(i = 0; i < off; ++i)
            buf[i] = buf[buflen - off + i];

        buflen = STREAM256_BLOCKBYTES + off;
        shake256_squeezeblocks(buf + off, 1, &state);
        ctr += rej_gamma1m1(a->coeffs + ctr, DILITHIUM_N - ctr, buf, buflen);
    }
}

/*************************************************
* Name:        polyeta_pack
*
* Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
*              Input coefficients are assumed to lie in [Q-ETA,Q+ETA].
*
* Arguments:   - unsigned char *r: pointer to output byte array with at least
*                                  POLETA_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void dilithium_polyeta_pack(unsigned char *r, const dilithium_poly *a, uint64_t dilithium_eta) {
  unsigned int i;
  unsigned char t[8];

    if (2*dilithium_eta <= 7) {
        for(i = 0; i < DILITHIUM_N/8; ++i) {
            t[0] = DILITHIUM_Q + dilithium_eta - a->coeffs[8*i+0];
            t[1] = DILITHIUM_Q + dilithium_eta - a->coeffs[8*i+1];
            t[2] = DILITHIUM_Q + dilithium_eta - a->coeffs[8*i+2];
            t[3] = DILITHIUM_Q + dilithium_eta - a->coeffs[8*i+3];
            t[4] = DILITHIUM_Q + dilithium_eta - a->coeffs[8*i+4];
            t[5] = DILITHIUM_Q + dilithium_eta - a->coeffs[8*i+5];
            t[6] = DILITHIUM_Q + dilithium_eta - a->coeffs[8*i+6];
            t[7] = DILITHIUM_Q + dilithium_eta - a->coeffs[8*i+7];

            r[3*i+0]  = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
            r[3*i+1]  = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
            r[3*i+2]  = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
        }
    } else {
        for(i = 0; i < DILITHIUM_N/2; ++i) {
            t[0] = DILITHIUM_Q + dilithium_eta - a->coeffs[2*i+0];
            t[1] = DILITHIUM_Q + dilithium_eta - a->coeffs[2*i+1];
            r[i] = t[0] | (t[1] << 4);
        }
    }

}

/*************************************************
* Name:        polyeta_unpack
*
* Description: Unpack polynomial with coefficients in [-ETA,ETA].
*              Output coefficients lie in [Q-ETA,Q+ETA].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const unsigned char *a: byte array with bit-packed polynomial
**************************************************/
void dilithium_polyeta_unpack(dilithium_poly *r, const unsigned char *a, uint64_t dilithium_eta) {
    unsigned int i;

    if (2*dilithium_eta <= 7) {
        for(i = 0; i < DILITHIUM_N/8; ++i) {
            r->coeffs[8*i+0] = a[3*i+0] & 0x07;
            r->coeffs[8*i+1] = (a[3*i+0] >> 3) & 0x07;
            r->coeffs[8*i+2] = ((a[3*i+0] >> 6) | (a[3*i+1] << 2)) & 0x07;
            r->coeffs[8*i+3] = (a[3*i+1] >> 1) & 0x07;
            r->coeffs[8*i+4] = (a[3*i+1] >> 4) & 0x07;
            r->coeffs[8*i+5] = ((a[3*i+1] >> 7) | (a[3*i+2] << 1)) & 0x07;
            r->coeffs[8*i+6] = (a[3*i+2] >> 2) & 0x07;
            r->coeffs[8*i+7] = (a[3*i+2] >> 5) & 0x07;

            r->coeffs[8*i+0] = DILITHIUM_Q + dilithium_eta - r->coeffs[8*i+0];
            r->coeffs[8*i+1] = DILITHIUM_Q + dilithium_eta - r->coeffs[8*i+1];
            r->coeffs[8*i+2] = DILITHIUM_Q + dilithium_eta - r->coeffs[8*i+2];
            r->coeffs[8*i+3] = DILITHIUM_Q + dilithium_eta - r->coeffs[8*i+3];
            r->coeffs[8*i+4] = DILITHIUM_Q + dilithium_eta - r->coeffs[8*i+4];
            r->coeffs[8*i+5] = DILITHIUM_Q + dilithium_eta - r->coeffs[8*i+5];
            r->coeffs[8*i+6] = DILITHIUM_Q + dilithium_eta - r->coeffs[8*i+6];
            r->coeffs[8*i+7] = DILITHIUM_Q + dilithium_eta - r->coeffs[8*i+7];
        }
    } else {
        for(i = 0; i < DILITHIUM_N/2; ++i) {
            r->coeffs[2*i+0] = a[i] & 0x0F;
            r->coeffs[2*i+1] = a[i] >> 4;
            r->coeffs[2*i+0] = DILITHIUM_Q + dilithium_eta - r->coeffs[2*i+0];
            r->coeffs[2*i+1] = DILITHIUM_Q + dilithium_eta - r->coeffs[2*i+1];
        }
    }

}

/*************************************************
* Name:        polyt1_pack
*
* Description: Bit-pack polynomial t1 with coefficients fitting in 9 bits.
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - unsigned char *r: pointer to output byte array with at least
*                                  POLT1_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void dilithium_polyt1_pack(unsigned char *r, const dilithium_poly *a) {
#if DILITHIUM_D != 14
#error "polyt1_pack() assumes D == 14"
#endif
    unsigned int i;

    for(i = 0; i < DILITHIUM_N/8; ++i) {
        r[9*i+0]  = (a->coeffs[8*i+0] >> 0);
        r[9*i+1]  = (a->coeffs[8*i+0] >> 8) | (a->coeffs[8*i+1] << 1);
        r[9*i+2]  = (a->coeffs[8*i+1] >> 7) | (a->coeffs[8*i+2] << 2);
        r[9*i+3]  = (a->coeffs[8*i+2] >> 6) | (a->coeffs[8*i+3] << 3);
        r[9*i+4]  = (a->coeffs[8*i+3] >> 5) | (a->coeffs[8*i+4] << 4);
        r[9*i+5]  = (a->coeffs[8*i+4] >> 4) | (a->coeffs[8*i+5] << 5);
        r[9*i+6]  = (a->coeffs[8*i+5] >> 3) | (a->coeffs[8*i+6] << 6);
        r[9*i+7]  = (a->coeffs[8*i+6] >> 2) | (a->coeffs[8*i+7] << 7);
        r[9*i+8]  = (a->coeffs[8*i+7] >> 1);
    }

}

/*************************************************
* Name:        polyt1_unpack
*
* Description: Unpack polynomial t1 with 9-bit coefficients.
*              Output coefficients are standard representatives.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const unsigned char *a: byte array with bit-packed polynomial
**************************************************/
void dilithium_polyt1_unpack(dilithium_poly *r, const unsigned char *a) {
    unsigned int i;

    for(i = 0; i < DILITHIUM_N/8; ++i) {
        r->coeffs[8*i+0] = ((a[9*i+0] >> 0) | ((uint32_t)a[9*i+1] << 8)) & 0x1FF;
        r->coeffs[8*i+1] = ((a[9*i+1] >> 1) | ((uint32_t)a[9*i+2] << 7)) & 0x1FF;
        r->coeffs[8*i+2] = ((a[9*i+2] >> 2) | ((uint32_t)a[9*i+3] << 6)) & 0x1FF;
        r->coeffs[8*i+3] = ((a[9*i+3] >> 3) | ((uint32_t)a[9*i+4] << 5)) & 0x1FF;
        r->coeffs[8*i+4] = ((a[9*i+4] >> 4) | ((uint32_t)a[9*i+5] << 4)) & 0x1FF;
        r->coeffs[8*i+5] = ((a[9*i+5] >> 5) | ((uint32_t)a[9*i+6] << 3)) & 0x1FF;
        r->coeffs[8*i+6] = ((a[9*i+6] >> 6) | ((uint32_t)a[9*i+7] << 2)) & 0x1FF;
        r->coeffs[8*i+7] = ((a[9*i+7] >> 7) | ((uint32_t)a[9*i+8] << 1)) & 0x1FF;
    }

}

/*************************************************
* Name:        polyt0_pack
*
* Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
*              Input coefficients are assumed to lie in ]Q-2^{D-1}, Q+2^{D-1}].
*
* Arguments:   - unsigned char *r: pointer to output byte array with at least
*                                  POLT0_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void dilithium_polyt0_pack(unsigned char *r, const dilithium_poly *a) {
  unsigned int i;
  uint32_t t[4];

  for(i = 0; i < DILITHIUM_N/4; ++i) {
    t[0] = DILITHIUM_Q + (1U << (DILITHIUM_D-1)) - a->coeffs[4*i+0];
    t[1] = DILITHIUM_Q + (1U << (DILITHIUM_D-1)) - a->coeffs[4*i+1];
    t[2] = DILITHIUM_Q + (1U << (DILITHIUM_D-1)) - a->coeffs[4*i+2];
    t[3] = DILITHIUM_Q + (1U << (DILITHIUM_D-1)) - a->coeffs[4*i+3];

    r[7*i+0]  =  t[0];
    r[7*i+1]  =  t[0] >> 8;
    r[7*i+1] |=  t[1] << 6;
    r[7*i+2]  =  t[1] >> 2;
    r[7*i+3]  =  t[1] >> 10;
    r[7*i+3] |=  t[2] << 4;
    r[7*i+4]  =  t[2] >> 4;
    r[7*i+5]  =  t[2] >> 12;
    r[7*i+5] |=  t[3] << 2;
    r[7*i+6]  =  t[3] >> 6;
  }

}

/*************************************************
* Name:        polyt0_unpack
*
* Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
*              Output coefficients lie in ]Q-2^{D-1},Q+2^{D-1}].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const unsigned char *a: byte array with bit-packed polynomial
**************************************************/
void dilithium_polyt0_unpack(dilithium_poly *r, const unsigned char *a) {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N/4; ++i) {
    r->coeffs[4*i+0]  = a[7*i+0];
    r->coeffs[4*i+0] |= (uint32_t)(a[7*i+1] & 0x3F) << 8;

    r->coeffs[4*i+1]  = a[7*i+1] >> 6;
    r->coeffs[4*i+1] |= (uint32_t)a[7*i+2] << 2;
    r->coeffs[4*i+1] |= (uint32_t)(a[7*i+3] & 0x0F) << 10;

    r->coeffs[4*i+2]  = a[7*i+3] >> 4;
    r->coeffs[4*i+2] |= (uint32_t)a[7*i+4] << 4;
    r->coeffs[4*i+2] |= (uint32_t)(a[7*i+5] & 0x03) << 12;

    r->coeffs[4*i+3]  = a[7*i+5] >> 2;
    r->coeffs[4*i+3] |= (uint32_t)a[7*i+6] << 6;

    r->coeffs[4*i+0] = DILITHIUM_Q + (1U << (DILITHIUM_D-1)) - r->coeffs[4*i+0];
    r->coeffs[4*i+1] = DILITHIUM_Q + (1U << (DILITHIUM_D-1)) - r->coeffs[4*i+1];
    r->coeffs[4*i+2] = DILITHIUM_Q + (1U << (DILITHIUM_D-1)) - r->coeffs[4*i+2];
    r->coeffs[4*i+3] = DILITHIUM_Q + (1U << (DILITHIUM_D-1)) - r->coeffs[4*i+3];
  }
}

/*************************************************
* Name:        polyz_pack
*
* Description: Bit-pack polynomial z with coefficients
*              in [-(GAMMA1 - 1), GAMMA1 - 1].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - unsigned char *r: pointer to output byte array with at least
*                                  POLZ_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void dilithium_polyz_pack(unsigned char *r, const dilithium_poly *a) {
#if DILITHIUM_GAMMA1 > (1 << 19)
#error "polyz_pack() assumes GAMMA1 <= 2^{19}"
#endif
  unsigned int i;
  uint32_t t[2];

  for(i = 0; i < DILITHIUM_N/2; ++i) {
    /* Map to {0,...,2*GAMMA1 - 2} */
    t[0] = DILITHIUM_GAMMA1 - 1 - a->coeffs[2*i+0];
    t[0] += ((int32_t)t[0] >> 31) & DILITHIUM_Q;
    t[1] = DILITHIUM_GAMMA1 - 1 - a->coeffs[2*i+1];
    t[1] += ((int32_t)t[1] >> 31) & DILITHIUM_Q;

    r[5*i+0]  = t[0];
    r[5*i+1]  = t[0] >> 8;
    r[5*i+2]  = t[0] >> 16;
    r[5*i+2] |= t[1] << 4;
    r[5*i+3]  = t[1] >> 4;
    r[5*i+4]  = t[1] >> 12;
  }
}

/*************************************************
* Name:        polyz_unpack
*
* Description: Unpack polynomial z with coefficients
*              in [-(GAMMA1 - 1), GAMMA1 - 1].
*              Output coefficients are standard representatives.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const unsigned char *a: byte array with bit-packed polynomial
**************************************************/
void dilithium_polyz_unpack(dilithium_poly *r, const unsigned char *a) {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N/2; ++i) {
    r->coeffs[2*i+0]  = a[5*i+0];
    r->coeffs[2*i+0] |= (uint32_t)a[5*i+1] << 8;
    r->coeffs[2*i+0] |= (uint32_t)(a[5*i+2] & 0x0F) << 16;

    r->coeffs[2*i+1]  = a[5*i+2] >> 4;
    r->coeffs[2*i+1] |= (uint32_t)a[5*i+3] << 4;
    r->coeffs[2*i+1] |= (uint32_t)a[5*i+4] << 12;

    r->coeffs[2*i+0] = DILITHIUM_GAMMA1 - 1 - r->coeffs[2*i+0];
    r->coeffs[2*i+0] += ((int32_t)r->coeffs[2*i+0] >> 31) & DILITHIUM_Q;
    r->coeffs[2*i+1] = DILITHIUM_GAMMA1 - 1 - r->coeffs[2*i+1];
    r->coeffs[2*i+1] += ((int32_t)r->coeffs[2*i+1] >> 31) & DILITHIUM_Q;
  }
}

/*************************************************
* Name:        polyw1_pack
*
* Description: Bit-pack polynomial w1 with coefficients in [0, 15].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - unsigned char *r: pointer to output byte array with at least
*                                  POLW1_SIZE_PACKED bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void dilithium_polyw1_pack(unsigned char *r, const dilithium_poly *a) {
  unsigned int i;

  for(i = 0; i < DILITHIUM_N/2; ++i)
    r[i] = a->coeffs[2*i+0] | (a->coeffs[2*i+1] << 4);
}
