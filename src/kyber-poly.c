#include <stdio.h>
#include "kyber-poly.h"
#include "kyber-ntt.h"
#include "kyber-polyvec.h"
#include "kyber-reduce.h"
#include "kyber-cbd.h"
#include "Tpm.h"

/*************************************************
* Name:        poly_compress
*
* Description: Compression and subsequent serialization of a polynomial
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const poly *a:    pointer to input polynomial
**************************************************/
void kyber_poly_compress(unsigned char *r, kyber_poly *a, uint64_t kyber_polycompressedbytes) {
  uint8_t t[8];
  int i,j,k=0;

  kyber_poly_csubq(a);

  if (kyber_polycompressedbytes == 96) {
      for(i=0;i<KYBER_N;i+=8)
      {
          for(j=0;j<8;j++)
              t[j] = ((((uint32_t)a->coeffs[i+j] << 3) + KYBER_Q/2) / KYBER_Q) & 7;

          r[k]   =  t[0]       | (t[1] << 3) | (t[2] << 6);
          r[k+1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
          r[k+2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
          k += 3;
      }
  } else if (kyber_polycompressedbytes == 128) {
      for(i=0;i<KYBER_N;i+=8)
      {
          for(j=0;j<8;j++)
              t[j] = ((((uint32_t)a->coeffs[i+j] << 4) + KYBER_Q/2) / KYBER_Q) & 15;

          r[k]   = t[0] | (t[1] << 4);
          r[k+1] = t[2] | (t[3] << 4);
          r[k+2] = t[4] | (t[5] << 4);
          r[k+3] = t[6] | (t[7] << 4);
          k += 4;
      }
  } else if (kyber_polycompressedbytes == 160) {
      for(i=0;i<KYBER_N;i+=8)
      {
          for(j=0;j<8;j++)
              t[j] = ((((uint32_t)a->coeffs[i+j] << 5) + KYBER_Q/2) / KYBER_Q) & 31;

          r[k]   =  t[0]       | (t[1] << 5);
          r[k+1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
          r[k+2] = (t[3] >> 1) | (t[4] << 4);
          r[k+3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
          r[k+4] = (t[6] >> 2) | (t[7] << 3);
          k += 5;
      }
  }
}

/*************************************************
* Name:        poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              approximate inverse of poly_compress
*
* Arguments:   - poly *r:                pointer to output polynomial
*              - const unsigned char *a: pointer to input byte array
**************************************************/
void kyber_poly_decompress(kyber_poly *r, const unsigned char *a, uint64_t kyber_polycompressedbytes) {
  int i;

  if (kyber_polycompressedbytes == 96) {
      for(i=0;i<KYBER_N;i+=8)
      {
          r->coeffs[i+0] =  (((a[0] & 7) * KYBER_Q) + 4) >> 3;
          r->coeffs[i+1] = ((((a[0] >> 3) & 7) * KYBER_Q) + 4) >> 3;
          r->coeffs[i+2] = ((((a[0] >> 6) | ((a[1] << 2) & 4)) * KYBER_Q) + 4) >> 3;
          r->coeffs[i+3] = ((((a[1] >> 1) & 7) * KYBER_Q) + 4) >> 3;
          r->coeffs[i+4] = ((((a[1] >> 4) & 7) * KYBER_Q) + 4) >> 3;
          r->coeffs[i+5] = ((((a[1] >> 7) | ((a[2] << 1) & 6)) * KYBER_Q) + 4) >> 3;
          r->coeffs[i+6] = ((((a[2] >> 2) & 7) * KYBER_Q) + 4) >> 3;
          r->coeffs[i+7] = ((((a[2] >> 5)) * KYBER_Q) + 4) >> 3;
          a += 3;
      }
  } else if (kyber_polycompressedbytes == 128) {
      for(i=0;i<KYBER_N;i+=8)
      {
          r->coeffs[i+0] = (((a[0] & 15) * KYBER_Q) + 8) >> 4;
          r->coeffs[i+1] = (((a[0] >> 4) * KYBER_Q) + 8) >> 4;
          r->coeffs[i+2] = (((a[1] & 15) * KYBER_Q) + 8) >> 4;
          r->coeffs[i+3] = (((a[1] >> 4) * KYBER_Q) + 8) >> 4;
          r->coeffs[i+4] = (((a[2] & 15) * KYBER_Q) + 8) >> 4;
          r->coeffs[i+5] = (((a[2] >> 4) * KYBER_Q) + 8) >> 4;
          r->coeffs[i+6] = (((a[3] & 15) * KYBER_Q) + 8) >> 4;
          r->coeffs[i+7] = (((a[3] >> 4) * KYBER_Q) + 8) >> 4;
          a += 4;
      }
  } else if (kyber_polycompressedbytes == 160) {
      for(i=0;i<KYBER_N;i+=8)
      {
          r->coeffs[i+0] =  (((a[0] & 31) * KYBER_Q) + 16) >> 5;
          r->coeffs[i+1] = ((((a[0] >> 5) | ((a[1] & 3) << 3)) * KYBER_Q) + 16) >> 5;
          r->coeffs[i+2] = ((((a[1] >> 2) & 31) * KYBER_Q) + 16) >> 5;
          r->coeffs[i+3] = ((((a[1] >> 7) | ((a[2] & 15) << 1)) * KYBER_Q) + 16) >> 5;
          r->coeffs[i+4] = ((((a[2] >> 4) | ((a[3] &  1) << 4)) * KYBER_Q) + 16) >> 5;
          r->coeffs[i+5] = ((((a[3] >> 1) & 31) * KYBER_Q) + 16) >> 5;
          r->coeffs[i+6] = ((((a[3] >> 6) | ((a[4] &  7) << 2)) * KYBER_Q) + 16) >> 5;
          r->coeffs[i+7] =  (((a[4] >> 3) * KYBER_Q) + 16) >> 5;
          a += 5;
      }
  }
}

/*************************************************
* Name:        poly_tobytes
*
* Description: Serialization of a polynomial
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const poly *a:    pointer to input polynomial
**************************************************/
void kyber_poly_tobytes(unsigned char *r, kyber_poly *a) {
  int i;
  uint16_t t0, t1;

  kyber_poly_csubq(a);

  for(i=0;i<KYBER_N/2;i++){
    t0 = a->coeffs[2*i];
    t1 = a->coeffs[2*i+1];
    r[3*i] = t0 & 0xff;
    r[3*i+1] = (t0 >> 8) | ((t1 & 0xf) << 4);
    r[3*i+2] = t1 >> 4;
  }
}

/*************************************************
* Name:        poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of poly_tobytes
*
* Arguments:   - poly *r:                pointer to output polynomial
*              - const unsigned char *a: pointer to input byte array
**************************************************/
void kyber_poly_frombytes(kyber_poly *r, const unsigned char *a) {
  int i;

  for(i=0;i<KYBER_N/2;i++){
    r->coeffs[2*i]   = a[3*i]        | ((uint16_t)a[3*i+1] & 0x0f) << 8;
    r->coeffs[2*i+1] = a[3*i+1] >> 4 | ((uint16_t)a[3*i+2] & 0xff) << 4;
  }
}

/*************************************************
* Name:        poly_getnoise
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA
*
* Arguments:   - poly *r:                   pointer to output polynomial
*              - const unsigned char *seed: pointer to input seed
*              - unsigned char nonce:       one-byte input nonce
**************************************************/
void kyber_poly_getnoise(kyber_poly *r,const unsigned char *seed, unsigned char nonce,
        uint64_t kyber_eta) {
  unsigned char buf[kyber_eta*KYBER_N/4];
  unsigned char extseed[KYBER_SYMBYTES+1];

  for(size_t i = 0; i < KYBER_SYMBYTES; i++)
    extseed[i] = seed[i];
  extseed[KYBER_SYMBYTES] = nonce;

  CryptHashBlock(TPM_ALG_SHAKE256,
          KYBER_SYMBYTES+1, extseed,
          kyber_eta*KYBER_N/4, buf);

  kyber_cbd(r, buf);
}

/*************************************************
* Name:        poly_ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *r: pointer to in/output polynomial
**************************************************/
void kyber_poly_ntt(kyber_poly *r) {
  kyber_ntt(r->coeffs);
  kyber_poly_reduce(r);
}

/*************************************************
* Name:        poly_invntt
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void kyber_poly_invntt(kyber_poly *r) {
  kyber_invntt(r->coeffs);
}


/*************************************************
* Name:        poly_basemul
*
* Description: Multiplication of two polynomials in NTT domain
*
* Arguments:   - poly *r:       pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void kyber_poly_basemul(kyber_poly *r, const kyber_poly *a, const kyber_poly *b)
{
  unsigned int i;

  for(i = 0; i < KYBER_N/4; ++i) {
    basemul(r->coeffs + 4*i, a->coeffs + 4*i, b->coeffs + 4*i, kyber_zetas[64 + i]);
    basemul(r->coeffs + 4*i + 2, a->coeffs + 4*i + 2, b->coeffs + 4*i + 2, -kyber_zetas[64 + i]);
  }
}

/*************************************************
* Name:        poly_frommont
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from Montgomery domain to normal domain
*
* Arguments:   - poly *r:       pointer to input/output polynomial
**************************************************/
void kyber_poly_frommont(kyber_poly *r)
{
  int i;
  const int16_t f = (1ULL << 32) % KYBER_Q;

  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = kyber_montgomery_reduce((int32_t)r->coeffs[i]*f);
}

/*************************************************
* Name:        poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r:       pointer to input/output polynomial
**************************************************/
void kyber_poly_reduce(kyber_poly *r)
{
  int i;

  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = kyber_barrett_reduce(r->coeffs[i]);
}

/*************************************************
* Name:        poly_csubq
*
* Description: Applies conditional subtraction of q to each coefficient of a polynomial
*              for details of conditional subtraction of q see comments in reduce.c
*
* Arguments:   - poly *r:       pointer to input/output polynomial
**************************************************/
void kyber_poly_csubq(kyber_poly *r)
{
  int i;

  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = kyber_csubq(r->coeffs[i]);
}

/*************************************************
* Name:        poly_add
*
* Description: Add two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void kyber_poly_add(kyber_poly *r, const kyber_poly *a, const kyber_poly *b) {
  int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract two polynomials
*
* Arguments: - poly *r:       pointer to output polynomial
*            - const poly *a: pointer to first input polynomial
*            - const poly *b: pointer to second input polynomial
**************************************************/
void kyber_poly_sub(kyber_poly *r, const kyber_poly *a, const kyber_poly *b)
{
  int i;
  for(i=0;i<KYBER_N;i++)
    r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/*************************************************
* Name:        poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r:                  pointer to output polynomial
*              - const unsigned char *msg: pointer to input message
**************************************************/
void kyber_poly_frommsg(kyber_poly *r, const unsigned char msg[KYBER_SYMBYTES])
{
  uint16_t i,j,mask;

  for(i=0;i<KYBER_SYMBYTES;i++) {
    for(j=0;j<8;j++) {
      mask = -((msg[i] >> j)&1);
      r->coeffs[8*i+j] = mask & ((KYBER_Q+1)/2);
    }
  }
}

/*************************************************
* Name:        poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - unsigned char *msg: pointer to output message
*              - const poly *a:      pointer to input polynomial
**************************************************/
void kyber_poly_tomsg(unsigned char msg[KYBER_SYMBYTES], kyber_poly *a) {
  uint16_t t;
  int i,j;

  kyber_poly_csubq(a);

  for(i=0;i<KYBER_SYMBYTES;i++)
  {
    msg[i] = 0;
    for(j=0;j<8;j++)
    {
      t = (((a->coeffs[8*i+j] << 1) + KYBER_Q/2) / KYBER_Q) & 1;
      msg[i] |= t << j;
    }
  }
}
