#include <stdio.h>
#include "kyber-polyvec.h"
#include "kyber-cbd.h"
#include "kyber-reduce.h"

/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void kyber_polyvec_compress(unsigned char *r, kyber_polyvec *a,
        const uint64_t kyber_k, const uint64_t kyber_polyveccompressedbytes)
{
    kyber_polyvec_csubq(a, kyber_k);

    if (kyber_polyveccompressedbytes == (kyber_k * 352)) {
      uint16_t t[8];
      for(size_t i = 0; i < kyber_k; i++) {
        for(size_t j = 0; j < KYBER_N/8; j++) {
          for(size_t k = 0; k < 8; k++)
              t[k] = ((((uint32_t)a->vec[i].coeffs[8*j+k] << 11) + KYBER_Q/2) / KYBER_Q) & 0x7ff;

          r[11*j+ 0] =  t[0] & 0xff;
          r[11*j+ 1] = (t[0] >>  8) | ((t[1] & 0x1f) << 3);
          r[11*j+ 2] = (t[1] >>  5) | ((t[2] & 0x03) << 6);
          r[11*j+ 3] = (t[2] >>  2) & 0xff;
          r[11*j+ 4] = (t[2] >> 10) | ((t[3] & 0x7f) << 1);
          r[11*j+ 5] = (t[3] >>  7) | ((t[4] & 0x0f) << 4);
          r[11*j+ 6] = (t[4] >>  4) | ((t[5] & 0x01) << 7);
          r[11*j+ 7] = (t[5] >>  1) & 0xff;
          r[11*j+ 8] = (t[5] >>  9) | ((t[6] & 0x3f) << 2);
          r[11*j+ 9] = (t[6] >>  6) | ((t[7] & 0x07) << 5);
          r[11*j+10] = (t[7] >>  3);
        }
        r += 352;
      }
    } else if (kyber_polyveccompressedbytes == (kyber_k * 320)) {
      uint16_t t[4];
      for(size_t i = 0; i < kyber_k; i++) {
        for(size_t j = 0; j < KYBER_N/4; j++) {
          for(size_t k = 0; k < 4; k++)
              t[k] = ((((uint32_t)a->vec[i].coeffs[4*j+k] << 10) + KYBER_Q/2) / KYBER_Q) & 0x3ff;

          r[5*j+ 0] =  t[0] & 0xff;
          r[5*j+ 1] = (t[0] >>  8) | ((t[1] & 0x3f) << 2);
          r[5*j+ 2] = (t[1] >>  6) | ((t[2] & 0x0f) << 4);
          r[5*j+ 3] = (t[2] >>  4) | ((t[3] & 0x03) << 6);
          r[5*j+ 4] = (t[3] >>  2);
        }
        r += 320;
      }
    }
}

/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress
*
* Arguments:   - polyvec *r:       pointer to output vector of polynomials
*              - unsigned char *a: pointer to input byte array
**************************************************/
void kyber_polyvec_decompress(kyber_polyvec *r, const unsigned char *a,
        const uint64_t kyber_k, const uint64_t kyber_polyveccompressedbytes) {
    if (kyber_polyveccompressedbytes == (kyber_k * 352)) {
      for(size_t i = 0; i < kyber_k; i++) {
        for(size_t j = 0; j < KYBER_N/8; j++) {
          r->vec[i].coeffs[8*j+0] =  (((a[11*j+ 0]       | (((uint32_t)a[11*j+ 1] & 0x07) << 8)) * KYBER_Q) +1024) >> 11;
          r->vec[i].coeffs[8*j+1] = ((((a[11*j+ 1] >> 3) | (((uint32_t)a[11*j+ 2] & 0x3f) << 5)) * KYBER_Q) +1024) >> 11;
          r->vec[i].coeffs[8*j+2] = ((((a[11*j+ 2] >> 6) | (((uint32_t)a[11*j+ 3] & 0xff) << 2) |  (((uint32_t)a[11*j+ 4] & 0x01) << 10)) * KYBER_Q) + 1024) >> 11;
          r->vec[i].coeffs[8*j+3] = ((((a[11*j+ 4] >> 1) | (((uint32_t)a[11*j+ 5] & 0x0f) << 7)) * KYBER_Q) + 1024) >> 11;
          r->vec[i].coeffs[8*j+4] = ((((a[11*j+ 5] >> 4) | (((uint32_t)a[11*j+ 6] & 0x7f) << 4)) * KYBER_Q) + 1024) >> 11;
          r->vec[i].coeffs[8*j+5] = ((((a[11*j+ 6] >> 7) | (((uint32_t)a[11*j+ 7] & 0xff) << 1) |  (((uint32_t)a[11*j+ 8] & 0x03) <<  9)) * KYBER_Q) + 1024) >> 11;
          r->vec[i].coeffs[8*j+6] = ((((a[11*j+ 8] >> 2) | (((uint32_t)a[11*j+ 9] & 0x1f) << 6)) * KYBER_Q) + 1024) >> 11;
          r->vec[i].coeffs[8*j+7] = ((((a[11*j+ 9] >> 5) | (((uint32_t)a[11*j+10] & 0xff) << 3)) * KYBER_Q) + 1024) >> 11;
        }
        a += 352;
      }
    } else if (kyber_polyveccompressedbytes == (kyber_k * 320)) {
      for(size_t i = 0; i < kyber_k; i++) {
        for(size_t j = 0; j < KYBER_N/4; j++) {
          r->vec[i].coeffs[4*j+0] =  (((a[5*j+ 0]       | (((uint32_t)a[5*j+ 1] & 0x03) << 8)) * KYBER_Q) + 512) >> 10;
          r->vec[i].coeffs[4*j+1] = ((((a[5*j+ 1] >> 2) | (((uint32_t)a[5*j+ 2] & 0x0f) << 6)) * KYBER_Q) + 512) >> 10;
          r->vec[i].coeffs[4*j+2] = ((((a[5*j+ 2] >> 4) | (((uint32_t)a[5*j+ 3] & 0x3f) << 4)) * KYBER_Q) + 512) >> 10;
          r->vec[i].coeffs[4*j+3] = ((((a[5*j+ 3] >> 6) | (((uint32_t)a[5*j+ 4] & 0xff) << 2)) * KYBER_Q) + 512) >> 10;
        }
        a += 320;
      }
    }
}

/*************************************************
* Name:        polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void kyber_polyvec_tobytes(unsigned char *r, kyber_polyvec *a, const uint64_t kyber_k) {
  for(size_t i = 0; i < kyber_k; i++)
    kyber_poly_tobytes(r+i*KYBER_POLYBYTES, &a->vec[i]);
}

/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes
*
* Arguments:   - unsigned char *r: pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void kyber_polyvec_frombytes(kyber_polyvec *r, const unsigned char *a, const uint64_t kyber_k) {
  for(size_t i = 0; i < kyber_k; i++)
    kyber_poly_frombytes(&r->vec[i], a+i*KYBER_POLYBYTES);
}

/*************************************************
* Name:        polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void kyber_polyvec_ntt(kyber_polyvec *r, const uint64_t kyber_k) {
  for(size_t i = 0; i < kyber_k; i++)
    kyber_poly_ntt(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_invntt
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void kyber_polyvec_invntt(kyber_polyvec *r, const uint64_t kyber_k) {
  for(size_t i = 0; i < kyber_k; i++)
    kyber_poly_invntt(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_pointwise_acc
*
* Description: Pointwise multiply elements of a and b and accumulate into r
*
* Arguments: - poly *r:          pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void kyber_polyvec_pointwise_acc(kyber_poly *r, const kyber_polyvec *a, const kyber_polyvec *b,
        const uint64_t kyber_k) {
  kyber_poly t;

  kyber_poly_basemul(r, &a->vec[0], &b->vec[0]);
  for(size_t i=1;i<kyber_k;i++) {
    kyber_poly_basemul(&t, &a->vec[i], &b->vec[i]);
    kyber_poly_add(r, r, &t);
  }

  kyber_poly_reduce(r);
}

/*************************************************
* Name:        polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - poly *r:       pointer to input/output polynomial
**************************************************/
void kyber_polyvec_reduce(kyber_polyvec *r, const uint64_t kyber_k)
{
  for(size_t i=0;i<kyber_k;i++)
    kyber_poly_reduce(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_csubq
*
* Description: Applies conditional subtraction of q to each coefficient
*              of each element of a vector of polynomials
*              for details of conditional subtraction of q see comments in reduce.c
*
* Arguments:   - poly *r:       pointer to input/output polynomial
**************************************************/
void kyber_polyvec_csubq(kyber_polyvec *r, const uint64_t kyber_k)
{
  for(size_t i=0;i<kyber_k;i++)
    kyber_poly_csubq(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r:       pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void kyber_polyvec_add(kyber_polyvec *r, const kyber_polyvec *a, const kyber_polyvec *b,
        const uint64_t kyber_k) {
  for(size_t i = 0; i < kyber_k; i++)
    kyber_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);

}
