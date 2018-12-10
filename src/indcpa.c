#include <string.h>
#include "indcpa.h"
#include "poly.h"
#include "polyvec.h"
#include "fips202.h"
#include "ntt.h"

#include "KYBER_KeyGen_fp.h"
// Random functions from TPM
#include "Tpm.h"
#include "CryptRand_fp.h"

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              compressed and serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   unsigned char *r:          pointer to the output serialized public key
*              const poly *pk:            pointer to the input public-key polynomial
*              const unsigned char *seed: pointer to the input public seed
**************************************************/
static void pack_pk(unsigned char *r, const polyvec *pk,
        const unsigned char *seed, const uint64_t kyber_k,
        const uint64_t kyber_polyveccompressedbytes) {
  polyvec_compress(r, pk, kyber_k, kyber_polyveccompressedbytes);
  for(size_t i = 0; i < KYBER_SYMBYTES; i++)
    r[i+kyber_polyveccompressedbytes] = seed[i];
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize and decompress public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk:                   pointer to output public-key vector of polynomials
*              - unsigned char *seed:           pointer to output seed to generate matrix A
*              - const unsigned char *packedpk: pointer to input serialized public key
**************************************************/
//static void unpack_pk(polyvec *pk, unsigned char *seed,
//        const unsigned char *packedpk, const uint64_t kyber_k,
//        const uint64_t kyber_polyveccompressedbytes) {
//  polyvec_decompress(pk, packedpk, kyber_k);
//
//  for(size_t i = 0; i < KYBER_SYMBYTES; i++)
//    seed[i] = packedpk[i+kyber_polyveccompressedbytes];
//}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   unsigned char *r:          pointer to the output serialized ciphertext
*              const poly *pk:            pointer to the input vector of polynomials b
*              const unsigned char *seed: pointer to the input polynomial v
**************************************************/
//static void pack_ciphertext(unsigned char *r, const polyvec *b, const poly *v,
//        const uint64_t kyber_k, const uint64_t kyber_polyveccompressedbytes) {
//  polyvec_compress(r, b, kyber_k);
//  poly_compress(r+kyber_polyveccompressedbytes, v);
//}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b:             pointer to the output vector of polynomials b
*              - poly *v:                pointer to the output polynomial v
*              - const unsigned char *c: pointer to the input serialized ciphertext
**************************************************/
//static void unpack_ciphertext(polyvec *b, poly *v, const unsigned char *c,
//        const uint64_t kyber_k, const uint64_t kyber_polyveccompressedbytes) {
//  polyvec_decompress(b, c, kyber_k);
//  poly_decompress(v, c+kyber_polyveccompressedbytes);
//}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - unsigned char *r:  pointer to output serialized secret key
*              - const polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(unsigned char *r, const polyvec *sk, const uint64_t kyber_k) {
  polyvec_tobytes(r, sk, kyber_k);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key;
*              inverse of pack_sk
*
* Arguments:   - polyvec *sk:                   pointer to output vector of polynomials (secret key)
*              - const unsigned char *packedsk: pointer to input serialized secret key
**************************************************/
//static void unpack_sk(polyvec *sk, const unsigned char *packedsk, const uint64_t kyber_k) {
//  polyvec_frombytes(sk, packedsk, kyber_k);
//}

#define gen_a(A,B,C)  gen_matrix(A,B,0,C)
#define gen_at(A,B,C) gen_matrix(A,B,1,C)

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              SHAKE-128
*
* Arguments:   - polyvec *a:                pointer to ouptput matrix A
*              - const unsigned char *seed: pointer to input seed
*              - int transposed:            boolean deciding whether A or A^T is generated
**************************************************/
static void gen_matrix(polyvec *a, const unsigned char *seed, int transposed, const uint64_t kyber_k) {
  unsigned int pos=0, ctr;
  uint16_t val;
  unsigned int nblocks;
  const unsigned int maxnblocks=4;
  uint8_t buf[SHAKE128_RATE*maxnblocks];
  int i,j;
  uint64_t state[25]; // SHAKE state
  unsigned char extseed[KYBER_SYMBYTES+2];

  for(i=0;i<KYBER_SYMBYTES;i++)
    extseed[i] = seed[i];


  for(i = 0; i < (int)kyber_k; i++) {
    for(j = 0; j < (int)kyber_k; j++) {
      ctr = pos = 0;
      nblocks = maxnblocks;
      if(transposed) {
        extseed[KYBER_SYMBYTES]   = i;
        extseed[KYBER_SYMBYTES+1] = j;
      } else {
        extseed[KYBER_SYMBYTES]   = j;
        extseed[KYBER_SYMBYTES+1] = i;
      }

      shake128_absorb(state,extseed,KYBER_SYMBYTES+2);
      shake128_squeezeblocks(buf,nblocks,state);

      while(ctr < KYBER_N) {
        val = (buf[pos] | ((uint16_t) buf[pos+1] << 8)) & 0x1fff;
        if(val < KYBER_Q) {
            a[i].vec[j].coeffs[ctr++] = val;
        }
        pos += 2;

        if(pos > SHAKE128_RATE*nblocks-2) {
          nblocks = 1;
          shake128_squeezeblocks(buf,nblocks,state);
          pos = 0;
        }
      }
    }
  }
}


/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - unsigned char *pk: pointer to output public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
void indcpa_keypair(unsigned char *pk,
                   unsigned char *sk, const uint64_t kyber_k,
                   const uint64_t kyber_polyveccompressedbytes,
                   const uint64_t kyber_eta) {
  polyvec a[kyber_k], e, pkpv, skpv;
  unsigned char buf[KYBER_SYMBYTES+KYBER_SYMBYTES];
  unsigned char *publicseed = buf;
  unsigned char *noiseseed = buf+KYBER_SYMBYTES;
  unsigned char nonce=0;

  CryptRandomGenerate(KYBER_SYMBYTES, buf);
  sha3_512(buf, buf, KYBER_SYMBYTES);

  gen_a(a, publicseed, kyber_k);

  for(size_t i = 0; i < kyber_k; i++)
    poly_getnoise(skpv.vec+i, noiseseed, nonce++, kyber_eta);

  polyvec_ntt(&skpv, kyber_k);

  for(size_t i = 0; i < kyber_k; i++)
    poly_getnoise(e.vec+i, noiseseed, nonce++, kyber_eta);

  // matrix-vector multiplication
  for(size_t i = 0; i < kyber_k; i++)
    polyvec_pointwise_acc(&pkpv.vec[i], &skpv, a + i, kyber_k);

  polyvec_invntt(&pkpv, kyber_k);
  polyvec_add(&pkpv,&pkpv,&e, kyber_k);

  pack_sk(sk, &skpv, kyber_k);
  pack_pk(pk, &pkpv, publicseed, kyber_k, kyber_polyveccompressedbytes);
}


/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - unsigned char *c:          pointer to output ciphertext (of length KYBER_INDCPA_BYTES bytes)
*              - const unsigned char *m:    pointer to input message (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const unsigned char *pk:   pointer to input public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - const unsigned char *coin: pointer to input random coins used as seed (of length KYBER_SYMBYTES bytes)
*                                           to deterministically generate all randomness
**************************************************/
//void indcpa_enc(unsigned char *c,
//               const unsigned char *m,
//               const unsigned char *pk,
//               const unsigned char *coins)
//{
//  polyvec sp, pkpv, ep, at[KYBER_K], bp;
//  poly v, k, epp;
//  unsigned char seed[KYBER_SYMBYTES];
//  int i;
//  unsigned char nonce=0;
//
//
//  unpack_pk(&pkpv, seed, pk);
//
//  poly_frommsg(&k, m);
//
//  polyvec_ntt(&pkpv, kyber_k);
//
//  gen_at(at, seed, kyber_k);
//
//  for(i=0;i<KYBER_K;i++)
//    poly_getnoise(sp.vec+i,coins,nonce++);
//
//  polyvec_ntt(&sp);
//
//  for(i=0;i<KYBER_K;i++)
//    poly_getnoise(ep.vec+i,coins,nonce++);
//
//  // matrix-vector multiplication
//  for(i=0;i<KYBER_K;i++)
//    polyvec_pointwise_acc(&bp.vec[i],&sp,at+i);
//
//  polyvec_invntt(&bp);
//  polyvec_add(&bp, &bp, &ep);
//
//  polyvec_pointwise_acc(&v, &pkpv, &sp);
//  poly_invntt(&v);
//
//  poly_getnoise(&epp,coins,nonce++);
//
//  poly_add(&v, &v, &epp);
//  poly_add(&v, &v, &k);
//
//  pack_ciphertext(c, &bp, &v);
//}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - unsigned char *m:        pointer to output decrypted message (of length KYBER_INDCPA_MSGBYTES)
*              - const unsigned char *c:  pointer to input ciphertext (of length KYBER_INDCPA_BYTES)
*              - const unsigned char *sk: pointer to input secret key (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
//void indcpa_dec(unsigned char *m,
//               const unsigned char *c,
//               const unsigned char *sk)
//{
//  polyvec bp, skpv;
//  poly v, mp;
//
//  unpack_ciphertext(&bp, &v, c);
//  unpack_sk(&skpv, sk);
//
//  polyvec_ntt(&bp);
//
//  polyvec_pointwise_acc(&mp,&skpv,&bp);
//  poly_invntt(&mp);
//
//  poly_sub(&mp, &mp, &v);
//
//  poly_tomsg(m, &mp);
//}
