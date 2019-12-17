#include <stddef.h>
#include "Tpm.h"
#include "nttru-crypto-stream.h"
#include "nttru-params.h"
#include "nttru.h"
#include "nttru-kem.h"
#include "nttru-poly.h"

static const unsigned char n[16] = {0};

int nttru_crypto_kem_keypair(unsigned char *pk, unsigned char *sk, RAND_STATE *rand) {
  unsigned int i;
  unsigned char coins[NTTRU_N];
  nttru_poly hhat, fhat;

  do {
    DRBG_Generate(rand, (unsigned char*) &coins, 32);
    nttru_crypto_stream(coins, NTTRU_N, n, coins);
  } while(nttru_keygen(&hhat, &fhat, coins));

  nttru_poly_pack_uniform(pk, &hhat);
  nttru_poly_pack_uniform(sk, &fhat);
  for(i = 0; i < NTTRU_PUBLICKEYBYTES; ++i)
    sk[i + NTTRU_POLY_PACKED_UNIFORM_BYTES] = pk[i];

  return 0;
}

int nttru_crypto_kem_enc(unsigned char *c, unsigned char *k, const unsigned char *pk, RAND_STATE *rand) {
  unsigned int i;
  unsigned char buf[32 + NTTRU_COINBYTES];
  nttru_poly hhat, chat, m;

  DRBG_Generate(rand, (unsigned char*) &buf, 32);
  nttru_crypto_stream(buf, NTTRU_N/2, n, buf);
  nttru_poly_short(&m, buf);
  nttru_poly_pack_short(buf, &m);
  CryptHashBlock(TPM_ALG_SHA512,
          NTTRU_MSGBYTES, buf,
          2*NTTRU_MSGBYTES, buf);
  nttru_crypto_stream(buf + 32, NTTRU_COINBYTES, n, buf + 32);

  nttru_poly_unpack_uniform(&hhat, pk);
  nttru_encrypt(&chat, &hhat, &m, buf + 32);
  nttru_poly_pack_uniform(c, &chat);

  for (i = 0; i < NTTRU_SHAREDKEYBYTES; ++i)
    k[i] = buf[i];

  return 0;
}

int nttru_crypto_kem_dec(unsigned char *k,
                   const unsigned char *c,
                   const unsigned char *sk)
{
  unsigned int i;
  unsigned char buf[32 + NTTRU_COINBYTES];
  int16_t t;
  int32_t fail;
  nttru_poly m, hhat, chat, fhat;

  nttru_poly_unpack_uniform(&chat, c);
  nttru_poly_unpack_uniform(&fhat, sk);
  nttru_decrypt(&m, &chat, &fhat);

  nttru_poly_pack_short(buf, &m);
  CryptHashBlock(TPM_ALG_SHA512,
          NTTRU_MSGBYTES, buf,
          2*NTTRU_MSGBYTES, buf);
  nttru_crypto_stream(buf + 32, NTTRU_COINBYTES, n, buf + 32);

  nttru_poly_unpack_uniform(&hhat, sk + NTTRU_POLY_PACKED_UNIFORM_BYTES);
  nttru_encrypt(&fhat, &hhat, &m, buf + 32);

  t = 0;
  for(i = 0; i < NTTRU_N; ++i)
    t |= chat.coeffs[i] ^ fhat.coeffs[i];

  fail = (uint16_t)t;
  fail = (-fail) >> 31;
  for(i = 0; i < NTTRU_SHAREDKEYBYTES; ++i)
    k[i] = buf[i] & ~(-fail);

  return fail;
}
