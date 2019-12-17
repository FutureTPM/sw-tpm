#include <stdint.h>
#include "nttru-params.h"
#include "nttru-fq.h"
#include "Tpm.h"

int16_t nttru_fqmontred(int32_t a) {
  int32_t t;
  int16_t u;

  u = a * NTTRU_QINV;
  t = (int32_t)u * NTTRU_Q;
  t = a - t;
  t >>= 16;
  return t;
}

int16_t nttru_fqred16(int16_t a) {
  int16_t t;

  t = a & 0x1FFF;
  a >>= 13;
  t += (a << 9) - a;
  return t;
}

int16_t nttru_fqcsubq(int16_t a) {
  a += (a >> 15) & NTTRU_Q;
  a -= NTTRU_Q;
  a += (a >> 15) & NTTRU_Q;
  return a;
}

int16_t nttru_fqmul(int16_t a, int16_t b) {
  return nttru_fqmontred((int32_t)a*b);
}

int16_t nttru_fqinv(int16_t a) {
  unsigned int i;
  int16_t t;

  t = a;
  for(i = 1; i <= 12; ++i) {
    a = nttru_fqmul(a, a);
    if(i != 9) t = nttru_fqmul(t, a);
  }

  return t;
}

int16_t nttru_fquniform(RAND_STATE *rand) {
  int16_t r;

  do {
    DRBG_Generate(rand, (unsigned char*) &r, 2);
    r &= 0x1FFF;
  } while(r >= NTTRU_Q);

  return r;
}
