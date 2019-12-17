#ifndef NTTRU_REDUCE_H
#define NTTRU_REDUCE_H

#include <stdint.h>
#include "Tpm.h"

#define NTTRU_MONT 4088 // 2^16 % NTTRU_Q
#define NTTRU_QINV 57857 // q^(-1) mod 2^16

int16_t nttru_fqmontred(int32_t a);
int16_t nttru_fqred16(int16_t a);
int16_t nttru_fqcsubq(int16_t a);
int16_t nttru_fqmul(int16_t a, int16_t b);
int16_t nttru_fqinv(int16_t a);
int16_t nttru_fquniform(RAND_STATE *rand);

#endif
