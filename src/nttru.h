#ifndef NTTRU_H
#define NTTRU_H

#include "nttru-poly.h"

int nttru_keygen(nttru_poly *hhat, nttru_poly *fhat, const unsigned char *coins);
void nttru_encrypt(nttru_poly *chat,
                  const nttru_poly *hhat,
                  const nttru_poly *m,
                  const unsigned char *coins);
void nttru_decrypt(nttru_poly *m,
                  const nttru_poly *chat,
                  const nttru_poly *fhat);

#endif
