#include "nttru-params.h"
#include "nttru-poly.h"
#include "nttru.h"

int nttru_keygen(nttru_poly *hhat, nttru_poly *fhat, const unsigned char coins[NTTRU_N]) {
  int r;
  nttru_poly f, g;

  nttru_poly_short(&f, coins);
  nttru_poly_short(&g, coins + NTTRU_N/2);
  nttru_poly_triple(&g, &g);
  nttru_poly_triple(&f, &f);
  f.coeffs[0] += 1;
  nttru_poly_ntt(fhat, &f);
  nttru_poly_ntt(&g, &g);
  nttru_poly_freeze(fhat);
  r = nttru_poly_baseinv(&f, fhat);
  nttru_poly_basemul(hhat, &f, &g);
  nttru_poly_freeze(hhat);
  return r;
}

void nttru_encrypt(nttru_poly *chat,
                  const nttru_poly *hhat,
                  const nttru_poly *m,
                  const unsigned char coins[NTTRU_N/2])
{
  nttru_poly r, mhat;

  nttru_poly_short(&r, coins);
  nttru_poly_ntt(&r, &r);
  nttru_poly_ntt(&mhat, m);
  nttru_poly_basemul(chat, &r, hhat);
  nttru_poly_reduce(chat);
  nttru_poly_add(chat, chat, &mhat);
  nttru_poly_freeze(chat);
}

void nttru_decrypt(nttru_poly *m,
                  const nttru_poly *chat,
                  const nttru_poly *fhat)
{
  nttru_poly_basemul(m, chat, fhat);
  nttru_poly_reduce(m);
  nttru_poly_invntt(m, m);
  nttru_poly_crepmod3(m, m);
}
