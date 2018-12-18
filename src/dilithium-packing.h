#ifndef PACKING_H
#define PACKING_H

#include "dilithium-params.h"
#include "dilithium-polyvec.h"

void dilithium_pack_pk(unsigned char *pk,
             const unsigned char rho[DILITHIUM_SEEDBYTES], const dilithium_polyveck *t1,
             uint64_t dilithium_k, uint64_t dilithium_polt1_size_packed);
void dilithium_pack_sk(unsigned char *sk,
             const unsigned char rho[DILITHIUM_SEEDBYTES],
             const unsigned char key[DILITHIUM_SEEDBYTES],
             const unsigned char tr[DILITHIUM_CRHBYTES],
             const dilithium_polyvecl *s1,
             const dilithium_polyveck *s2,
             const dilithium_polyveck *t0,
             uint64_t dilithium_k,
             uint64_t dilithium_l,
             uint64_t dilithium_poleta_size_packed,
             uint64_t dilithium_polt0_size_packed,
             uint64_t dilithium_eta);
void dilithium_pack_sig(unsigned char *sig,
              const dilithium_polyvecl *z, const dilithium_polyveck *h, const dilithium_poly *c,
              uint64_t dilithium_k, uint64_t dilithium_l,
              uint64_t dilithium_polz_size_packed, uint64_t dilithium_omega);

void dilithium_unpack_pk(unsigned char rho[DILITHIUM_SEEDBYTES], dilithium_polyveck *t1,
               const unsigned char *pk,
               uint64_t dilithium_k, uint64_t dilithium_polt1_size_packed);
void dilithium_unpack_sk(unsigned char rho[DILITHIUM_SEEDBYTES],
               unsigned char key[DILITHIUM_SEEDBYTES],
               unsigned char tr[DILITHIUM_CRHBYTES],
               dilithium_polyvecl *s1,
               dilithium_polyveck *s2,
               dilithium_polyveck *t0,
               const unsigned char *sk,
               uint64_t dilithium_k,
               uint64_t dilithium_l,
               uint64_t dilithium_poleta_size_packed,
               uint64_t dilithium_polt0_size_packed,
               uint64_t dilithium_eta);
int dilithium_unpack_sig(dilithium_polyvecl *z, dilithium_polyveck *h, dilithium_poly *c,
               const unsigned char *sig,
               uint64_t dilithium_k, uint64_t dilithium_l,
               uint64_t dilithium_polz_size_packed, uint64_t dilithium_omega);

#endif
