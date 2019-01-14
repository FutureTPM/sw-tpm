#include "Tpm.h"
#include "dilithium-params.h"
#include "dilithium-sign.h"
#include "fips202.h"
#include "dilithium-polyvec.h"
#include "dilithium-sign.h"
#include "dilithium-packing.h"

typedef struct {
    uint64_t k;
    uint64_t l;
    uint64_t eta;
    uint64_t setabits;
    uint64_t beta;
    uint64_t omega;
    uint64_t polt0_size_packed;
    uint64_t polt1_size_packed;
    uint64_t poleta_size_packed;
    uint64_t polz_size_packed;
    uint64_t crypto_publickeybytes;
    uint64_t crypto_secretkeybytes;
    uint64_t crypto_bytes;
    uint64_t pol_size_packed;
    uint64_t polw1_size_packed;
    uint64_t polveck_size_packed;
    uint64_t polvecl_size_packed;
} DilithiumParams;

static DilithiumParams generate_dilithium_params(BYTE mode) {
    DilithiumParams params;

    switch(mode) {
        case 0:
            params.k = 3;
            params.l = 2;
            params.eta = 7;
            params.setabits = 4;
            params.beta = 375;
            params.omega = 64;
            break;
        case 1:
            params.k = 4;
            params.l = 3;
            params.eta = 6;
            params.setabits = 4;
            params.beta = 325;
            params.omega = 80;
            break;
        case 2:
            params.k = 5;
            params.l = 4;
            params.eta = 5;
            params.setabits = 4;
            params.beta = 275;
            params.omega = 96;
            break;
        case 3:
            params.k = 6;
            params.l = 5;
            params.eta = 3;
            params.setabits = 3;
            params.beta = 175;
            params.omega = 120;
            break;
    }

    params.pol_size_packed     = ((DILITHIUM_N * DILITHIUM_QBITS) / 8);
    params.polt1_size_packed   = ((DILITHIUM_N * (DILITHIUM_QBITS - DILITHIUM_D)) / 8);
    params.polt0_size_packed   = ((DILITHIUM_N * DILITHIUM_D) / 8);
    params.poleta_size_packed  = ((DILITHIUM_N * params.setabits) / 8);
    params.polz_size_packed    = ((DILITHIUM_N * (DILITHIUM_QBITS - 3)) / 8);
    params.polw1_size_packed   = ((DILITHIUM_N * 4) / 8);
    params.polveck_size_packed = (params.k * params.pol_size_packed);
    params.polvecl_size_packed = (params.l * params.pol_size_packed);

    params.crypto_publickeybytes = (DILITHIUM_SEEDBYTES + params.k*params.polt1_size_packed);
    params.crypto_secretkeybytes = (2*DILITHIUM_SEEDBYTES + (params.l + params.k)*params.poleta_size_packed + DILITHIUM_CRHBYTES + params.k*params.polt0_size_packed);
    params.crypto_bytes = (params.l * params.polz_size_packed + (params.omega + params.k) + (DILITHIUM_N/8 + 8));

    return params;
}

LIB_EXPORT TPM_RC
CryptDilithiumSign(
	     TPMT_SIGNATURE      *sigOut,
	     OBJECT              *key,           // IN: key to use
	     TPM2B_DIGEST        *hIn            // IN: the digest to sign
	     )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    DilithiumParams params;
    unsigned long long i, j;
    unsigned int n;
    unsigned char seedbuf[2*DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES];
    unsigned char tr[DILITHIUM_CRHBYTES];
    unsigned char *rho, *key_, *mu;
    uint16_t nonce = 0;
    dilithium_poly c, chat;
    dilithium_polyvecl mat[6], s1, y, yhat, z; // Max K in Dilithium
    dilithium_polyveck s2, t0, w, w1;
    dilithium_polyveck h, wcs2, wcs20, ct0, tmp;

    pAssert(sigOut != NULL && key != NULL && hIn != NULL);

    // Set mode used in signature
    sigOut->signature.dilithium.mode = key->publicArea.parameters.dilithiumDetail.mode;

    TEST(sigOut->sigAlg);
    switch(sigOut->sigAlg)
	{
	  case ALG_NULL_VALUE:
	    sigOut->signature.dilithium.sig.t.size = 0;
	    return TPM_RC_SUCCESS;
	  case ALG_DILITHIUM_VALUE:
	    break;
	  default:
	    retVal = TPM_RC_SCHEME;
        return retVal;
	}

    if (sigOut->signature.dilithium.mode >= 0 && sigOut->signature.dilithium.mode <= 3) {
        params = generate_dilithium_params(sigOut->signature.dilithium.mode);
    } else {
        return TPM_RC_VALUE;
    }

    rho = seedbuf;
    key_ = seedbuf + DILITHIUM_SEEDBYTES;
    mu = seedbuf + 2*DILITHIUM_SEEDBYTES;
    dilithium_unpack_sk(rho, key_, tr, &s1, &s2, &t0,
            (unsigned char *)&key->sensitive.sensitive.dilithium.b.buffer, params.k,
            params.l, params.poleta_size_packed, params.polt0_size_packed,
            params.eta);

    /* Copy tr and message into the sm buffer,
     * backwards since m and sm can be equal in SUPERCOP API */
    for(i = 1; i <= hIn->b.size; ++i)
      sigOut->signature.dilithium.sig.b.buffer[params.crypto_bytes + hIn->b.size - i] = hIn->b.buffer[hIn->b.size - i];
    for(i = 0; i < DILITHIUM_CRHBYTES; ++i)
      sigOut->signature.dilithium.sig.b.buffer[params.crypto_bytes - DILITHIUM_CRHBYTES + i] = tr[i];

    /* Compute CRH(tr, msg) */
    shake256(mu, DILITHIUM_CRHBYTES,
            sigOut->signature.dilithium.sig.b.buffer + params.crypto_bytes - DILITHIUM_CRHBYTES,
            DILITHIUM_CRHBYTES + hIn->b.size);

    /* Expand matrix and transform vectors */
    dilithium_expand_mat(mat, rho, params.k, params.l);
    dilithium_polyvecl_ntt(&s1, params.l);
    dilithium_polyveck_ntt(&s2, params.k);
    dilithium_polyveck_ntt(&t0, params.k);

    rej:
    if(_plat__IsCanceled()) ERROR_RETURN(TPM_RC_CANCELED);

    /* Sample intermediate vector y */
    for(i = 0; i < params.l; ++i)
      dilithium_poly_uniform_gamma1m1(y.vec+i, key_, nonce++);

    /* Matrix-vector multiplication */
    yhat = y;
    dilithium_polyvecl_ntt(&yhat, params.l);
    for(i = 0; i < params.k; ++i) {
      dilithium_polyvecl_pointwise_acc_invmontgomery(w.vec+i, mat+i, &yhat,
              params.l);
      dilithium_poly_reduce(w.vec+i);
      dilithium_poly_invntt_montgomery(w.vec+i);
    }

    /* Decompose w and call the random oracle */
    dilithium_polyveck_csubq(&w, params.k);
    dilithium_polyveck_decompose(&w1, &tmp, &w, params.k);
    dilithium_challenge(&c, mu, &w1, params.k, params.polw1_size_packed);

    /* Compute z, reject if it reveals secret */
    chat = c;
    dilithium_poly_ntt(&chat);
    for(i = 0; i < params.l; ++i) {
      dilithium_poly_pointwise_invmontgomery(z.vec+i, &chat, s1.vec+i);
      dilithium_poly_invntt_montgomery(z.vec+i);
    }
    dilithium_polyvecl_add(&z, &z, &y, params.l);
    dilithium_polyvecl_freeze(&z, params.l);
    if(dilithium_polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - params.beta, params.l))
      goto rej;

    /* Compute w - cs2, reject if w1 can not be computed from it */
    for(i = 0; i < params.k; ++i) {
      dilithium_poly_pointwise_invmontgomery(wcs2.vec+i, &chat, s2.vec+i);
      dilithium_poly_invntt_montgomery(wcs2.vec+i);
    }
    dilithium_polyveck_sub(&wcs2, &w, &wcs2, params.k);
    dilithium_polyveck_freeze(&wcs2, params.k);
    dilithium_polyveck_decompose(&tmp, &wcs20, &wcs2, params.k);
    dilithium_polyveck_csubq(&wcs20, params.k);
    if(dilithium_polyveck_chknorm(&wcs20, DILITHIUM_GAMMA2 - params.beta, params.k))
      goto rej;

    for(i = 0; i < params.k; ++i)
      for(j = 0; j < DILITHIUM_N; ++j)
        if(tmp.vec[i].coeffs[j] != w1.vec[i].coeffs[j])
          goto rej;

    /* Compute hints for w1 */
    for(i = 0; i < params.k; ++i) {
      dilithium_poly_pointwise_invmontgomery(ct0.vec+i, &chat, t0.vec+i);
      dilithium_poly_invntt_montgomery(ct0.vec+i);
    }

    dilithium_polyveck_csubq(&ct0, params.k);
    if(dilithium_polyveck_chknorm(&ct0, DILITHIUM_GAMMA2, params.k))
      goto rej;

    dilithium_polyveck_add(&tmp, &wcs2, &ct0, params.k);
    dilithium_polyveck_csubq(&tmp, params.k);
    n = dilithium_polyveck_make_hint(&h, &wcs2, &tmp, params.k);
    if(n > params.omega)
      goto rej;

    /* Write signature */
    dilithium_pack_sig((unsigned char *)&sigOut->signature.dilithium.sig.b.buffer, &z, &h,
            &c, params.k, params.l, params.polz_size_packed, params.omega);

    printf("Digest length is %d\n", hIn->b.size);
    sigOut->signature.dilithium.sig.b.size = hIn->b.size + params.crypto_bytes;

Exit:
    return retVal;
}

LIB_EXPORT TPM_RC
CryptDilithiumValidateSignature(
			  TPMT_SIGNATURE  *sig,           // IN: signature
			  OBJECT          *key,           // IN: public dilithium key
			  TPM2B_DIGEST    *digest         // IN: The digest being validated
			  )
{
    TPM_RC   retVal = TPM_RC_SUCCESS;
    DilithiumParams params;
    unsigned long long i;
    unsigned char rho[DILITHIUM_SEEDBYTES];
    unsigned char mu[DILITHIUM_CRHBYTES];
    dilithium_poly c, chat, cp;
    dilithium_polyvecl mat[6], z; // Max K for Dilithium
    dilithium_polyveck t1, w1, h, tmp1, tmp2;
    TPM2B_DILITHIUM_MESSAGE message_tmp;

    pAssert(sig != NULL && key != NULL && digest != NULL);

    // Can't verify signatures with a key of different mode
    if (sig->signature.dilithium.mode != key->publicArea.parameters.dilithiumDetail.mode)
        ERROR_RETURN(TPM_RC_SIGNATURE);

    switch(sig->sigAlg) {
	  case ALG_DILITHIUM_VALUE:
	    break;
	  default:
	    return TPM_RC_SCHEME;
	}

    TEST(sig->sigAlg);
    if (sig->signature.dilithium.mode >= 0 && sig->signature.dilithium.mode <= 3) {
        params = generate_dilithium_params(sig->signature.dilithium.mode);
    } else {
        return TPM_RC_SUCCESS + 2;
    }

    if(sig->signature.dilithium.sig.b.size < params.crypto_bytes)
      goto badsig;

    message_tmp.b.size = sig->signature.dilithium.sig.b.size - params.crypto_bytes;

    dilithium_unpack_pk(rho, &t1, key->publicArea.unique.dilithium.b.buffer, params.k, params.polt1_size_packed);
    if(dilithium_unpack_sig(&z, &h, &c, sig->signature.dilithium.sig.b.buffer, params.k, params.l, params.polz_size_packed, params.omega))
      goto badsig;
    if(dilithium_polyvecl_chknorm(&z, DILITHIUM_GAMMA1 - params.beta, params.l))
      goto badsig;

    /* Compute CRH(CRH(rho, t1), msg) using m as "playground" buffer */
    if(sig->signature.dilithium.sig.b.buffer != message_tmp.b.buffer)
      for(i = 0; i < message_tmp.b.size; ++i)
        message_tmp.b.buffer[params.crypto_bytes + i] = sig->signature.dilithium.sig.b.buffer[params.crypto_bytes + i];

    shake256(message_tmp.b.buffer + params.crypto_bytes - DILITHIUM_CRHBYTES,
            DILITHIUM_CRHBYTES,
            key->publicArea.unique.dilithium.b.buffer, params.crypto_publickeybytes);
    shake256(mu, DILITHIUM_CRHBYTES,
            message_tmp.b.buffer + params.crypto_bytes - DILITHIUM_CRHBYTES,
            DILITHIUM_CRHBYTES + message_tmp.b.size);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    dilithium_expand_mat(mat, rho, params.k, params.l);
    dilithium_polyvecl_ntt(&z, params.l);
    for(i = 0; i < params.k; ++i)
      dilithium_polyvecl_pointwise_acc_invmontgomery(tmp1.vec+i, mat+i, &z, params.l);

    chat = c;
    dilithium_poly_ntt(&chat);
    dilithium_polyveck_shiftl(&t1, DILITHIUM_D, params.k);
    dilithium_polyveck_ntt(&t1, params.k);
    for(i = 0; i < params.k; ++i)
      dilithium_poly_pointwise_invmontgomery(tmp2.vec+i, &chat, t1.vec+i);

    dilithium_polyveck_sub(&tmp1, &tmp1, &tmp2, params.k);
    dilithium_polyveck_reduce(&tmp1, params.k);
    dilithium_polyveck_invntt_montgomery(&tmp1, params.k);

    /* Reconstruct w1 */
    dilithium_polyveck_csubq(&tmp1, params.k);
    dilithium_polyveck_use_hint(&w1, &tmp1, &h, params.k);

    /* Call random oracle and verify challenge */
    dilithium_challenge(&cp, mu, &w1, params.k, params.polw1_size_packed);
    for(i = 0; i < DILITHIUM_N; ++i)
      if(c.coeffs[i] != cp.coeffs[i])
        goto badsig;

    /* All good, copy msg, return 0 */
    for(i = 0; i < message_tmp.b.size; ++i)
      message_tmp.b.buffer[i] = sig->signature.dilithium.sig.b.buffer[params.crypto_bytes + i];

    if (!MemoryEqual2B(&digest->b, &message_tmp.b)) {
        printf("Dilithium Signature verification failed\n");
        printf("Digest is (%d bytes):\n", digest->b.size);
        for (size_t i = 0; i < digest->b.size; i++) {
            printf("%02X", digest->b.buffer[i]);
        }
        printf("\nMessage is (%d bytes):\n", message_tmp.b.size);
        for (size_t i = 0; i < message_tmp.b.size; i++) {
            printf("%02X", message_tmp.b.buffer[i]);
        }
        printf("\n");
        goto badsig;
    }

Exit:
    return retVal;

    /* Signature verification failed */
    badsig:
    return TPM_RC_SIGNATURE;
}

LIB_EXPORT TPM_RC
CryptDilithiumGenerateKey(
            // IN/OUT: The object structure in which the key is created.
		    OBJECT              *dilithiumKey,
            // IN: if not NULL, the deterministic RNG state
		    RAND_STATE          *rand
		    )
{
    TPMT_PUBLIC         *publicArea = &dilithiumKey->publicArea;
    TPMT_SENSITIVE      *sensitive = &dilithiumKey->sensitive;
    TPM_RC               retVal = TPM_RC_NO_RESULT;
    unsigned int i;
    unsigned char seedbuf[3*DILITHIUM_SEEDBYTES];
    unsigned char tr[DILITHIUM_CRHBYTES];
    unsigned char *rho, *rhoprime, *key;
    uint16_t nonce = 0;
    dilithium_polyvecl mat[6]; // MAX K in Dilithium
    dilithium_polyvecl s1, s1hat;
    dilithium_polyveck s2, t, t1, t0;
    DilithiumParams params;

    pAssert(dilithiumKey != NULL);

    // Dilithium is only used for signing
    if (!IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
        ERROR_RETURN(TPM_RC_NO_RESULT);

    if (publicArea->parameters.dilithiumDetail.mode >= 0 && publicArea->parameters.dilithiumDetail.mode <= 3) {
        params = generate_dilithium_params(publicArea->parameters.dilithiumDetail.mode);
    } else {
        return TPM_RC_VALUE;
    }

    /* Expand 32 bytes of randomness into rho, rhoprime and key */
    CryptRandomGenerate(DILITHIUM_SEEDBYTES, seedbuf);
    shake256(seedbuf, 3*DILITHIUM_SEEDBYTES, seedbuf, DILITHIUM_SEEDBYTES);
    rho = seedbuf;
    rhoprime = rho + DILITHIUM_SEEDBYTES;
    key = rho + 2*DILITHIUM_SEEDBYTES;

    /* Expand matrix */
    dilithium_expand_mat(mat, rho, params.k, params.l);

    /* Sample short vectors s1 and s2 */
    for(i = 0; i < params.l; ++i)
      dilithium_poly_uniform_eta(s1.vec+i, rhoprime, nonce++, params.eta);
    for(i = 0; i < params.k; ++i)
      dilithium_poly_uniform_eta(s2.vec+i, rhoprime, nonce++, params.eta);

    /* Matrix-vector multiplication */
    s1hat = s1;
    dilithium_polyvecl_ntt(&s1hat, params.l);
    for(i = 0; i < params.k; ++i) {
      dilithium_polyvecl_pointwise_acc_invmontgomery(t.vec+i, mat+i, &s1hat, params.l);
      dilithium_poly_reduce(t.vec+i);
      dilithium_poly_invntt_montgomery(t.vec+i);
    }

    /* Add noise vector s2 */
    dilithium_polyveck_add(&t, &t, &s2, params.k);

    /* Extract t1 and write public key */
    dilithium_polyveck_freeze(&t, params.k);
    dilithium_polyveck_power2round(&t1, &t0, &t, params.k);
    dilithium_pack_pk((unsigned char *)&publicArea->unique.dilithium.b.buffer, rho, &t1, params.k,
            params.polt1_size_packed);

    /* Compute CRH(rho, t1) and write secret key */
    shake256(tr, DILITHIUM_CRHBYTES, (unsigned char *)&publicArea->unique.dilithium.b.buffer,
            params.crypto_publickeybytes);
    dilithium_pack_sk((unsigned char *)&sensitive->sensitive.dilithium.b.buffer, rho, key, tr, &s1, &s2, &t0,
            params.k, params.l, params.poleta_size_packed,
            params.polt0_size_packed, params.eta);

    publicArea->unique.dilithium.b.size = params.crypto_publickeybytes;
    sensitive->sensitive.dilithium.b.size = params.crypto_secretkeybytes;

    retVal = TPM_RC_SUCCESS;

 Exit:
    return retVal;
}
