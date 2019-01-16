#ifndef CRYPTDILITHIUM_FP_H
#define CRYPTDILITHIUM_FP_H

LIB_EXPORT BOOL CryptDilithiumInit(void);
LIB_EXPORT BOOL CryptDilithiumStartup(void);

LIB_EXPORT TPM_RC
CryptDilithiumSign(
	     TPMT_SIGNATURE      *sigOut,
	     OBJECT              *key,           // IN: key to use
	     TPM2B_DIGEST        *hIn            // IN: the digest to sign
	     );

LIB_EXPORT TPM_RC
CryptDilithiumValidateSignature(
			  TPMT_SIGNATURE  *sig,           // IN: signature
			  OBJECT          *key,           // IN: public modulus
			  TPM2B_DIGEST    *digest         // IN: The digest being validated
			  );

LIB_EXPORT TPM_RC
CryptDilithiumGenerateKey(
            // IN/OUT: The object structure in which the key is created.
		    OBJECT              *dilithiumKey,
            // IN: if not NULL, the deterministic RNG state
		    RAND_STATE          *rand
		    );
#endif
