#ifndef KYBER_DEC_FP_H
#define KYBER_DEC_FP_H

typedef struct {
    // Possible security values are 2 (512 bits), 3 (768 bits)
    // and 4 (1024 bits).
    BYTE	                sec_sel;
    TPM2B_KYBER_SECRET_KEY	secret_key;
    TPM2B_KYBER_CIPHER_TEXT	cipher_text;
} KYBER_Dec_In;

#define RC_KYBER_Dec_sec_sel		(TPM_RC_P + TPM_RC_1)
#define RC_KYBER_Dec_secret_key		(TPM_RC_P + TPM_RC_2)
#define RC_KYBER_Dec_cipher_text	(TPM_RC_P + TPM_RC_3)

typedef struct {
    TPM2B_KYBER_SHARED_KEY	shared_key;
} KYBER_Dec_Out;

TPM_RC
TPM2_KYBER_Dec(
         KYBER_Dec_In      *in,            // IN: input parameter list
		 KYBER_Dec_Out     *out            // OUT: output parameter list
		 );

#endif
