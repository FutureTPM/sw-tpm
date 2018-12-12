#ifndef KYBER_ENC_FP_H
#define KYBER_ENC_FP_H

typedef struct {
    BYTE	sec_sel; // Possible security values are 2 (512), 3 (768) and 4 (1024).
    TPM2B_KYBER_PUBLIC_KEY	public_key;
} KYBER_Enc_In;

#define RC_KYBER_Enc_sec_sel		(TPM_RC_P + TPM_RC_1)
#define RC_KYBER_Enc_public_key		(TPM_RC_P + TPM_RC_2)

typedef struct {
    TPM2B_KYBER_SHARED_KEY	shared_key;
    TPM2B_KYBER_CIPHER_TEXT	cipher_text;
} KYBER_Enc_Out;

TPM_RC
TPM2_KYBER_Enc(
         KYBER_Enc_In      *in,            // IN: input parameter list
		 KYBER_Enc_Out     *out            // OUT: output parameter list
		 );

#endif
