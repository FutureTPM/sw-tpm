#ifndef KYBER_2PHASE_KEX_FP_H
#define KYBER_2PHASE_KEX_FP_H

typedef struct {
    TPMI_DH_OBJECT          static_key;
    TPMI_DH_OBJECT          ephemeral_key;
    TPM2B_KYBER_CIPHER_TEXT cipher_text_static;
} Kyber_2Phase_KEX_In;

#define RC_Kyber_2Phase_KEX_static_key	       (TPM_RC_P + TPM_RC_1)
#define RC_Kyber_2Phase_KEX_ephemeral_key	   (TPM_RC_P + TPM_RC_2)
#define RC_Kyber_2Phase_KEX_cipher_text_static (TPM_RC_P + TPM_RC_3)

typedef struct {
    TPM2B_KYBER_SHARED_KEY  shared_key;
    TPM2B_KYBER_CIPHER_TEXT cipher_text_1;
    TPM2B_KYBER_CIPHER_TEXT cipher_text_2;
} Kyber_2Phase_KEX_Out;

TPM_RC
TPM2_Kyber_2Phase_KEX(
		  Kyber_2Phase_KEX_In     *in,            // IN: input parameter list
		  Kyber_2Phase_KEX_Out    *out            // OUT: output parameter list
		  );

#endif
