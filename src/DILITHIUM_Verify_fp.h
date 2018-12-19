#ifndef DILITHIUM_VERIFY_FP_H
#define DILITHIUM_VERIFY_FP_H

typedef struct {
    BYTE	                        mode;
    TPM2B_DILITHIUM_PUBLIC_KEY	    public_key;
    TPM2B_DILITHIUM_SIGNED_MESSAGE	signed_message;
} DILITHIUM_Verify_In;

#define RC_DILITHIUM_Verify_mode		    (TPM_RC_P + TPM_RC_1)
#define RC_DILITHIUM_Verify_public_key	    (TPM_RC_P + TPM_RC_2)
#define RC_DILITHIUM_Verify_signed_message	(TPM_RC_P + TPM_RC_3)

typedef struct {
    TPM2B_DILITHIUM_MESSAGE	    message;
} DILITHIUM_Verify_Out;

TPM_RC
TPM2_DILITHIUM_Verify(
         DILITHIUM_Verify_In      *in,            // IN: input parameter list
		 DILITHIUM_Verify_Out     *out            // OUT: output parameter list
		 );


#endif
