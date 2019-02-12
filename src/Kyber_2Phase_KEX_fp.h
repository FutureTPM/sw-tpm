/*
 * MIT License

 * Copyright (c) 2019 Luís Fiolhais, Paulo Martins, Leonel Sousa (INESC-ID)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
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
