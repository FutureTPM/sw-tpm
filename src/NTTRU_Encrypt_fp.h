/*
 * MIT License
 *
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
#ifndef NTTRU_ENCRYPT_FP_H
#define NTTRU_ENCRYPT_FP_H

typedef struct {
    TPMI_DH_OBJECT		keyHandle;
    TPM2B_MAX_BUFFER	message;
} NTTRU_Encrypt_In;

#define RC_NTTRU_Encrypt_key_handle 	(TPM_RC_H + TPM_RC_1)
#define RC_NTTRU_Encrypt_message		(TPM_RC_P + TPM_RC_1)

typedef struct {
    TPM2B_NTTRU_ENCRYPT	outData;
} NTTRU_Encrypt_Out;

TPM_RC
TPM2_NTTRU_Encrypt(
		 NTTRU_Encrypt_In      *in,            // IN: input parameter list
		 NTTRU_Encrypt_Out     *out            // OUT: output parameter list
		 );

#endif
