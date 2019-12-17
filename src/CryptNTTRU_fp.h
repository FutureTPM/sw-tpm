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
#ifndef CRYPTNTTRU_FP_H
#define CRYPTNTTRU_FP_H

LIB_EXPORT BOOL CryptNTTRUInit(void);
LIB_EXPORT BOOL CryptNTTRUStartup(void);

LIB_EXPORT TPM_RC
CryptNTTRUGenerateKey(
            // IN/OUT: The object structure in which the key is created.
		    OBJECT              *nttruKey,
            // IN: if not NULL, the deterministic RNG state
		    RAND_STATE          *rand
		    );

LIB_EXPORT TPM_RC
CryptNTTRUEncapsulate(
            // IN: The object structure which contains the public key used in
            // the encapsulation.
		    TPMT_PUBLIC             *publicArea,
            // OUT: the shared key
            TPM2B_NTTRU_SHARED_KEY  *ss,
            // OUT: the cipher text
            TPM2B_NTTRU_CIPHER_TEXT *ct
		 );

LIB_EXPORT TPM_RC
CryptNTTRUDecapsulate(
            // IN: The object structure which contains the secret key used in
            // the decapsulation.
		    TPMT_SENSITIVE          *sensitive,
            // IN: the cipher text
            TPM2B_NTTRU_CIPHER_TEXT *ct,
            // OUT: the shared key
            TPM2B_NTTRU_SHARED_KEY  *ss
		 );

LIB_EXPORT TPM_RC
CryptNTTRUValidateCipherTextSize(
            // IN: the cipher text
            TPM2B_NTTRU_CIPHER_TEXT *ct
		 );
#endif
