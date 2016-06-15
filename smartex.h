/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Smartex.io Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>

#define	NOERROR	0
#define	ERROR 	-1
#define SHA256_STRING 33
#define SHA256_HEX_STRING 65
#define RIPEMD_AND_PADDING 22
#define RIPEMD_AND_PADDING_STRING 23
#define RIPEMD_HEX 40
#define RIPEMD_HEX_STRING 41
#define RIPEMD_AND_PADDING_HEX 44
#define RIPEMD_AND_PADDING_HEX_STRING 45
#define CHECKSUM 8
#define CHECKSUM_STRING 9
#define SIN 35
#define SIN_STRING 36

int generatePem(char **pem);
int generateSinFromPem(char *pem, char **sin);
int getPublicKeyFromPem(char *pemstring, char **pubkey);
int signMessageWithPem(char *pem, char *message, char **signature);
