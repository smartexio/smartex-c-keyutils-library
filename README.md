# Using the Smartex Key Utilities Library

This is the Smartex API utilities library. It is used to :
- create keys
- retrieving public keys
- create a SIN to use when retrieving tokens from the Smartex API
- Sign a payload to use in the `X-Signature` header field of a Smartex API request.

## Quick Start
### Installation

To use the library in your project clone the github repository and include the smartex.h header. 
This will enable you to access the following functions :

```c
int generatePem(char **pem) // creates an ECKEY and sets the value of pem to the PEM encoding of the key
int getPublicKeyFromPem(char *pemstring, char **pubkey) //takes a pem string and sets the value of pubkey to the compressed public key extracted from the pem
int generateSinFromPem(char *pem, char **sin) //gets the base58 unique identifier associated with the pem
int signMessageWithPem(char *message, char *pem, char **signature) //sets signature to the signature of the sha256 of the message
```

## API Documentation

API Documentation is available on the [Smartex site](https://smartex.io/api).

## Running the Tests

```bash
$ sh build.sh
```