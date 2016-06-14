#include "smartex.h"

static void runPublicKeyTest();
static void runSinTest();
static void runSignatureTest();

int main() {
    runPublicKeyTest();
    runSinTest();
    runSignatureTest();
    return 0;
}

static void runSignatureTest() {
    int signa;
    char *message = "https://smartex.io/invoices{\"currency\":\"USD\",\"price\":10,\"token\":\"3yHuXP7GVbqEh1rsDaodCzbMR5TZsxbMHEPnigsKyY86\"}";
    char *pem = malloc(240);
    char *signature = calloc(145, sizeof(char));
    char *actual_start = calloc(4, sizeof(char));
    char *expected_start = calloc(5, sizeof(char));

    pem[239]='\0';
    generatePem(&pem);
    signa = signMessageWithPem(message, pem, &signature);
    if (signa == ERROR) {
        printf("Signature Error.\n");
    };
    actual_start[3] = '\0';
    memcpy(actual_start, signature, 4);
    if (strlen(signature) == 138) {
        memcpy(expected_start, "3043", 4);
        expected_start[4] = '\0';
    } else if (strlen(signature) == 140) {
        memcpy(expected_start, "3044", 4);
        expected_start[4] = '\0';
    } else if (strlen(signature) == 142) {
        memcpy(expected_start, "3045", 4);
        expected_start[4] = '\0';
    } else if (strlen(signature) == 144) {
        memcpy(expected_start, "3046", 4);
        expected_start[4] = '\0';
    } else {
        printf("%lu is not a valid signature length\n", (unsigned long)strlen(signature));
    }

    if (strcmp(actual_start, expected_start) == 0)
        printf("[PASSED] Signature Test - Expected: %s - Actual: %s for %s\n", expected_start, actual_start, signature);
    else
        printf("[FAILED] Signature Test - Expected: %s - Actual: %s for %s\n", expected_start, actual_start, signature);
        printf("\n");

    free(expected_start);
    free(pem);
    free(signature);
    free(actual_start);
}

static void runSinTest() {
    char *fixed_pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEILrVeiUtzVEodjMvTsMwKYDMn+0UN5fzCRY3vozAsRZnoAcGBSuBBAAK\noUQDQgAE8Db3K3DhLumyt3haSuAlu74pXf7nd2nhVKdlbrp/cwe7AhU2Dj5aCbPX\n2aZXU/fGVlg8kwSt9fjlSFipl1wVvw==\n-----END EC PRIVATE KEY-----\n";
    int singood;
    char *expected_sin = "Tf5tYNrKfAdiSjuzsZwRbne6QyWpgKtH6DZ";
    char *sin = calloc(35, sizeof(char));

    singood = generateSinFromPem(fixed_pem, &sin);
    if (singood == ERROR)
        printf("Sin Error\n");
    if (strcmp(expected_sin, sin) == 0)
        printf("[PASSED] Sin Test - Expected: %s - Actual: %s\n", expected_sin, sin);
    else
        printf("[FAILED] Sin Test - Expected: %s - Actual: %s\n", expected_sin, sin);

    free(sin);
}

static void runPublicKeyTest(){
    char *pub = malloc(67);
    char *fixed_pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEILrVeiUtzVEodjMvTsMwKYDMn+0UN5fzCRY3vozAsRZnoAcGBSuBBAAK\noUQDQgAE8Db3K3DhLumyt3haSuAlu74pXf7nd2nhVKdlbrp/cwe7AhU2Dj5aCbPX\n2aZXU/fGVlg8kwSt9fjlSFipl1wVvw==\n-----END EC PRIVATE KEY-----\n";
    char *expected_pub = "03F036F72B70E12EE9B2B7785A4AE025BBBE295DFEE77769E154A7656EBA7F7307";
    int pubgood = getPublicKeyFromPem(fixed_pem, &pub);
    if (pubgood == ERROR)
        printf("Error retrieving public key\n");
    if (strcmp(expected_pub, pub) == 0)
        printf("[PASSED] Public Key Test - Expected: %s - Actual: %s\n", expected_pub, pub);
    else
        printf("[FAILED] Public Key Test - Expected: %s - Actual: %s\n", expected_pub, pub);

    free(pub);
}