#include <stdio.h>
#include <windows.h>
#include <Shlwapi.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void generateRSAKeyPair(const char *privateKeyFileName, const char *publicKeyFileName) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    if (rsa && e) {
        if (BN_set_word(e, RSA_F4) && RSA_generate_key_ex(rsa, 2048, e, NULL)) {
            FILE *privateKeyFile = fopen(privateKeyFileName, "wb");
            FILE *publicKeyFile = fopen(publicKeyFileName, "wb");
            if (privateKeyFile) {
                PEM_write_RSAPrivateKey(privateKeyFile, rsa, NULL, NULL, 0, NULL, NULL);
                PEM_write_RSAPublicKey(publicKeyFile, rsa);
                fclose(publicKeyFile);
                fclose(privateKeyFile);
            }
        }

        BN_free(e);
        RSA_free(rsa);
    }
}


void generateECDSAKeyPair(const char *privateKeyFileName, const char *publicKeyFileName) {
    EC_KEY *ecKey = EC_KEY_new();
    EC_GROUP *ecGroup = EC_GROUP_new_by_curve_name(NID_secp256k1); // Selecciona la curva ECDSA

    if (ecKey && ecGroup) {
        if (EC_KEY_set_group(ecKey, ecGroup) && EC_KEY_generate_key(ecKey)) {
            FILE *privateKeyFile = fopen(privateKeyFileName, "wb");
            FILE *publicKeyFile = fopen(publicKeyFileName, "wb");
            
            if (privateKeyFile) {
                PEM_write_ECPrivateKey(privateKeyFile, ecKey, NULL, NULL, 0, NULL, NULL);
                fclose(privateKeyFile);
            }

            if (publicKeyFile) {
                PEM_write_EC_PUBKEY(publicKeyFile, ecKey);
                fclose(publicKeyFile);
            }
        }

        EC_KEY_free(ecKey);
        EC_GROUP_free(ecGroup);
    }
}

int main() {

    generateECDSAKeyPair("C:\\Users\\usuario\\Desktop\\clave_privada_firma.pem", "C:\\Users\\usuario\\Desktop\\clave_publica_firma.pem");
    generateRSAKeyPair("C:\\Users\\usuario\\Desktop\\clave_privada_rsa.pem", "C:\\Users\\usuario\\Desktop\\clave_publica_rsa.pem");
    
    return 0;
}