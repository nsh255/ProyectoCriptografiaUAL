#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
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

void generateRandomKey(unsigned char *key, int keyLength) {
    RAND_bytes(key, keyLength);
}

void generateRandomIV(unsigned char *iv, int ivLength) {
    RAND_bytes(iv, ivLength);
}

void saveKeyToFile(const char *keyFileName, const unsigned char *key, int keyLength) {
    FILE *keyFile = fopen(keyFileName, "wb");
    if (keyFile) {
        fwrite(key, 1, keyLength, keyFile);
        fclose(keyFile);
    }
}

void saveIVToFile(const char *ivFileName, const unsigned char *iv, int ivLength) {
    FILE *ivFile = fopen(ivFileName, "wb");
    if (ivFile) {
        fwrite(iv, 1, ivLength, ivFile);
        fclose(ivFile);
    }
}

void encryptWithPublicKey(const char* inputFileName, const char* outputFileName, RSA* publicKey) {
    // Abre el archivo de entrada y el archivo de salida
    FILE* inputFile = fopen(inputFileName, "rb");
    FILE* outputFile = fopen(outputFileName, "wb");

    if (inputFile && outputFile) {
        // Tamaño del buffer de entrada
        size_t inputBufferSize = RSA_size(publicKey);

        unsigned char inputBuffer[inputBufferSize];
        unsigned char outputBuffer[inputBufferSize];

        // Lee datos del archivo de entrada y los encripta con la clave pública
        while (1) {
            size_t bytesRead = fread(inputBuffer, 1, inputBufferSize, inputFile);
            if (bytesRead == 0) {
                break;
            }

            int encryptedSize = RSA_public_encrypt(bytesRead, inputBuffer, outputBuffer, publicKey, RSA_PKCS1_PADDING);
            if (encryptedSize < 0) {
                // Manejo de error
                break;
            }

            fwrite(outputBuffer, 1, encryptedSize, outputFile);
        }

        // Cierra los archivos
        fclose(inputFile);
        fclose(outputFile);

        remove(inputFileName);
    }
}

void decryptWithPrivateKey(const char* inputFileName, const char* outputFileName, RSA* privateKey) {
    // Abre el archivo cifrado de entrada y el archivo de salida
    FILE* inputFile = fopen(inputFileName, "rb");
    FILE* outputFile = fopen(outputFileName, "wb");

    if (inputFile && outputFile) {
        // Tamaño del buffer de entrada
        size_t inputBufferSize = RSA_size(privateKey);

        unsigned char inputBuffer[inputBufferSize];
        unsigned char outputBuffer[inputBufferSize];

        // Lee datos cifrados del archivo de entrada y los descifra con la clave privada
        while (1) {
            size_t bytesRead = fread(inputBuffer, 1, inputBufferSize, inputFile);
            if (bytesRead == 0) {
                break;
            }
            
            int decryptedSize = RSA_private_decrypt(bytesRead, inputBuffer, outputBuffer, privateKey, RSA_PKCS1_PADDING);
            if (decryptedSize < 0) {
                // Manejo de error
                break;
            }

            fwrite(outputBuffer, 1, decryptedSize, outputFile);
        }

        // Cierra los archivos
        fclose(inputFile);
        fclose(outputFile);

        remove(inputFileName);
    }
}

void encriptacion(const char *inputFileName, const char *outputFileName, const char *keyFileName, const char *ivFileName, const char *publicKey, const char *privateKey) {
    unsigned char key[32];
    unsigned char iv[16];

    generateRandomKey(key, sizeof(key));
    saveKeyToFile(keyFileName, key, sizeof(key));

    generateRandomIV(iv, sizeof(iv));
    saveIVToFile(ivFileName, iv, sizeof(iv));

    generateRSAKeyPair(privateKey, publicKey);

    FILE* publicKeyFile = fopen(publicKey, "rb");
    RSA* clavePublica = PEM_read_RSAPublicKey(publicKeyFile, NULL, NULL, NULL);
    fclose(publicKeyFile);

    const char *claveAEScifrada = "AEScifrado.txt";
    const char *ivAEScifrada = "IVcifrado.txt";

    encryptWithPublicKey(keyFileName, claveAEScifrada, clavePublica);
    encryptWithPublicKey(ivFileName, ivAEScifrada, clavePublica);

    RSA_free(clavePublica);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    FILE *inputFile = fopen(inputFileName, "rb");
    FILE *outputFile = fopen(outputFileName, "wb");

    if (inputFile && outputFile) {
        unsigned char buffer[1024];
        int bytesRead, encryptedLength;

        while ((bytesRead = fread(buffer, 1, sizeof(buffer), inputFile)) > 0) {
            EVP_EncryptUpdate(ctx, buffer, &encryptedLength, buffer, bytesRead);
            fwrite(buffer, 1, encryptedLength, outputFile);
        }

        EVP_EncryptFinal_ex(ctx, buffer, &encryptedLength);
        fwrite(buffer, 1, encryptedLength, outputFile);

        fclose(inputFile);
        fclose(outputFile);
        remove(inputFileName);
        remove(publicKey);
        EVP_CIPHER_CTX_free(ctx);
    } else {
        printf("Error al abrir los archivos de entrada o salida.\n");
    }
}

void desencriptacion(const char *inputFileName, const char *outputFileName, const char *keyFileName, const char *ivFileName, const char *privateKey) {
    unsigned char key[32];
    unsigned char iv[16];

    const char *claveAEScifrada = "AEScifrado.txt";
    const char *ivAEScifrada = "IVcifrado.txt";

    FILE *privateKeyFile = fopen(privateKey, "rb");
    RSA *clavePrivada = PEM_read_RSAPrivateKey(privateKeyFile, NULL, NULL, NULL);
    fclose(privateKeyFile);

    decryptWithPrivateKey(claveAEScifrada, keyFileName, clavePrivada);
    decryptWithPrivateKey(ivAEScifrada, ivFileName, clavePrivada);

    RSA_free(clavePrivada);

    FILE *keyFile = fopen(keyFileName, "rb");
    if (keyFile) {
        fread(key, 1, sizeof(key), keyFile);
        fclose(keyFile);

        FILE *ivFile = fopen(ivFileName, "rb");
        if (ivFile) {
            fread(iv, 1, sizeof(iv), ivFile);
            fclose(ivFile);
        } else {
            printf("Error: no se encontró el archivo IV.\n");
            return;
        }
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

        FILE *inputFile = fopen(inputFileName, "rb");
        FILE *outputFile = fopen(outputFileName, "wb");

        if (inputFile && outputFile) {
            unsigned char buffer[1024];
            int bytesRead, decryptedLength;

            while ((bytesRead = fread(buffer, 1, sizeof(buffer), inputFile)) > 0) {
                EVP_DecryptUpdate(ctx, buffer, &decryptedLength, buffer, bytesRead);
                fwrite(buffer, 1, decryptedLength, outputFile);
            }

            EVP_DecryptFinal_ex(ctx, buffer, &decryptedLength);
            fwrite(buffer, 1, decryptedLength, outputFile);

            fclose(inputFile);
            fclose(outputFile);
            remove(keyFileName);
            remove(ivFileName);
            remove(inputFileName);
            remove(privateKey);
            EVP_CIPHER_CTX_free(ctx);
        } else {
            printf("Error al abrir los archivos de entrada o salida.\n");
        }
    } else {
        printf("Error: no se encontró el archivo de clave.\n");
    }
}

int main() {
    const char *ArchivoAEncriptar = "prueba.txt"; // Ruta al archivo de entrada
    const char *ArchivoADesencriptar = "prueba.enc"; // Ruta al archivo de salida en desencriptación
    const char *keyFileName = "Clave.txt"; // Ruta al archivo de clave
    const char *ivFileName = "IV.txt"; // Ruta al archivo IV
    const char *privateKeyFileName = "privado.pem"; 
    const char *publicKeyFileName = "publico.pem";
    const char *clavecifrada = "AEScifrado.txt";

    // Verificar si el archivo de clave existe
    FILE *keyFile = fopen(clavecifrada, "rb");
    if (keyFile) {
        fclose(keyFile);
        desencriptacion(ArchivoADesencriptar, ArchivoAEncriptar, keyFileName, ivFileName, privateKeyFileName);
    } else {
        encriptacion(ArchivoAEncriptar, ArchivoADesencriptar, keyFileName, ivFileName, publicKeyFileName, privateKeyFileName);
    }

    return 0;
}
