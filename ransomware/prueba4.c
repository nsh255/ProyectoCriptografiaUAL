#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <tchar.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

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

        while ((bytesRead = fread(buffer, 1, sizeof(buffer), input) > 0)) {
            EVP_EncryptUpdate(ctx, buffer, &encryptedLength, buffer, bytesRead);
            fwrite(buffer, 1, encryptedLength, output);
        }

        EVP_EncryptFinal_ex(ctx, buffer, &encryptedLength);
        fwrite(buffer, 1, encryptedLength, output);

        EVP_CIPHER_CTX_free(ctx);

        fclose(input);
        fclose(output);
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

        unsigned char buffer[1024];
        int bytesRead, decryptedLength;

        while ((bytesRead = fread(buffer, 1, sizeof(buffer), input) > 0)) {
            EVP_DecryptUpdate(ctx, buffer, &decryptedLength, buffer, bytesRead);
            fwrite(buffer, 1, decryptedLength, output);
        }

        EVP_DecryptFinal_ex(ctx, buffer, &decryptedLength);
        fwrite(buffer, 1, decryptedLength, output);

        EVP_CIPHER_CTX_free(ctx);

        fclose(input);
        fclose(output);
    } else {
        printf("Error: No se pudieron abrir los archivos de entrada o salida.\n");
    }
}

int main() {
    // Inicializar OpenSSL
    OpenSSL_add_all_algorithms();

    // Definir la ruta completa de la carpeta a encriptar
    const char *Aencriptar = "C:\\Users\\usuario\\Desktop\\patata"; // Ruta a la carpeta con archivos a encriptar

    // Definir la ruta completa de la carpeta de salida para archivos encriptados
    const char *ADesencriptar = "C:\\Users\\usuario\\Desktop\\encriptao"; // Ruta a la carpeta donde se guardarán archivos encriptados

    // Definir la ruta completa al archivo de clave
    const char *keyFileName = "C:\\Users\\usuario\\Desktop\\Clave.txt";

    // Definir la ruta completa al archivo del IV
    const char *ivFileName = "C:\\Users\\usuario\\Desktop\\IV.txt";

    // Definir la clave y el vector de inicialización (IV)
    unsigned char key[32];
    unsigned char iv[16];

    // Verificar si el archivo de clave existe
    FILE *keyFile = fopen(keyFileName, "rb");
    if (keyFile) {
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

        // Realizar operaciones de descifrado sobre los archivos de la carpeta "encriptao"
        WIN32_FIND_DATA findFileData;
        HANDLE hFind = FindFirstFile(_T(ADesencriptar), &findFileData);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    char inputFile[MAX_PATH];
                    char outputFile[MAX_PATH];

                    snprintf(inputFile, sizeof(inputFile), "%s\\%s", ADesencriptar, findFileData.cFileName);
                    snprintf(outputFile, sizeof(outputFile), "%s\\%s", Aencriptar, findFileData.cFileName);

                    decryptFile(inputFile, outputFile, key, iv);
                }
            } while (FindNextFile(hFind, &findFileData) != 0);

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

        // Realizar operaciones de cifrado sobre los archivos de la carpeta "patata"
        WIN32_FIND_DATA findFileData;
        HANDLE hFind = FindFirstFile(_T(Aencriptar), &findFileData);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    char inputFile[MAX_PATH];
                    char outputFile[MAX_PATH];

                    snprintf(inputFile, sizeof(inputFile), "%s\\%s", Aencriptar, findFileData.cFileName);
                    snprintf(outputFile, sizeof(outputFile), "%s\\%s.enc", ADesencriptar, findFileData.cFileName);

                    encryptFile(inputFile, outputFile, key, iv);
                }
            } while (FindNextFile(hFind, &findFileData) != 0);

            FindClose(hFind);
            printf("Archivos encriptados con éxito y la clave se ha guardado en '%s'.\n", keyFileName);
        } else {
            printf("Error al abrir la carpeta de archivos a encriptar.\n");
        }
    }

    return 0;
}