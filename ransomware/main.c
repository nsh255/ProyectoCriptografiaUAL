#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <sys/stat.h>

#define INPUT_FOLDER "C:\\Users\\usuario\\Desktop\\Pruebas para criptografía"
#define OUTPUT_FOLDER "C:\\Users\\usuario\\Desktop\\Archivos encriptados"
#define KEYFILE "C:\\Users\\usuario\\Desktop\\Clave.txt"

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    exit(1);
}

int isRegularFile(const char *path) {
    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        return 0;
    }
    return S_ISREG(path_stat.st_mode);
}

void ensureOutputFolderExists() {
    struct stat st = {0};
    if (stat(OUTPUT_FOLDER, &st) == -1) {
        mkdir(OUTPUT_FOLDER);
        chmod(OUTPUT_FOLDER, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH); // Establecer permisos
    }
}

void encryptFiles(const unsigned char *key) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Crear la carpeta de salida en el escritorio
    char outputFolderPath[256];
    snprintf(outputFolderPath, sizeof(outputFolderPath), "%s/%s", getenv("USERPROFILE"), OUTPUT_FOLDER);
    mkdir(outputFolderPath);

    // Abrir la carpeta de origen
    DIR *dir = opendir(INPUT_FOLDER);
    if (dir == NULL) {
        perror("Error al abrir la carpeta de origen");
        exit(1);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char inputFilePath[512];
        char outputFilePath[512];
        snprintf(inputFilePath, sizeof(inputFilePath), "%s/%s", INPUT_FOLDER, entry->d_name);
        snprintf(outputFilePath, sizeof(outputFilePath), "%s/%s.enc", outputFolderPath, entry->d_name);

        if (isRegularFile(inputFilePath)) {
            // Inicializar el contexto de cifrado
            EVP_CIPHER_CTX *ctx;
            EVP_CIPHER_CTX_init(ctx);

            // Configurar el cifrado AES-128 en modo CBC
            if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, NULL)) {
                handleErrors();
            }

            // Abrir el archivo de entrada para cifrar
            FILE *inputFile = fopen(inputFilePath, "rb");
            if (inputFile == NULL) {
                perror("Error al abrir el archivo de entrada");
                exit(1);
            }

            // Crear el archivo de salida cifrado
            FILE *outputFile = fopen(outputFilePath, "wb");
            if (outputFile == NULL) {
                perror("Error al crear el archivo de salida cifrado");
                exit(1);
            }

            // Realizar el cifrado en bloques de 128 bits
            unsigned char inbuf[16], outbuf[16];
            int bytesRead, bytesWritten;
            while (1) {
                bytesRead = fread(inbuf, 1, sizeof(inbuf), inputFile);
                if (bytesRead <= 0) break;
                if (1 != EVP_EncryptUpdate(ctx, outbuf, &bytesWritten, inbuf, bytesRead)) {
                    handleErrors();
                }
                fwrite(outbuf, 1, bytesWritten, outputFile);
            }

            // Finalizar el cifrado
            if (1 != EVP_EncryptFinal_ex(ctx, outbuf, &bytesWritten)) {
                handleErrors();
            }
            fwrite(outbuf, 1, bytesWritten, outputFile);

            // Liberar recursos
            fclose(inputFile);
            fclose(outputFile);
            EVP_CIPHER_CTX_cleanup(ctx);
        }
    }

    closedir(dir);

    printf("Los archivos se han encriptado con éxito y se han guardado en la carpeta '%s'.\n", OUTPUT_FOLDER);
}

void decryptFiles(const unsigned char *key) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    char outputFolderPath[256];
    snprintf(outputFolderPath, sizeof(outputFolderPath), "%s/%s", getenv("USERPROFILE"), "decrypted_files");
    mkdir(outputFolderPath);

    DIR *dir = opendir(OUTPUT_FOLDER);
    if (dir == NULL) {
        perror("Error al abrir la carpeta de origen");
        exit(1);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char inputFilePath[512];
        char outputFilePath[512];
        snprintf(inputFilePath, sizeof(inputFilePath), "%s/%s", OUTPUT_FOLDER, entry->d_name);
        snprintf(outputFilePath, sizeof(outputFilePath), "%s/%s.dec", outputFolderPath, entry->d_name);

        if (isRegularFile(inputFilePath)) {
            EVP_CIPHER_CTX *ctx;
            EVP_CIPHER_CTX_init(ctx);

            if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, NULL)) {
                handleErrors();
            }

            FILE *inputFile = fopen(inputFilePath, "rb");
            if (inputFile == NULL) {
                perror("Error al abrir el archivo de entrada cifrado");
                exit(1);
            }

            FILE *outputFile = fopen(outputFilePath, "wb");
            if (outputFile == NULL) {
                perror("Error al crear el archivo de salida desencriptado");
                exit(1);
            }

            unsigned char inbuf[16], outbuf[16];
            int bytesRead, bytesWritten;
            while (1) {
                bytesRead = fread(inbuf, 1, sizeof(inbuf), inputFile);
                if (bytesRead <= 0) break;
                if (1 != EVP_DecryptUpdate(ctx, outbuf, &bytesWritten, inbuf, bytesRead)) {
                    handleErrors();
                }
                fwrite(outbuf, 1, bytesWritten, outputFile);
            }

            if (1 != EVP_DecryptFinal_ex(ctx, outbuf, &bytesWritten)) {
                handleErrors();
            }
            fwrite(outbuf, 1, bytesWritten, outputFile);

            fclose(inputFile);
            fclose(outputFile);
            EVP_CIPHER_CTX_cleanup(ctx);
        }
    }

    closedir(dir);

    printf("Los archivos se han desencriptado con éxito y se han guardado en la carpeta 'decrypted_files'.\n");
}

int main() {
    FILE *keyFile = fopen(KEYFILE, "rb");
    unsigned char key[16];

    if (keyFile != NULL) {
        fread(key, 1, sizeof(key), keyFile);
        fclose(keyFile);
        decryptFiles(key);
    } else {
        if (RAND_bytes(key, sizeof(key)) != 1) {
            handleErrors();
        }
        keyFile = fopen(KEYFILE, "wb");
        if (keyFile == NULL) {
            perror("Error al abrir el archivo de clave");
            return 1;
        }
        fwrite(key, 1, sizeof(key), keyFile);
        fclose(keyFile);
        encryptFiles(key);
    }

    return 0;
}
