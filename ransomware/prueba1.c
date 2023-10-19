#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <dirent.h>
#include <sys/stat.h>

#define INPUT_FOLDER "C:\\Users\\usuario\\Desktop\\Pruebas para criptografía"
#define OUTPUT_FOLDER "C:\\Users\\usuario\\Desktop\\Archivos encriptados"
#define DECRYPTED_FOLDER "C:\\Users\\usuario\\Desktop\\Archivos desencriptados"
#define KEYFILE "C:\\Users\\usuario\\Desktop\\Clave.txt"

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    exit(1);
}

void ensureOutputFolderExists(const char *folderPath) {
    struct stat st = {0};
    if (stat(folderPath, &st) == -1) {
        mkdir(folderPath);
    }
}

void encryptFiles(const unsigned char *key) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Crear la carpeta de salida en el escritorio
    ensureOutputFolderExists(OUTPUT_FOLDER);

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
        snprintf(inputFilePath, sizeof(inputFilePath), "%s\\%s", INPUT_FOLDER, entry->d_name);
        snprintf(outputFilePath, sizeof(outputFilePath), "%s\\%s.enc", OUTPUT_FOLDER, entry->d_name);

        struct stat path_stat;
        if (stat(inputFilePath, &path_stat) != 0) {
            continue;  // Ignorar elementos no válidos
        }

        if (S_ISREG(path_stat.st_mode)) {
            // Inicializar el contexto de cifrado
            EVP_CIPHER_CTX *ctx;
            EVP_CIPHER_CTX_new();

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
            EVP_CIPHER_CTX_free(ctx);
        }
    }

    closedir(dir);

    // Eliminar la carpeta de origen
    rmdir(INPUT_FOLDER);

    printf("Los archivos se han encriptado con éxito y la carpeta de origen se ha eliminado.\n");
}

void decryptFiles(const unsigned char *key) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Crear la carpeta de salida para archivos desencriptados
    ensureOutputFolderExists(DECRYPTED_FOLDER);

    // Abrir la carpeta de archivos encriptados
    DIR *dir = opendir(OUTPUT_FOLDER);
    if (dir == NULL) {
        perror("Error al abrir la carpeta de archivos encriptados");
        exit(1);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char inputFilePath[512];
        char outputFilePath[512];
        snprintf(inputFilePath, sizeof(inputFilePath), "%s\\%s", OUTPUT_FOLDER, entry->d_name);
        snprintf(outputFilePath, sizeof(outputFilePath), "%s\\%s.dec", DECRYPTED_FOLDER, entry->d_name);

        struct stat path_stat;
        if (stat(inputFilePath, &path_stat) != 0) {
            continue;  // Ignorar elementos no válidos
        }

        if (S_ISREG(path_stat.st_mode)) {
            // Inicializar el contexto de cifrado para desencriptar
            EVP_CIPHER_CTX *ctx;
            EVP_CIPHER_CTX_new();

            // Configurar el cifrado AES-128 en modo CBC
            if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, NULL)) {
                handleErrors();
            }

            // Abrir el archivo de entrada encriptado para desencriptar
            FILE *inputFile = fopen(inputFilePath, "rb");
            if (inputFile == NULL) {
                perror("Error al abrir el archivo encriptado");
                exit(1);
            }

            // Crear el archivo de salida desencriptado
            FILE *outputFile = fopen(outputFilePath, "wb");
            if (outputFile == NULL) {
                perror("Error al crear el archivo desencriptado");
                exit(1);
            }

            // Realizar la desencriptación en bloques de 128 bits
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

            // Finalizar la desencriptación
            if (1 != EVP_DecryptFinal_ex(ctx, outbuf, &bytesWritten)) {
                handleErrors();
            }
            fwrite(outbuf, 1, bytesWritten, outputFile);

            // Liberar recursos
            fclose(inputFile);
            fclose(outputFile);
            EVP_CIPHER_CTX_free(ctx);
        }
    }

    closedir(dir);

    printf("Los archivos se han desencriptado con éxito y se han guardado en la carpeta 'Archivos desencriptados'.\n");
}

int main() {
    FILE *keyFile = fopen(KEYFILE, "rb");
    unsigned char key[16];

    if (keyFile != NULL) {
        fread(key, 1, sizeof(key), keyFile);
        fclose(keyFile);
        // Llamar a la función para desencriptar
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
        // Llamar a la función para encriptar
        encryptFiles(key);
    }

    return 0;
}
