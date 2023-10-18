#include <stdio.h>
#include <string.h>
#include <dirent.h> 
#include <openssl/evp.h> 
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <sys/stat.h>

#define INPUT_FOLDER "C://Users//usuario//Desktop//Pruebas para Criptografía"
#define OUTPUT_FOLDER "C://Users//usuario//Desktop//encripted"
#define KEYFILE "key.txt"

int isRegularFile(const char *path) {
    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        return 0;
    }
    return S_ISREG(path_stat.st_mode);
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    exit(1);
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
        if (entry->d_type == DT_REG) {
            // Construir las rutas de entrada y salida
            char inputFilePath[512];
            char outputFilePath[512];
            snprintf(inputFilePath, sizeof(inputFilePath), "%s/%s/%s", INPUT_FOLDER, entry->d_name);
            snprintf(outputFilePath, sizeof(outputFilePath), "%s/%s/%s.enc", outputFolderPath, entry->d_name);

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

    // Cerrar la carpeta de origen
    closedir(dir);

    printf("Los archivos se han encriptado con éxito y se han guardado en la carpeta '%s'.\n", OUTPUT_FOLDER);
}

void decryptFiles(const unsigned char *key) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Crear la carpeta de salida en el escritorio
    char outputFolderPath[256];
    snprintf(outputFolderPath, sizeof(outputFolderPath), "%s/%s", getenv("USERPROFILE"), "decrypted_files");
    mkdir(outputFolderPath, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    // Abrir la carpeta de origen
    DIR *dir = opendir(OUTPUT_FOLDER);
    if (dir == NULL) {
        perror("Error al abrir la carpeta de origen");
        exit(1);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            // Construir las rutas de entrada y salida
            char inputFilePath[512];
            char outputFilePath[512];
            snprintf(inputFilePath, sizeof(inputFilePath), "%s/%s", OUTPUT_FOLDER, entry->d_name);
            snprintf(outputFilePath, sizeof(outputFilePath), "%s/%s.dec", outputFolderPath, entry->d_name);

            // Inicializar el contexto de cifrado
            EVP_CIPHER_CTX *ctx;
            EVP_CIPHER_CTX_init(ctx);

            // Configurar el cifrado AES-128 en modo CBC
            if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, NULL)) {
                handleErrors();
            }

            // Abrir el archivo de entrada cifrado
            FILE *inputFile = fopen(inputFilePath, "rb");
            if (inputFile == NULL) {
                perror("Error al abrir el archivo de entrada cifrado");
                exit(1);
            }

            // Crear el archivo de salida desencriptado
            FILE *outputFile = fopen(outputFilePath, "wb");
            if (outputFile == NULL) {
                perror("Error al crear el archivo de salida desencriptado");
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
            EVP_CIPHER_CTX_cleanup(ctx);
        }
    }

    // Cerrar la carpeta de origen
    closedir(dir);

    printf("Los archivos se han desencriptado con éxito y se han guardado en la carpeta 'decrypted_files'.\n");
}

int main() {
    // Comprobar si existe una clave en el escritorio
    FILE *keyFile = fopen(KEYFILE, "rb");
    unsigned char key[16];

    if (keyFile != NULL) {
        // La clave existe, leerla
        fread(key, 1, sizeof(key), keyFile);
        fclose(keyFile);
        // Realizar la desencriptación de archivos en la carpeta
        decryptFiles(key);
    } else {
        // La clave no existe, generar una nueva clave
        if (RAND_bytes(key, sizeof(key)) != 1) {
            handleErrors();
        }
        // Guardar la clave en el escritorio
        keyFile = fopen(KEYFILE, "wb");
        if (keyFile == NULL) {
            perror("Error al abrir el archivo de clave");
            return 1;
        }
        fwrite(key, 1, sizeof(key), keyFile);
        fclose(keyFile);
        // Encriptar archivos en la carpeta
        encryptFiles(key);
    }

    return 0;
}