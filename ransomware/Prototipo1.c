#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <tchar.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* TODO
Me gustaría extraer las zonas donde se comprime y se descomprime el archivo y ponerlos en dos funciones distintas llamadas encriptacion y desencriptacion
Todo lo demás esta correcto tal y como está, si puedes quitar los comentarios de chatgpt y cambiar los nombres de las variables haciendo clic derecho y Rename symbol
*/
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

int main() {
    // Inicializar OpenSSL
    OpenSSL_add_all_algorithms();

    // Definir la ruta completa al archivo de entrada en el escritorio
    const char *ArchivoAEncriptar = "prueba.txt"; // Reemplaza "tu-usuario" por tu nombre de usuario

    // Definir la ruta completa al archivo de salida (donde se guardará el archivo encriptado)
    const char *ArchivoADesencriptar = "C:\\Users\\Vatalefort\\Desktop\\prueba.enc"; // Ruta completa al escritorio

    // Definir la ruta completa al archivo de clave
    const char *keyFileName = "C:\\Users\\Vatalefort\\Desktop\\Clave.txt"; // Ruta completa al escritorio

    // Definir la ruta completa al archivo del IV
    const char *ivFileName = "C:\\Users\\Vatalefort\\Desktop\\IV.txt"; // Ruta completa al escritorio

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

        // Crear el contexto de descifrado
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

        // Abrir los archivos de entrada y salida
        FILE *inputFile = fopen(ArchivoADesencriptar, "rb");
        FILE *outputFile = fopen(ArchivoAEncriptar, "wb");

        if (inputFile && outputFile) {
            unsigned char buffer[1024];
            int bytesRead, decryptedLength;

            // Proceso de descifrado
            while ((bytesRead = fread(buffer, 1, sizeof(buffer), inputFile)) > 0) {
                EVP_DecryptUpdate(ctx, buffer, &decryptedLength, buffer, bytesRead);
                fwrite(buffer, 1, decryptedLength, outputFile);
            }

            EVP_DecryptFinal_ex(ctx, buffer, &decryptedLength);
            fwrite(buffer, 1, decryptedLength, outputFile);

            // Cerrar los archivos
            fclose(inputFile);
            fclose(outputFile);

            // Liberar recursos
            EVP_CIPHER_CTX_free(ctx);

            remove(ArchivoADesencriptar);
            printf("El archivo se ha desencriptado con éxito.\n");
        } else {
            printf("Error al abrir los archivos de entrada o salida.\n");
        }
    } else {
        // Si el archivo de clave no existe, generamos una nueva clave y la guardamos
        generateRandomKey(key, sizeof(key));
        saveKeyToFile(keyFileName, key, sizeof(key));

        // Generar un IV aleatorio
        generateRandomIV(iv, sizeof(iv));
        saveIVToFile(ivFileName, iv, sizeof(iv));

        // Abrir los archivos de entrada y salida para encriptar
        FILE *inputFile = fopen(ArchivoAEncriptar, "rb");
        FILE *outputFile = fopen(ArchivoADesencriptar, "wb");

        if (inputFile && outputFile) {
            // Crear el contexto de cifrado
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

            unsigned char buffer[1024];
            int bytesRead, encryptedLength;

            // Proceso de cifrado
            while ((bytesRead = fread(buffer, 1, sizeof(buffer), inputFile)) > 0) {
                EVP_EncryptUpdate(ctx, buffer, &encryptedLength, buffer, bytesRead);
                fwrite(buffer, 1, encryptedLength, outputFile);
            }

            EVP_EncryptFinal_ex(ctx, buffer, &encryptedLength);
            fwrite(buffer, 1, encryptedLength, outputFile);

            // Cerrar los archivos
            fclose(inputFile);
            fclose(outputFile);

            // Liberar recursos
            EVP_CIPHER_CTX_free(ctx);

            remove(ArchivoAEncriptar);
            printf("El archivo se ha encriptado con éxito y la clave se ha guardado en '%s'.\n", keyFileName);
        } else {
            printf("Error al abrir los archivos de entrada o salida.\n");
        }
    }

    return 0;
}