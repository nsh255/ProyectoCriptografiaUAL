#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

int signRSAWithECDSA(const char *private_key_path, const char *file_path, const char *signature_path) {
    int ret = 0;
    //RAND_poll(); // Inicializar generador de números aleatorios

    // Leer la clave privada
    FILE *private_key_file = fopen(private_key_path, "r");
    if (!private_key_file)
        return 0;

    EC_KEY *private_key = PEM_read_ECPrivateKey(private_key_file, NULL, NULL, NULL);
    if (!private_key)
        return 0;

    fclose(private_key_file);

    // Leer el archivo a firmar
    FILE *file = fopen(file_path, "rb");
    if (!file)
        return 0;

    fseek(file, 0L, SEEK_END); //puntero a final archivo

    long file_size = ftell(file); //determina el tamaño del archivo

    rewind(file); //Puntero vuelve a inico del archivo

    unsigned char *data = malloc(file_size); //Asigna memoria para almacenar el contenido del archivo
    if (!data)
        return 0;

    fread(data, 1, file_size, file);
    fclose(file);

    // Firmar el archivo
    ECDSA_SIG *signature = ECDSA_do_sign(data, file_size, private_key);
    if (!signature){
        //ERR_print_errors_fp(stderr);
        return 0;
}
    // Guardar la firma
    FILE *signature_file = fopen(signature_path, "wb");
    if (!signature_file) return 0;

    i2d_ECDSA_SIG(signature, NULL); // Serializar la firma para determinar el tamaño
    unsigned char *sig_data = malloc(i2d_ECDSA_SIG(signature, NULL));
    unsigned char *p = sig_data;
    i2d_ECDSA_SIG(signature, &p);
    fwrite(sig_data, 1, p - sig_data, signature_file);
    free(sig_data);


    fclose(signature_file);

    // Liberar recursos
    ECDSA_SIG_free(signature);
    EC_KEY_free(private_key);
    free(data);

    return ret;
}


// Función para calcular la firma ECDSA de la clave privada RSA
/*int signRSAWithECDSA(const char *rsaPrivateKeyFile, const char *ecdsaPrivateKeyFile, const char *signatureFile) {
    // Cargar la clave privada RSA desde el archivo
    FILE *rsaFile = fopen(rsaPrivateKeyFile, "rb");
    if (!rsaFile) {
        perror("Error al abrir el archivo de clave privada RSA");
        return 1;
    }

    fseek(rsaFile, 0, SEEK_END);
    long rsaFileSize = ftell(rsaFile);
    fseek(rsaFile, 0, SEEK_SET);

    char *rsaData = (char *)malloc(rsaFileSize + 1);
    if (!rsaData) {
        perror("Error de asignación de memoria para la clave privada RSA");
        fclose(rsaFile);
        return 1;
    }

    fread(rsaData, 1, rsaFileSize, rsaFile);
    fclose(rsaFile);

    rsaData[rsaFileSize] = '\0';

    // Cargar la clave privada ECDSA desde el archivo
    FILE *ecdsaFile = fopen(ecdsaPrivateKeyFile, "rb");
    if (!ecdsaFile) {
        perror("Error al abrir el archivo de clave privada ECDSA");
        free(rsaData);
        return 1;
    }

    fseek(ecdsaFile, 0, SEEK_END);
    long ecdsaFileSize = ftell(ecdsaFile);
    fseek(ecdsaFile, 0, SEEK_SET);

    char *ecdsaData = (char *)malloc(ecdsaFileSize + 1);
    if (!ecdsaData) {
        perror("Error de asignación de memoria para la clave privada ECDSA");
        fclose(ecdsaFile);
        free(rsaData);
        return 1;
    }

    fread(ecdsaData, 1, ecdsaFileSize, ecdsaFile);
    fclose(ecdsaFile);

    ecdsaData[ecdsaFileSize] = '\0';

    // Cargar la clave privada ECDSA desde el archivo
    BIO *ecdsaBio = BIO_new_mem_buf((void *)ecdsaData, -1);
    if (!ecdsaBio) {
        perror("Error al crear el objeto BIO para la clave privada ECDSA");
        free(rsaData);
        free(ecdsaData);
        return 1;
    }

    EC_KEY *ecdsaKey = PEM_read_bio_ECPrivateKey(ecdsaBio, NULL, NULL, NULL);
    BIO_free(ecdsaBio);

    if (!ecdsaKey) {
        perror("Error al leer la clave privada ECDSA");
        free(rsaData);
        free(ecdsaData);
        return 1;
    }

    // Crear un objeto EVP_PKEY a partir de la clave privada ECDSA
    EVP_PKEY *ecdsaPkey = EVP_PKEY_new();
    if (!ecdsaPkey) {
        perror("Error al crear el objeto EVP_PKEY para la clave privada ECDSA");
        free(rsaData);
        free(ecdsaData);
        EC_KEY_free(ecdsaKey);
        return 1;
    }

    if (EVP_PKEY_set1_EC_KEY(ecdsaPkey, ecdsaKey) != 1) {
        perror("Error al configurar la clave privada ECDSA en el objeto EVP_PKEY");
        free(rsaData);
        free(ecdsaData);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(ecdsaPkey);
        return 1;
    }

    // Crear el contexto de firma ECDSA
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("Error al crear el contexto de firma");
        free(rsaData);
        free(ecdsaData);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(ecdsaPkey);
        return 1;
    }

    // Inicializar la firma ECDSA
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, ecdsaPkey) != 1) {
        perror("Error al inicializar la firma ECDSA");
        free(rsaData);
        free(ecdsaData);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(ecdsaPkey);
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    // Actualizar la firma con los datos de la clave privada RSA
    if (EVP_DigestSignUpdate(mdctx, rsaData, rsaFileSize) != 1) {
        perror("Error al actualizar la firma con los datos de la clave privada RSA");
        free(rsaData);
        free(ecdsaData);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(ecdsaPkey);
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    // Obtener la firma
    unsigned char *signature = NULL;
    size_t signatureLen = 0;

    if (EVP_DigestSignFinal(mdctx, NULL, &signatureLen) != 1) {
        perror("Error al obtener la longitud de la firma");
        free(rsaData);
        free(ecdsaData);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(ecdsaPkey);
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    signature = (unsigned char *)malloc(signatureLen);
    if (!signature) {
        perror("Error de asignación de memoria para la firma");
        free(rsaData);
        free(ecdsaData);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(ecdsaPkey);
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    if (EVP_DigestSignFinal(mdctx, signature, &signatureLen) != 1) {
        perror("Error al obtener la firma");
        free(rsaData);
        free(ecdsaData);
        free(signature);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(ecdsaPkey);
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    // Abrir el archivo de salida para la firma
    FILE *signatureFilePtr = fopen(signatureFile, "wb");
    if (!signatureFilePtr) {
        perror("Error al abrir el archivo de salida para la firma");
        free(rsaData);
        free(ecdsaData);
        free(signature);
        EC_KEY_free(ecdsaKey);
        EVP_PKEY_free(ecdsaPkey);
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    // Escribir la firma en el archivo de salida
    fwrite(signature, 1, signatureLen, signatureFilePtr);

    // Cerrar el archivo de salida para la firma
    fclose(signatureFilePtr);

    // Liberar la memoria y recursos
    free(rsaData);
    free(ecdsaData);
    free(signature);
    EC_KEY_free(ecdsaKey);
    EVP_PKEY_free(ecdsaPkey);
    EVP_MD_CTX_free(mdctx);

    printf("La clave privada RSA fue firmada con éxito. La firma se guardó en %s.\n", signatureFile);

    return 0;
}*/

int main() {
    const char *rsaPrivateKeyFile = "C:\\Users\\usuario\\Desktop\\clave_privada_rsa.pem";
    const char *ecdsaPrivateKeyFile = "C:\\Users\\usuario\\Desktop\\claves\\clave_privada_firma.pem";
    const char *signatureFile = "C:\\Users\\usuario\\Desktop\\firma_ecdsa.txt";

    // Firmar la clave privada RSA con ECDSA y guardar la firma en un archivo separado
    signRSAWithECDSA(ecdsaPrivateKeyFile, rsaPrivateKeyFile, signatureFile);

    return 0;
}
