#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int signRSAWithECDSA(const char *ruta_archivo, const char *clave_privada, const char *rutaAFirma) {
     // Leer el archivo a firmar
    FILE *file = fopen(ruta_archivo, "rb");
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


    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, file_size, hash);

    // Abrir el archivo de clave privada
    FILE *clave_privada_file = fopen(clave_privada, "r");
    if (!clave_privada_file) {
        fprintf(stderr, "Error al abrir el archivo de clave privada\n");
        exit(EXIT_FAILURE);
    }

    // Leer la clave privada
    EC_KEY *private_key = PEM_read_ECPrivateKey(clave_privada_file, NULL, NULL, NULL);
    fclose(clave_privada_file); // Cerrar el archivo después de leer la clave privada

    if (!private_key) {
        fprintf(stderr, "Error al leer la clave privada\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    ECDSA_SIG *firma = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, private_key);
    if (!firma) {
        fprintf(stderr, "Error al firmar el archivo\n");
        exit(EXIT_FAILURE);
    }

    unsigned char *der_signature = NULL;
    int der_signature_len = i2d_ECDSA_SIG(firma, &der_signature);
    if (der_signature_len <= 0) {
        fprintf(stderr, "Error al codificar la firma en formato DER\n");
        exit(EXIT_FAILURE);
    }

    FILE *firma_file = fopen(rutaAFirma, "wb");
    if (!firma_file) {
        fprintf(stderr, "Error al abrir el archivo de firma\n");
        exit(EXIT_FAILURE);
    }

    fwrite(der_signature, 1, der_signature_len, firma_file);
    fclose(firma_file);

    OPENSSL_free(der_signature);  // Liberar la memoria asignada por i2d_ECDSA_SIG

    /*FILE *clave_publica_file = fopen(rutaAFirma, "w");
    if (!clave_publica_file) {
        fprintf(stderr, "Error al abrir el archivo de clave pública\n");
        exit(EXIT_FAILURE);
    }

    PEM_write_EC_PUBKEY(clave_publica_file, private_key);
    fclose(clave_publica_file);*/

    printf("Firma exitosa\n");

    free(data);
    ECDSA_SIG_free(firma);
    EC_KEY_free(private_key);
}


int main() {
    const char *rsaPrivateKeyFile = "C:\\Users\\usuario\\Desktop\\clave_privada_rsa.pem";
    const char *ecdsaPrivateKeyFile = "C:\\Users\\usuario\\Desktop\\claves\\clave_privada_firma.pem";
    const char *signatureFile = "C:\\Users\\usuario\\Desktop\\firma_ecdsa.txt";

    // Firmar la clave privada RSA con ECDSA y guardar la firma en un archivo separado
    signRSAWithECDSA(rsaPrivateKeyFile, ecdsaPrivateKeyFile, signatureFile);

    return 0;
}
