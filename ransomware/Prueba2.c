#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs.h>

int main() {
    
    // Generamos un par de claves.
    uint8_t *public_key = malloc(OQS_KEM_classic_mceliece_348864_length_public_key);
    uint8_t *secret_key = malloc(OQS_KEM_classic_mceliece_348864_length_secret_key);

    if (OQS_KEM_classic_mceliece_348864_keypair(public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error al generar el par de claves.\n");
        free(public_key);
        free(secret_key);
        return 1;
    }

    // Ingresamos el texto por teclado
    printf("Ingresa el texto a cifrar: ");
    char input_text[256]; // Se asume que el texto tiene como máximo 255 caracteres.
    fgets(input_text, sizeof(input_text), stdin);
    input_text[strcspn(input_text, "\n")] = '\0'; // Elimina el carácter de nueva línea.

    // Encriptamos el mensaje.
    size_t ciphertext_size = OQS_KEM_classic_mceliece_348864_length_ciphertext;
    unsigned char *ciphertext = malloc(ciphertext_size);
    uint8_t *shared_secret = malloc(OQS_KEM_classic_mceliece_348864_length_shared_secret);

    if (OQS_KEM_classic_mceliece_348864_encaps(ciphertext, shared_secret, public_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error al encriptar el mensaje.\n");
        free(public_key);
        free(secret_key);
        free(ciphertext);
        free(shared_secret);
        return 1;
    }

    // Imprimimos el mensaje cifrado.
    printf("Texto cifrado: ");
    for (size_t i = 0; i < ciphertext_size; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Desciframos el mensaje.
    unsigned char *decrypted_text = malloc(strlen(input_text) + 1);
    if (OQS_KEM_classic_mceliece_348864_decaps(decrypted_text, ciphertext, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error al descifrar el mensaje.\n");
        free(public_key);
        free(secret_key);
        free(ciphertext);
        free(shared_secret);
        free(decrypted_text);
        return 1;
    }

    // Imprimimos el texto descifrado.
    printf("Texto descifrado: %s\n", decrypted_text);

    // Liberamos las claves y la memoria asignada.
    OQS_MEM_secure_free(public_key, OQS_KEM_classic_mceliece_348864_length_public_key);
    OQS_MEM_secure_free(secret_key, OQS_KEM_classic_mceliece_348864_length_secret_key);
    free(ciphertext);
    free(shared_secret);
    free(decrypted_text);

    return 0;
}