#include <oqs.h>
#include <string.h>

int main() {
    
    //if(OQS_OK != OQS_init()) return 1;

    //inicializar libreria
    OQS_init();

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864);

    //claves
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);

    //generar par de claves
    OQS_KEM_keypair(kem, public_key, secret_key);

    //texto
    const char * message = "Por favor profe apruebanos";
    size_t message_len = strlen(message);
    uint8_t *ciphertext = malloc(kem->length_ciphertext+message_len);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    memcpy(ciphertext + kem->length_ciphertext, message, message_len);

    uint8_t *decrypted_message = malloc(message_len);
    OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
    memcpy(decrypted_message, shared_secret + kem->length_shared_secret, message_len);
    printf("Decrypted message: %s\n", decrypted_message);

    OQS_KEM_free(kem);
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret);
    free(decrypted_message);
    // shut down the library
    //OQS_shutdown();
    return 0;
}