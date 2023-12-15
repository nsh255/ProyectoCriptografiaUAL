#include <stdio.h>
#include <stdlib.h>
#include <oqs.h>

int main() {
    OQS_KEM *kem = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *ciphertext = NULL;
	uint8_t *shared_secret_e = NULL;
	uint8_t *shared_secret_d = NULL;
    kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_460896);
    if (kem == NULL) return 1;
    
    // Asignar memoria
    public_key = malloc(kem->length_public_key);
	secret_key = malloc(kem->length_secret_key);
	ciphertext = malloc(kem->length_ciphertext);
	shared_secret_e = malloc(kem->length_shared_secret);
	shared_secret_d = malloc(kem->length_shared_secret);
    
    if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) || (shared_secret_e == NULL) || (shared_secret_d == NULL)) return 2;

    OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
    if (rc != OQS_SUCCESS) return 3;
    
    printf("Introduce el mensaje: ");
    scanf("%s", shared_secret_e);
    shared_secret_e = "h";

    rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS) return 4;

    printf("La codificacion del mensaje es: ");
    for (size_t i = 0; i < OQS_KEM_classic_mceliece_460896_length_ciphertext; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    rc = OQS_KEM_decaps(kem, shared_secret_e, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) return 5;
    
    printf("La decodificacion del mensaje es: ");
    for (size_t i = 0; i < OQS_KEM_classic_mceliece_460896_length_shared_secret; i++) {
        printf("%s", shared_secret_d[i]);
    }
    printf("\n");

    return 0;
}

