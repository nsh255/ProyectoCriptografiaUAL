/*#include <stdio.h>
#include <stdlib.h>
#include <oqs.h>

int main() {
  // Generamos un par de claves.
  uint8_t *public_key = NULL;
  uint8_t *secret_key = NULL;
  OQS_STATUS clave = OQS_KEM_classic_mceliece_348864_keypair(public_key, secret_key);
  
  if (clave != OQS_SUCCESS) {
    fprintf(stderr, "Error al generar el par de claves.\n");
    return 1;
  }

  // Encriptamos un mensaje.
  size_t ciphertext_size = OQS_KEM_classic_mceliece_348864_length_ciphertext;
  unsigned char *ciphertext = malloc(ciphertext_size);
  uint8_t *shared_secret = malloc(OQS_KEM_classic_mceliece_348864_length_shared_secret);

  if (OQS_KEM_classic_mceliece_348864_encaps(ciphertext, shared_secret, public_key) != OQS_SUCCESS) {
    fprintf(stderr, "Error al encriptar el mensaje.\n");
    free(ciphertext);
    free(shared_secret);
    return 1;
  }

  // Imprimimos el mensaje encriptado.
  printf("Ciphertext: ");
  for (size_t i = 0; i < ciphertext_size; i++) {
    printf("%02x", ciphertext[i]);
  }
  printf("\n");

  // Liberamos las claves y la memoria asignada.
  OQS_MEM_secure_free(public_key, OQS_KEM_classic_mceliece_348864_length_public_key);
  OQS_MEM_secure_free(secret_key, OQS_KEM_classic_mceliece_348864_length_secret_key);
  free(ciphertext);
  free(shared_secret);

  return 0;
}*/
#include <stdio.h>
#include <stdlib.h>
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

    // Encriptamos un mensaje.
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

    // Imprimimos el mensaje encriptado.
    printf("Ciphertext: ");
    for (size_t i = 0; i < ciphertext_size; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Liberamos las claves y la memoria asignada.
    OQS_MEM_secure_free(public_key, OQS_KEM_classic_mceliece_348864_length_public_key);
    OQS_MEM_secure_free(secret_key, OQS_KEM_classic_mceliece_348864_length_secret_key);
    free(ciphertext);
    free(shared_secret);

    return 0;
}