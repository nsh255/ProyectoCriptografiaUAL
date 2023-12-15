#include <stdio.h>
#include <string.h>

// Función para convertir una cadena de caracteres a binario
void stringToBinary(const char *inputString) {
    printf("Cadena '%s' en binario: ", inputString);

    // Recorre cada carácter de la cadena e imprime su representación binaria
    for (int i = 0; i < strlen(inputString); ++i) {
        for (int j = 7; j >= 0; --j) {
            printf("%d", (inputString[i] >> j) & 1);
        }
        printf(" ");
    }

    printf("\n");
}

// Función para convertir una cadena binaria a una cadena de caracteres
void binaryToString(const char *binaryString) {
    int length = strlen(binaryString);

    // Asegura que la longitud de la cadena binaria sea múltiplo de 8
    if (length % 8 != 0) {
        printf("Error: La cadena binaria no tiene longitud válida.\n");
        return;
    }

    printf("Cadena binaria '%s' convertida a caracteres: ", binaryString);

    // Recorre la cadena binaria de 8 en 8 bits y convierte a caracteres
    for (int i = 0; i < length; i += 8) {
        char resultChar = 0;

        for (int j = 0; j < 8; ++j) {
            resultChar = (resultChar << 1) | (binaryString[i + j] - '0');
        }

        printf("%c", resultChar);
    }

    printf("\n");
}

int main() {
    // Ejemplo de uso con cadena de caracteres
    const char *inputString = "Hola";

    // Llama a la función para convertir la cadena a binario
    stringToBinary(inputString);

    // Ejemplo de cadena binaria
    const char *binaryString = "01001000011011110110110001100001";

    // Llama a la función para convertir binario a cadena de caracteres
    binaryToString(binaryString);

    return 0;
}
