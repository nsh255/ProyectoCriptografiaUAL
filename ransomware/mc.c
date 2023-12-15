#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#define N 7
#define K 4

void text_to_code(const char *input, int *output) {
    int len = strlen(input);
    for (int i = 0; i < len; ++i) {
        for (int j = 7; j >= 0; --j) {
            output[(i * 8) + (7 - j)] = (input[i] >> j) & 1;
        }
    }
}

int *matrix_multiply(int *matrix, int **matrix2) {
    printf("Matrix: ");
    int *result = calloc(N, sizeof(int));
    for (int i = 0; i < N; ++i) {
        printf("%d ", matrix[i]);
        result[i] = 0;
        for (int j = 0; j < N; ++j) {
            printf("%d ", matrix2[i][j]);
            result[i] += matrix2[i][j] * matrix[j];
        }
    }
    printf("Result: ");
    return result;
}

// Invierte una matriz
int **matrix_inverse(int **matrix)
{
    int **result = malloc(sizeof(int *) * N);
    for (int i = 0; i < N; i++)
    {
        result[i] = malloc(sizeof(int) * N);
        for (int j = 0; j < N; j++)
        {
            result[i][j] = (i == j) ? 1 : 0;
        }
    }
    return result;
}

// Corrige los errores en una matriz de código de Hamming
int **correct_errors_hamming(int **matrix)
{
    int **error_locations = malloc(sizeof(int *) * N);
    for (int i = 0; i < N; i++)
    {
        error_locations[i] = malloc(sizeof(int) * 1);
        error_locations[i][0] = -1;
    }

    // Encuentra las posiciones de los errores
    for (int i = 0; i < N; i++)
    {
        for (int j = 0; j < N; j++)
        {
            if (matrix[i][j] != matrix[i][N - 1])
            {
                error_locations[i][0] = j;
                break;
            }
        }
    }

    // Corrige los errores
    for (int i = 0; i < N; i++)
    {
        if (error_locations[i][0] != -1)
        {
            matrix[i][error_locations[i][0]] = 1 - matrix[i][error_locations[i][0]];
        }
    }

    return matrix;
}

// Cifra el texto claro con códigos de Hamming
int *encrypt_hamming(char *text, int **generator_matrix, int **parity_matrix)
{
    // Convierte el texto claro en una matriz de código
    //int *code_matrix = malloc(sizeof(int) * N * strlen(text));
    printf("Text: ");
    int *code_matrix = calloc(N * strlen(text), sizeof(int));
    text_to_code(text, code_matrix);
    printf("Code matrix: ");
    // Multiplica la matriz de código por la matriz de generadores
    int *ciphertext = matrix_multiply(code_matrix, generator_matrix);

    return ciphertext;
}

// Descifra el texto cifrado con códigos de Hamming
char *decrypt_hamming(int *ciphertext, int **generator_matrix, int **parity_matrix)
{
    // Invierte la matriz de generadores
    int **inverse_generator_matrix = matrix_inverse(generator_matrix);

    // Multiplica la matriz cifrada por la inversa de la matriz de generadores
    int *corrected_ciphertext = matrix_multiply(ciphertext, inverse_generator_matrix);

    // Corrige los errores en la matriz cifrada corregida
//    corrected_ciphertext = correct_errors_hamming(corrected_ciphertext);

    // Convierte la matriz cifrada corregida en texto claro
    char *plaintext = calloc(N + 1, sizeof(char)); // +1 para el carácter nulo al final
    if (plaintext == NULL)
    {
        // Manejar error de asignación de memoria
        printf("Error: No se pudo asignar memoria para el texto claro.\n");
        exit(1);
    }

    for (int i = 0; i < N; i++)
    {
        char str[2] = {corrected_ciphertext[i] + '0', '\0'};
        strncat(plaintext, str, 1);
    }

    return plaintext;
}

// Ejemplo de uso
int main()
{
    // Matriz generadora (G)
    int generatorMatrix[K][N] = {
        {1, 0, 0, 0, 1, 1, 1},
        {0, 1, 0, 0, 1, 0, 1},
        {0, 0, 1, 0, 1, 1, 0},
        {0, 0, 0, 1, 0, 1, 1}
    };

    // Matriz de paridad (H)
    int parityMatrix[N-K][N] = {
        {1, 1, 1, 1, 0, 0, 0},
        {1, 0, 1, 0, 1, 0, 1},
        {0, 1, 1, 0, 0, 1, 1}
    };

     // Convertir las matrices a punteros dobles
    int **genMatrix = (int **)malloc(K * sizeof(int *));
    for (int i = 0; i < K; ++i) {
        genMatrix[i] = (int *)malloc(N * sizeof(int));
        for (int j = 0; j < N; ++j) {
            genMatrix[i][j] = generatorMatrix[i][j];
        }
    }

    int **parityMatrixPtr = (int **)malloc((N - K) * sizeof(int *));
    for (int i = 0; i < (N - K); ++i) {
        parityMatrixPtr[i] = (int *)malloc(N * sizeof(int));
        for (int j = 0; j < N; ++j) {
            parityMatrixPtr[i][j] = parityMatrix[i][j];
        }
    }

    // Genera el texto claro
    char *text = "Hola mundo!";
    // Cifra el texto claro
    int *ciphertext = encrypt_hamming(text, genMatrix, parityMatrixPtr);
    printf("Ciphertext: ");
    // Descifra el texto cifrado
    char *plaintext = decrypt_hamming(ciphertext, genMatrix, parityMatrixPtr);

    // Imprime el texto claro descifrado
    printf("%s\n", plaintext);

    // Libera la memoria asignada a plaintext
    free(plaintext);

    // Libera la memoria asignada a ciphertext
    free(ciphertext);


    return 0;
}