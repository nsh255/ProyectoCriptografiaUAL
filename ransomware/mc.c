#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#define N 256
#define K 128

// Convierte el texto claro en una matriz de código de Hamming
int **text_to_code_matrix_hamming(char *text)
{
    int **matrix = malloc(sizeof(int *) * N);
    for (int i = 0; i < N; i++)
    {
        matrix[i] = malloc(sizeof(int) * 1);
        matrix[i][0] = text[i] - '0';
    }
    return matrix;
}

// Multiplica dos matrices
int **matrix_multiply(int **matrix1, int **matrix2)
{
    int **result = malloc(sizeof(int *) * N);
    for (int i = 0; i < N; i++)
    {
        result[i] = malloc(sizeof(int) * N);
        for (int j = 0; j < N; j++)
        {
            result[i][j] = 0;
            for (int k = 0; k < N; k++)
            {
                result[i][j] += matrix1[i][k] * matrix2[k][j];
            }
        }
    }
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
int **encrypt_hamming(char *text, int **generator_matrix, int **parity_matrix)
{
    // Convierte el texto claro en una matriz de código
    int **code_matrix = text_to_code_matrix_hamming(text);

    // Multiplica la matriz de código por la matriz de generadores
    int **ciphertext = matrix_multiply(code_matrix, generator_matrix);

    return ciphertext;
}

// Descifra el texto cifrado con códigos de Hamming
char *decrypt_hamming(int **ciphertext, int **generator_matrix, int **parity_matrix)
{
    // Invierte la matriz de generadores
    int **inverse_generator_matrix = matrix_inverse(generator_matrix);

    // Multiplica la matriz cifrada por la inversa de la matriz de generadores
    int **corrected_ciphertext = matrix_multiply(ciphertext, inverse_generator_matrix);

    // Corrige los errores en la matriz cifrada corregida
    corrected_ciphertext = correct_errors_hamming(corrected_ciphertext);

    // Convierte la matriz cifrada corregida en texto claro
    char *plaintext = calloc(N + 1, sizeof(char)); // +1 para el carácter nulo al final
    if (plaintext == NULL)
    {
        // Manejar error de asignación de memoria
        exit(1);
    }

    for (int i = 0; i < N; i++)
    {
        char str[2] = {corrected_ciphertext[i][0] + '0', '\0'};
        strncat(plaintext, str, 1);
    }

    return plaintext;
}

// Ejemplo de uso
int main()
{
    // Genera la clave pública
    int generator_matrix[7][4] = {{1, 0, 0, 0, 1, 1, 1}, 
                                  {1, 1, 0, 0, 0, 1, 1}, 
                                  {1, 1, 1, 0, 0, 0, 1}, 
                                  {0, 1, 1, 1, 0, 0, 1}, 
                                  {0, 0, 1, 1, 1, 0, 1}, 
                                  {0, 0, 0, 1, 1, 1, 1}};
                                  
    int parity_matrix[7][3] = {{1, 1, 1, 1, 0, 0, 0}, 
                               {1, 1, 0, 0, 1, 1, 0}, 
                               {1, 0, 1, 0, 1, 0, 1}};

    // Genera el texto claro
    char *text = "Hola mundo!";

    // Cifra el texto claro
    int **ciphertext = encrypt_hamming(text, generator_matrix, parity_matrix);

    // Descifra el texto cifrado
    char *plaintext = decrypt_hamming(ciphertext, generator_matrix, parity_matrix);

    // Imprime el texto claro descifrado
    printf("%s\n", plaintext);

    // Libera la memoria asignada a plaintext
    free(plaintext);

    // Libera la memoria asignada a ciphertext
    for (int i = 0; i < N; i++)
    {
        free(ciphertext[i]);
    }
    free(ciphertext);

    // Libera la memoria asignada a generator_matrix
    for (int i = 0; i < N; i++)
    {
        free(generator_matrix[i]);
    }
    free(generator_matrix);

    // Libera la memoria asignada a parity_matrix
    for (int i = 0; i < N; i++)
    {
        free(parity_matrix[i]);
    }
    free(parity_matrix);

    return 0;
}