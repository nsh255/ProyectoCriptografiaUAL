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

void code_to_text(const int *input, char *output) {
    int len = sizeof(input);
    for (int i = 0; i < len; ++i) {
        output[i] = 0;
        for (int j = 0; j < 8; ++j) {
            output[i] |= input[(i * 8) + j] << (7 - j);
        }
    }
}

int main()
{
    char *input = "hola mundo";
    int *output = malloc(sizeof(int) * strlen(input) * sizeof(char));
    text_to_code(input, output);

    for (int i = 0; i < strlen(input) * 8; i++)
    {
        printf("%d", output[i]);
    }

    printf("\n"); 
    printf("%d\n", sizeof(output));
    char *output2 = malloc(sizeof(char) * sizeof(output));
    code_to_text(output, output2);

    printf("%s\n", output2);

}