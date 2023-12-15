#include <stdio.h>
#include <stdlib.h>

#define N 10
#define K 8

typedef struct
{
  int **g;
  int d;
} McElieceKey;

McElieceKey generate_key()
{
  McElieceKey key;
  key.g = malloc(N * sizeof(int *));
  for (int i = 0; i < N; i++)
  {
    key.g[i] = malloc(N * sizeof(int));
    for (int j = 0; j < N; j++)
    {
      key.g[i][j] = rand() % 2;
    }
  }
  key.d = rand() % 2;
  return key;
}

void encrypt(McElieceKey key, int *m, int *c)
{
  int m2[N + 1];
  m2[0] = m[0];
  for (int i = 1; i < N + 1; i++)
  {
    m2[i] = m[i - 1];
  }
  encrypt(key, m2, c);
}

int decrypt(McElieceKey key, int *c, int *m)
{
  int m2[N + 1];
  decrypt(key, c, m2);
  return m[0];
}

int main()
{
  McElieceKey key = generate_key();
  int m = 1234;
  int c[N];

  printf("Mensaje original: %d\n", m);
  encrypt(key, &m, c);
  // Introducimos errores en el mensaje cifrado
  for (int i = 0; i < N; i++)
  {
    c[i] = c[i] ^ rand() % 2;
  }

  int m_decrypted[N + 1];
  decrypt(key, c, m_decrypted);
  int m2 = m_decrypted[0];

  if (m == m2)
  {
    printf("Encriptación y descifrado correctos\n");
  }
  else
  {
    printf("Encriptación o descifrado incorrectos\n");
  }

  return 0;
}