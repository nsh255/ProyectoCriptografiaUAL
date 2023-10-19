#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>

int CopyFiles(const char *sourcePath, const char *destPath) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile(strcat(strcat(sourcePath, "\\"), "*"), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return 1; // Error al buscar archivos en la carpeta de origen.
    }

    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char sourceFilePath[MAX_PATH];
            char destFilePath[MAX_PATH];

            PathCombineA(sourceFilePath, sourcePath, findFileData.cFileName);
            PathCombineA(destFilePath, destPath, findFileData.cFileName);

            if (!CopyFile(sourceFilePath, destFilePath, FALSE)) {
                return 2; // Error al copiar archivos.
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
    return 0; // Éxito.
}

int main() {
    const char *sourceFolder = "C:\\Users\\usuario\\Desktop\\Pruebas para criptografía";
    const char *destFolder = "C:\\Users\\usuario\\Desktop\\Archivos encriptados";

    if (!CreateDirectory(destFolder, NULL) && ERROR_ALREADY_EXISTS != GetLastError()) {
        printf("Error al crear la carpeta de destino. Código de error: %d\n", GetLastError());
        return 1;
    }

    int result = CopyFiles(sourceFolder, destFolder);

    if (result == 0) {
        printf("Archivos copiados con éxito.\n");
    } else if (result == 1) {
        printf("Error al buscar archivos en la carpeta de origen.\n");
    } else if (result == 2) {
        printf("Error al copiar archivos.\n");
    }

    return result;
}
