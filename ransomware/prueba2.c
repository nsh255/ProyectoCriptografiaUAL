#include <windows.h>
#include <tchar.h>
#include <stdio.h>

int main() {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile(_T("C:\\Users\\usuario\\Desktop\\patata"), &findFileData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        _tprintf(_T("No se pudo abrir la carpeta. Error %d: %s\n"), GetLastError(), strerror(GetLastError()));
        return 1;
    } else {
        int numero;
        do {
            if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                _tprintf(_T("Nombre del archivo: %s\n"), findFileData.cFileName);
                _tprintf(_T("Ingresa un número: "));
                scanf("%d", &numero);
            }
        } while (FindNextFile(hFind, &findFileData) != 0);
        FindClose(hFind);
    }

    return 0;
}