#include <iostream>

#include "eris.h"

int main() {
    DWORD pid = Eris::GetPID("whatever.exe");

    std::cout << 
        (pid == 0 ? "Process not found" : "Process found") << std::endl;

    HANDLE Handle = Eris::Hijack(pid);

    if (Handle != nullptr) {
        std::cout << "Successfully hijacked handle: " << Handle << std::endl;
    }
    else {
        std::cerr << "Failed to hijack handle" << std::endl;
    }

    getchar();
    return 0;
}
