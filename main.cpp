#include <iostream>

#include "eris.h"

int main() {
    DWORD pid = eris::get_pid("whatever.exe");

    std::cout << 
        (pid == 0 ? "Process not found" : "Process found") << std::endl;

    HANDLE handle = eris::hijack(pid);

    if (handle != nullptr) {
        std::cout << "Successfully hijacked handle: " << handle << std::endl;
    }

    //NTSTATUS status = eris::read_vm(handle, (PVOID)address, buffer, sizeof(buffer));

    getchar();
    return 0;
}