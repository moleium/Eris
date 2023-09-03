# Eris
A Minimalisic C++ library for hijacking handles in Windows processes.

## Usage
To use the Eris library, simply include the `eris.h` header file and `eris.cpp` in your code and call `Hijack` function.

Here's an example of how you would use Eris to take over a process:
```cpp
#include "eris.h"

int main() {
    DWORD pid = Eris::GetPID("whatever.exe");

    std::cout << 
        (pid == 0 ? "Process not found" : "Process found") << std::endl;

    HANDLE Handle = Eris::Hijack(pid);

    if (Handle != nullptr) {
        std::cout << "Successfully hijacked handle: " << Handle << std::endl;
        // Output -> 0xb18
    }
    else {
        std::cerr << "Failed to hijack handle" << std::endl;
    }

    getchar();
    return 0;
}
```

## Contributing
Contributions to the Eris library are welcome, If you have any suggestions or improvements, feel free to open an issue or submit a pull request.

## License
The Eris library is licensed under the MIT license. See the [LICENSE] file for more information.