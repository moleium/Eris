# Eris
A Minimalisic C++ library for hijacking handles in Windows processes.

## Usage
To use the Eris library, simply include the `eris.h` header file and `eris.cpp` in your code and call `hijack` function.

Here's an example of how you would use Eris to take over a process:
```cpp
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

    getchar();
    return 0;
}
```

## Contributing
Contributions to the Eris library are welcome, If you have any suggestions or improvements, feel free to open an issue or submit a pull request.

## License
The Eris library is licensed under the MIT license. See the [LICENSE] file for more information.