# syscalls-cpp

syscalls-cpp is a C++20 policy-based framework for crafting undetectable/protected syscalls (x86 / x64). It leverages a policy-based design to let you mix and match different strategies for memory allocation and stub generation at compile-time, giving you full control over your operational security tradeoffs.

The core principle is **modularity**. You are not given a black box; you are given building blocks.

**The library automatically resolves system call numbers by directly parsing ntdll.dll's metadata. This method is resilient to user-mode hooks by leveraging the PE's structure—the exception directory on x64 and sorted export addresses on x86—and can find adjacent syscalls if a target is patched.**

[![SEC_NO_CHANGE](https://raw.githubusercontent.com/sapdragon/syscalls-cpp/refs/heads/main/docs/images/protection_demo.gif)](https://raw.githubusercontent.com/sapdragon/syscalls-cpp/refs/heads/main/docs/images/protection_demo.gif)

*Allocation demonstration: an attempt to patch a system call located in a section with the `SEC_NO_CHANGE` flag fails.

## The Building Blocks: Provided Policies

You can combine any allocation policy with any stub generation policy.

#### Allocation Policies (`IsAllocationPolicy`)

| Policy             | Method                                                |
| ------------------ | ----------------------------------------------------- | 
| `allocator::section` | `NtCreateSection` with `SEC_NO_CHANGE` flag           | 
| `allocator::heap`    | `HeapCreate` with `HEAP_CREATE_ENABLE_EXECUTE`        |
| `allocator::memory`    | `NtAllocateVirtualMemory` (`RW` -> `RX`)       |

    

#### Stub Generation Policies (`IsStubGenerationPolicy`)

| Policy                | Method                                              |
| --------------------- | ----------------------------------------------------|
| `generator::direct` | Uses a classic, self-contained `syscall` instruction|
| `generator::gadget` only | (Only x64) Jumps to a `syscall; ret` gadget found in `ntdll.dll|
| `generator::exception` | Triggers a breakpoint (`ud2`) to perform the syscall via a custom Vectored Exception Handler (VEH). |

#### Parsing Policies (`IsSyscallParsingPolicy`)
| Policy | Method |
| :--- | :--- |
| `parser::directory` | On x64, maps the exception directory (.pdata) to the export table to determine the order of syscalls. On x86, it sorts exported Zw* functions by their memory addresses to calculate their numbers. |
| `parser::signature` | Scans function prologues for the `mov r10, rcx; mov eax, syscall_id` signature with hooks detection. |


## Installation

The recommended way to install and manage the library is through the C++ package manager [vcpkg](https://vcpkg.io/).

```sh
vcpkg install syscalls-cpp
```

This command will download, build, and install `syscalls-cpp`, making it easily accessible for your projects with automatic MSBuild and CMake integration.

### Conan

You can also use [Conan](https://conan.io/). Add the following to your `conanfile.txt`:

```ini
[requires]
syscalls-cpp/1.2.0
```

For manual setup, you can clone this repository and add the `include` directory to your project's include paths.


## Community Ports

Community-maintained ports and bindings:

| Language | Repository |
| :--- | :--- |
| Rust | [orange-cpp/syscalls-rs](https://github.com/orange-cpp/syscalls-rs) |

> These ports are maintained by the community and may differ from the C++ implementation in API, features, and release cadence.

## Example: Crafting Your Strategy

The power is in the combination. Here is how you build and use a syscall manager.

### Standard Usage
```cpp
#include <iostream>
#include "syscall.hpp"

int main() {
    auto syscallManager = syscall::SectionDirectManager::create();
    // Add module keys to create({ ... }); when more than ntdll is needed.
    if (!syscallManager)
    {
        std::cerr << "initialization failed!\n";
        return 1;
    }

    PVOID pBaseAddress = nullptr;
    SIZE_T uSize = 0x1000;

    syscallManager->invoke<NTSTATUS>(
        SYSCALL_ID("NtAllocateVirtualMemory"),
        NtCurrentProcess(),
        &pBaseAddress,
        0, &uSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (pBaseAddress)
        std::cout << "allocation successful at 0x" << pBaseAddress << std::endl;

    return 0;
}
```

### Advanced Usage

For more control, you can specify your own policy or build a custom allocators / generators / parsers

```cpp
#include "syscall.hpp"

using UniqueSecretOwnPolicyManager = syscall::Manager<
        syscall::policies::allocator::heap, // heap allocator
        syscall::policies::generator::direct, // direct!!
        syscall::policies::parser::directory,
        syscall::policies::parser::signature
>;

// Or select a custom parser chain directly:
// imagine you wrote a MyCustomParser policy
/*
using SuperCustomManager = syscall::Manager<
    syscall::policies::allocator::heap,
    syscall::policies::generator::direct,
    MyCustomParser,
    syscall::policies::parser::signature
>;
*/
```

> [!WARNING]
> ### `NULL` vs. `nullptr` on x64
> **Always use `nullptr` instead of `NULL`** when invoking syscalls on x64 platforms.
>
> The `NULL` macro is often defined as an integer `0` (a 32-bit `int`). Passing it to a syscall expecting a 64-bit pointer can corrupt the stack, as the compiler may treat it as an integer and fail to properly extend it. This leads to argument misalignment and unpredictable crashes.
>
> `nullptr` is type-safe and guarantees the correct 64-bit null pointer representation, preventing this subtle but critical bug.

## Extensibility

The true power of the framework is its extensibility. You can easily write your own policies. Simply create a class that satisfies the required `concept` (`IsAllocationPolicy`, `IsStubGenerationPolicy`, or `IsSyscallParsingPolicy`), and it will be seamlessly compatible with the `Manager`.

## Configuration

For easier debugging, you can disable the compile-time hashing mechanism by defining the `SYSCALLS_NO_HASH` macro. This will cause the manager to use `std::string` for syscall names instead of integer hashes.

-   **MSVC:** `/DSYSCALLS_NO_HASH`
-   **GCC/Clang:** `-DSYSCALLS_NO_HASH`

## Requirements

-   A C++20 compatible compiler (MSVC, Clang, GCC).
-   Windows targets (x86/x64)

## LICENSE
MIT
