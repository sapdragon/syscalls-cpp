# syscalls-cpp

syscalls-cpp is just another syscall library. It leverages a policy-based design to let you mix and match different strategies for memory allocation and stub generation at compile-time, giving you full control over your operational security tradeoffs.

The core principle is **modularity**. You are not given a black box; you are given building blocks.

**The library automatically resolves system call numbers by directly parsing `ntdll.dll` and is resilient to user-mode hooks by searching for adjacent syscalls if a target is patched.**

## The Building Blocks: Provided Policies

You can combine any allocation policy with any stub generation policy.

#### Allocation Policies (`IsAllocationPolicy`)

| Policy             | Method                                                |
| ------------------ | ----------------------------------------------------- | 
| `SectionAllocator` | `NtCreateSection` with `SEC_NO_CHANGE` flag           | 
| `HeapAllocator`    | `HeapCreate` with `HEAP_CREATE_ENABLE_EXECUTE`        |
| `VirtualMemoryAllocator`    | `NtAllocateVirtualMemory` (`RW` -> `RX`)       |

#### Stub Generation Policies (`IsStubGenerationPolicy`)

| Policy                | Method                                              |
| --------------------- | ----------------------------------------------------|
| `GadgetStubGenerator` | Jumps to a `syscall; ret` gadget found in `ntdll.dll|
| `DirectStubGenerator` | Uses a classic, self-contained `syscall` instruction|
| `ExceptionStubGenerator` | Triggers a breakpoint (`ud2`) to perform the syscall via a custom Vectored Exception Handler (VEH). |


#### Parsing Policies (`IsSyscallParsingPolicy`)
| Policy | Method |
| :--- | :--- |
| `ExceptionDirectoryParser` | Parses the PE exception directory (`.pdata` section) of the module. This is the most reliable method. |
| `SignatureScanningParser` | Scans function prologues for the `mov r10, rcx; mov eax, syscall_id` signature with hooks detection. This is a robust fallback. |


## Example: Crafting Your Strategy

The power is in the combination. Here is how you build and use a syscall manager.

### Standard Usage
```cpp
#include <iostream>
#include "syscall.hpp"

int main() {
    SyscallSectionGadget syscallManager;
    // you can add your own modules for parsing syscalls, by default only ntdll is parsed
    if (!syscallManager.initialize(/* SYSCALL_ID("ntdll.dll"),  SYSCALL_ID("win32u.dll")*/))
    {
        std::cerr << "initialization failed!\n";
        return 1;
    }

    PVOID pBaseAddress = nullptr;
    SIZE_T uSize = 0x1000;

    syscallManager.invoke<NTSTATUS>(
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
        syscall::policies::HeapAllocator, // heap allocator
        syscall::policies::GadgetStubGenerator // gadget by ntdll
        DefaultParserChain  // default exception directory + improved halo gates as a fallback is used
>;

// or, let's build a custom parser chain using the ParserChain_t helper
// imagine you wrote a MyCustomParser policy
/*
using MyParserChain = syscall::ParserChain_t<
    MyCustomParser,
    syscall::policies::SignatureScanningParser
>;

using SuperCustomManager = syscall::Manager<
    syscall::policies::HeapAllocator,
    syscall::policies::GadgetStubGenerator,
    MyParserChain // own custom chain!!!
>;
*/
```

## Extensibility

The true power of the framework is its extensibility. You can easily write your own policies. Simply create a class that satisfies the required `concept` (`IsAllocationPolicy`, `IsStubGenerationPolicy`, or `IsSyscallParsingPolicy`), and it will be seamlessly compatible with the `Manager`.

## Configuration

For easier debugging, you can disable the compile-time hashing mechanism by defining the `SYSCALLS_NO_HASH` macro. This will cause the manager to use `std::string` for syscall names instead of integer hashes.

-   **MSVC:** `/DSYSCALLS_NO_HASH`
-   **GCC/Clang:** `-DSYSCALLS_NO_HASH`

## Requirements

-   A C++20 compatible compiler (MSVC, Clang, GCC).
-   Windows x64 target.