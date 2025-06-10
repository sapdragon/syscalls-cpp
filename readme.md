# syscalls-cpp

syscalls-cpp is just another syscall library. It leverages a policy-based design to let you mix and match different strategies for memory allocation and stub generation at compile-time, giving you full control over your operational security tradeoffs.

The core principle is **modularity**. You are not given a black box; you are given building blocks.

## The Building Blocks: Provided Policies

You can combine any allocation policy with any stub generation policy.

#### Allocation Policies (`IsAllocationPolicy`)

| Policy             | Method                                                |
| ------------------ | ----------------------------------------------------- | 
| `SectionAllocator` | `NtCreateSection` with `SEC_NO_CHANGE` flag           | 
| `HeapAllocator`    | `HeapCreate` with `HEAP_CREATE_ENABLE_EXECUTE`        |

#### Stub Generation Policies (`IsStubGenerationPolicy`)

| Policy                | Method                                              |
| --------------------- | ----------------------------------------------------|
| `GadgetStubGenerator` | Jumps to a `syscall; ret` gadget found in `ntdll.dll|
| `DirectStubGenerator` | Uses a classic, self-contained `syscall` instruction|

## Example: Crafting Your Strategy

The power is in the combination. Here is how you build and use a custom syscall manager.

```cpp
#include <iostream>
#include "syscall.hpp"

int main() {
    using MyStealthyManager = syscall::Manager<
        syscall::policies::HeapAllocator,        
        syscall::policies::GadgetStubGenerator   
    >;

    MyStealthyManager syscallManager;
    if (!syscallManager.initialize()) 
    {
        std::cerr << "initialization failed!\n";
        return 1;
    }
    
    PVOID pBaseAddress = nullptr;
    SIZE_T uSize = 0x1000;

    syscallManager.invoke<NTSTATUS>(
        "NtAllocateVirtualMemory",
        NtCurrentProcess(),
        &baseAdpBaseAddressdress,
        0, &uSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (pBaseAddress)
        std::cout << "allocation successful at 0x" << baseAddress << std::endl;

    return 0;
}
```

## Extensibility

The true power of the framework is its extensibility. You can easily write your own policies. Simply create a class that satisfies the required `concept` (`IsAllocationPolicy` or `IsStubGenerationPolicy`), and it will be seamlessly compatible with the `Manager`.

## Requirements

-   A C++20 compatible compiler (MSVC, Clang, GCC).
-   Windows x64 target.