#include <iostream>
#include <syscalls-cpp/syscall.hpp>
int main()
{
    std::optional optSyscallManager = syscall::Manager<syscall::policies::allocator::section, syscall::policies::generator::direct>::initialize();
    if (!optSyscallManager.has_value()) {
        std::cerr << "initialization failed!\n";
        return 1;
    }

    auto& syscallManager = optSyscallManager.value();

    PVOID pBaseAddress = nullptr;
    SIZE_T uSize = 0x1000;

    std::ignore = syscallManager.invoke<NTSTATUS>(
        SYSCALL_ID("NtAllocateVirtualMemory"),
        syscall::native::getCurrentProcess(),
        &pBaseAddress,
        0, &uSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (pBaseAddress)
        std::cout << "allocation successful at 0x" << pBaseAddress << std::endl;

    return 0;
}