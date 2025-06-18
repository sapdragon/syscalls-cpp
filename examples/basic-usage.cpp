#include <iostream>
#include <syscalls-cpp/syscall.hpp>

int main() 
{
    syscall::Manager<syscall::policies::allocator::section, syscall::policies::generator::direct> syscallManager;
    if (!syscallManager.initialize())
    {
        std::cerr << "initialization failed!\n";
        return 1;
    }

    PVOID pBaseAddress = nullptr;
    SIZE_T uSize = 0x1000;

    syscallManager.invoke<NTSTATUS>(
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