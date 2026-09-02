#ifndef SYSCALL_ALIASES_HPP
#define SYSCALL_ALIASES_HPP

#include "syscall.hpp"

namespace syscall
{
    template<typename AllocPolicy, typename StubPolicy, typename... ParserArgs>
    class Manager;

    template<typename AllocPolicy, typename StubPolicy>
    class Manager<AllocPolicy, StubPolicy>
        : public Manager<AllocPolicy, StubPolicy, syscall::policies::parser::directory, syscall::policies::parser::signature>
    {
    public:
        static std::optional<Manager> initialize( const std::vector<SyscallKey_t>& vecModuleKeys = { SYSCALL_ID("ntdll.dll") } )
        {
            std::optional optManager = Manager<AllocPolicy, StubPolicy, syscall::policies::parser::directory, syscall::policies::parser::signature>::initialize(vecModuleKeys);

            if (!optManager.has_value())
                return std::nullopt;

            return Manager(std::move(optManager.value()));
        }
    };

    template< typename AllocPolicy, typename StubPolicy, IsSyscallParsingPolicy... ParsersInChain >
    class Manager<AllocPolicy, StubPolicy, ParsersInChain...>
        : public ManagerImpl<AllocPolicy, StubPolicy, ParsersInChain...>
    {
        Manager(ManagerImpl<AllocPolicy, StubPolicy, ParsersInChain...>&& managerImpl)
            : ManagerImpl<AllocPolicy, StubPolicy, ParsersInChain...>(std::move(managerImpl))
        { }
    public:
        static std::optional<Manager> initialize(const std::vector<SyscallKey_t>& vecModuleKeys = { SYSCALL_ID("ntdll.dll") })
        {
            std::optional optManagerImpl = ManagerImpl<AllocPolicy, StubPolicy, ParsersInChain...>::initialize(vecModuleKeys);
            if (!optManagerImpl.has_value())
                return std::nullopt;

            return Manager(std::move(optManagerImpl.value()));
        }
    };

#if SYSCALL_PLATFORM_WINDOWS_64
    using SectionGadgetManager = Manager<policies::allocator::section, policies::generator::gadget>;
    using HeapGadgetManager = Manager<policies::allocator::heap, policies::generator::gadget>;
#endif

    using SectionDirectManager = Manager<policies::allocator::section, policies::generator::direct>;
}

#endif
