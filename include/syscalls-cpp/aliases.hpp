#ifndef SYSCALL_ALIASES_HPP
#define SYSCALL_ALIASES_HPP

#include "syscall.hpp"

namespace syscall
{
    using DefaultParserChain = syscall::ParserChain_t<
        syscall::policies::parser::directory,
        syscall::policies::parser::signature
    >;

    // @note / sapdragon: fucking templates, is that a legal cpp hack? unpack overloads...
    template<typename AllocPolicy, typename StubPolicy, typename... ParserArgs>
    class Manager : public Manager<AllocPolicy, StubPolicy, DefaultParserChain>
    {
    };

    template< typename AllocPolicy, typename StubPolicy, IsSyscallParsingPolicy... ParsersInChain >
    class Manager<AllocPolicy, StubPolicy, ParserChain_t<ParsersInChain...>>
        : public ManagerImpl<AllocPolicy, StubPolicy, ParsersInChain...>
    {
    };

    template< typename AllocPolicy, typename StubPolicy, typename FirstParser, typename... FallbackParsers>
    class Manager<AllocPolicy, StubPolicy, FirstParser, FallbackParsers...>
        : public ManagerImpl<AllocPolicy, StubPolicy, FirstParser, FallbackParsers...>
    {
    };

#if SYSCALL_PLATFORM_WINDOWS_64
    using SectionGadgetManager = Manager<policies::allocator::section, policies::generator::gadget>;
    using HeapGadgetManager = Manager<policies::allocator::heap, policies::generator::gadget>;
#endif

    using SectionDirectManager = Manager<policies::allocator::section, policies::generator::direct>;
}

#endif
