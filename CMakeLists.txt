cmake_minimum_required(VERSION 3.15)

project(syscalls-cpp VERSION 1.0.0 LANGUAGES CXX)

add_library(syscalls-cpp INTERFACE)

target_include_directories(syscalls-cpp INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

install(
    TARGETS syscalls-cpp
    EXPORT syscalls-cpp-targets 
)

install(
    FILES 
        crt.hpp,
        hash.hpp,
        shared.hpp,
        native_api.hpp,
        syscall.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    EXPORT syscalls-cpp-targets
    FILE syscalls-cpp-config.cmake
    NAMESPACE syscalls-cpp::
    DESTINATION share/syscalls-cpp
)