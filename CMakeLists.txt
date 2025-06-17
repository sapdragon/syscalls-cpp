cmake_minimum_required(VERSION 3.15)
project(syscalls-cpp VERSION 1.0.0 LANGUAGES CXX)

include(GNUInstallDirs)

add_library(syscalls-cpp INTERFACE)
add_library(sapdragon::syscalls-cpp ALIAS syscalls-cpp)

target_include_directories(syscalls-cpp INTERFACE
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

file(GLOB HEADER_FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp")

install(
    FILES ${HEADER_FILES}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    TARGETS syscalls-cpp
    EXPORT syscalls-cpp-targets
)

install(
    EXPORT syscalls-cpp-targets
    FILE syscalls-cpp-config.cmake
    NAMESPACE sapdragon::
    DESTINATION share/syscalls-cpp
)