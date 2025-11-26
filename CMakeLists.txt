cmake_minimum_required(VERSION 3.15)
project(syscalls-cpp VERSION 1.0.0 LANGUAGES CXX)

option(SYSCALL_CPP_BUILD_EXAMPLES "Build example executables" ${PROJECT_IS_TOP_LEVEL})

include(GNUInstallDirs)

add_library(${PROJECT_NAME} INTERFACE)
add_library(sapdragon::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_20)

target_include_directories(${PROJECT_NAME} INTERFACE
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if (SYSCALL_CPP_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

install(
    TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-targets
)

install(
    EXPORT ${PROJECT_NAME}-targets
    FILE ${PROJECT_NAME}-config.cmake
    NAMESPACE sapdragon::
    DESTINATION share/${PROJECT_NAME}
)