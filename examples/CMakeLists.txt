project(syscall_examples)

add_executable(basic_usage basic-usage.cpp)
target_link_libraries(basic_usage PRIVATE syscalls-cpp)
set_target_properties(basic_usage PROPERTIES CXX_STANDARD 20)

add_executable(custom_generator custom-generator.cpp)
target_link_libraries(custom_generator PRIVATE syscalls-cpp)
set_target_properties(custom_generator PROPERTIES CXX_STANDARD 20)