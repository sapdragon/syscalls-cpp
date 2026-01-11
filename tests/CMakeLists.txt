include(FetchContent)

FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.15.2
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(test_hash test_hash.cpp)
target_link_libraries(test_hash PRIVATE syscalls-cpp GTest::gtest_main)
target_compile_features(test_hash PRIVATE cxx_std_20)
add_test(NAME test_hash COMMAND $<TARGET_FILE:test_hash>)

add_executable(test_crt test_crt.cpp)
target_link_libraries(test_crt PRIVATE syscalls-cpp GTest::gtest_main)
target_compile_features(test_crt PRIVATE cxx_std_20)
add_test(NAME test_crt COMMAND $<TARGET_FILE:test_crt>)

add_executable(test_integration test_integration.cpp)
target_link_libraries(test_integration PRIVATE syscalls-cpp GTest::gtest_main)
target_compile_features(test_integration PRIVATE cxx_std_20)
add_test(NAME test_integration COMMAND $<TARGET_FILE:test_integration>)
