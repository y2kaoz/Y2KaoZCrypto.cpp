add_executable(Sha1Tests 
    $<TARGET_OBJECTS:Sha1Optimized>
    Y2KaoZ/Crypto/Sha1/Sha1.cpp 
)
add_test(NAME Sha1Tests COMMAND Sha1Tests)

target_include_directories(Sha1Tests PRIVATE "../src/")
target_compile_options(Sha1Tests PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

find_package(Catch2 3 REQUIRED)
target_link_libraries(Sha1Tests PRIVATE Catch2::Catch2WithMain OpenSSL::Crypto)
