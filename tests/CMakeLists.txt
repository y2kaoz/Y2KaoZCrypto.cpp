add_executable(Sha1Tests Y2KaoZ/Crypto/Sha1/Sha1.cpp)
add_test(NAME Sha1Tests COMMAND Sha1Tests)

add_executable(Srp6MathTest Y2KaoZ/Crypto/Srp6/Srp6Math.cpp)
add_test(NAME Srp6MathTest COMMAND Srp6MathTest)

find_package(Catch2 3 REQUIRED)
target_link_libraries(Sha1Tests PRIVATE Catch2::Catch2WithMain ${PROJECT_NAME})
target_link_libraries(Srp6MathTest PRIVATE Catch2::Catch2WithMain ${PROJECT_NAME})
