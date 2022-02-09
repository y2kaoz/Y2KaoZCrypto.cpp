add_executable(Sha1Tests Y2KaoZ/Crypto/Sha1/Sha1.cpp)
add_test(NAME Sha1Tests COMMAND Sha1Tests)

add_executable(Srp6Test Y2KaoZ/Crypto/Srp6/Srp6.cpp)
add_test(NAME Srp6Test COMMAND Srp6Test)

find_package(Catch2 3 REQUIRED)
target_link_libraries(Sha1Tests PRIVATE Catch2::Catch2WithMain ${PROJECT_NAME})
target_link_libraries(Srp6Test PRIVATE Catch2::Catch2WithMain ${PROJECT_NAME})
