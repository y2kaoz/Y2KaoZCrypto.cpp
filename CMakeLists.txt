cmake_minimum_required(VERSION 3.22)

SET(CMAKE_INSTALL_PREFIX "./Y2KaoZCrypto.cpp/")
project(Y2KaoZCrypto VERSION 0.0.0.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL 
    REQUIRED COMPONENTS 
        Crypto
)

add_subdirectory("src/Y2KaoZ/Crypto/Sha1")

#SHARED
add_library(${PROJECT_NAME}Shared SHARED 
    $<TARGET_OBJECTS:Sha1Optimized>
)
target_include_directories(${PROJECT_NAME}Shared PUBLIC "./src/")
set_target_properties(${PROJECT_NAME}Shared PROPERTIES OUTPUT_NAME ${PROJECT_NAME}-${PROJECT_VERSION})
install(TARGETS ${PROJECT_NAME}Shared DESTINATION "lib")

#SHARED + DEBUG
add_library(${PROJECT_NAME}SharedDebug SHARED 
    $<TARGET_OBJECTS:Sha1Debug>
)
target_include_directories(${PROJECT_NAME}SharedDebug PUBLIC "./src/")
set_target_properties(${PROJECT_NAME}SharedDebug PROPERTIES OUTPUT_NAME ${PROJECT_NAME}Debug-${PROJECT_VERSION})
install(TARGETS ${PROJECT_NAME}SharedDebug DESTINATION "lib")

#STATIC
add_library(${PROJECT_NAME}Static STATIC 
    $<TARGET_OBJECTS:Sha1Optimized>
)
target_link_libraries(${PROJECT_NAME}Static PRIVATE OpenSSL::Crypto)
target_include_directories(${PROJECT_NAME}Static PUBLIC "./src/")
set_target_properties(${PROJECT_NAME}Static PROPERTIES OUTPUT_NAME ${PROJECT_NAME}-${PROJECT_VERSION})
install(TARGETS ${PROJECT_NAME}Static DESTINATION "lib")

#STATIC + DEBUG
add_library(${PROJECT_NAME}StaticDebug STATIC 
    $<TARGET_OBJECTS:Sha1Debug>
)
target_include_directories(${PROJECT_NAME}StaticDebug PUBLIC "./src/")
target_link_libraries(${PROJECT_NAME}StaticDebug PRIVATE OpenSSL::Crypto)
set_target_properties(${PROJECT_NAME}StaticDebug PROPERTIES OUTPUT_NAME ${PROJECT_NAME}Debug-${PROJECT_VERSION})
install(TARGETS ${PROJECT_NAME}StaticDebug DESTINATION "lib")

configure_file(CMakeLists.txt.in CMakeLists.txt.out @ONLY)
install(FILES "${PROJECT_BINARY_DIR}/CMakeLists.txt.out" DESTINATION "." RENAME CMakeLists.txt)

add_subdirectory("./tests")
