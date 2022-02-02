set(HEADERS "Sha1.hpp")
set(SOURCES "Sha1.cpp")

add_library(Sha1Optimized OBJECT ${SOURCES} ${HEADERS})
set_target_properties(Sha1Optimized PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(Sha1Optimized PRIVATE "../../../")
target_compile_options(Sha1Optimized PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Os)

add_library(Sha1Debug OBJECT ${SOURCES} ${HEADERS})
set_target_properties(Sha1Debug PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(Sha1Debug PRIVATE "../../../")
target_compile_options(Sha1Debug PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Og -g2)

install(FILES ${HEADERS} DESTINATION "include/Y2KaoZ/Crypto/Sha1")