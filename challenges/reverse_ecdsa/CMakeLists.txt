cmake_minimum_required(VERSION 3.10)
project(reverse_ecdsa)

set(CMAKE_C_STANDARD 99)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Add your source files
add_executable(reverse_ecdsa main.c ecdsa.c)

# Link against OpenSSL and your ecdsa library
target_link_libraries(reverse_ecdsa ${OPENSSL_LIBRARIES})