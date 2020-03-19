cmake_minimum_required(VERSION 2.8)

project(llb)
set (VERSION 0.0.3)

OPTION(DEBUG "add debug flags" OFF)

add_definitions("-D_DEFAULT_SOURCE")
find_package(OpenSSL REQUIRED)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})

include_directories(include)
file(GLOB SOURCES src/*.c)

set(AUTHOR "Andrea Giacomo Baldan")
set(LICENSE "BSD2 license")

# Executable
add_executable(llb ${SOURCES} include/llb_internal.h)

if (APPLE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I/usr/local/opt/openssl/include")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I/usr/local/opt/openssl/include")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L/usr/local/opt/openssl/lib")
endif (APPLE)

if (DEBUG)
    message(STATUS "Configuring build for debug")
    TARGET_LINK_LIBRARIES(llb pthread ssl crypto)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wunused -Werror -pedantic \
    -Wno-unused-result -std=c11 -ggdb -fsanitize=address \
    -fsanitize=undefined -fno-omit-frame-pointer -pg")
else (DEBUG)
    message(STATUS "Configuring build for production")
    TARGET_LINK_LIBRARIES(llb pthread ssl crypto)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wunused -Werror -pedantic \
    -Wno-unused-result -std=c11 -O3")
endif (DEBUG)
