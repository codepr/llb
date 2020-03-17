cmake_minimum_required(VERSION 2.8)

project(npt)
set (VERSION 0.0.1)

OPTION(DEBUG "add debug flags" OFF)

add_definitions("-D_DEFAULT_SOURCE")
find_package(OpenSSL REQUIRED)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})

include_directories(include)
file(GLOB SOURCES src/*.c)

set(AUTHOR "Andrea Giacomo Baldan")
set(LICENSE "BSD2 license")

# Executable
add_executable(npt ${SOURCES} include/npt_internal.h)

if (DEBUG)
    message(STATUS "Configuring build for debug")
    TARGET_LINK_LIBRARIES(npt pthread ssl crypto crypt)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wunused -Werror -pedantic \
    -Wno-unused-result -std=c11 -ggdb -fsanitize=address \
    -fsanitize=undefined -fno-omit-frame-pointer -pg")
else (DEBUG)
    message(STATUS "Configuring build for production")
    TARGET_LINK_LIBRARIES(npt pthread ssl crypto crypt)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wunused -Werror -pedantic \
    -Wno-unused-result -std=c11 -O3")
endif (DEBUG)
