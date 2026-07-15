cmake_minimum_required(VERSION 3.20)
project(pqproxy LANGUAGES C VERSION 0.1.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON) # liburing / Linux

if(NOT MSVC)
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

set(PIQUE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../pique" CACHE PATH "Path to pique (libpqwire)")

if(NOT EXISTS "${PIQUE_ROOT}/include/pqwire.h")
    message(FATAL_ERROR "pique not found at PIQUE_ROOT=${PIQUE_ROOT}")
endif()

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(URING REQUIRED liburing)

add_library(pqwire STATIC
    ${PIQUE_ROOT}/src/pqwire.c
    ${PIQUE_ROOT}/src/scram.c
)
target_include_directories(pqwire PUBLIC ${PIQUE_ROOT}/include)

add_library(pqproxy_core STATIC
    src/rewrite_engine.c
    src/identity.c
    src/tls_mtls.c
    src/ktls.c
    src/backend_pool.c
    src/iouring_loop.c
)
target_include_directories(pqproxy_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(pqproxy_core PRIVATE
    ${URING_INCLUDE_DIRS}
)
target_link_libraries(pqproxy_core PUBLIC
    pqwire
    OpenSSL::SSL
    OpenSSL::Crypto
    ${URING_LIBRARIES}
)

add_executable(pqproxy src/main.c)
target_link_libraries(pqproxy PRIVATE pqproxy_core)

enable_testing()
add_executable(test_rewrite tests/test_rewrite.c)
target_link_libraries(test_rewrite PRIVATE pqproxy_core)
add_test(NAME rewrite_engine COMMAND test_rewrite)

add_executable(test_identity tests/test_identity.c)
target_link_libraries(test_identity PRIVATE pqproxy_core)
add_test(NAME identity_parse COMMAND test_identity)

add_executable(test_backend_pool tests/test_backend_pool.c)
target_link_libraries(test_backend_pool PRIVATE pqproxy_core pthread)
add_test(NAME backend_pool COMMAND test_backend_pool)
