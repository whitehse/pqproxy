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
    src/scram_client.c
    src/backend_pool.c
    src/metrics.c
    src/metrics_http.c
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
    pthread
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

add_executable(test_scram_client tests/test_scram_client.c)
target_link_libraries(test_scram_client PRIVATE pqproxy_core)
add_test(NAME scram_client COMMAND test_scram_client)

add_executable(test_scram_live tests/test_scram_live.c)
target_link_libraries(test_scram_live PRIVATE pqproxy_core)
# Optional live Postgres: scripts/run_live_scram_test.sh (skips if no initdb)
add_test(NAME scram_live_pg
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_live_scram_test.sh)
set_tests_properties(scram_live_pg PROPERTIES
                     TIMEOUT 60
                     ENVIRONMENT "PQPROXY_SKIP_LIVE_PG=$ENV{PQPROXY_SKIP_LIVE_PG}")

add_executable(test_reconnect tests/test_reconnect.c)
target_link_libraries(test_reconnect PRIVATE pqproxy_core pthread)
add_test(NAME backend_reconnect COMMAND test_reconnect)

add_executable(test_metrics tests/test_metrics.c)
target_link_libraries(test_metrics PRIVATE pqproxy_core)
add_test(NAME metrics COMMAND test_metrics)

add_executable(test_metrics_http tests/test_metrics_http.c)
target_link_libraries(test_metrics_http PRIVATE pqproxy_core)
add_test(NAME metrics_http COMMAND test_metrics_http)

add_executable(load_harness tests/load_harness.c)
target_link_libraries(load_harness PRIVATE pqproxy_core)

add_executable(test_rls_proxy tests/test_rls_proxy.c)
target_link_libraries(test_rls_proxy PRIVATE pqproxy_core)
add_test(NAME rls_integration
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_rls_integration.sh)
set_tests_properties(rls_integration PROPERTIES TIMEOUT 90)

# Full TCP e2e: ephemeral Postgres + pqproxy (+ optional mTLS) + load + /metrics
add_test(NAME e2e_proxy_rls
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_e2e_proxy.sh)
set_tests_properties(e2e_proxy_rls PROPERTIES
                     TIMEOUT 120
                     ENVIRONMENT "PQPROXY_SKIP_LIVE_PG=$ENV{PQPROXY_SKIP_LIVE_PG}")
