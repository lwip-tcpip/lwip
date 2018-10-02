cmake_minimum_required(VERSION 3.8)

project(example_app C)

set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(LWIP_CONTRIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(LWIP_DIR         ${CMAKE_CURRENT_SOURCE_DIR}/../../../../lwip)

include(${LWIP_CONTRIB_DIR}/ports/CMakeCommon.cmake)

set (LWIP_DEFINITIONS -DLWIP_DEBUG)
set (LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    "${LWIP_CONTRIB_DIR}/"
    "${LWIP_CONTRIB_DIR}/ports/unix/port/include"
    "${LWIP_CONTRIB_DIR}/examples/example_app"
)

include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_CONTRIB_DIR}/Filelists.cmake)
include(${LWIP_CONTRIB_DIR}/ports/unix/Filelists.cmake)

add_executable(example_app ${LWIP_CONTRIB_DIR}/examples/example_app/test.c default_netif.c)
target_include_directories(example_app PRIVATE ${LWIP_INCLUDE_DIRS})
target_compile_options(example_app PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(example_app PRIVATE ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_link_libraries(example_app ${LWIP_SANITIZER_LIBS} lwipcontribexamples lwipcontribapps lwipcontribaddons lwipallapps lwipcontribportunix lwipcore)

add_executable(makefsdata ${lwipmakefsdata_SRCS})
target_compile_options(makefsdata PRIVATE ${LWIP_COMPILER_FLAGS})
target_include_directories(makefsdata PRIVATE ${LWIP_INCLUDE_DIRS})
target_link_libraries(makefsdata ${LWIP_SANITIZER_LIBS})