if(NOT ${CMAKE_VERSION} VERSION_LESS "3.10.0")
    include_guard(GLOBAL)
endif()

set(LWIP_CONTRIB_DIR ${LWIP_DIR}/contrib)

# ARM mbedtls support https://tls.mbed.org/
if(NOT DEFINED LWIP_MBEDTLSDIR)
    set(LWIP_MBEDTLSDIR ${LWIP_DIR}/../mbedtls)
    message(STATUS "LWIP_MBEDTLSDIR not set - using default location ${LWIP_MBEDTLSDIR}")
endif()
if(EXISTS ${LWIP_MBEDTLSDIR}/CMakeLists.txt)
    set(LWIP_HAVE_MBEDTLS ON BOOL)

    # Prevent building MBEDTLS programs and tests
    set(ENABLE_PROGRAMS OFF CACHE BOOL "")
    set(ENABLE_TESTING  OFF CACHE BOOL "")

    # mbedtls uses cmake. Sweet!
    add_subdirectory(${LWIP_MBEDTLSDIR} mbedtls)

    set (LWIP_MBEDTLS_DEFINITIONS
        LWIP_HAVE_MBEDTLS=1
    )
    set (LWIP_MBEDTLS_INCLUDE_DIRS
        ${LWIP_MBEDTLSDIR}/include
    )
    set (LWIP_MBEDTLS_LINK_LIBRARIES
        mbedtls
        mbedcrypto
        mbedx509
    )
endif()

set(LWIP_COMPILER_FLAGS_GNU_CLANG
    -g
    -Wall
    -pedantic
    -Werror
    -Wparentheses
    -Wsequence-point
    -Wswitch-default
    -Wextra
    -Wundef
    -Wshadow
    -Wpointer-arith
    -Wcast-qual
    -Wc++-compat
    -Wwrite-strings
    -Wold-style-definition
    -Wcast-align
    -Wmissing-prototypes
    -Wnested-externs
    -Wunreachable-code
    -Wuninitialized
    -Wmissing-prototypes
    -Waggregate-return
    -Wlogical-not-parentheses
)

if (NOT LWIP_HAVE_MBEDTLS)
    list(APPEND LWIP_COMPILER_FLAGS_GNU_CLANG
        -Wredundant-decls
    )
endif()

if(CMAKE_C_COMPILER_ID STREQUAL GNU)
    list(APPEND LWIP_COMPILER_FLAGS_GNU_CLANG
        -Wlogical-op
        -Wtrampolines
    )

    if (NOT LWIP_HAVE_MBEDTLS)
        list(APPEND LWIP_COMPILER_FLAGS_GNU_CLANG
            -Wc90-c99-compat
        )
    endif()

    if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.9)
        if(LWIP_USE_SANITIZERS)
            list(APPEND LWIP_COMPILER_FLAGS_GNU_CLANG
                -fsanitize=address
                -fsanitize=undefined
                -fno-sanitize=alignment
                -fstack-protector
                -fstack-check
            )
            set(LWIP_SANITIZER_LIBS asan ubsan)
        endif()
    endif()

    set(LWIP_COMPILER_FLAGS ${LWIP_COMPILER_FLAGS_GNU_CLANG})
endif()

if(CMAKE_C_COMPILER_ID STREQUAL Clang)
    list(APPEND LWIP_COMPILER_FLAGS_GNU_CLANG
        -Wdocumentation
        -Wno-documentation-deprecated-sync
    )

    if(LWIP_USE_SANITIZERS)
        list(APPEND LWIP_COMPILER_FLAGS_GNU_CLANG
            -fsanitize=address
            -fsanitize=undefined
            -fno-sanitize=alignment
        )
        set(LWIP_SANITIZER_LIBS asan ubsan)
    endif()

    set(LWIP_COMPILER_FLAGS ${LWIP_COMPILER_FLAGS_GNU_CLANG})
endif()

if(CMAKE_C_COMPILER_ID STREQUAL MSVC)
    # TODO
endif()
