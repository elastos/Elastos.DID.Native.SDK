project(did-test C)

include(ProjectDefaults)
include(CheckIncludeFile)
include(CheckFunctionExists)

check_include_file(unistd.h HAVE_UNISTD_H)
if(HAVE_UNISTD_H)
    add_definitions(-DHAVE_UNISTD_H=1)
endif()

check_include_file(getopt.h HAVE_GETOPT_H)
if(HAVE_GETOPT_H)
    add_definitions(-DHAVE_GETOPT_H=1)
endif()

check_include_file(sys/time.h HAVE_SYS_TIME_H)
if(HAVE_SYS_TIME_H)
    add_definitions(-DHAVE_SYS_TIME_H=1)
endif()

check_include_file(malloc.h HAVE_MALLOC_H)
if(HAVE_MALLOC_H)
    add_definitions(-DHAVE_MALLOC_H=1)
endif()

check_include_file(io.h HAVE_IO_H)
if(HAVE_IO_H)
    add_definitions(-DHAVE_IO_H=1)
endif()

check_include_file(sys/resource.h HAVE_SYS_RESOURCE_H)
if(HAVE_SYS_RESOURCE_H)
    add_definitions(-DHAVE_SYS_RESOURCE_H=1)
endif()

check_include_file(glob.h HAVE_GLOB_H)
if(HAVE_GLOB_H)
    add_definitions(-DHAVE_GLOB_H=1)
endif()

file(GLOB UTILITY_SOURCE "utility/*.c")
file(GLOB VC-TESTS "vctests/*.c")
file(GLOB DID-TESTS "didtests/*.c")
file(GLOB DOC-TESTS "doctests/*.c")
file(GLOB IDCHAIN-TESTS "idchaintests/*.c")
file(GLOB DSTORE-TESTS "dstoretests/*.c")
file(GLOB VP-TESTS "vptests/*.c")
file(GLOB ISSUER-TESTS "issuertests/*.c")
file(GLOB HDKEY-TESTS "hdkeytests/*.c")
file(GLOB JWT-TESTS "jwttests/*.c")

set(SRC
    tests.c
    ${UTILITY_SOURCE}
    ${VC-TESTS}
    ${DID-TESTS}
    ${DOC-TESTS}
    ${IDCHAIN-TESTS}
    ${DSTORE-TESTS}
    ${VP-TESTS}
    ${ISSUER-TESTS}
    ${HDKEY-TESTS}
    ${JWT-TESTS}
    )

if(NOT WIN32)
    file(GLOB TEST-ADAPTER "testadapter/*.c")
    set(SRC
        ${SRC}
        ${TEST-ADAPTER})
endif()

add_definitions(-DLIBCONFIG_STATIC)

if(ENABLE_SHARED)
    add_definitions(-DCRYSTAL_DYNAMIC)
else()
    add_definitions(-DCRYSTAL_STATIC)
endif()

if (NOT ENABLE_SHARED)
    set(STATIC_LIBS
        cjson
        curl
        ssl)
endif()

set(LIBS
    ${STATIC_LIBS}
    eladid
    hdkey-static
    crypto)

set(DEPS
    ela-did
    CUnit
    hdkey)

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN
        -D_CRT_SECURE_NO_WARNINGS
        -D_CRT_NONSTDC_NO_WARNINGS)

    # Force source code encoding to utf-8
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /utf-8")
    set(LIBS
        ${LIBS}
        cunit
        pthread
        Ws2_32
        Shlwapi
        crystal)
    set(DEPS
        ${DEPS}
        libcrystal)
else()
    set(LIBS
        ${LIBS}
        cunit
        pthread
        spvadapter-shared)
    set(DEPS
        ${DEPS}
        spvadapter)
endif()

set(INCLUDE
    utility
    .
    ../src
    ../src/utility
    ../src/adapter
    ../src/jwt
    ../src/meta
    ../hdkey
    ${PROJECT_INT_DIST_DIR}/include)

set(LINK
    ${CMAKE_CURRENT_BINARY_DIR}/../src
    ${CMAKE_CURRENT_BINARY_DIR}/../hdkey
    ${PROJECT_INT_DIST_DIR}/lib)

if(WIN32)
    set(INCLUDE
        ../src/win
        ${INCLUDE})
else()
    set(INCLUDE
        ../adapter/spvadapter
        ${INCLUDE})

    set(LINK
        ${CMAKE_CURRENT_BINARY_DIR}/../adapter/spvadapter
        ${LINK})
endif()

include_directories(${INCLUDE})
link_directories(${LINK})

add_executable(didtest
    ${SRC})

add_dependencies(didtest ${DEPS})
target_link_libraries(didtest ${LIBS})

install(TARGETS didtest
    RUNTIME DESTINATION "bin"
    ARCHIVE DESTINATION "lib"
    LIBRARY DESTINATION "lib")

install(DIRECTORY resources
    DESTINATION "etc/did")