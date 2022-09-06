project(samples C)

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

check_include_file(sys/resource.h HAVE_SYS_RESOURCE_H)
if(HAVE_SYS_RESOURCE_H)
    add_definitions(-DHAVE_SYS_RESOURCE_H=1)
endif()

check_include_file(direct.h HAVE_DIRECT_H)
if(HAVE_DIRECT_H)
    add_definitions(-DHAVE_DIRECT_H=1)
endif()

set(SRC
    assistadapter.c
    createpresentation.c
    didurlsample.c
    entity.c
    initailizedid.c
    issuecredential.c
    parsejwt.c
    presentationinjwt.c
    restorefrommnemonic.c
    rootidentitysample.c
    main.c)

set(LIBS
    eladid-static
    hdkey-static
    cjose
    jansson
    curl
    ssl)

if(ENABLE_UNICODE_NORMALIZATION)
    set(LIBS
        ${LIBS}
        utf8proc)
endif()

set(LIBS
    ${LIBS}
    crypto
    zip
    z)

set(DEPS
    ela-did
    libcurl
    hdkey)

if(WIN32)
    set(LIBS
        ${LIBS}
        crystal_s
        libsodium.lib
        pthread
        Ws2_32
        crypt32
        Iphlpapi
        Shlwapi)
    set(DEPS
        ${DEPS}
        libcrystal)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(LIBS
        ${LIBS}
        sodium
        pthread
        m)
else()
    set(LIBS
        ${LIBS}
        sodium)
endif()

set(INCLUDE
    .
    ../src
    ../src/utility
    ../src/jwt
    ../src/meta
    ../src/backend
    ../hdkey
    ${PROJECT_INT_DIST_DIR}/include)

include_directories(${INCLUDE})

link_directories(
    ${CMAKE_CURRENT_BINARY_DIR}/../src
    ${CMAKE_CURRENT_BINARY_DIR}/../hdkey
    ${PROJECT_INT_DIST_DIR}/lib)

add_executable(samples ${SRC})
add_dependencies(samples ${DEPS})
target_link_libraries(samples ${LIBS})

if(DARWIN OR IOS)
    set_property(TARGET samples APPEND_STRING PROPERTY
        LINK_FLAGS "-framework CoreFoundation -framework Security")
endif()

install(TARGETS samples
    RUNTIME DESTINATION "${PROJECT_INT_DIST_DIR}/bin"
    ARCHIVE DESTINATION "${PROJECT_INT_DIST_DIR}/lib"
    LIBRARY DESTINATION "${PROJECT_INT_DIST_DIR}/lib")
