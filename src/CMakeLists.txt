include(ProjectDefaults)
include(CheckIncludeFile)

check_include_file(unistd.h HAVE_UNISTD_H)
if(HAVE_UNISTD_H)
    add_definitions(-DHAVE_UNISTD_H=1)
endif()

check_include_file(stdlib.h HAVE_STDLIB_H)
if(HAVE_STDLIB_H)
    add_definitions(-DHAVE_STDLIB_H=1)
endif()

check_include_file(malloc.h HAVE_MALLOC_H)
if(HAVE_MALLOC_H)
    add_definitions(-DHAVE_MALLOC_H=1)
endif()

check_include_file(io.h HAVE_IO_H)
if(HAVE_IO_H)
    add_definitions(-DHAVE_IO_H=1)
endif()

check_include_file(glob.h HAVE_GLOB_H)
if(HAVE_GLOB_H)
    add_definitions(-DHAVE_GLOB_H=1)
endif()

check_include_file(dirent.h HAVE_DIRENT_H)
if(HAVE_DIRENT_H)
    add_definitions(-DHAVE_DIRENT_H=1)
endif()

check_include_file(sys/time.h HAVE_SYS_TIME_H)
if(HAVE_SYS_TIME_H)
    add_definitions(-DHAVE_SYS_TIME_H=1)
endif()

check_include_file(utime.h HAVE_UTIME_H)
if(HAVE_UTIME_H)
    add_definitions(-DHAVE_UTIME_H=1)
endif()

check_include_file(time.h HAVE_TIME_H)
if(HAVE_TIME_H)
    add_definitions(-DHAVE_TIME_H=1)
endif()

check_include_file(direct.h HAVE_DIRECT_H)
if(HAVE_DIRECT_H)
    add_definitions(-DHAVE_DIRECT_H=1)
endif()

if(NOT ENABLE_JWT)
    add_definitions(-DDISABLE_JWT=1)
endif()

file(GLOB utility-SOURCES "utility/*.c")
file(GLOB backend-SOURCES "backend/*.c")
file(GLOB jwt-SOURCES "jwt/*.c")
file(GLOB meta-SOURCES "meta/*.c")

set(SRC
    diderror.c
    did.c
    didurl.c
    diddocument.c
    didencryption.c
    credential.c
    didstore.c
    didbackend.c
    didbiography.c
    credentialbiography.c
    mnemonic.c
    presentation.c
    issuer.c
    ticket.c
    rootidentity.c
    features.c
    ${utility-SOURCES}
    ${backend-SOURCES}
    ${meta-SOURCES})

set(HEADERS
    ela_did.h)

if(ENABLE_JWT)
    set(HEADERS
        ${HEADERS}
        jwt/ela_jwt.h)
    set(SRC
        ${SRC}
        ${jwt-SOURCES})
endif()

if(ENABLE_JWT)
    set(HEADER_FILTER "ela_*.h")
else()
    set(HEADER_FILTER "ela_did.h")
endif()

if(ENABLE_JWT)
   set(JWT_INCLUDE jwt)
   set(JWT_LIBS cjose)
   set(JWT_DEPENDS libcjose)
endif()

set(INCLUDE
    BEFORE
    utility
    backend
    #adapter
    ${JWT_INCLUDE}
    meta
    .
    ../hdkey
    ${PROJECT_INT_DIST_DIR}/include)

set(LIBS
    curl
    ssl
    crypto
    ${JWT_LIBS}
    jansson
    zip
    z)

if(ENABLE_UNICODE_NORMALIZATION)
    add_definitions(
        -DENABLE_UNICODE_NORMALIZATION=1
        -DUTF8PROC_STATIC)

    set(LIBS
        ${LIBS}
        utf8proc)
endif()

set(ELADID_DEPENDS libressl libsodium libcurl hdkey libjansson ${JWT_DEPENDS} libzip)

if(WIN32)
    add_definitions(
        -DWIN32_LEAN_AND_MEAN
        -D_CRT_SECURE_NO_WARNINGS
        -D_CRT_NONSTDC_NO_WARNINGS)

    # Force source code encoding to utf-8
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /utf-8")

    set(LIBS
        ${LIBS}
        crystal
        pthread
        libsodium.lib
        Ws2_32
        Crypt32)

    set(ELADID_DEPENDS
        libcrystal
        ${ELADID_DEPENDS})
else()
    set(LIBS
        ${LIBS}
        sodium)
endif()

set(EXPORT_FILES ela_did.h)

if(ENABLE_JWT)
    set(EXPORT_FILES
        ${EXPORT_FILES}
        jwt/ela_jwt.h)
endif()

if(DARWIN OR IOS)
    set(SYMBOL_FORMAT
        "{printf \"_%s\\n\",$1}")

    if(ENABLE_JWT)
        set(GEN_CMD grep -r --include=${HEADER_FILTER} "^DID_API" ${CMAKE_CURRENT_SOURCE_DIR} | grep -o "[A-Za-z0-9_]*(" | awk -F "(" ${SYMBOL_FORMAT} > ${CMAKE_CURRENT_BINARY_DIR}/export.symbols)
    else()
        set(GEN_CMD grep -r --include=${HEADER_FILTER} "^DID_API" ${CMAKE_CURRENT_SOURCE_DIR} | grep -o "[A-Za-z0-9_]*(" | awk -F "(" ${SYMBOL_FORMAT} | grep -v "_GetJw" > ${CMAKE_CURRENT_BINARY_DIR}/export.symbols)
    endif()

    add_custom_command(
        COMMAND ${GEN_CMD}
        #DEPENDS ela_did.h jwt/ela_jwt.h
        DEPENDS ${EXPORT_FILES}
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/export.symbols
        VERBATIM
    )

    add_custom_target(exportSymbols
        ALL
        COMMAND echo Generate export symbols...
        DEPENDS export.symbols
    )

    set(ELADID_DEPENDS ${ELADID_DEPENDS} exportSymbols)
endif()

if(WIN32)
    set(SYSTEM_LIBS Ws2_32 Iphlpapi)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(SYSTEM_LIBS pthread m)
endif()

include_directories(${INCLUDE})

link_directories(
    ../hdkey
    ${PROJECT_INT_DIST_DIR}/lib)

add_definitions(-DDID_BUILD)

add_custom_target(ela-did)

set(CMAKE_C_STANDARD 99)

if(ENABLE_STATIC)
    add_library(eladid-static STATIC ${SRC})
    add_dependencies(eladid-static ${ELADID_DEPENDS})

    #target_compile_definitions(eladid-static PRIVATE DID_STATIC CRYSTAL_STATIC)
    target_compile_definitions(eladid-static PRIVATE DID_STATIC CURL_STATICLIB SODIUM_STATIC)
    set_target_properties(eladid-static PROPERTIES OUTPUT_NAME eladid${STATIC_LIB_DECORATOR})
    if(WIN32)
        set_target_properties(eladid-static PROPERTIES LINK_FLAGS /FORCE:MULTIPLE)
    endif()

    add_dependencies(ela-did eladid-static)

    install(TARGETS eladid-static
        RUNTIME DESTINATION "bin"
        ARCHIVE DESTINATION "lib"
        LIBRARY DESTINATION "lib")
endif()

if(ENABLE_SHARED)
    add_library(eladid-shared SHARED ${SRC})
    add_dependencies(eladid-shared ${ELADID_DEPENDS})

    #target_compile_definitions(eladid-shared PRIVATE DID_DYNAMIC CRYSTAL_DYNAMIC)
    target_compile_definitions(eladid-shared PRIVATE DID_DYNAMIC CURL_STATICLIB SODIUM_STATIC)
    set_target_properties(eladid-shared PROPERTIES
        OUTPUT_NAME eladid${SHARED_LIB_DECORATOR}
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR})
    if(WIN32)
        set_target_properties(eladid-shared PROPERTIES LINK_FLAGS /FORCE:MULTIPLE)
    endif()
    if(DARWIN OR IOS)
        set_property(SOURCE ${SRC} APPEND PROPERTY
            OBJECT_DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/export.symbols")
        set_property(TARGET eladid-shared APPEND_STRING PROPERTY
            LINK_FLAGS "-framework CoreFoundation -framework Security -Wl,-exported_symbols_list,\"${CMAKE_CURRENT_BINARY_DIR}/export.symbols\"")
    endif()
    target_include_directories(eladid-shared
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
            $<INSTALL_INTERFACE:include>
    )
    target_link_libraries(eladid-shared PRIVATE hdkey-static ${LIBS} ${SYSTEM_LIBS})

    add_dependencies(ela-did eladid-shared)

    install(TARGETS eladid-shared
        EXPORT ElastosDIDConfig
        RUNTIME DESTINATION "bin"
        ARCHIVE DESTINATION "lib"
        LIBRARY DESTINATION "lib")

    install(EXPORT
            ElastosDIDConfig
        NAMESPACE
            "ElastosDID::"
        DESTINATION
            share/ElastosDID/cmake
    )

    export(
        TARGETS
            eladid-shared
        FILE
            ElastosDIDConfig.cmake
    )
endif()

install(FILES ${HEADERS} DESTINATION "include")


