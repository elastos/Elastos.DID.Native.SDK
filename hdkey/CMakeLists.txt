include(ProjectDefaults)
include(CheckIncludeFile)

check_include_file(alloca.h HAVE_ALLOCA_H)
if(HAVE_ALLOCA_H)
    add_definitions(-DHAVE_ALLOCA_H=1)
endif()

check_include_file(unistd.h HAVE_UNISTD_H)
if(HAVE_UNISTD_H)
    add_definitions(-DHAVE_UNISTD_H=1)
endif()

check_include_file(malloc.h HAVE_MALLOC_H)
if(HAVE_MALLOC_H)
    add_definitions(-DHAVE_MALLOC_H=1)
endif()

file( GLOB BR-SOURCES "BR/*.c" )

set(SRC
    HDkey.c
    crypto.c
    ${BR-SOURCES})

set(HEADERS
    crypto.h
    HDkey.h)

set(LIBS
    crypto)

if (ENABLE_UNICODE_NORMALIZATION)
    add_definitions(-DENABLE_UNICODE_NORMALIZATION=1)

    set(LIBS
        ${LIBS}
        utf8proc)
endif()

include_directories(
    BEFORE
    .
    BR
    secp256k1
    ${PROJECT_INT_DIST_DIR}/include)

if(WIN32)
    add_definitions(
        -DWIN32_LEAN_AND_MEAN
        -D_CRT_SECURE_NO_WARNINGS
        -D_CRT_NONSTDC_NO_WARNINGS)

    # Force source code encoding to utf-8
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /utf-8")

    set(ENABLE_STATIC TRUE)

    set(LIBS
        ${LIBS}
        crystal
        pthread
        Ws2_32)
endif()

if(MSVC)
    add_definitions(/FI"BRNameFix.h")
    add_definitions(/FI"secp256k1_name_fix.h")
else()
    # GCC or Clang
    add_definitions(-include BRNameFix.h)
    add_definitions(-include secp256k1_name_fix.h)
endif()

link_directories(
    ${PROJECT_INT_DIST_DIR}/lib)

set(HDKEY_DEPENDS libressl)

add_custom_target(hdkey)

set(CMAKE_C_STANDARD 11)

if(ENABLE_STATIC)
    add_library(hdkey-static STATIC ${SRC})
    add_dependencies(hdkey-static ${HDKEY_DEPENDS})
    if(RASPBERRYPI)
        target_compile_definitions(hdkey-static PRIVATE static_assert=_Static_assert)
    endif()

    set_target_properties(hdkey-static PROPERTIES OUTPUT_NAME hdkey${STATIC_LIB_DECORATOR})
    if(WIN32)
        set_target_properties(hdkey-static PROPERTIES LINK_FLAGS /FORCE:MULTIPLE)
    endif()

    add_dependencies(hdkey hdkey-static)

    install(TARGETS hdkey-static
        RUNTIME DESTINATION "bin"
        ARCHIVE DESTINATION "lib"
        LIBRARY DESTINATION "lib")
endif()

if(ENABLE_SHARED)
    add_library(hdkey-shared SHARED ${SRC})
    add_dependencies(hdkey-shared ${HDKEY_DEPENDS})
    if(RASPBERRYPI)
        target_compile_definitions(hdkey-shared PRIVATE static_assert=_Static_assert)
    endif()

    set_target_properties(hdkey-shared PROPERTIES
        OUTPUT_NAME hdkey${SHARED_LIB_DECORATOR}
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR})
    if(WIN32)
        set_target_properties(hdkey-shared PROPERTIES LINK_FLAGS /FORCE:MULTIPLE)
    endif()

    target_link_libraries(hdkey-shared ${LIBS} ${SYSTEM_LIBS})

    add_dependencies(hdkey hdkey-shared)

    install(TARGETS hdkey-shared
        RUNTIME DESTINATION "bin"
        ARCHIVE DESTINATION "lib"
        LIBRARY DESTINATION "lib")
endif()

install(FILES ${HEADERS} DESTINATION "include")