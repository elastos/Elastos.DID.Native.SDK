include(AddSubModule)

add_submodule(platform-specific)
add_submodule(libressl
    DEPENDS platform-specific)
add_submodule(libcrystal
    DEPENDS platform-specific)
add_submodule(libsodium
    DEPENDS platform-specific)

if (ENABLE_TESTS)
    add_submodule(CUnit
        DEPENDS platform-specific)
    add_submodule(nodejs)
endif()

if (ENABLE_UNICODE_NORMALIZATION)
    add_submodule(libutf8proc
        DEPENDS platform-specific)    
endif()

if(NOT HDKEY_ONLY)
    add_submodule(zlib
        DEPENDS platform-specific)
    add_submodule(libzip
        DEPENDS zlib platform-specific)
    add_submodule(libcurl
        DEPENDS libressl zlib platform-specific)
    add_submodule(libjansson
        DIRECTORY jansson
        DEPENDS platform-specific)
    if (ENABLE_JWT)
        add_submodule(libcjose
            DIRECTORY cjose
            DEPENDS libjansson libressl platform-specific)
    endif()
endif()

if(WIN32)
    add_submodule(pthreads-w32
        DEPENDS platform-specific)
    add_dependencies(libcrystal pthreads-w32)
endif()
