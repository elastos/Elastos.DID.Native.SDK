project(platform-specific)

include(ProjectDefaults)
include(ExternalProject)
include(ExternalConfigureArgs)

if(ANDROID)
    set(MAKE_STANDALONE_TOOLCHAIN
        "${CMAKE_ANDROID_NDK}/build/tools/make_standalone_toolchain.py")

    if(NOT EXISTS ${MAKE_STANDALONE_TOOLCHAIN})
        message(FATAL_ERROR
            "Android NDK: make_standalone_toolchain.py is missing.")
    endif()

    if(${CMAKE_ANDROID_STL_TYPE} MATCHES "^c\\+\\+_")
        set(STL_LIBRARY "libc++")
    elseif(${CMAKE_ANDROID_STL_TYPE} MATCHES "^stlport_")
        set(STL_LIBRARY "stlport")
    else()
        set(STL_LIBRARY "gnustl")
    endif()

    ExternalProject_Add(
        android-toolchain

        SOURCE_DIR ${CMAKE_ANDROID_NDK}
        BUILD_IN_SOURCE 1

        CONFIGURE_COMMAND echo Done
        BUILD_COMMAND echo Done
        INSTALL_COMMAND ${MAKE_STANDALONE_TOOLCHAIN}
            --force
            --verbose
            --arch ${CMAKE_ANDROID_ARCH}
            --api ${CMAKE_SYSTEM_VERSION}
            --stl ${STL_LIBRARY}
            --install-dir ${XDK_TOOLCHAIN}
    )

    add_custom_target(platform-specific
        COMMENT "Build platform-specific: Android Standalone Toolchain"
        COMMAND echo Done)
    add_dependencies(platform-specific
        android-toolchain
        flatcc-parser)
elseif(WIN32)
    set(CYGWIN_RUNTIME_HASH "821840842061c1cfc734a0bcfb607bd7")
    set(CYGWIN_LIBATTR_HASH "486d0440f560d516879bfb22317f805d")
    set(CYGWIN_LIBICONV_HASH "af70e0b4817c78e9d9db93de32665d90")
    set(CYGWIN_LIBSIGSEGV_HASH "3C74C7599DCEAAF18EE182F54F66BBCC")
    set(CYGWIN_LIBINTL8_HASH "01e53b522f96dac03e19dfc489626a33")
    set(CYGWIN_PATCH_HASH "c254e28e0687685e74b8213af0b2c6c0")
    set(CYGWIN_DIFF_HASH "7a2adbf1d2c3fda1d7471e799c1eb47b")

    set(URL_PREFIX "http://mirrors.kernel.org/sourceware/cygwin/x86_64/release")

    ExternalProject_Add(
        cygwin-runtime

        PREFIX ${PROJECT_DEPS_BUILD_PREFIX}
        URL "${URL_PREFIX}/cygwin/cygwin-3.4.6-1.tar.xz"
        URL_HASH MD5=${CYGWIN_RUNTIME_HASH}
        DOWNLOAD_NAME "cygwin-3.4.6-1.tar.xz"
        DOWNLOAD_DIR ${PROJECT_DEPS_TARBALL_DIR}
        DOWNLOAD_NO_PROGRESS 1

        BUILD_IN_SOURCE 1

        CONFIGURE_COMMAND echo Done
        BUILD_COMMAND echo Done
        INSTALL_COMMAND if not exist ${PROJECT_HOST_TOOLS_DIR} mkdir ${PROJECT_HOST_TOOLS_DIR}
                COMMAND xcopy /s /e /q /y . ${PROJECT_HOST_TOOLS_DIR}
    )

    ExternalProject_Add(
        cygwin-libattr

        DEPENDS cygwin-runtime

        PREFIX ${PROJECT_DEPS_BUILD_PREFIX}
        URL "${URL_PREFIX}/attr/libattr1/libattr1-2.5.1-1.20.g0981a7bfe487.tar.xz"
        URL_HASH MD5=${CYGWIN_LIBATTR_HASH}
        DOWNLOAD_NAME "libattr1-2.5.1-1.20.g0981a7bfe487.tar.xz"
        DOWNLOAD_DIR ${PROJECT_DEPS_TARBALL_DIR}
        DOWNLOAD_NO_PROGRESS 1

        BUILD_IN_SOURCE 1

        CONFIGURE_COMMAND echo Done
        BUILD_COMMAND echo Done
        INSTALL_COMMAND xcopy /s /e /q /y . ${PROJECT_HOST_TOOLS_DIR}
    )

    ExternalProject_Add(
        cygwin-libiconv

        DEPENDS cygwin-runtime

        PREFIX ${PROJECT_DEPS_BUILD_PREFIX}
        URL "${URL_PREFIX}/libiconv/libiconv2/libiconv2-1.17-1.tar.xz"
        URL_HASH MD5=${CYGWIN_LIBICONV_HASH}
        DOWNLOAD_NAME "libiconv2-1.17-1.tar.xz"
        DOWNLOAD_DIR ${PROJECT_DEPS_TARBALL_DIR}
        DOWNLOAD_NO_PROGRESS 1

        BUILD_IN_SOURCE 1

        CONFIGURE_COMMAND echo Done
        BUILD_COMMAND echo Done
        INSTALL_COMMAND xcopy /s /e /q /y . ${PROJECT_HOST_TOOLS_DIR}\\usr
    )

    ExternalProject_Add(
        cygwin-libsigsegv

        DEPENDS cygwin-runtime

        PREFIX ${PROJECT_DEPS_BUILD_PREFIX}
        URL "${URL_PREFIX}/libsigsegv/libsigsegv2/libsigsegv2-2.10-2.tar.xz"
        URL_HASH MD5=${CYGWIN_LIBSIGSEGV_HASH}
        DOWNLOAD_NAME "libsigsegv2-2.10-2.tar.xz"
        DOWNLOAD_DIR ${PROJECT_DEPS_TARBALL_DIR}
        DOWNLOAD_NO_PROGRESS 1

        BUILD_IN_SOURCE 1

        CONFIGURE_COMMAND echo Done
        BUILD_COMMAND echo Done
        INSTALL_COMMAND xcopy /s /e /q /y . ${PROJECT_HOST_TOOLS_DIR}\\usr
    )

    ExternalProject_Add(
        cygwin-libintl8

        DEPENDS cygwin-runtime

        PREFIX ${PROJECT_DEPS_BUILD_PREFIX}
        URL "${URL_PREFIX}/gettext/libintl8/libintl8-0.21.1-2.tar.xz"
        URL_HASH MD5=${CYGWIN_LIBINTL8_HASH}
        DOWNLOAD_NAME "libintl8-0.21.1-2.tar.xz"
        DOWNLOAD_DIR ${PROJECT_DEPS_TARBALL_DIR}
        DOWNLOAD_NO_PROGRESS 1

        BUILD_IN_SOURCE 1

        CONFIGURE_COMMAND echo Done
        BUILD_COMMAND echo Done
        INSTALL_COMMAND xcopy /s /e /q /y . ${PROJECT_HOST_TOOLS_DIR}\\usr
    )

    ExternalProject_Add(
        cygwin-patch

        DEPENDS cygwin-runtime cygwin-libattr cygwin-libintl8 cygwin-libiconv

        PREFIX ${PROJECT_DEPS_BUILD_PREFIX}
        URL "${URL_PREFIX}/patch/patch-2.7.6-17.tar.xz"
        URL_HASH MD5=${CYGWIN_PATCH_HASH}
        DOWNLOAD_NAME "patch-2.7.6-17.tar.xz"
        DOWNLOAD_DIR ${PROJECT_DEPS_TARBALL_DIR}
        DOWNLOAD_NO_PROGRESS 1

        BUILD_IN_SOURCE 1

        CONFIGURE_COMMAND echo Done
        BUILD_COMMAND echo Done
        INSTALL_COMMAND xcopy /s /e /q /y . ${PROJECT_HOST_TOOLS_DIR}\\usr
    )

    ExternalProject_Add(
        cygwin-diff

        DEPENDS cygwin-runtime cygwin-libattr cygwin-libintl8 cygwin-libiconv

        PREFIX ${PROJECT_DEPS_BUILD_PREFIX}
        URL "${URL_PREFIX}/diffutils/diffutils-3.9-1.tar.xz"
        URL_HASH MD5=${CYGWIN_DIFF_HASH}
        DOWNLOAD_NAME "diffutils-3.9-1.tar.xz"
        DOWNLOAD_DIR ${PROJECT_DEPS_TARBALL_DIR}
        DOWNLOAD_NO_PROGRESS 1

        BUILD_IN_SOURCE 1

        CONFIGURE_COMMAND echo Done
        BUILD_COMMAND echo Done
        INSTALL_COMMAND xcopy /s /e /q /y . ${PROJECT_HOST_TOOLS_DIR}\\usr
    )

    add_custom_target(platform-specific
        COMMENT "Build platform-specific: Cygwin Runtime"
        COMMAND echo Done
    )
    add_dependencies(platform-specific
        cygwin-patch)
else()
    add_custom_target(platform-specific
        COMMENT "Build platform-specific: None"
        COMMAND echo Done
    )
endif()
