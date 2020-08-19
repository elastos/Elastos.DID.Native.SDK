project(CUnit)

include(ExternalProject)
include(ProjectDefaults)

if(WIN32)
    include(ExternalCMakeArgs)

    ExternalProject_Add(
        CUnit

        PREFIX ${PROJECT_DEPS_BUILD_PREFIX}
        URL "https://github.com/jacklicn/CUnit/archive/v2.1-3.tar.gz"
        URL_HASH SHA256=b9ba84b54b916d81608572985d558b23bdcd7739180852273948de5cdc3a2cca
        DOWNLOAD_NAME "CUnit-2.1-3.tar.gz"
        DOWNLOAD_DIR ${PROJECT_DEPS_TARBALL_DIR}
        DOWNLOAD_NO_PROGRESS 1

        PATCH_COMMAND ${PATCH_EXE} -s -p1 < ${CMAKE_CURRENT_LIST_DIR}/CUnit.patch

        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${PROJECT_INT_DIST_DIR}
            ${CMAKE_ARGS_INIT}
    )

else()
    include(ExternalConfigureArgs)

    set(CONFIGURE_CMD
        aclocal &&
        autoconf &&
        autoreconf -if &&
        ./configure)

    set(CONFIGURE_ARGS
        "--prefix=${PROJECT_INT_DIST_DIR}"
        "--enable-shared=no"
        "--disable-shared"
        "--enable-static=yes"
        ${CONFIGURE_ARGS_INIT})

    set(BUILD_CMD "make")

    set(INSTALL_CMD "make")
    set(INSTALL_ARGS "install")

    ExternalProject_Add(
        CUnit

        PREFIX ${PROJECT_DEPS_BUILD_PREFIX}
        URL "https://github.com/jacklicn/CUnit/archive/v2.1-3.tar.gz"
        URL_HASH SHA256=b9ba84b54b916d81608572985d558b23bdcd7739180852273948de5cdc3a2cca
        DOWNLOAD_NAME "CUnit-2.1-3.tar.gz"
        DOWNLOAD_DIR ${PROJECT_DEPS_TARBALL_DIR}
        DOWNLOAD_NO_PROGRESS 1

        BUILD_IN_SOURCE 1

        CONFIGURE_COMMAND ${CONFIGURE_CMD} ${CONFIGURE_ARGS}
        BUILD_COMMAND ${BUILD_CMD} ${BUILD_ARGS}
        INSTALL_COMMAND ${INSTALL_CMD} ${INSTALL_ARGS}
    )
endif()
