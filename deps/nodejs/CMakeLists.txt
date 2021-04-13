project(nodejs)

include(ProjectDefaults)
include(ExternalProject)

if(UNIX)
    if(APPLE)
        set(PACKAGE_PREFIX "darwin-x64.tar.gz")
        set(PACKAGE_HASH b762b72fc149629b7e394ea9b75a093cad709a9f2f71480942945d8da0fc1218)
    else()
        set(PACKAGE_PREFIX "linux-x64.tar.xz")
        set(PACKAGE_HASH 85a89d2f68855282c87851c882d4c4bbea4cd7f888f603722f0240a6e53d89df)
    endif()

elseif(WIN32)
    set(PACKAGE_PREFIX "win-x64.zip")
    set(PACKAGE_HASH e469db37b4df74627842d809566c651042d86f0e6006688f0f5fe3532c6dfa41)
else()
endif()

set(PACKAGE_NAME "node-v14.16.1-${PACKAGE_PREFIX}")
set(PACKAGE_URL "https://nodejs.org/dist/v14.16.1/${PACKAGE_NAME}")

ExternalProject_Add(
    nodejs

    PREFIX ${PROJECT_DEPS_BUILD_PREFIX}

    URL ${PACKAGE_URL}
    URL_HASH SHA256=${PACKAGE_HASH}
    DOWNLOAD_NAME "nodejs-v14.16.1.${PACKAGE_PREFIX}"
    DOWNLOAD_DIR ${PROJECT_DEPS_TARBALL_DIR}
    DOWNLOAD_NO_PROGRESS 1

    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)
