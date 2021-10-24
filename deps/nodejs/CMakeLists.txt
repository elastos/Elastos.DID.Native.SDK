project(nodejs)

include(ProjectDefaults)
include(ExternalProject)

if(UNIX)
    if(APPLE)
        set(PACKAGE_PREFIX "darwin-x64.tar.gz")
        set(PACKAGE_HASH b762b72fc149629b7e394ea9b75a093cad709a9f2f71480942945d8da0fc1218)
    elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        if (${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "aarch64")
            set(PACKAGE_PREFIX "linux-arm64.tar.gz")
            set(PACKAGE_HASH 58cb307666ed4aa751757577a563b8a1e5d4ee73a9fac2b495e5c463682a07d1)
        elseif(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "armv7l")
            set(PACKAGE_PREFIX "linux-armv7l.tar.gz")
            set(PACKAGE_HASH 54efe997dbeff971b1e39c8eb910566ecb68cfd6140a6b5c738265d4b5842d24)
        elseif(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
            set(PACKAGE_PREFIX "linux-x64.tar.gz")
            set(PACKAGE_HASH 068400cb9f53d195444b9260fd106f7be83af62bb187932656b68166a2f87f44)
        else()
            message(FATAL_ERROR "Do not support ${CMAKE_SYSTEM}")
        endif()
    else()
        message(FATAL_ERROR "Do not support ${CMAKE_SYSTEM}")
    endif()
elseif(WIN32)
    set(PACKAGE_PREFIX "win-x64.zip")
    set(PACKAGE_HASH e469db37b4df74627842d809566c651042d86f0e6006688f0f5fe3532c6dfa41)
else()
    message(FATAL_ERROR "Do not support ${CMAKE_SYSTEM}")
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
