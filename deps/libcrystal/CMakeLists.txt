project(libcrystal)

include(ProjectDefaults)
include(ExternalProject)
include(ExternalCMakeArgs)

ExternalProject_Add(
    libcrystal

    PREFIX ${PROJECT_DEPS_BUILD_PREFIX}
    URL "https://github.com/iwhisperio/libcrystal/archive/release-v1.0.6.tar.gz"
    URL_HASH SHA256=24513b4f8971a35a4fd29f85f21dba2ae55e06fe5fe34a533a3013da98a2c98b
    DOWNLOAD_NAME "libcrystal-v1.0.6.tar.gz"
    DOWNLOAD_DIR ${PROJECT_DEPS_TARBALL_DIR}
    DOWNLOAD_NO_PROGRESS 1

    PATCH_COMMAND ${PATCH_EXE} -s -p1 < ${CMAKE_CURRENT_LIST_DIR}/crystal.patch

    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${PROJECT_INT_DIST_DIR}
        -DENABLE_STATIC=${ENABLE_STATIC}
        -DENABLE_SHARED=${ENABLE_SHARED}
        -DENABLE_CRYPTO=FALSE
        -DENABLE_TESTS=FALSE
        -DENABLE_BASE58=FALSE
        ${CMAKE_ARGS_INIT}
)

if(ENABLE_SHARED)
    if(WIN32)
        set(INSTALL_DESTINATION bin)
    else()
        set(INSTALL_DESTINATION lib)
    endif()

    string(CONCAT SHARED_LIBRARY_NAME
        "${PROJECT_INT_DIST_DIR}/${INSTALL_DESTINATION}/"
        "${CMAKE_SHARED_LIBRARY_PREFIX}"
        "crystal"
        "${CMAKE_SHARED_LIBRARY_SUFFIX}")

    get_filename_component(SHARED_LIBRARY_NAME "${SHARED_LIBRARY_NAME}"
                       REALPATH BASE_DIR "${CMAKE_CURRENT_LIST_DIR}")

    install(PROGRAMS "${SHARED_LIBRARY_NAME}"
        DESTINATION ${INSTALL_DESTINATION})
endif()
