project(jansson)

include(ProjectDefaults)
include(ExternalProject)
include(ExternalCMakeArgs)

ExternalProject_Add(
    libjansson

    PREFIX ${PROJECT_DEPS_BUILD_PREFIX}
    URL "https://github.com/akheron/jansson/archive/v2.13.1.tar.gz"
    URL_HASH SHA256=f22901582138e3203959c9257cf83eba9929ac41d7be4a42557213a22ebcc7a0
    DOWNLOAD_NAME "jansson-2.13.1.tar.gz"
    DOWNLOAD_DIR ${PROJECT_DEPS_TARBALL_DIR}
    DOWNLOAD_NO_PROGRESS 1

    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${PROJECT_INT_DIST_DIR}
        ${CMAKE_ARGS_INIT}
)

if(WIN32)
    if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
        ExternalProject_Add_Step(
            libjansson post-install
            DEPENDEES install
            WORKING_DIRECTORY "${PROJECT_INT_DIST_DIR}/lib"
            COMMAND copy jansson_d.lib jansson.lib /y
        )
    endif()
endif()
