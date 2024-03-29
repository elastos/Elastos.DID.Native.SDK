cmake_minimum_required(VERSION 3.5)
#cmake_policy(VERSION 3.10)
cmake_policy(VERSION 3.5)
project(Elastos-DID VERSION 1.0.0 LANGUAGES C)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
include(ProjectDefaults)
include(DistPackage)
include(AddSubModule)

if(WIN32)
    set(ENABLE_SHARED_DEFAULT TRUE)
    set(ENABLE_STATIC_DEFAULT FALSE)
else()
    set(ENABLE_SHARED_DEFAULT TRUE)
    set(ENABLE_STATIC_DEFAULT TRUE)
endif()

if(CMAKE_CROSSCOMPILING)
    set(ENABLE_TESTS_DEFAULT FALSE)
    set(ENABLE_APPS_DEFAULT FALSE)
else()
    set(ENABLE_TESTS_DEFAULT TRUE)
    set(ENABLE_APPS_DEFAULT TRUE)
endif()

set(ENABLE_SHARED ${ENABLE_SHARED_DEFAULT} CACHE BOOL "Build shared library")
set(ENABLE_STATIC ${ENABLE_STATIC_DEFAULT} CACHE BOOL "Build static library")
set(HDKEY_ONLY FALSE CACHE BOOL "Build HDKey only")
set(ENABLE_UNICODE_NORMALIZATION TRUE CACHE BOOL "Enable unicode normalization for mnemonic")
set(ENABLE_JWT TRUE CACHE BOOL "Build JWT")
set(ENABLE_PYTHON FALSE CACHE BOOL "Build Python cffi module")
set(ENABLE_TESTS ${ENABLE_TESTS_DEFAULT} CACHE BOOL "Build test cases")
set(ENABLE_APPS ${ENABLE_APPS_DEFAULT} CACHE BOOL "Build DID utils")
set(ENABLE_SAMPLES ${ENABLE_APPS_DEFAULT} CACHE BOOL "Build DID Samples")
set(ENABLE_DOCS FALSE CACHE BOOL "Build APIs documentation")

if(NOT ENABLE_JWT)
    set(ENABLE_TESTS FALSE)
    set(ENABLE_APPS FALSE)
    set(ENABLE_PYTHON FALSE)
endif()

if(ENABLE_PYTHON OR ENABLE_TESTS)
    set(ENABLE_STATIC TRUE)
endif()

add_subdirectory(deps)
add_subdirectory(hdkey)

if(NOT HDKEY_ONLY)
    add_subdirectory(src)

    if(ENABLE_PYTHON)
        add_subdirectory(python)
    endif()

    if(ENABLE_TESTS)
        add_subdirectory(tests)
    endif()

    if(ENABLE_APPS)
        add_subdirectory(apps)
    endif()

    if(ENABLE_SAMPLES)
        add_subdirectory(samples)
    endif()
endif()

if(ENABLE_DOCS)
   add_subdirectory(docs)
endif()

# Alias target for package. But it fix issue about making package
# inrelevant to udpatation of cmake scripts.
add_custom_target(dist
    COMMAND ${CMAKE_MAKE_PROGRAM} package
    COMMENT "Build distrubtion package")
