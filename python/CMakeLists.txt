project(eladid_cffi VERSION 1.0.0)

include(ProjectDefaults)

find_package(Python3 COMPONENTS Interpreter Development)

execute_process(COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/get_suffix.py OUTPUT_VARIABLE CFFI_EXT)

string(REGEX REPLACE "\n$" "" CFFI_EXT "${CFFI_EXT}")
set(CFFI_MODULE_NAME "eladid${CFFI_EXT}")
set(ENABLE_UNICODE_NORMALIZATION TRUE CACHE BOOL "Enable unicode normalization for mnemonic")

set(CP ${CMAKE_COMMAND} -E copy)
set(MKDIR ${CMAKE_COMMAND} -E make_directory)

if(NOT WIN32)
    set(VENV_ACTIVATE . ${CMAKE_CURRENT_BINARY_DIR}/venv/bin/activate)
else()
    set(VENV_ACTIVATE ${CMAKE_CURRENT_BINARY_DIR}/venv/Scripts/activate.bat)
endif()

add_custom_command(
    COMMAND ${Python3_EXECUTABLE} -m venv ${CMAKE_CURRENT_BINARY_DIR}/venv
    COMMAND ${VENV_ACTIVATE} && pip install cffi
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/venv
    VERBATIM
)

add_custom_command(
    COMMAND ${MKDIR} ${CMAKE_CURRENT_BINARY_DIR}/include
    COMMAND ${CP} ${CMAKE_CURRENT_SOURCE_DIR}/../src/ela_did.h ${CMAKE_CURRENT_BINARY_DIR}/include
    COMMAND ${CP} ${CMAKE_CURRENT_SOURCE_DIR}/../src/jwt/ela_jwt.h ${CMAKE_CURRENT_BINARY_DIR}/include
    COMMAND ${CP} ${CMAKE_CURRENT_SOURCE_DIR}/ela_did.ffi.h ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${CP} ${CMAKE_CURRENT_SOURCE_DIR}/ela_jwt.ffi.h ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../src/ela_did.h ${CMAKE_CURRENT_SOURCE_DIR}/../src/jwt/ela_jwt.h ${CMAKE_CURRENT_SOURCE_DIR}/ela_did.ffi.h ${CMAKE_CURRENT_SOURCE_DIR}/ela_jwt.ffi.h
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/include
    VERBATIM
)

add_custom_command(
    COMMAND ${MKDIR} ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMAND ${CP} ${PROJECT_INT_DIST_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}curl${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMAND ${CP} ${PROJECT_INT_DIST_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}ssl${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMAND ${CP} ${PROJECT_INT_DIST_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}crypto${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMAND ${CP} ${PROJECT_INT_DIST_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}jansson${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMAND ${CP} ${PROJECT_INT_DIST_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}cjose${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMAND ${CP} ${PROJECT_INT_DIST_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}utf8proc${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMAND ${CP} ${PROJECT_INT_DIST_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}sodium${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMAND ${CP} ${PROJECT_INT_DIST_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}zip${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMAND ${CP} ${PROJECT_INT_DIST_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}z${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMAND ${CP} ${CMAKE_CURRENT_BINARY_DIR}/../src/${CMAKE_STATIC_LIBRARY_PREFIX}eladid${STATIC_LIB_DECORATOR}${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMAND ${CP} ${CMAKE_CURRENT_BINARY_DIR}/../hdkey/${CMAKE_STATIC_LIBRARY_PREFIX}hdkey${STATIC_LIB_DECORATOR}${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_CURRENT_BINARY_DIR}/lib
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/../src/${CMAKE_STATIC_LIBRARY_PREFIX}eladid${STATIC_LIB_DECORATOR}${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_CURRENT_BINARY_DIR}/../hdkey/${CMAKE_STATIC_LIBRARY_PREFIX}hdkey${STATIC_LIB_DECORATOR}${CMAKE_STATIC_LIBRARY_SUFFIX}
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lib
    VERBATIM
)

add_custom_command(
    COMMAND ${VENV_ACTIVATE} && python ${CMAKE_CURRENT_SOURCE_DIR}/build.py
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/venv ${CMAKE_CURRENT_BINARY_DIR}/include ${CMAKE_CURRENT_BINARY_DIR}/lib ${CMAKE_CURRENT_SOURCE_DIR}/build.py
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${CFFI_MODULE_NAME}
    VERBATIM
)

add_custom_target(eladid_cffi_shared
    ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${CFFI_MODULE_NAME}
    VERBATIM
)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${CFFI_MODULE_NAME}
    DESTINATION "lib")
