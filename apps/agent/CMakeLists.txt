project(agent C)

include(ProjectDefaults)
include(CheckIncludeFile)
include(CheckFunctionExists)

check_include_file(unistd.h HAVE_UNISTD_H)
if(HAVE_UNISTD_H)
    add_definitions(-DHAVE_UNISTD_H=1)
endif()

check_include_file(getopt.h HAVE_GETOPT_H)
if(HAVE_GETOPT_H)
    add_definitions(-DHAVE_GETOPT_H=1)
endif()

check_include_file(sys/time.h HAVE_SYS_TIME_H)
if(HAVE_SYS_TIME_H)
    add_definitions(-DHAVE_SYS_TIME_H=1)
endif()

check_include_file(sys/resource.h HAVE_SYS_RESOURCE_H)
if(HAVE_SYS_RESOURCE_H)
    add_definitions(-DHAVE_SYS_RESOURCE_H=1)
endif()

check_include_file(direct.h HAVE_DIRECT_H)
if(HAVE_DIRECT_H)
    add_definitions(-DHAVE_DIRECT_H=1)
endif()

set(SRC
    main.c)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(SYSTEM_LIBS pthread dl)
endif()

include_directories(
    ../../src
    ${PROJECT_INT_DIST_DIR}/include)

link_directories(
    ${PROJECT_INT_DIST_DIR}/lib
    ${CMAKE_CURRENT_BINARY_DIR}/../../src)

set(LIBS
    eladid)

if(WIN32)
    set(LIBS
        ${LIBS}
        crystal)
endif()

add_executable(agent ${SRC})
target_compile_definitions(agent PRIVATE CRYSTAL_DYNAMIC)
target_link_libraries(agent ${LIBS} ${SYSTEM_LIBS})

install(TARGETS agent
    RUNTIME DESTINATION "${PROJECT_INT_DIST_DIR}/bin"
    ARCHIVE DESTINATION "${PROJECT_INT_DIST_DIR}/lib"
    LIBRARY DESTINATION "${PROJECT_INT_DIST_DIR}/lib")
