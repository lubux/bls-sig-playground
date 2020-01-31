cmake_minimum_required(VERSION 3.10)
project(threshold_sig_playground)


set(CMAKE_CXX_STANDARD 14)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libBLS ${CMAKE_CURRENT_SOURCE_DIR}/libBLS/threshold_encryption )


find_library(BLE_LOC bls PATHS ./libBLS/build)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 7.0)
        message(FATAL_ERROR "Require at least gcc-7.0")
    endif()
endif()

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(STATUS "*** Have SIZEOF void * = 8, so 64-bit")
else ()
    message(FATAL_ERROR "*** SIZEOF void * != 8, so not 64-bit - libBLS supports only 64-bit")
endif ()

if( NOT DEFINED DEPS_INSTALL_ROOT )
    set( DEPS_SOURCES_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/libBLS/deps")
    set( DEPS_INSTALL_ROOT "${DEPS_SOURCES_ROOT}/deps_inst/x86_or_x64")
endif()


include_directories( "${DEPS_INSTALL_ROOT}/include" ${CMAKE_BINARY_DIR}/libBLS/deps/include )
link_directories( "${DEPS_INSTALL_ROOT}/lib" )
set( CMAKE_PREFIX_PATH "${DEPS_INSTALL_ROOT}" )

find_library( GMP_LIBRARY NAMES "gmp" PATHS "${DEPS_INSTALL_ROOT}/lib" )
find_library( GMPXX_LIBRARY NAMES "gmpxx" PATHS "${DEPS_INSTALL_ROOT}/lib" )
find_library( SSL_LIB NAMES "ssl" PATHS "${DEPS_INSTALL_ROOT}/lib")
find_library( CRYPTO_LIB NAMES "crypto"  PATHS "${DEPS_INSTALL_ROOT}/lib")
find_library( FF_LIB NAMES NAMES "ff" PATHS "${DEPS_INSTALL_ROOT}/lib")
find_library( PBC_LIB NAMES NAMES "pbc" PATHS "${DEPS_INSTALL_ROOT}/lib")

set(HUNTER_ENABLED OFF )

option(BUILD_WITH_FPIC "Build with -fPIC" OFF)

set(PROJECT_VERSION 0.4.0)
add_definitions(-DBLS_VERSION=${PROJECT_VERSION})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -fpermissive -fPIC -std=c++17 -Wno-error=parentheses -Wno-error=char-subscripts -Wno-error=unused-variable -Wno-error=unused-parameter -Wno-error=int-in-bool-context")


include_directories(${Boost_INCLUDE_DIRS})

add_executable(requested_demo demo.cpp bls-demo-util.cpp bls-demo-util.h)

target_link_libraries(requested_demo ${PBC_LIB} ${FF_LIB} ${BLE_LOC} ${GMPXX_LIBRARY} ${GMP_LIBRARY} ${BOOST_LIBS_4_BLS} ${CRYPTO_LIB} ${SSL_LIB})