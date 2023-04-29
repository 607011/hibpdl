cmake_minimum_required(VERSION 3.16)

project(hibpdl
        VERSION 1.0.0
        DESCRIPTION "HaveIBeenPwned Hash Downloader"
        LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(UNIX)
  set(CMAKE_CXX_FLAGS "-pthread -Wno-deprecated-declarations")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -O0 -g3 -ggdb -DDEBUG -pedantic -Wall -Wextra -Wconversion -Wreorder -Wuninitialized -Wtype-limits -Wno-pragmas")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG -Wno-deprecated")
elseif(WIN32)
  set(CMAKE_CXX_FLAGS_DEBUG "/Od /Wall /Zi /wd5045 /wd5039 /wd5027 /wd4191 /wd4365 /wd4668 /wd4355 /wd4800 /wd4774 /wd4606 /wd4626 /wd4625 /wd4061 /wd4514 /wd4820 /D_CRT_SECURE_NO_WARNINGS /D__STDC_WANT_SECURE_LIB__")
  set(CMAKE_CXX_FLAGS_RELEASE "/O2 /W1 /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /D__STDC_WANT_SECURE_LIB__")
endif(UNIX)

if (CMAKE_CXX_COMPILER_ID MATCHES ".*Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-format-security")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -glldb")
endif()

add_definitions(-DCPPHTTPLIB_OPENSSL_SUPPORT -DPROJECT_NAME="${CMAKE_PROJECT_NAME}" -DPROJECT_VERSION="${CMAKE_PROJECT_VERSION}")

add_subdirectory(3rdparty/cpp-httplib)

set(OPENSSL_ROOT $ENV{OPENSSL_ROOT_DIR})
find_package(OpenSSL)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libs: ${OPENSSL_LIBRARIES}")

set(HIBPDL_SOURCES
  src/main.cpp
  src/hash_count.cpp
  src/hibpdl.cpp
  src/util.cpp
)

if (WIN32)
  set(HIBPDL_SOURCES ${HIBPDL_SOURCES} 3rdparty/getopt-for-windows/getopt.c)
  set(PROJECT_INCLUDE_DIRS ${PROJECT_INCLUDE_DIRS} 3rdparty/getopt-for-windows)
endif()

add_executable(hibpdl ${HIBPDL_SOURCES})

target_include_directories(hibpdl
  PRIVATE ${PROJECT_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIR}
  3rdparty/cpp-httplib
  build
)

target_link_libraries(hibpdl
  ${OPENSSL_LIBRARIES}
)

install(TARGETS hibpdl RUNTIME DESTINATION bin)
