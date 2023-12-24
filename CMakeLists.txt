cmake_minimum_required(VERSION 3.11 FATAL_ERROR)
project(elf-sign VERSION 0.1.1000)

option(LIEF_DOC "Build LIEF docs" OFF)
option(LIEF_PYTHON_API "Build LIEF Python API" OFF)
option(LIEF_EXAMPLES "Build LIEF examples" OFF)
option(LIEF_TESTS "Build LIEF tests" OFF)

if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded" CACHE STRING "CRT option")
endif()

set(vendorLIEF_submodule_dir "${CMAKE_CURRENT_LIST_DIR}/third-party/LIEF")

if(EXISTS "${vendorLIEF_submodule_dir}")
  add_subdirectory("${vendorLIEF_submodule_dir}")
endif()

if(CMAKE_BUILD_TYPE MATCHES "Debug")
  set(PROJECT_NAME_TEST "${PROJECT_NAME}-test")
  add_executable(${PROJECT_NAME_TEST}
    ${PROJECT_SOURCE_DIR}/src/test.cpp
    ${PROJECT_SOURCE_DIR}/src/elf.cpp
  )
  target_link_libraries(${PROJECT_NAME_TEST} PRIVATE LIEF::LIEF)
  target_include_directories(${PROJECT_NAME_TEST} PRIVATE
    ${PROJECT_SOURCE_DIR}/third/LIEF/include
    ${PROJECT_SOURCE_DIR}/include
  )
endif()

add_executable(${PROJECT_NAME}
  ${PROJECT_SOURCE_DIR}/src/main.cpp
  ${PROJECT_SOURCE_DIR}/src/elf.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE LIEF::LIEF)
target_include_directories(${PROJECT_NAME} PRIVATE
  ${PROJECT_SOURCE_DIR}/third/LIEF/include
  ${PROJECT_SOURCE_DIR}/include
)