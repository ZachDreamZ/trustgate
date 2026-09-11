cmake_minimum_required(VERSION 3.20)

project(trustgate VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /EHsc)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

file(GLOB_RECURSE TG_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_executable(tg ${TG_SOURCES})
target_include_directories(tg PRIVATE "${CMAKE_SOURCE_DIR}/src")

enable_testing()

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_FOUND)
  add_test(NAME smoke
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/smoke.py"
            --tg "$<TARGET_FILE:tg>")
  set_tests_properties(smoke PROPERTIES TIMEOUT 180)
else()
  message(STATUS "Python3 interpreter not found - smoke test not registered. Run tests/smoke.py manually.")
endif()
