cmake_minimum_required(VERSION 3.20)

project(trustgate VERSION 0.3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(TG_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(MSVC)
  add_compile_options(/W4 /EHsc)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

file(GLOB_RECURSE TG_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_executable(tg ${TG_SOURCES})
target_include_directories(tg PRIVATE "${CMAKE_SOURCE_DIR}/src")

if(TG_ENABLE_SANITIZERS)
  if(MSVC)
    message(FATAL_ERROR "TG_ENABLE_SANITIZERS currently supports GCC/Clang only")
  endif()
  target_compile_options(tg PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(tg PRIVATE -fsanitize=address,undefined)
endif()

enable_testing()

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_FOUND)
  add_test(NAME smoke
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/smoke.py"
            --tg "$<TARGET_FILE:tg>")
  set_tests_properties(smoke PROPERTIES TIMEOUT 180)

  add_test(NAME fingerprint-crypto
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/fingerprint_crypto.py"
            --tg "$<TARGET_FILE:tg>")
  set_tests_properties(fingerprint-crypto PROPERTIES TIMEOUT 60)

  add_test(NAME gate-security
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/gate_security.py"
            --tg "$<TARGET_FILE:tg>")
  set_tests_properties(gate-security PROPERTIES TIMEOUT 90)

  add_test(NAME eval-schema-security
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/eval_schema_security.py"
            --tg "$<TARGET_FILE:tg>")
  set_tests_properties(eval-schema-security PROPERTIES TIMEOUT 60)

  add_test(NAME attestation-security
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/attestation_security.py"
            --tg "$<TARGET_FILE:tg>")
  set_tests_properties(attestation-security PROPERTIES TIMEOUT 60)
else()
  message(STATUS "Python3 interpreter not found - Python test suites not registered. Run tests manually.")
endif()
