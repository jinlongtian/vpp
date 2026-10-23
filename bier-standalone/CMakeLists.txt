cmake_minimum_required(VERSION 3.16)

project(bier-standalone C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

add_compile_options(-Wall -Wextra)

add_library(bier STATIC
  src/bier_codec.c
  src/bier_domain.c
  src/bier_forward.c
  src/json.c
  src/bier_config.c
)

target_include_directories(bier
  PUBLIC include
  PRIVATE src
)

add_executable(bierd app/bierd.c)
target_link_libraries(bierd PRIVATE bier)

enable_testing()

add_executable(test_bier tests/test_bier.c)
target_link_libraries(test_bier PRIVATE bier)
add_test(NAME bier_unit COMMAND test_bier)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  add_test(
    NAME bier_e2e
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e_udp.py
            $<TARGET_FILE:bierd> ${CMAKE_CURRENT_SOURCE_DIR}/configs/example.json
  )
  set_tests_properties(bier_e2e PROPERTIES TIMEOUT 20)
endif()
