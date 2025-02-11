cmake_minimum_required(VERSION 3.30)
project(LargeLoader)

set(CMAKE_CXX_STANDARD 17)

add_library(LargeLoader SHARED src/LargeLoader.c src/city.c)
target_include_directories(LargeLoader PUBLIC include)
target_compile_definitions(LargeLoader PRIVATE LL_EXPORTS)
