cmake_minimum_required (VERSION 2.6)
project (SslParser)

file(GLOB_RECURSE src "src/*.c")
include_directories("inc")
add_executable(SslParser ${src})
