cmake_minimum_required(VERSION 2.8)

project(main)

file(GLOB files
     "src/*.c"
     "src/*/*.c"
)

add_executable(main ${files})