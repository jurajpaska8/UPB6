cmake_minimum_required(VERSION 3.17)
project(vulnerabilitiesUPB C)

set(CMAKE_C_STANDARD 11)

add_executable(vulnerabilitiesUPB main.c)

target_sources(vulnerabilitiesUPB PRIVATE sqlite/sqlite3.c)