cmake_minimum_required(VERSION 3.9)
project(code C)

set(CMAKE_C_STANDARD 99)
include(FindJSON-C.cmake)
include(FindPCAP.cmake)

add_executable(code main.c)
target_link_libraries(code ${PCAP_LIBRARY} ${JSON-C_LIBRARY})