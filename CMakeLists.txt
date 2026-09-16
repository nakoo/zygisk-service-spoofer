cmake_minimum_required(VERSION 3.22.1)
project(zygisk_service_spoofer C CXX)

set(CMAKE_CXX_STANDARD 20)

add_library(service_spoofer SHARED jni/main.cpp)

target_include_directories(service_spoofer PRIVATE
    jni
)

target_link_libraries(service_spoofer PRIVATE
    log
)
