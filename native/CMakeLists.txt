cmake_minimum_required(VERSION 3.16)
project(nyx_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Suppress policy warnings for pybind11's FindPythonLibsNew
cmake_policy(SET CMP0148 NEW)

find_package(pybind11 REQUIRED)

pybind11_add_module(nyx_grpc_parser
    grpc_parser/bindings.cpp
    grpc_parser/parser.cpp
)

target_include_directories(nyx_grpc_parser PRIVATE grpc_parser)
