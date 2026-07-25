#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "parser.hpp"

namespace py = pybind11;

PYBIND11_MODULE(nyx_grpc_parser, m) {
    m.doc() = "Nyx gRPC binary frame parser";

    py::class_<nyx::GrpcFrame>(m, "GrpcFrame")
        .def_readonly("compressed", &nyx::GrpcFrame::compressed)
        .def_readonly("length", &nyx::GrpcFrame::length)
        .def_readonly("data", &nyx::GrpcFrame::data);

    py::class_<nyx::GrpcMessage>(m, "GrpcMessage")
        .def_readonly("fields", &nyx::GrpcMessage::fields);

    m.def("parse_grpc_frame", &nyx::parse_grpc_frame,
          py::arg("raw_bytes"),
          "Parse a raw gRPC frame.");

    m.def("extract_messages", &nyx::extract_messages,
          py::arg("stream_bytes"),
          "Extract all gRPC messages from an HTTP/2 stream.");
}