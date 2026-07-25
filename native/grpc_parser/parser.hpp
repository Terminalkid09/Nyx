#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace nyx {

struct GrpcFrame {
    bool compressed;
    uint32_t length;
    std::vector<uint8_t> data;
};

struct GrpcMessage {
    std::map<int, std::string> fields;
};

GrpcFrame parse_grpc_frame(const std::string& raw_bytes);

std::vector<GrpcMessage> extract_messages(const std::string& stream_bytes);

std::string decode_field(int wire_type, const uint8_t* data, size_t len);

}