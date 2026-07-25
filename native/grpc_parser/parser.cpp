#include "parser.hpp"
#include <cstring>

namespace nyx {

GrpcFrame parse_grpc_frame(const std::string& raw_bytes) {
    GrpcFrame frame;
    if (raw_bytes.size() < 5) {
        frame.compressed = false;
        frame.length = 0;
        return frame;
    }

    frame.compressed = (raw_bytes[0] & 0x01) != 0;
    frame.length = 0;
    for (int i = 1; i <= 4; ++i) {
        frame.length = (frame.length << 8) | static_cast<uint8_t>(raw_bytes[i]);
    }

    size_t header_size = 5;
    size_t remaining = raw_bytes.size() - header_size;
    size_t data_len = std::min<size_t>(frame.length, remaining);
    frame.data.assign(raw_bytes.begin() + header_size,
                      raw_bytes.begin() + header_size + data_len);
    return frame;
}

std::vector<GrpcMessage> extract_messages(const std::string& stream_bytes) {
    std::vector<GrpcMessage> messages;
    size_t offset = 0;

    while (offset < stream_bytes.size()) {
        std::string remaining = stream_bytes.substr(offset);
        GrpcFrame frame = parse_grpc_frame(remaining);

        if (frame.length == 0) break;

        GrpcMessage msg;
        const uint8_t* data = frame.data.data();
        size_t remaining_in_frame = frame.data.size();
        int field_number = 1;

        while (remaining_in_frame > 0) {
            uint8_t key = data[0];
            if (key == 0) break;

            int wire_type = key & 0x07;
            std::string value = decode_field(wire_type, data, remaining_in_frame);
            msg.fields[field_number++] = value;

            size_t consumed = 1;
            if (wire_type == 0) {
                while (consumed < remaining_in_frame &&
                       (data[consumed - 1] & 0x80)) {
                    consumed++;
                }
            }
            data += consumed;
            remaining_in_frame -= (remaining_in_frame < consumed) ? remaining_in_frame : consumed;
        }

        messages.push_back(std::move(msg));
        offset += 5 + frame.length;
    }

    return messages;
}

std::string decode_field(int wire_type, const uint8_t* data, size_t len) {
    if (wire_type == 0 && len > 0) {
        uint64_t value = 0;
        int shift = 0;
        size_t i = 0;
        while (i < len && i < 10) {
            value |= static_cast<uint64_t>(data[i] & 0x7F) << shift;
            if (!(data[i] & 0x80)) break;
            shift += 7;
            i++;
        }
        return std::to_string(value);
    }
    return "<binary>";
}

}