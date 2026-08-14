#include <tailgate/control/base/H2.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace tailgate::control::base
{
namespace
{

constexpr std::uint8_t H2FlagEndStream = 0x01;
constexpr std::uint8_t H2FlagEndHeaders = 0x04;
constexpr std::uint8_t H2FlagAck = 0x01;
constexpr std::uint16_t H2SettingsInitialWindowSize = 0x04;
constexpr std::uint8_t HpackIndexedMask = 0x80;
constexpr std::uint8_t HpackIndexedPrefixMask = 0x7f;
constexpr std::uint8_t HpackLiteralIncrementalMask = 0x40;
constexpr std::uint8_t HpackLiteralIncrementalPrefixMask = 0x3f;
constexpr std::uint8_t HpackDynamicTableSizeUpdateMask = 0x20;
constexpr std::uint8_t HpackDynamicTableSizeUpdatePrefixMask = 0x1f;
constexpr std::uint8_t HpackLiteralPrefixMask = 0x0f;
constexpr std::uint8_t HpackHuffmanMask = 0x80;
constexpr std::uint8_t HpackStringLengthPrefixMask = 0x7f;
constexpr std::size_t BitsPerByte = 8;
constexpr std::size_t MaximumHpackPaddingBits = 7;
constexpr std::size_t HpackEntryOverhead = 32;
constexpr int MinimumHttpStatus = 100;
constexpr int MaximumHttpStatus = 599;

struct HpackStaticHeaderField
{
    std::string_view Name;
    std::string_view Value;
};

constexpr std::array<HpackStaticHeaderField, 62> HpackStaticHeaders = {
    HpackStaticHeaderField{.Name = "", .Value = ""},
    HpackStaticHeaderField{.Name = ":authority", .Value = ""},
    HpackStaticHeaderField{.Name = ":method", .Value = "GET"},
    HpackStaticHeaderField{.Name = ":method", .Value = "POST"},
    HpackStaticHeaderField{.Name = ":path", .Value = "/"},
    HpackStaticHeaderField{.Name = ":path", .Value = "/index.html"},
    HpackStaticHeaderField{.Name = ":scheme", .Value = "http"},
    HpackStaticHeaderField{.Name = ":scheme", .Value = "https"},
    HpackStaticHeaderField{.Name = ":status", .Value = "200"},
    HpackStaticHeaderField{.Name = ":status", .Value = "204"},
    HpackStaticHeaderField{.Name = ":status", .Value = "206"},
    HpackStaticHeaderField{.Name = ":status", .Value = "304"},
    HpackStaticHeaderField{.Name = ":status", .Value = "400"},
    HpackStaticHeaderField{.Name = ":status", .Value = "404"},
    HpackStaticHeaderField{.Name = ":status", .Value = "500"},
    HpackStaticHeaderField{.Name = "accept-charset", .Value = ""},
    HpackStaticHeaderField{.Name = "accept-encoding", .Value = "gzip, deflate"},
    HpackStaticHeaderField{.Name = "accept-language", .Value = ""},
    HpackStaticHeaderField{.Name = "accept-ranges", .Value = ""},
    HpackStaticHeaderField{.Name = "accept", .Value = ""},
    HpackStaticHeaderField{.Name = "access-control-allow-origin", .Value = ""},
    HpackStaticHeaderField{.Name = "age", .Value = ""},
    HpackStaticHeaderField{.Name = "allow", .Value = ""},
    HpackStaticHeaderField{.Name = "authorization", .Value = ""},
    HpackStaticHeaderField{.Name = "cache-control", .Value = ""},
    HpackStaticHeaderField{.Name = "content-disposition", .Value = ""},
    HpackStaticHeaderField{.Name = "content-encoding", .Value = ""},
    HpackStaticHeaderField{.Name = "content-language", .Value = ""},
    HpackStaticHeaderField{.Name = "content-length", .Value = ""},
    HpackStaticHeaderField{.Name = "content-location", .Value = ""},
    HpackStaticHeaderField{.Name = "content-range", .Value = ""},
    HpackStaticHeaderField{.Name = "content-type", .Value = ""},
    HpackStaticHeaderField{.Name = "cookie", .Value = ""},
    HpackStaticHeaderField{.Name = "date", .Value = ""},
    HpackStaticHeaderField{.Name = "etag", .Value = ""},
    HpackStaticHeaderField{.Name = "expect", .Value = ""},
    HpackStaticHeaderField{.Name = "expires", .Value = ""},
    HpackStaticHeaderField{.Name = "from", .Value = ""},
    HpackStaticHeaderField{.Name = "host", .Value = ""},
    HpackStaticHeaderField{.Name = "if-match", .Value = ""},
    HpackStaticHeaderField{.Name = "if-modified-since", .Value = ""},
    HpackStaticHeaderField{.Name = "if-none-match", .Value = ""},
    HpackStaticHeaderField{.Name = "if-range", .Value = ""},
    HpackStaticHeaderField{.Name = "if-unmodified-since", .Value = ""},
    HpackStaticHeaderField{.Name = "last-modified", .Value = ""},
    HpackStaticHeaderField{.Name = "link", .Value = ""},
    HpackStaticHeaderField{.Name = "location", .Value = ""},
    HpackStaticHeaderField{.Name = "max-forwards", .Value = ""},
    HpackStaticHeaderField{.Name = "proxy-authenticate", .Value = ""},
    HpackStaticHeaderField{.Name = "proxy-authorization", .Value = ""},
    HpackStaticHeaderField{.Name = "range", .Value = ""},
    HpackStaticHeaderField{.Name = "referer", .Value = ""},
    HpackStaticHeaderField{.Name = "refresh", .Value = ""},
    HpackStaticHeaderField{.Name = "retry-after", .Value = ""},
    HpackStaticHeaderField{.Name = "server", .Value = ""},
    HpackStaticHeaderField{.Name = "set-cookie", .Value = ""},
    HpackStaticHeaderField{.Name = "strict-transport-security", .Value = ""},
    HpackStaticHeaderField{.Name = "transfer-encoding", .Value = ""},
    HpackStaticHeaderField{.Name = "user-agent", .Value = ""},
    HpackStaticHeaderField{.Name = "vary", .Value = ""},
    HpackStaticHeaderField{.Name = "via", .Value = ""},
    HpackStaticHeaderField{.Name = "www-authenticate", .Value = ""},
};

struct HpackHuffmanCode
{
    std::uint32_t Bits;
    std::uint8_t Length;
};

constexpr std::array<HpackHuffmanCode, 256> HpackHuffmanCodes = {
    HpackHuffmanCode{.Bits = 0x1ff8, .Length = 13},
    HpackHuffmanCode{.Bits = 0x7fffd8, .Length = 23},
    HpackHuffmanCode{.Bits = 0xfffffe2, .Length = 28},
    HpackHuffmanCode{.Bits = 0xfffffe3, .Length = 28},
    HpackHuffmanCode{.Bits = 0xfffffe4, .Length = 28},
    HpackHuffmanCode{.Bits = 0xfffffe5, .Length = 28},
    HpackHuffmanCode{.Bits = 0xfffffe6, .Length = 28},
    HpackHuffmanCode{.Bits = 0xfffffe7, .Length = 28},
    HpackHuffmanCode{.Bits = 0xfffffe8, .Length = 28},
    HpackHuffmanCode{.Bits = 0xffffea, .Length = 24},
    HpackHuffmanCode{.Bits = 0x3ffffffc, .Length = 30},
    HpackHuffmanCode{.Bits = 0xfffffe9, .Length = 28},
    HpackHuffmanCode{.Bits = 0xfffffea, .Length = 28},
    HpackHuffmanCode{.Bits = 0x3ffffffd, .Length = 30},
    HpackHuffmanCode{.Bits = 0xfffffeb, .Length = 28},
    HpackHuffmanCode{.Bits = 0xfffffec, .Length = 28},
    HpackHuffmanCode{.Bits = 0xfffffed, .Length = 28},
    HpackHuffmanCode{.Bits = 0xfffffee, .Length = 28},
    HpackHuffmanCode{.Bits = 0xfffffef, .Length = 28},
    HpackHuffmanCode{.Bits = 0xffffff0, .Length = 28},
    HpackHuffmanCode{.Bits = 0xffffff1, .Length = 28},
    HpackHuffmanCode{.Bits = 0xffffff2, .Length = 28},
    HpackHuffmanCode{.Bits = 0x3ffffffe, .Length = 30},
    HpackHuffmanCode{.Bits = 0xffffff3, .Length = 28},
    HpackHuffmanCode{.Bits = 0xffffff4, .Length = 28},
    HpackHuffmanCode{.Bits = 0xffffff5, .Length = 28},
    HpackHuffmanCode{.Bits = 0xffffff6, .Length = 28},
    HpackHuffmanCode{.Bits = 0xffffff7, .Length = 28},
    HpackHuffmanCode{.Bits = 0xffffff8, .Length = 28},
    HpackHuffmanCode{.Bits = 0xffffff9, .Length = 28},
    HpackHuffmanCode{.Bits = 0xffffffa, .Length = 28},
    HpackHuffmanCode{.Bits = 0xffffffb, .Length = 28},
    HpackHuffmanCode{.Bits = 0x14, .Length = 6},
    HpackHuffmanCode{.Bits = 0x3f8, .Length = 10},
    HpackHuffmanCode{.Bits = 0x3f9, .Length = 10},
    HpackHuffmanCode{.Bits = 0xffa, .Length = 12},
    HpackHuffmanCode{.Bits = 0x1ff9, .Length = 13},
    HpackHuffmanCode{.Bits = 0x15, .Length = 6},
    HpackHuffmanCode{.Bits = 0xf8, .Length = 8},
    HpackHuffmanCode{.Bits = 0x7fa, .Length = 11},
    HpackHuffmanCode{.Bits = 0x3fa, .Length = 10},
    HpackHuffmanCode{.Bits = 0x3fb, .Length = 10},
    HpackHuffmanCode{.Bits = 0xf9, .Length = 8},
    HpackHuffmanCode{.Bits = 0x7fb, .Length = 11},
    HpackHuffmanCode{.Bits = 0xfa, .Length = 8},
    HpackHuffmanCode{.Bits = 0x16, .Length = 6},
    HpackHuffmanCode{.Bits = 0x17, .Length = 6},
    HpackHuffmanCode{.Bits = 0x18, .Length = 6},
    HpackHuffmanCode{.Bits = 0x0, .Length = 5},
    HpackHuffmanCode{.Bits = 0x1, .Length = 5},
    HpackHuffmanCode{.Bits = 0x2, .Length = 5},
    HpackHuffmanCode{.Bits = 0x19, .Length = 6},
    HpackHuffmanCode{.Bits = 0x1a, .Length = 6},
    HpackHuffmanCode{.Bits = 0x1b, .Length = 6},
    HpackHuffmanCode{.Bits = 0x1c, .Length = 6},
    HpackHuffmanCode{.Bits = 0x1d, .Length = 6},
    HpackHuffmanCode{.Bits = 0x1e, .Length = 6},
    HpackHuffmanCode{.Bits = 0x1f, .Length = 6},
    HpackHuffmanCode{.Bits = 0x5c, .Length = 7},
    HpackHuffmanCode{.Bits = 0xfb, .Length = 8},
    HpackHuffmanCode{.Bits = 0x7ffc, .Length = 15},
    HpackHuffmanCode{.Bits = 0x20, .Length = 6},
    HpackHuffmanCode{.Bits = 0xffb, .Length = 12},
    HpackHuffmanCode{.Bits = 0x3fc, .Length = 10},
    HpackHuffmanCode{.Bits = 0x1ffa, .Length = 13},
    HpackHuffmanCode{.Bits = 0x21, .Length = 6},
    HpackHuffmanCode{.Bits = 0x5d, .Length = 7},
    HpackHuffmanCode{.Bits = 0x5e, .Length = 7},
    HpackHuffmanCode{.Bits = 0x5f, .Length = 7},
    HpackHuffmanCode{.Bits = 0x60, .Length = 7},
    HpackHuffmanCode{.Bits = 0x61, .Length = 7},
    HpackHuffmanCode{.Bits = 0x62, .Length = 7},
    HpackHuffmanCode{.Bits = 0x63, .Length = 7},
    HpackHuffmanCode{.Bits = 0x64, .Length = 7},
    HpackHuffmanCode{.Bits = 0x65, .Length = 7},
    HpackHuffmanCode{.Bits = 0x66, .Length = 7},
    HpackHuffmanCode{.Bits = 0x67, .Length = 7},
    HpackHuffmanCode{.Bits = 0x68, .Length = 7},
    HpackHuffmanCode{.Bits = 0x69, .Length = 7},
    HpackHuffmanCode{.Bits = 0x6a, .Length = 7},
    HpackHuffmanCode{.Bits = 0x6b, .Length = 7},
    HpackHuffmanCode{.Bits = 0x6c, .Length = 7},
    HpackHuffmanCode{.Bits = 0x6d, .Length = 7},
    HpackHuffmanCode{.Bits = 0x6e, .Length = 7},
    HpackHuffmanCode{.Bits = 0x6f, .Length = 7},
    HpackHuffmanCode{.Bits = 0x70, .Length = 7},
    HpackHuffmanCode{.Bits = 0x71, .Length = 7},
    HpackHuffmanCode{.Bits = 0x72, .Length = 7},
    HpackHuffmanCode{.Bits = 0xfc, .Length = 8},
    HpackHuffmanCode{.Bits = 0x73, .Length = 7},
    HpackHuffmanCode{.Bits = 0xfd, .Length = 8},
    HpackHuffmanCode{.Bits = 0x1ffb, .Length = 13},
    HpackHuffmanCode{.Bits = 0x7fff0, .Length = 19},
    HpackHuffmanCode{.Bits = 0x1ffc, .Length = 13},
    HpackHuffmanCode{.Bits = 0x3ffc, .Length = 14},
    HpackHuffmanCode{.Bits = 0x22, .Length = 6},
    HpackHuffmanCode{.Bits = 0x7ffd, .Length = 15},
    HpackHuffmanCode{.Bits = 0x3, .Length = 5},
    HpackHuffmanCode{.Bits = 0x23, .Length = 6},
    HpackHuffmanCode{.Bits = 0x4, .Length = 5},
    HpackHuffmanCode{.Bits = 0x24, .Length = 6},
    HpackHuffmanCode{.Bits = 0x5, .Length = 5},
    HpackHuffmanCode{.Bits = 0x25, .Length = 6},
    HpackHuffmanCode{.Bits = 0x26, .Length = 6},
    HpackHuffmanCode{.Bits = 0x27, .Length = 6},
    HpackHuffmanCode{.Bits = 0x6, .Length = 5},
    HpackHuffmanCode{.Bits = 0x74, .Length = 7},
    HpackHuffmanCode{.Bits = 0x75, .Length = 7},
    HpackHuffmanCode{.Bits = 0x28, .Length = 6},
    HpackHuffmanCode{.Bits = 0x29, .Length = 6},
    HpackHuffmanCode{.Bits = 0x2a, .Length = 6},
    HpackHuffmanCode{.Bits = 0x7, .Length = 5},
    HpackHuffmanCode{.Bits = 0x2b, .Length = 6},
    HpackHuffmanCode{.Bits = 0x76, .Length = 7},
    HpackHuffmanCode{.Bits = 0x2c, .Length = 6},
    HpackHuffmanCode{.Bits = 0x8, .Length = 5},
    HpackHuffmanCode{.Bits = 0x9, .Length = 5},
    HpackHuffmanCode{.Bits = 0x2d, .Length = 6},
    HpackHuffmanCode{.Bits = 0x77, .Length = 7},
    HpackHuffmanCode{.Bits = 0x78, .Length = 7},
    HpackHuffmanCode{.Bits = 0x79, .Length = 7},
    HpackHuffmanCode{.Bits = 0x7a, .Length = 7},
    HpackHuffmanCode{.Bits = 0x7b, .Length = 7},
    HpackHuffmanCode{.Bits = 0x7ffe, .Length = 15},
    HpackHuffmanCode{.Bits = 0x7fc, .Length = 11},
    HpackHuffmanCode{.Bits = 0x3ffd, .Length = 14},
    HpackHuffmanCode{.Bits = 0x1ffd, .Length = 13},
    HpackHuffmanCode{.Bits = 0xffffffc, .Length = 28},
    HpackHuffmanCode{.Bits = 0xfffe6, .Length = 20},
    HpackHuffmanCode{.Bits = 0x3fffd2, .Length = 22},
    HpackHuffmanCode{.Bits = 0xfffe7, .Length = 20},
    HpackHuffmanCode{.Bits = 0xfffe8, .Length = 20},
    HpackHuffmanCode{.Bits = 0x3fffd3, .Length = 22},
    HpackHuffmanCode{.Bits = 0x3fffd4, .Length = 22},
    HpackHuffmanCode{.Bits = 0x3fffd5, .Length = 22},
    HpackHuffmanCode{.Bits = 0x7fffd9, .Length = 23},
    HpackHuffmanCode{.Bits = 0x3fffd6, .Length = 22},
    HpackHuffmanCode{.Bits = 0x7fffda, .Length = 23},
    HpackHuffmanCode{.Bits = 0x7fffdb, .Length = 23},
    HpackHuffmanCode{.Bits = 0x7fffdc, .Length = 23},
    HpackHuffmanCode{.Bits = 0x7fffdd, .Length = 23},
    HpackHuffmanCode{.Bits = 0x7fffde, .Length = 23},
    HpackHuffmanCode{.Bits = 0xffffeb, .Length = 24},
    HpackHuffmanCode{.Bits = 0x7fffdf, .Length = 23},
    HpackHuffmanCode{.Bits = 0xffffec, .Length = 24},
    HpackHuffmanCode{.Bits = 0xffffed, .Length = 24},
    HpackHuffmanCode{.Bits = 0x3fffd7, .Length = 22},
    HpackHuffmanCode{.Bits = 0x7fffe0, .Length = 23},
    HpackHuffmanCode{.Bits = 0xffffee, .Length = 24},
    HpackHuffmanCode{.Bits = 0x7fffe1, .Length = 23},
    HpackHuffmanCode{.Bits = 0x7fffe2, .Length = 23},
    HpackHuffmanCode{.Bits = 0x7fffe3, .Length = 23},
    HpackHuffmanCode{.Bits = 0x7fffe4, .Length = 23},
    HpackHuffmanCode{.Bits = 0x1fffdc, .Length = 21},
    HpackHuffmanCode{.Bits = 0x3fffd8, .Length = 22},
    HpackHuffmanCode{.Bits = 0x7fffe5, .Length = 23},
    HpackHuffmanCode{.Bits = 0x3fffd9, .Length = 22},
    HpackHuffmanCode{.Bits = 0x7fffe6, .Length = 23},
    HpackHuffmanCode{.Bits = 0x7fffe7, .Length = 23},
    HpackHuffmanCode{.Bits = 0xffffef, .Length = 24},
    HpackHuffmanCode{.Bits = 0x3fffda, .Length = 22},
    HpackHuffmanCode{.Bits = 0x1fffdd, .Length = 21},
    HpackHuffmanCode{.Bits = 0xfffe9, .Length = 20},
    HpackHuffmanCode{.Bits = 0x3fffdb, .Length = 22},
    HpackHuffmanCode{.Bits = 0x3fffdc, .Length = 22},
    HpackHuffmanCode{.Bits = 0x7fffe8, .Length = 23},
    HpackHuffmanCode{.Bits = 0x7fffe9, .Length = 23},
    HpackHuffmanCode{.Bits = 0x1fffde, .Length = 21},
    HpackHuffmanCode{.Bits = 0x7fffea, .Length = 23},
    HpackHuffmanCode{.Bits = 0x3fffdd, .Length = 22},
    HpackHuffmanCode{.Bits = 0x3fffde, .Length = 22},
    HpackHuffmanCode{.Bits = 0xfffff0, .Length = 24},
    HpackHuffmanCode{.Bits = 0x1fffdf, .Length = 21},
    HpackHuffmanCode{.Bits = 0x3fffdf, .Length = 22},
    HpackHuffmanCode{.Bits = 0x7fffeb, .Length = 23},
    HpackHuffmanCode{.Bits = 0x7fffec, .Length = 23},
    HpackHuffmanCode{.Bits = 0x1fffe0, .Length = 21},
    HpackHuffmanCode{.Bits = 0x1fffe1, .Length = 21},
    HpackHuffmanCode{.Bits = 0x3fffe0, .Length = 22},
    HpackHuffmanCode{.Bits = 0x1fffe2, .Length = 21},
    HpackHuffmanCode{.Bits = 0x7fffed, .Length = 23},
    HpackHuffmanCode{.Bits = 0x3fffe1, .Length = 22},
    HpackHuffmanCode{.Bits = 0x7fffee, .Length = 23},
    HpackHuffmanCode{.Bits = 0x7fffef, .Length = 23},
    HpackHuffmanCode{.Bits = 0xfffea, .Length = 20},
    HpackHuffmanCode{.Bits = 0x3fffe2, .Length = 22},
    HpackHuffmanCode{.Bits = 0x3fffe3, .Length = 22},
    HpackHuffmanCode{.Bits = 0x3fffe4, .Length = 22},
    HpackHuffmanCode{.Bits = 0x7ffff0, .Length = 23},
    HpackHuffmanCode{.Bits = 0x3fffe5, .Length = 22},
    HpackHuffmanCode{.Bits = 0x3fffe6, .Length = 22},
    HpackHuffmanCode{.Bits = 0x7ffff1, .Length = 23},
    HpackHuffmanCode{.Bits = 0x3ffffe0, .Length = 26},
    HpackHuffmanCode{.Bits = 0x3ffffe1, .Length = 26},
    HpackHuffmanCode{.Bits = 0xfffeb, .Length = 20},
    HpackHuffmanCode{.Bits = 0x7fff1, .Length = 19},
    HpackHuffmanCode{.Bits = 0x3fffe7, .Length = 22},
    HpackHuffmanCode{.Bits = 0x7ffff2, .Length = 23},
    HpackHuffmanCode{.Bits = 0x3fffe8, .Length = 22},
    HpackHuffmanCode{.Bits = 0x1ffffec, .Length = 25},
    HpackHuffmanCode{.Bits = 0x3ffffe2, .Length = 26},
    HpackHuffmanCode{.Bits = 0x3ffffe3, .Length = 26},
    HpackHuffmanCode{.Bits = 0x3ffffe4, .Length = 26},
    HpackHuffmanCode{.Bits = 0x7ffffde, .Length = 27},
    HpackHuffmanCode{.Bits = 0x7ffffdf, .Length = 27},
    HpackHuffmanCode{.Bits = 0x3ffffe5, .Length = 26},
    HpackHuffmanCode{.Bits = 0xfffff1, .Length = 24},
    HpackHuffmanCode{.Bits = 0x1ffffed, .Length = 25},
    HpackHuffmanCode{.Bits = 0x7fff2, .Length = 19},
    HpackHuffmanCode{.Bits = 0x1fffe3, .Length = 21},
    HpackHuffmanCode{.Bits = 0x3ffffe6, .Length = 26},
    HpackHuffmanCode{.Bits = 0x7ffffe0, .Length = 27},
    HpackHuffmanCode{.Bits = 0x7ffffe1, .Length = 27},
    HpackHuffmanCode{.Bits = 0x3ffffe7, .Length = 26},
    HpackHuffmanCode{.Bits = 0x7ffffe2, .Length = 27},
    HpackHuffmanCode{.Bits = 0xfffff2, .Length = 24},
    HpackHuffmanCode{.Bits = 0x1fffe4, .Length = 21},
    HpackHuffmanCode{.Bits = 0x1fffe5, .Length = 21},
    HpackHuffmanCode{.Bits = 0x3ffffe8, .Length = 26},
    HpackHuffmanCode{.Bits = 0x3ffffe9, .Length = 26},
    HpackHuffmanCode{.Bits = 0xffffffd, .Length = 28},
    HpackHuffmanCode{.Bits = 0x7ffffe3, .Length = 27},
    HpackHuffmanCode{.Bits = 0x7ffffe4, .Length = 27},
    HpackHuffmanCode{.Bits = 0x7ffffe5, .Length = 27},
    HpackHuffmanCode{.Bits = 0xfffec, .Length = 20},
    HpackHuffmanCode{.Bits = 0xfffff3, .Length = 24},
    HpackHuffmanCode{.Bits = 0xfffed, .Length = 20},
    HpackHuffmanCode{.Bits = 0x1fffe6, .Length = 21},
    HpackHuffmanCode{.Bits = 0x3fffe9, .Length = 22},
    HpackHuffmanCode{.Bits = 0x1fffe7, .Length = 21},
    HpackHuffmanCode{.Bits = 0x1fffe8, .Length = 21},
    HpackHuffmanCode{.Bits = 0x7ffff3, .Length = 23},
    HpackHuffmanCode{.Bits = 0x3fffea, .Length = 22},
    HpackHuffmanCode{.Bits = 0x3fffeb, .Length = 22},
    HpackHuffmanCode{.Bits = 0x1ffffee, .Length = 25},
    HpackHuffmanCode{.Bits = 0x1ffffef, .Length = 25},
    HpackHuffmanCode{.Bits = 0xfffff4, .Length = 24},
    HpackHuffmanCode{.Bits = 0xfffff5, .Length = 24},
    HpackHuffmanCode{.Bits = 0x3ffffea, .Length = 26},
    HpackHuffmanCode{.Bits = 0x7ffff4, .Length = 23},
    HpackHuffmanCode{.Bits = 0x3ffffeb, .Length = 26},
    HpackHuffmanCode{.Bits = 0x7ffffe6, .Length = 27},
    HpackHuffmanCode{.Bits = 0x3ffffec, .Length = 26},
    HpackHuffmanCode{.Bits = 0x3ffffed, .Length = 26},
    HpackHuffmanCode{.Bits = 0x7ffffe7, .Length = 27},
    HpackHuffmanCode{.Bits = 0x7ffffe8, .Length = 27},
    HpackHuffmanCode{.Bits = 0x7ffffe9, .Length = 27},
    HpackHuffmanCode{.Bits = 0x7ffffea, .Length = 27},
    HpackHuffmanCode{.Bits = 0x7ffffeb, .Length = 27},
    HpackHuffmanCode{.Bits = 0xffffffe, .Length = 28},
    HpackHuffmanCode{.Bits = 0x7ffffec, .Length = 27},
    HpackHuffmanCode{.Bits = 0x7ffffed, .Length = 27},
    HpackHuffmanCode{.Bits = 0x7ffffee, .Length = 27},
    HpackHuffmanCode{.Bits = 0x7ffffef, .Length = 27},
    HpackHuffmanCode{.Bits = 0x7fffff0, .Length = 27},
    HpackHuffmanCode{.Bits = 0x3ffffee, .Length = 26},
};

struct HpackStringField
{
    bool Huffman = false;
    std::size_t Offset = 0;
    std::size_t Length = 0;
};

std::optional<std::uint32_t> ReadHpackInteger(const std::vector<std::uint8_t>& data,
                                              std::size_t& offset,
                                              std::uint8_t prefixMask)
{
    if (offset >= data.size())
    {
        return std::nullopt;
    }

    std::uint32_t value = data[offset] & prefixMask;
    ++offset;
    if (value < prefixMask)
    {
        return value;
    }

    std::uint32_t shift = 0;
    while (offset < data.size())
    {
        const std::uint8_t byte = data[offset++];
        const std::uint32_t remainder = byte & 0x7f;
        if (shift >= std::numeric_limits<std::uint32_t>::digits ||
            remainder > (std::numeric_limits<std::uint32_t>::max() - value) >> shift)
        {
            return std::nullopt;
        }
        value += remainder << shift;
        if ((byte & 0x80) == 0)
        {
            return value;
        }
        shift += 7;
    }
    return std::nullopt;
}

std::optional<HpackStringField> ReadHpackStringField(const std::vector<std::uint8_t>& data,
                                                     std::size_t& offset)
{
    if (offset >= data.size())
    {
        return std::nullopt;
    }

    const bool huffman = (data[offset] & HpackHuffmanMask) != 0;
    const auto length = ReadHpackInteger(data, offset, HpackStringLengthPrefixMask);
    if (!length || *length > data.size() - offset)
    {
        return std::nullopt;
    }

    const HpackStringField field{
        .Huffman = huffman,
        .Offset = offset,
        .Length = *length,
    };
    offset += *length;
    return field;
}

std::optional<std::string> DecodeHpackString(const std::vector<std::uint8_t>& data,
                                             const HpackStringField& field)
{
    if (!field.Huffman)
    {
        return std::string(reinterpret_cast<const char*>(data.data() + field.Offset), field.Length);
    }

    std::string result;
    std::uint32_t code = 0;
    std::size_t codeLength = 0;
    const std::size_t endBit = (field.Offset + field.Length) * BitsPerByte;
    for (std::size_t bitOffset = field.Offset * BitsPerByte; bitOffset < endBit; ++bitOffset)
    {
        code =
            (code << 1) |
            ((data[bitOffset / BitsPerByte] >> (BitsPerByte - 1 - bitOffset % BitsPerByte)) & 0x01);
        ++codeLength;

        bool decoded = false;
        for (std::size_t symbol = 0; symbol < HpackHuffmanCodes.size(); ++symbol)
        {
            const auto& encodedSymbol = HpackHuffmanCodes[symbol];
            if (encodedSymbol.Length == codeLength && encodedSymbol.Bits == code)
            {
                result.push_back(static_cast<char>(symbol));
                code = 0;
                codeLength = 0;
                decoded = true;
                break;
            }
        }
        if (!decoded && codeLength == 30)
        {
            return std::nullopt;
        }
    }

    if (codeLength > MaximumHpackPaddingBits)
    {
        return std::nullopt;
    }
    const std::uint32_t expectedPadding =
        codeLength == 0 ? 0 : (std::uint32_t{1} << codeLength) - 1;
    if (code != expectedPadding)
    {
        return std::nullopt;
    }
    return result;
}

void AppendFrameHeader(std::vector<std::uint8_t>& out,
                       std::uint32_t length,
                       H2FrameType type,
                       std::uint8_t flags,
                       std::uint32_t streamId)
{
    out.push_back(static_cast<std::uint8_t>((length >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((length >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(length & 0xff));
    out.push_back(static_cast<std::uint8_t>(type));
    out.push_back(flags);
    out.push_back(static_cast<std::uint8_t>((streamId >> 24) & 0x7f));
    out.push_back(static_cast<std::uint8_t>((streamId >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((streamId >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(streamId & 0xff));
}

void AppendHpackIndexed(std::vector<std::uint8_t>& out, int index)
{
    if (index > 127)
    {
        throw std::runtime_error("HPACK indexed helper only supports small static indices.");
    }
    out.push_back(static_cast<std::uint8_t>(0x80 | index));
}

void AppendHpackLiteralIndexed(std::vector<std::uint8_t>& out,
                               int nameIndex,
                               const std::string& value)
{
    if (nameIndex > 63 || value.size() > 127)
    {
        throw std::runtime_error("HPACK literal helper only supports small fields.");
    }
    out.push_back(static_cast<std::uint8_t>(0x40 | nameIndex));
    out.push_back(static_cast<std::uint8_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void AppendHpackLiteralNew(std::vector<std::uint8_t>& out,
                           const std::string& name,
                           const std::string& value)
{
    if (name.size() > 127 || value.size() > 127)
    {
        throw std::runtime_error("HPACK literal helper only supports small fields.");
    }
    out.push_back(0x00);
    out.push_back(static_cast<std::uint8_t>(name.size()));
    out.insert(out.end(), name.begin(), name.end());
    out.push_back(static_cast<std::uint8_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

} // namespace

std::vector<std::uint8_t> BuildH2Preface(std::uint32_t initialWindowSize)
{
    const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    std::vector<std::uint8_t> out(preface.begin(), preface.end());
    AppendFrameHeader(out, 6, H2FrameType::Settings, 0, 0);
    out.push_back(static_cast<std::uint8_t>((H2SettingsInitialWindowSize >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(H2SettingsInitialWindowSize & 0xff));
    out.push_back(static_cast<std::uint8_t>((initialWindowSize >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((initialWindowSize >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((initialWindowSize >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(initialWindowSize & 0xff));
    return out;
}

std::vector<std::uint8_t> BuildH2SettingsAck()
{
    std::vector<std::uint8_t> out;
    AppendFrameHeader(out, 0, H2FrameType::Settings, H2FlagAck, 0);
    return out;
}

std::vector<std::uint8_t> BuildH2PingAck(const std::vector<std::uint8_t>& payload)
{
    constexpr std::size_t pingPayloadSize = 8;
    if (payload.size() != pingPayloadSize)
    {
        throw std::runtime_error("HTTP/2 PING payload must be 8 bytes.");
    }
    std::vector<std::uint8_t> out;
    AppendFrameHeader(out, pingPayloadSize, H2FrameType::Ping, H2FlagAck, 0);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<std::uint8_t> BuildH2WindowUpdate(std::uint32_t streamId, std::uint32_t increment)
{
    std::vector<std::uint8_t> out;
    AppendFrameHeader(out, 4, H2FrameType::WindowUpdate, 0, streamId);
    out.push_back(static_cast<std::uint8_t>((increment >> 24) & 0x7f));
    out.push_back(static_cast<std::uint8_t>((increment >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((increment >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(increment & 0xff));
    return out;
}

std::vector<std::uint8_t>
BuildH2Headers(const std::string& method,
               const std::string& path,
               const std::string& authority,
               const std::string& contentType,
               const std::vector<std::pair<std::string, std::string>>& extraHeaders,
               std::uint32_t streamId,
               bool endStream)
{
    std::vector<std::uint8_t> hpack;
    if (method == "POST")
    {
        AppendHpackIndexed(hpack, 3);
    }
    else if (method == "GET")
    {
        AppendHpackIndexed(hpack, 2);
    }
    else
    {
        AppendHpackLiteralIndexed(hpack, 2, method);
    }

    if (path == "/")
    {
        AppendHpackIndexed(hpack, 4);
    }
    else
    {
        AppendHpackLiteralIndexed(hpack, 4, path);
    }

    AppendHpackIndexed(hpack, 6);
    AppendHpackLiteralIndexed(hpack, 1, authority);
    AppendHpackLiteralIndexed(hpack, 31, contentType);
    for (const auto& header : extraHeaders)
    {
        AppendHpackLiteralNew(hpack, header.first, header.second);
    }

    std::vector<std::uint8_t> out;
    std::uint8_t flags = H2FlagEndHeaders;
    if (endStream)
    {
        flags |= H2FlagEndStream;
    }
    AppendFrameHeader(
        out, static_cast<std::uint32_t>(hpack.size()), H2FrameType::Headers, flags, streamId);
    out.insert(out.end(), hpack.begin(), hpack.end());
    return out;
}

std::vector<std::uint8_t>
BuildH2Data(const std::vector<std::uint8_t>& data, std::uint32_t streamId, bool endStream)
{
    std::vector<std::uint8_t> out;
    AppendFrameHeader(out,
                      static_cast<std::uint32_t>(data.size()),
                      H2FrameType::Data,
                      endStream ? H2FlagEndStream : 0,
                      streamId);
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

std::optional<H2Headers> H2HeaderDecoder::Decode(const std::vector<std::uint8_t>& headerBlock)
{
    const auto headerAt =
        [this](std::uint32_t index) -> std::optional<std::pair<std::string, std::string>>
    {
        if (index == 0)
        {
            return std::nullopt;
        }
        if (index < HpackStaticHeaders.size())
        {
            const auto& header = HpackStaticHeaders[index];
            return std::pair<std::string, std::string>{header.Name, header.Value};
        }

        const std::size_t dynamicIndex = index - HpackStaticHeaders.size();
        if (dynamicIndex >= m_dynamicTable.size())
        {
            return std::nullopt;
        }
        return m_dynamicTable[dynamicIndex];
    };
    const auto evictDynamicEntries = [this]()
    {
        while (m_dynamicTableSize > m_maximumDynamicTableSize && !m_dynamicTable.empty())
        {
            const auto& evicted = m_dynamicTable.back();
            m_dynamicTableSize -= evicted.first.size() + evicted.second.size() + HpackEntryOverhead;
            m_dynamicTable.pop_back();
        }
    };
    const auto addDynamicEntry =
        [this, &evictDynamicEntries](const std::string& name, const std::string& value)
    {
        const std::size_t entrySize = name.size() + value.size() + HpackEntryOverhead;
        if (entrySize > m_maximumDynamicTableSize)
        {
            m_dynamicTable.clear();
            m_dynamicTableSize = 0;
            return;
        }
        m_dynamicTable.emplace_front(name, value);
        m_dynamicTableSize += entrySize;
        evictDynamicEntries();
    };

    H2Headers result;
    std::size_t offset = 0;
    while (offset < headerBlock.size())
    {
        const std::uint8_t first = headerBlock[offset];
        if ((first & HpackIndexedMask) != 0)
        {
            const auto index = ReadHpackInteger(headerBlock, offset, HpackIndexedPrefixMask);
            if (!index)
            {
                return std::nullopt;
            }
            const auto header = headerAt(*index);
            if (!header)
            {
                return std::nullopt;
            }
            result.emplace(header->first, header->second);
            continue;
        }
        if ((first & HpackDynamicTableSizeUpdateMask) != 0 &&
            (first & HpackLiteralIncrementalMask) == 0)
        {
            const auto maximumSize =
                ReadHpackInteger(headerBlock, offset, HpackDynamicTableSizeUpdatePrefixMask);
            if (!maximumSize || *maximumSize > DefaultDynamicTableSize)
            {
                return std::nullopt;
            }
            m_maximumDynamicTableSize = *maximumSize;
            evictDynamicEntries();
            continue;
        }

        const bool addToDynamicTable = (first & HpackLiteralIncrementalMask) != 0;
        const std::uint8_t prefixMask =
            addToDynamicTable ? HpackLiteralIncrementalPrefixMask : HpackLiteralPrefixMask;
        const auto nameIndex = ReadHpackInteger(headerBlock, offset, prefixMask);
        if (!nameIndex)
        {
            return std::nullopt;
        }

        std::optional<std::string> name;
        if (*nameIndex == 0)
        {
            const auto nameField = ReadHpackStringField(headerBlock, offset);
            if (!nameField)
            {
                return std::nullopt;
            }
            name = DecodeHpackString(headerBlock, *nameField);
        }
        else
        {
            const auto indexedName = headerAt(*nameIndex);
            if (indexedName)
            {
                name = indexedName->first;
            }
        }

        const auto valueField = ReadHpackStringField(headerBlock, offset);
        if (!name || !valueField)
        {
            return std::nullopt;
        }
        const auto value = DecodeHpackString(headerBlock, *valueField);
        if (!value)
        {
            return std::nullopt;
        }
        const auto inserted = result.emplace(std::move(*name), std::move(*value));
        if (addToDynamicTable)
        {
            addDynamicEntry(inserted->first, inserted->second);
        }
    }
    return result;
}

std::optional<H2Headers> DecodeH2Headers(const std::vector<std::uint8_t>& headerBlock)
{
    H2HeaderDecoder decoder;
    return decoder.Decode(headerBlock);
}

std::optional<int> H2Status(const H2Headers& headers)
{
    const auto [begin, end] = headers.equal_range(":status");
    for (auto header = begin; header != end; ++header)
    {
        int status = 0;
        const auto parseResult = std::from_chars(
            header->second.data(), header->second.data() + header->second.size(), status);
        if (parseResult.ec == std::errc{} &&
            parseResult.ptr == header->second.data() + header->second.size() &&
            status >= MinimumHttpStatus && status <= MaximumHttpStatus)
        {
            return status;
        }
    }
    return std::nullopt;
}

std::optional<int> DecodeH2Status(const std::vector<std::uint8_t>& headerBlock)
{
    const auto headers = DecodeH2Headers(headerBlock);
    return headers ? H2Status(*headers) : std::nullopt;
}

std::vector<H2Frame> ParseH2Frames(const std::vector<std::uint8_t>& data)
{
    std::vector<std::uint8_t> copy = data;
    return TakeCompleteH2Frames(copy);
}

std::vector<H2Frame> TakeCompleteH2Frames(std::vector<std::uint8_t>& buffer)
{
    std::vector<H2Frame> frames;
    std::size_t offset = 0;
    while (offset + 9 <= buffer.size())
    {
        std::uint32_t length = (static_cast<std::uint32_t>(buffer[offset]) << 16) |
                               (static_cast<std::uint32_t>(buffer[offset + 1]) << 8) |
                               buffer[offset + 2];
        if (offset + 9 + length > buffer.size())
        {
            break;
        }

        H2Frame frame;
        frame.Length = length;
        frame.Type = static_cast<H2FrameType>(buffer[offset + 3]);
        frame.Flags = buffer[offset + 4];
        frame.StreamId = (static_cast<std::uint32_t>(buffer[offset + 5] & 0x7f) << 24) |
                         (static_cast<std::uint32_t>(buffer[offset + 6]) << 16) |
                         (static_cast<std::uint32_t>(buffer[offset + 7]) << 8) | buffer[offset + 8];
        frame.Payload.insert(frame.Payload.end(),
                             buffer.begin() + static_cast<std::ptrdiff_t>(offset + 9),
                             buffer.begin() + static_cast<std::ptrdiff_t>(offset + 9 + length));
        frames.push_back(std::move(frame));
        offset += 9 + length;
    }
    buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(offset));
    return frames;
}

} // namespace tailgate::control::base
