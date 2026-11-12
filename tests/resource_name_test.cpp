#include <pe-parse/parse.h>

#include <catch2/catch.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace peparse {

// Defined in parse.cpp; intentionally not part of the public header.
bool parse_resource_id(bounded_buffer *data,
                       std::uint32_t id,
                       std::string &result);

namespace {

struct test_buffer {
  std::vector<std::uint8_t> bytes;
  bounded_buffer *buf;

  explicit test_buffer(std::vector<std::uint8_t> b) : bytes(std::move(b)) {
    buf = makeBufferFromPointer(bytes.data(),
                                static_cast<std::uint32_t>(bytes.size()));
  }

  ~test_buffer() {
    deleteBuffer(buf);
  }
};

void append_u16(std::vector<std::uint8_t> &v, std::uint16_t w) {
  v.push_back(static_cast<std::uint8_t>(w & 0xff));
  v.push_back(static_cast<std::uint8_t>(w >> 8));
}

} // namespace

TEST_CASE("Resource name parsing", "[resource_name]") {
  SECTION("valid ASCII name") {
    std::vector<std::uint8_t> bytes;
    append_u16(bytes, 3);
    append_u16(bytes, 'A');
    append_u16(bytes, 'B');
    append_u16(bytes, 'C');

    test_buffer tb(bytes);
    std::string out;
    REQUIRE(parse_resource_id(tb.buf, 0, out));
    REQUIRE(out == "ABC");
  }

  SECTION("valid non-ASCII name converts to UTF-8") {
    std::vector<std::uint8_t> bytes;
    append_u16(bytes, 2);
    append_u16(bytes, 0x4e2d);
    append_u16(bytes, 0x6587);

    test_buffer tb(bytes);
    std::string out;
    REQUIRE(parse_resource_id(tb.buf, 0, out));
    REQUIRE(out == "\xe4\xb8\xad\xe6\x96\x87");
  }

  SECTION("name at a nonzero offset") {
    std::vector<std::uint8_t> bytes(10, 0xee);
    append_u16(bytes, 1);
    append_u16(bytes, 'X');

    test_buffer tb(bytes);
    std::string out;
    REQUIRE(parse_resource_id(tb.buf, 10, out));
    REQUIRE(out == "X");
  }

  SECTION("embedded NUL code unit is preserved") {
    std::vector<std::uint8_t> bytes;
    append_u16(bytes, 3);
    append_u16(bytes, 'A');
    append_u16(bytes, 0);
    append_u16(bytes, 'B');

    test_buffer tb(bytes);
    std::string out;
    REQUIRE(parse_resource_id(tb.buf, 0, out));
    REQUIRE(out == std::string("A\0B", 3));
  }

  SECTION("truncated surrogate pair is replaced") {
    std::vector<std::uint8_t> bytes;
    append_u16(bytes, 1);
    append_u16(bytes, 0xd800); // lone lead surrogate

    test_buffer tb(bytes);
    std::string out;
    REQUIRE(parse_resource_id(tb.buf, 0, out));
    REQUIRE(out == "\xef\xbf\xbd"); // U+FFFD
  }

  SECTION("complete surrogate pair converts") {
    std::vector<std::uint8_t> bytes;
    append_u16(bytes, 2);
    append_u16(bytes, 0xd83d);
    append_u16(bytes, 0xde00); // U+1F600

    test_buffer tb(bytes);
    std::string out;
    REQUIRE(parse_resource_id(tb.buf, 0, out));
    REQUIRE(out == "\xf0\x9f\x98\x80");
  }

  SECTION("zero length name") {
    std::vector<std::uint8_t> bytes;
    append_u16(bytes, 0);

    test_buffer tb(bytes);
    std::string out = "unchanged";
    REQUIRE(parse_resource_id(tb.buf, 0, out));
    REQUIRE(out.empty());
  }

  SECTION("trailing bytes are not treated as name content") {
    std::vector<std::uint8_t> bytes;
    append_u16(bytes, 1);
    append_u16(bytes, 'A');
    append_u16(bytes, 'B');
    append_u16(bytes, 'C');

    test_buffer tb(bytes);
    std::string out;
    REQUIRE(parse_resource_id(tb.buf, 0, out));
    REQUIRE(out == "A");
  }

  SECTION("declared length past end of buffer fails promptly") {
    std::vector<std::uint8_t> bytes;
    append_u16(bytes, 0xffff); // hostile length
    append_u16(bytes, 'A');

    test_buffer tb(bytes);
    std::string out;
    REQUIRE_FALSE(parse_resource_id(tb.buf, 0, out));
    REQUIRE(GetPEErr() != 0);
    REQUIRE(GetPEErrLoc().find("resource string offset=0x0") !=
            std::string::npos);
  }

  SECTION("declared length one unit too long fails") {
    std::vector<std::uint8_t> bytes;
    append_u16(bytes, 2);
    append_u16(bytes, 'A');

    test_buffer tb(bytes);
    std::string out;
    REQUIRE_FALSE(parse_resource_id(tb.buf, 0, out));
  }

  SECTION("failure carries the resource string offset") {
    std::vector<std::uint8_t> bytes(0x40, 0);
    append_u16(bytes, 0x100);

    test_buffer tb(bytes);
    std::string out;
    REQUIRE_FALSE(parse_resource_id(tb.buf, 0x40, out));
    REQUIRE(GetPEErrLoc().find("resource string offset=0x40") !=
            std::string::npos);
  }

  SECTION("missing length word fails") {
    test_buffer tb(std::vector<std::uint8_t>{0x01});
    std::string out;
    REQUIRE_FALSE(parse_resource_id(tb.buf, 0, out));
  }

  SECTION("null buffer fails") {
    std::string out;
    REQUIRE_FALSE(parse_resource_id(nullptr, 0, out));
  }
}

} // namespace peparse
