#include "hexlab/image/image.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <limits>
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

using namespace hexlab;
using namespace hexlab_test;

void storage_tests() {
    FixtureFile empty({});
    auto empty_store = FileStorage::open(empty.path).value();
    check(empty_store->size() == 0 && empty_store->read_at({0}, 0).value().bytes.empty(), "empty mapping zero read");
    check(!empty_store->read_at({0}, 1), "empty read rejected");
    FixtureFile fixture(bytes({0x11,0x22,0x33,0x44}));
    auto storage = FileStorage::open(fixture.path).value();
    check(!storage->read_at({4}, 1), "past end storage read");
    check(!storage->read_at({UINT64_MAX}, 2), "overflowing storage range");
    auto view = storage->read_at({1}, 2).value();
    storage.reset();
    check(view.bytes[0] == std::byte{0x22} && view.bytes[1] == std::byte{0x33}, "view owns input lifetime");
#ifdef _WIN32
    auto writer = CreateFileW(fixture.path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    check(writer == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION, "view prevents external write and truncate");
    if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
    view = {};
    writer = CreateFileW(fixture.path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    check(writer != INVALID_HANDLE_VALUE, "last view releases native handles");
    if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
#endif
    check(FileStorage::open(fixture.path.parent_path()).error().code == ErrorCode::io, "directory is not input file");
    check(FileStorage::open(fixture.path.parent_path()/"absent.fixture").error().code == ErrorCode::io, "missing input diagnostic");
}
ImageLayout layout() {
    return {{{7},64,1,ByteOrder::little}, Architecture::x86_64,ExecutionMode::x86_64,
            {{"test",{{7},0x1000},4,{1},2,true,false,true}}, {}};
}
void mapping_tests() {
    FixtureFile fixture(bytes({0x11,0x22,0x33,0x44}));
    auto storage = FileStorage::open(fixture.path).value();
    auto image = Image::create(storage, layout()).value();
    check(image->read({{7},0x1000},4).value() == bytes({0x22,0x33,0,0}), "backing and zero fill");
    check(image->to_file_offset({{7},0x1001}).value() == FileOffset{2}, "VA to file offset");
    check(image->to_address({2}).value() == Address{{7},0x1001}, "file offset to VA");
    check(!image->to_file_offset({{7},0x1002}), "zero fill has no file offset");
    check(!image->read({{8},0x1000},1) && !image->read({{7},0x1004},1), "wrong space and gap rejected");
    check(!image->read({{7},0x1003},2), "read crossing gap rejected");
    auto bad = layout(); bad.segments[0].begin.offset = UINT64_MAX;
    check(!Image::create(storage,bad), "virtual extent overflow");
    bad = layout(); bad.segments[0].file_begin.value = UINT64_MAX;
    check(!Image::create(storage,bad), "file extent overflow");
    bad = layout(); bad.segments[0].file_size = 4;
    check(!Image::create(storage,bad), "backing outside input");
    bad = layout(); bad.segments.push_back({"overlap",{{7},0x1001},1,{0},1,true,false,false});
    check(!Image::create(storage,bad), "overlapping virtual ranges rejected");
    auto adjacent = layout(); adjacent.segments.push_back({"next",{{7},0x1004},2,{2},2,true,false,false});
    image = Image::create(storage,adjacent).value();
    check(image->read({{7},0x1002},4).value() == bytes({0,0,0x33,0x44}), "adjacent segment read");
    check(!image->to_address({2}), "aliased file offset is ambiguous");
    auto with_empty=layout(); with_empty.segments.push_back({"empty",{{7},0x1001},0,{0},0,true,false,false});
    image=Image::create(storage,with_empty).value();
    check(image->read({{7},0x1001},1).has_value(), "empty segment cannot shadow initialized mapping");
    bad=layout(); bad.space.width_bits=32; bad.segments[0].begin.offset=0x100000000ULL;
    check(!Image::create(storage,bad), "address width enforced");
    bad=layout(); bad.entries.push_back({{7},0x1005});
    check(!Image::create(storage,bad), "entry must be mapped");
}
int main() { return run([] { storage_tests(); mapping_tests(); }); }
