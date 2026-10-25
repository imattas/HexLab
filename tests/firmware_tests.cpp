#include "hexlab/firmware/firmware.hpp"
#include "support/checks.hpp"
#include <string>
#include <stop_token>

using namespace hexlab;
using namespace hexlab::firmware;

int main() {
    return hexlab_test::run([] {
        const auto ihex = parse_intel_hex(":020000040001F9\n:0400100001020304E2\n:00000001FF\n");
        hexlab_test::check(ihex && ihex.value().segments.size() == 1, "Intel HEX yields one segment");
        if (ihex) {
            hexlab_test::check(ihex.value().segments[0].address == 0x10010, "extended linear address applied");
            hexlab_test::check(ihex.value().segments[0].bytes.size() == 4, "Intel HEX data retained");
            hexlab_test::check(ihex.value().segments[0].provenance.line == 2, "source line provenance retained");
            hexlab_test::check(ihex.value().termination == Termination::eof, "Intel HEX EOF retained");
        }
        const auto bad_checksum = parse_intel_hex(":0100000000FE\n:00000001FF\n");
        hexlab_test::check(!bad_checksum && bad_checksum.error().code == ErrorCode::integrity, "bad Intel checksum rejected");
        const auto no_eof = parse_intel_hex(":0100000000FF\n");
        hexlab_test::check(!no_eof, "Intel HEX requires EOF");

        const auto srec = parse_s_record("S1061000010203E3\nS9031000EC\n");
        hexlab_test::check(srec && srec.value().segments.size() == 1, "S-record yields data segment");
        if (srec) {
            hexlab_test::check(srec.value().segments[0].address == 0x1000, "S-record address decoded");
            hexlab_test::check(srec.value().start_address == 0x1000, "S-record start address decoded");
            hexlab_test::check(srec.value().termination == Termination::start_record, "S-record termination retained");
        }
        const auto overlap = parse_intel_hex(":020000000102FB\n:0100010000FE\n:00000001FF\n");
        hexlab_test::check(!overlap && overlap.error().code == ErrorCode::conflict, "overlapping records rejected");
        ParseOptions limits; limits.max_data_bytes = 1;
        const auto over_limit = parse_intel_hex(":020000000102FB\n:00000001FF\n", limits);
        hexlab_test::check(!over_limit && over_limit.error().code == ErrorCode::resource_limit, "data limit enforced");
        ParseOptions record_limit; record_limit.max_records = 1;
        const auto too_many_records = parse_intel_hex(":0100000000FF\n:00000001FF\n", record_limit);
        hexlab_test::check(!too_many_records && too_many_records.error().code == ErrorCode::resource_limit, "record limit enforced");
        const auto after_eof = parse_intel_hex(":00000001FF\n:0100000000FF\n");
        hexlab_test::check(!after_eof && after_eof.error().message.find("line 2") != std::string::npos, "post-EOF error identifies line");
        std::stop_source cancelled; cancelled.request_stop();
        const auto stopped = parse_s_record("S1061000010203E3\nS9031000EC\n", {}, cancelled.get_token());
        hexlab_test::check(!stopped && stopped.error().code == ErrorCode::canceled, "cancellation honored");
    });
}
