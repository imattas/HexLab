#pragma once
#include "hexlab/workspace/navigation.hpp"

namespace hexlab {
struct ListingRow {
    Location location;
    std::vector<std::byte> bytes;
    std::optional<Instruction> instruction;
    bool reachable=false;
    std::string status;
    // Produced with the row's source on the listing worker. Consumers must not
    // fall back to the decoder's unlinked displacement target.
    std::optional<Address> control_target;
};
struct ListingPage {std::vector<ListingRow> rows;std::optional<Location> next;};
struct ListingOptions {bool manual_decode=true;std::stop_token stop;};
struct ListingResult {Location begin;ListingPage page;};
struct ByteCell {
    std::byte value;
    std::optional<Address> address;
    std::optional<FileOffset> file_offset;
    bool initialized;
};
struct BytesPage {Location begin;std::vector<ByteCell> cells;std::optional<Location> next;};
HEXLAB_WORKSPACE_EXPORT Result<ListingPage> make_listing_page(const DocumentSnapshot&,Location,std::size_t row_limit=256);
HEXLAB_WORKSPACE_EXPORT Result<ListingPage> make_listing_page(const DocumentSnapshot&,Location,std::size_t,ListingOptions);
HEXLAB_WORKSPACE_EXPORT Result<BytesPage> make_bytes_page(const DocumentSnapshot&,Location,std::size_t byte_limit=256);
}
