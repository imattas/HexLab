#include "image_testing.hpp"
namespace hexlab::image_testing {
namespace {thread_local bool write_failure=false,publication_failure=false;}
void fail_next_write(){write_failure=true;}
void fail_next_publication(){publication_failure=true;}
bool take_write_failure(){bool value=write_failure;write_failure=false;return value;}
bool take_publication_failure(){bool value=publication_failure;publication_failure=false;return value;}
}
