#include "source_context_internal.hpp"
#include <algorithm>
namespace hexlab {
namespace {
struct Failed {
    Error error;
};
template <class T> T take(Result<T> value) {
    if (!value)
        throw Failed{value.error()};
    return std::move(value.value());
}
template <class F> Result<bool> guarded(F action) {
    try {
        return action();
    } catch (const Failed &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate source context binding"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Source context binding exceeds container bounds"};
    }
}
void check(bool condition, const char *message) {
    if (!condition)
        throw Failed{{ErrorCode::conflict, message}};
}
} // namespace
Result<bool> bind_derived_source(DerivedProposal &proposal, const Image &image, std::stop_token stop) {
    return guarded([&]() -> Result<bool> {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Source binding canceled"};
        const auto profile_count = image.layout().execution_profile ? image.layout().execution_profile->ranges.size() : 0;
        if (image.layout().domains.size() + profile_count + 1 > source_detail::domain_limit ||
            image.layout().domains.size() + profile_count + 1 > source_detail::domain_memory_limit / sizeof(DomainContext))
            return Error{ErrorCode::resource_limit, "Derived source domain binding exceeds its memory budget"};
        const auto primary_space = image.layout().space.id;
        std::vector<DomainContext> domains{{primary_space, image.decode_context(), {primary_space, 0}, 0}};
        domains.reserve(image.layout().domains.size() + 1);
        for (const auto &d : image.layout().domains) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "Source binding canceled"};
            domains.push_back({d.space.id, d.context, {d.space.id, 0}, 0});
        }
        if (image.layout().execution_profile)
            for (const auto &range : image.layout().execution_profile->ranges)
                domains.push_back({range.begin.space, range.context, range.begin, range.size});
        std::sort(domains.begin(), domains.end(),
                  [](const auto &a, const auto &b) {
                      if (a.space != b.space) return a.space.value < b.space.value;
                      if ((a.range_size == 0) != (b.range_size == 0)) return a.range_size == 0;
                      return a.range_begin.offset < b.range_begin.offset;
                  });
        for (const auto &d : domains)
            if (!source_detail::valid_context(d.context))
                return Error{ErrorCode::unsupported, "Invalid image domain context"};
        auto digest = take(image.mapping_fingerprint(stop));
        proposal.context = image.decode_context();
        proposal.domain_contexts = std::move(domains);
        proposal.mapping_fingerprint = digest;
        return true;
    });
}
Result<bool> validate_derived_source(const DerivedProposal &proposal, const Image &image, std::stop_token stop) {
    return guarded([&]() -> Result<bool> {
        DerivedProposal expected;
        take(bind_derived_source(expected, image, stop));
        check(proposal.context == expected.context, "Derived primary context differs from source image");
        check(proposal.mapping_fingerprint == expected.mapping_fingerprint,
              "Derived mapping fingerprint differs from source image");
        check(proposal.domain_contexts == expected.domain_contexts, "Derived domain contexts differ from source image");
        const auto fact = [&](const std::shared_ptr<const InstructionFact> &value) {
            if (stop.stop_requested())
                throw Failed{{ErrorCode::canceled, "Source fact validation canceled"}};
            check(bool(value), "Derived source contains a null instruction");
            check(take(image.context_at(value->instruction.address)) == value->instruction.context,
                  "Instruction domain context differs from authoritative image");
            check(image.code_window(value->instruction.address, value->instruction.length) == value->instruction.length,
                  "Instruction violates authoritative data/encryption policy");
        };
        if (proposal.functions) {
            for (const auto &i : proposal.functions->instructions)
                fact(i);
            for (const auto &b : proposal.functions->blocks) {
                check(bool(b), "Derived source contains a null block");
                for (const auto &i : b->instructions)
                    fact(i);
            }
            for (const auto &conflict : proposal.functions->conflicts) {
                if (conflict.first_fact)
                    fact(conflict.first_fact);
                if (conflict.second_fact)
                    fact(conflict.second_fact);
            }
        }
        return true;
    });
}
} // namespace hexlab
