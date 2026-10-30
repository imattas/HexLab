#ifndef HEXLAB_PLUGIN_SDK_H
#define HEXLAB_PLUGIN_SDK_H

/* Public C-only entry point for native HexLab plugin modules. */
#include "hexlab/plugins/plugin_abi.h"
#include <string.h>

/* Check an optional append-only ABI field without evaluating table more than
   once. The field's offset/size come from the caller's compile-time header;
   struct_size is copied from the runtime table and compared with overflow-safe
   arithmetic. All HexLab versioned tables expose struct_size at a fixed offset. */
static inline int hexlab_plugin_field_available(const void* table,
                                                size_t struct_size_offset,
                                                size_t field_offset,
                                                size_t field_size) {
    if (!table || struct_size_offset > (size_t)-1 - sizeof(uint32_t)) return 0;
    uint32_t available_size = 0;
    memcpy(&available_size, (const unsigned char*)table + struct_size_offset,
           sizeof(available_size));
    if ((size_t)available_size < field_offset) return 0;
    return field_size <= (size_t)available_size - field_offset;
}

#define HEXLAB_PLUGIN_HAS_FIELD(table_, table_type_, field_) \
    hexlab_plugin_field_available((table_), offsetof(table_type_, struct_size), \
                                  offsetof(table_type_, field_), \
                                  sizeof(((table_type_*)0)->field_))

#if defined(_WIN32)
#  define HEXLAB_PLUGIN_EXPORT __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#  define HEXLAB_PLUGIN_EXPORT __attribute__((visibility("default")))
#else
#  define HEXLAB_PLUGIN_EXPORT
#endif

#define HEXLAB_PLUGIN_API_INITIALIZER(id_, name_, version_, caps_, count_, start_, stop_) \
    { (uint32_t)sizeof(HexLabPluginApi), HEXLAB_PLUGIN_ABI_MAJOR, HEXLAB_PLUGIN_ABI_MINOR, \
      (id_), (name_), (version_), (caps_), (uint32_t)(count_), (start_), (stop_), 0, 0, 0, 0 }

#define HEXLAB_PLUGIN_API_INITIALIZER_V14(id_, name_, version_, caps_, count_, start_, stop_, declared_, declared_count_) \
    { (uint32_t)sizeof(HexLabPluginApi), HEXLAB_PLUGIN_ABI_MAJOR, HEXLAB_PLUGIN_ABI_MINOR, \
      (id_), (name_), (version_), (caps_), (uint32_t)(count_), (start_), (stop_), \
      (declared_), (uint32_t)(declared_count_), 0, 0 }

#define HEXLAB_PLUGIN_API_INITIALIZER_V15(id_, name_, version_, caps_, count_, start_, stop_, declared_, declared_count_) \
    HEXLAB_PLUGIN_API_INITIALIZER_V14(id_, name_, version_, caps_, count_, start_, stop_, declared_, declared_count_)

#define HEXLAB_CAPABILITY_INITIALIZER(id_, major_, minor_, flags_) \
    { (uint32_t)sizeof(HexLabCapability), (uint32_t)(major_), (uint32_t)(minor_), \
      (uint32_t)(flags_), (id_) }

#define HEXLAB_PLUGIN_API_INITIALIZER_V120(id_, name_, version_, caps_, count_, start_, stop_, \
                                            declared_, declared_count_, required_, required_count_) \
    { (uint32_t)sizeof(HexLabPluginApi), HEXLAB_PLUGIN_ABI_MAJOR, HEXLAB_PLUGIN_ABI_MINOR, \
      (id_), (name_), (version_), (caps_), (uint32_t)(count_), (start_), (stop_), \
      (declared_), (uint32_t)(declared_count_), (required_), (uint32_t)(required_count_) }

#endif
