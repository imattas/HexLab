#ifndef HEXLAB_PLUGIN_SDK_H
#define HEXLAB_PLUGIN_SDK_H

/* Public C-only entry point for native HexLab plugin modules. */
#include "hexlab/plugins/plugin_abi.h"

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
