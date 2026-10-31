enum class ArtifactEnum : int { ready = 5, done = -7 };

ArtifactEnum artifact_enum_value = ArtifactEnum::ready;
ArtifactEnum *artifact_enum_pointer = &artifact_enum_value;
int artifact_global_value = 17;

extern "C" __declspec(noinline) int artifact_entry(int parameter) {
    volatile int local_value = parameter + artifact_global_value;
    return local_value + static_cast<int>(artifact_enum_value);
}
