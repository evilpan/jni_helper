/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ART_RUNTIME_ART_METHOD_H_A
#define ART_RUNTIME_ART_METHOD_H_A

typedef unsigned int    uint32_t;
typedef unsigned short  uint16_t;

struct ArtMethod_5;
struct ArtMethod_6;
struct ArtMethod_7;
struct ArtMethod_8;
struct ArtMethod_9;
struct PtrSizedFields_5;
struct PtrSizedFields_6;
struct PtrSizedFields_7;
struct PtrSizedFields_8;
struct PtrSizedFields_9;

// 5.0
struct PtrSizedFields_5 {
    void* entry_point_from_interpreter_;
    void* entry_point_from_jni_;
    void* entry_point_from_quick_compiled_code_;
#if defined(ART_USE_PORTABLE_COMPILER)
    void* entry_point_from_portable_compiled_code_;
#endif
};

// 6.0
struct PtrSizedFields_6 {
    void* entry_point_from_interpreter_;
    void* entry_point_from_jni_;
    void* entry_point_from_quick_compiled_code_;
};

// 7.0
struct PtrSizedFields_7 {
    ArtMethod_7** dex_cache_resolved_methods_;
    void* dex_cache_resolved_types_;
    void* entry_point_from_jni_;
    void* entry_point_from_quick_compiled_code_;
};

// 8.0
struct PtrSizedFields_8 {
    ArtMethod_8** dex_cache_resolved_methods_;
    void* data_;
    void* entry_point_from_quick_compiled_code_;
} ptr_sized_fields_;

// 9.0
struct PtrSizedFields_9 {
    void* data_;
    void* entry_point_from_quick_compiled_code_;
};

struct ArtMethod_7 {
    uint32_t declaring_class_;
    uint32_t access_flags_;
    uint32_t dex_code_item_offset_;
    uint32_t dex_method_index_;
    uint16_t method_index_;
    uint16_t hotness_count_;
    struct PtrSizedFields_7 ptr_sized_fields_;
};
#endif  // ART_RUNTIME_ART_METHOD_H_A
