// MiniWorld PE SDK Analyzer - C++ standalone tool

#include <windows.h>
#include <commdlg.h>      // GetOpenFileNameW
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <chrono>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t  i64;

// RTTI 结构 (MSVC x64)
#pragma pack(push, 1)
struct TypeDescriptor {
    u64 pVFTable;     // +0x00 指向 type_info vftable
    u64 spare;        // +0x08 通常 NULL
    char name[];      // +0x10 类名 (".?AVClassName@@")
};

struct CompleteObjectLocator {
    u32 signature;        // +0x00 x64=1
    u32 offset;           // +0x04
    u32 cdOffset;         // +0x08
    u32 pTypeDescriptor;  // +0x0C RVA
    u32 pClassDescriptor; // +0x10 RVA
    u32 pSelf;            // +0x14 RVA to self
};

struct ClassHierarchyDescriptor {
    u32 signature;        // +0x00 always 0
    u32 attributes;       // +0x04
    u32 numBaseClasses;   // +0x08
    u32 pBaseClassArray;  // +0x0C RVA
};

struct BaseClassDescriptor {
    u32 pTypeDescriptor;   // +0x00 RVA
    u32 numContainedBases; // +0x04
    u32 mdisp;             // +0x08
    u32 pdisp;             // +0x0C
    u32 vdisp;             // +0x10
    u32 attributes;        // +0x14
};
#pragma pack(pop)

// 全局 PE 上下文
struct SectionInfo {
    u32 start_rva;
    u32 end_rva;
    u32 raw_offset;       // 文件偏移
    u32 raw_size;
    std::string name;
    bool is_executable;
    bool is_rdata;        // .rdata 或 .data
    const u8* data;       // 映射后的数据指针
};

static std::vector<SectionInfo> g_sections;
static u64 g_image_base = 0;
static const u8* g_pe_data = nullptr;
static size_t g_pe_size = 0;
static HANDLE g_file = NULL;
static HANDLE g_mapping = NULL;
static const u8* g_view = nullptr;

// 工具函数
static const SectionInfo* rva_to_section(u32 rva) {
    for (const auto& s : g_sections) {
        if (rva >= s.start_rva && rva < s.end_rva) return &s;
    }
    return nullptr;
}

static const u8* rva_to_ptr(u32 rva) {
    const SectionInfo* s = rva_to_section(rva);
    if (!s) return nullptr;
    u32 off = rva - s->start_rva;
    if (off >= s->raw_size) return nullptr;
    return s->data + off;
}

static bool read_dword(u32 rva, u32* out) {
    const u8* p = rva_to_ptr(rva);
    if (!p) return false;
    *out = *(const u32*)p;
    return true;
}

static bool read_qword(u32 rva, u64* out) {
    const u8* p = rva_to_ptr(rva);
    if (!p) return false;
    *out = *(const u64*)p;
    return true;
}

static std::string read_cstr(u32 rva, size_t max_len = 512) {
    const char* p = (const char*)rva_to_ptr(rva);
    if (!p) return "";
    const char* end = (const char*)memchr(p, 0, max_len);
    if (!end) end = p + max_len;
    return std::string(p, end);
}

static bool is_executable_rva(u32 rva) {
    const SectionInfo* s = rva_to_section(rva);
    if (!s) return false;
    return s->is_executable;
}

static bool is_rdata_rva(u32 rva) {
    const SectionInfo* s = rva_to_section(rva);
    if (!s) return false;
    return s->is_rdata;
}

// PE 加载
static bool load_pe(const wchar_t* path) {
    g_file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_file == INVALID_HANDLE_VALUE) {
        printf("错误: 无法打开文件 (GetLastError=%lu)\n", GetLastError());
        return false;
    }

    g_mapping = CreateFileMappingW(g_file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!g_mapping) {
        printf("错误: CreateFileMapping 失败\n");
        CloseHandle(g_file);
        return false;
    }

    g_view = (const u8*)MapViewOfFile(g_mapping, FILE_MAP_READ, 0, 0, 0);
    if (!g_view) {
        printf("错误: MapViewOfFile 失败\n");
        CloseHandle(g_mapping);
        CloseHandle(g_file);
        return false;
    }

    g_pe_data = g_view;
    g_pe_size = GetFileSize(g_file, nullptr);

    // 解析 DOS 头
    if (g_pe_size < sizeof(IMAGE_DOS_HEADER)) {
        printf("错误: 文件太小, 不是有效 PE\n");
        return false;
    }
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)g_view;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("错误: 无效 DOS 签名\n");
        return false;
    }

    // 解析 NT 头
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(g_view + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("错误: 无效 PE 签名\n");
        return false;
    }
    g_image_base = nt->OptionalHeader.ImageBase;

    // 解析段表
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    u16 num_sections = nt->FileHeader.NumberOfSections;

    g_sections.clear();
    g_sections.reserve(num_sections);
    for (u16 i = 0; i < num_sections; i++) {
        SectionInfo s;
        s.start_rva = sec[i].VirtualAddress;
        s.end_rva = s.start_rva + sec[i].Misc.VirtualSize;
        s.raw_offset = sec[i].PointerToRawData;
        s.raw_size = sec[i].SizeOfRawData;
        s.name.assign((const char*)sec[i].Name, strnlen((const char*)sec[i].Name, 8));
        s.is_executable = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        s.is_rdata = (s.name.find(".rdata") != std::string::npos ||
                      s.name.find(".data") != std::string::npos);
        s.data = g_view + s.raw_offset;
        g_sections.push_back(std::move(s));
    }

    return true;
}

static void unload_pe() {
    if (g_view) { UnmapViewOfFile(g_view); g_view = nullptr; }
    if (g_mapping) { CloseHandle(g_mapping); g_mapping = NULL; }
    if (g_file != INVALID_HANDLE_VALUE && g_file) { CloseHandle(g_file); g_file = NULL; }
}

// ============== RTTI 扫描 ==============
struct TypeDesc {
    u32 rva;
    std::string name;
    std::string section;
};

struct VtableFunc {
    u32 rva;
    u64 ea;
};

struct Vtable {
    std::string class_name;
    u32 vtable_rva;
    u32 col_rva;
    size_t nfunc;
    std::vector<VtableFunc> funcs;
    std::vector<std::string> bases;  // 继承链
};

// 扫描 TypeDescriptor
static void scan_type_descriptors(std::unordered_map<u32, TypeDesc>& out) {
    printf("  扫描 TypeDescriptor...\n");
    for (const auto& sec : g_sections) {
        if (!sec.is_rdata) continue;
        if (sec.raw_size < 0x20) continue;
        const u8* data = sec.data;
        size_t size = sec.raw_size;
        // TypeDescriptor: 24 字节头 + 变长 name
        // 特征: spare(8 字节)=0 + name 以 ".?A" 开头
        for (size_t off = 0; off + 19 < size; off += 8) {
            // 检查 spare 是否为 0
            u64 spare = *(const u64*)(data + off + 8);
            if (spare != 0) continue;
            // 检查 name 是否以 ".?A" 开头 (name 在 +0x10 = 16)
            if (off + 16 + 3 >= size) continue;
            if (memcmp(data + off + 16, ".?A", 3) != 0) continue;
            // 读类名
            const char* name_start = (const char*)(data + off + 16);
            const char* name_end = (const char*)memchr(name_start, 0, 512);
            if (!name_end || name_end - name_start > 512) continue;
            std::string name(name_start, name_end);
            u32 rva = sec.start_rva + (u32)off;
            TypeDesc td;
            td.rva = rva;
            td.name = name;
            td.section = sec.name;
            out[rva] = std::move(td);
        }
    }
    printf("  TypeDescriptor 找到: %zu\n", out.size());
}

// 扫描 CompleteObjectLocator (x64)
static void scan_cols(std::unordered_map<u32, u32>& out) {
    // out: col_rva -> td_rva
    printf("  扫描 CompleteObjectLocator...\n");
    for (const auto& sec : g_sections) {
        if (sec.name.find(".rdata") == std::string::npos) continue;
        const u8* data = sec.data;
        size_t size = sec.raw_size;
        // COL: 24 字节, 4 字节对齐
        // 特征: signature=1 + pSelf == 自身 RVA
        for (size_t off = 0; off + sizeof(CompleteObjectLocator) <= size; off += 4) {
            const CompleteObjectLocator* col = (const CompleteObjectLocator*)(data + off);
            // signature 必须是 1 (x64)
            if (col->signature != 1) continue;
            // offset 和 cdOffset 通常为 0
            if (col->offset > 0x1000 || col->cdOffset > 0x1000) continue;
            // pSelf 必须等于自身 RVA
            u32 col_rva = sec.start_rva + (u32)off;
            if (col->pSelf != col_rva) continue;
            // pTD 和 pCHD 必须是有效 RVA
            if (col->pTypeDescriptor == 0 || col->pClassDescriptor == 0) continue;
            out[col_rva] = col->pTypeDescriptor;
        }
    }
    printf("  CompleteObjectLocator 找到: %zu\n", out.size());
}

// 解析继承链
static std::vector<std::string> parse_inheritance(u32 chd_rva,
        const std::unordered_map<u32, TypeDesc>& tds) {
    std::vector<std::string> bases;
    u32 sig, num_bases, pBCA;
    if (!read_dword(chd_rva, &sig) || sig != 0) return bases;
    if (!read_dword(chd_rva + 8, &num_bases)) return bases;
    if (num_bases == 0 || num_bases > 64) return bases;
    if (!read_dword(chd_rva + 12, &pBCA)) return bases;
    if (!is_rdata_rva(pBCA)) return bases;

    for (u32 i = 0; i < num_bases; i++) {
        u32 pBCD_rva;
        if (!read_dword(pBCA + i * 4, &pBCD_rva)) break;
        if (!is_rdata_rva(pBCD_rva)) continue;
        // 读 BaseClassDescriptor 的 pTypeDescriptor
        u32 bcd_td;
        if (!read_dword(pBCD_rva, &bcd_td)) continue;
        auto it = tds.find(bcd_td);
        if (it != tds.end()) {
            bases.push_back(it->second.name);
        } else {
            // 尝试直接读
            std::string name = read_cstr(bcd_td + 16);
            if (!name.empty() && name.find(".?A") == 0) bases.push_back(name);
        }
    }
    return bases;
}

// 找 vtable: 找指向 COL 的 QWORD 指针, 其后是 vtable
static u32 find_vtable_for_col(u32 col_rva) {
    u64 col_va = g_image_base + col_rva;
    // 在 .rdata 段中搜指向 COL 的 QWORD
    for (const auto& sec : g_sections) {
        if (sec.name.find(".rdata") == std::string::npos) continue;
        const u8* data = sec.data;
        size_t size = sec.raw_size;
        const u8* target = (const u8*)&col_va;
        // 搜索 8 字节模式
        for (size_t off = 0; off + 16 <= size; off += 8) {
            if (memcmp(data + off, target, 8) != 0) continue;
            // off 处是指向 COL 的指针, vtable[0] 在 off+8
            u32 vtable_rva = sec.start_rva + (u32)off + 8;
            // 验证: vtable[0] 应该是可执行地址
            u64 first_func;
            if (read_qword(vtable_rva, &first_func)) {
                u32 func_rva = (u32)(first_func - g_image_base);
                if (is_executable_rva(func_rva)) return vtable_rva;
            }
        }
    }
    return 0;
}

// 扫描 vtable 函数指针
static std::vector<VtableFunc> scan_vtable_functions(u32 vtable_rva, size_t max_funcs = 512) {
    std::vector<VtableFunc> funcs;
    funcs.reserve(64);
    for (size_t i = 0; i < max_funcs; i++) {
        u64 func_ptr;
        if (!read_qword(vtable_rva + (u32)(i * 8), &func_ptr)) break;
        u32 func_rva = (u32)(func_ptr - g_image_base);
        if (!is_executable_rva(func_rva)) break;
        VtableFunc f;
        f.rva = func_rva;
        f.ea = func_ptr;
        funcs.push_back(f);
    }
    return funcs;
}

// 去掉 MSVC RTTI 前缀, 返回纯 mangled name
//   ".?AVVFW_Awaken@ActorFrostWyrm@@" -> "VFW_Awaken@ActorFrostWyrm"
static std::string strip_rtti_prefix(const std::string& raw) {
    std::string s = raw;
    // 去前缀 .?AV / .?AU / .?AW  (class / union / enum)
    size_t pos = s.find(".?AV");
    if (pos == std::string::npos) pos = s.find(".?AU");
    if (pos == std::string::npos) pos = s.find(".?AW4");
    if (pos != std::string::npos) {
        if (raw.compare(pos, 4, ".?AW4") == 0) s = s.substr(pos + 5);
        else s = s.substr(pos + 4);
    }
    // 去后缀 @@ (尾部)
    if (s.size() >= 2 && s.compare(s.size() - 2, 2, "@@") == 0) {
        s = s.substr(0, s.size() - 2);
    }
    return s;
}

// 解析 MSVC RTTI name -> "Namespace::Class" 格式
//   "VFW_Awaken@ActorFrostWyrm"     -> "ActorFrostWyrm::VFW_Awaken"
//   "vector@V@V@allocator@V@@@@std" -> 模板, 内部 @ 视为参数分隔, 简化处理
static std::string sanitize_class_name(const std::string& raw) {
    std::string mangled = strip_rtti_prefix(raw);
    if (mangled.empty()) return "Unknown";

    // 模板实例: 名字以 "?$" 开头表示是模板特化, 模板参数内 @ 不可作为命名空间分隔
    // 例: "?$vector@V@V@@std" -> std::vector<...>
    // 简化策略: 找到第一个 "?$", 取其前的名字, 然后整体视为模板名
    // 非模板: 按 @ 分割, 反序连接
    std::vector<std::string> parts;
    bool is_template = (mangled.find("?$") != std::string::npos);

    if (is_template) {
        // 模板: 找到 "?$" 位置, 之前是模板名, 之后整体视为参数
        size_t qpos = mangled.find("?$");
        std::string tmpl_name = mangled.substr(0, qpos);
        std::string rest = mangled.substr(qpos + 2);  // 去掉 "?$"
        // rest 末尾可能有多余 @, 去掉
        while (!rest.empty() && rest.back() == '@') rest.pop_back();

        // rest 按 @ 分割成参数 (简化, 不再展开嵌套模板)
        std::vector<std::string> ns_parts;
        std::string cur;
        // 用状态机处理, 简单按 @ 分割
        for (char c : rest) {
            if (c == '@') { if (!cur.empty()) { ns_parts.push_back(cur); cur.clear(); } }
            else cur += c;
        }
        if (!cur.empty()) ns_parts.push_back(cur);

        // 模板名按 @ 分割 (VFW_Awaken@ActorFrostWyrm -> ["VFW_Awaken", "ActorFrostWyrm"])
        std::vector<std::string> name_parts;
        std::string nc;
        for (char c : tmpl_name) {
            if (c == '@') { if (!nc.empty()) { name_parts.push_back(nc); nc.clear(); } }
            else nc += c;
        }
        if (!nc.empty()) name_parts.push_back(nc);

        // 命名空间部分: ns_parts 中最后一项通常是模板名所在命名空间
        // 实际 MSVC mangling 较复杂, 这里简化:
        // 把 name_parts 反序作为命名空间前缀, 模板参数附在末尾
        std::reverse(name_parts.begin(), name_parts.end());
        std::string result;
        for (size_t i = 0; i < name_parts.size(); i++) {
            if (i) result += "::";
            result += name_parts[i];
        }
        if (!ns_parts.empty()) {
            result += "<";
            for (size_t i = 0; i < ns_parts.size(); i++) {
                if (i) result += ", ";
                // 每个参数清理一下: 去前缀等
                std::string p = ns_parts[i];
                // 不展开嵌套, 直接用
                std::string cleaned;
                for (char c : p) {
                    if (isalnum((u8)c) || c == '_' || c == ':') cleaned += c;
                    else cleaned += '_';
                }
                result += cleaned;
            }
            result += ">";
        }
        // 清理非法字符
        std::string out;
        for (char c : result) {
            if (isalnum((u8)c) || c == '_' || c == ':') out += c;
            else out += '_';
        }
        if (!out.empty() && isdigit((u8)out[0])) out = "_" + out;
        return out;
    }

    // 非模板: 按 @ 分割, 反序, 用 :: 连接
    std::string cur;
    for (char c : mangled) {
        if (c == '@') { if (!cur.empty()) { parts.push_back(cur); cur.clear(); } }
        else cur += c;
    }
    if (!cur.empty()) parts.push_back(cur);

    std::reverse(parts.begin(), parts.end());
    std::string out;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i) out += "::";
        // 清理非法字符
        for (char c : parts[i]) {
            if (isalnum((u8)c) || c == '_') out += c;
            else if (c == ':') out += '_';
            else out += '_';
        }
    }
    if (out.empty()) out = "Unknown";
    if (isdigit((u8)out[0])) out = "_" + out;
    return out;
}

// 把 "Namespace::Class" 转成 C 合法标识符 "Namespace__Class"
static std::string to_c_ident(const std::string& name) {
    std::string out;
    for (char c : name) {
        if (isalnum((u8)c) || c == '_') out += c;
        else if (c == ':') out += "__";  // :: -> __
        else out += '_';
    }
    // 压缩连续下划线
    std::string final;
    bool prev_us = false;
    for (char c : out) {
        if (c == '_') {
            if (!prev_us) { final += c; prev_us = true; }
        } else {
            final += c; prev_us = false;
        }
    }
    if (!final.empty() && isdigit((u8)final[0])) final = "_" + final;
    return final;
}

// ============== 主分析 ==============
struct AnalysisResult {
    size_t type_descriptors = 0;
    size_t complete_object_locators = 0;
    size_t vtables_found = 0;
    size_t inheritance_chains = 0;
    size_t no_vtable_count = 0;
    std::vector<Vtable> vtables;
    std::unordered_map<std::string, std::vector<std::string>> inheritance_map;
};

static bool analyze(AnalysisResult& result) {
    auto t0 = std::chrono::steady_clock::now();

    printf("=== PE RTTI 分析 ===\n");
    printf("  ImageBase: 0x%llX\n", (unsigned long long)g_image_base);
    printf("  Sections:\n");
    for (const auto& s : g_sections) {
        printf("    %-8s  RVA=0x%X-0x%X  size=0x%X  %s%s\n",
               s.name.c_str(), s.start_rva, s.end_rva, s.raw_size,
               s.is_executable ? " [X]" : "",
               s.is_rdata ? " [R]" : "");
    }
    printf("\n");

    // 1. 扫描 TypeDescriptor
    std::unordered_map<u32, TypeDesc> tds;
    scan_type_descriptors(tds);
    result.type_descriptors = tds.size();
    if (tds.empty()) {
        printf("错误: 未找到 TypeDescriptor, RTTI 可能被移除\n");
        return false;
    }

    // 2. 扫描 CompleteObjectLocator
    std::unordered_map<u32, u32> cols;  // col_rva -> td_rva
    scan_cols(cols);
    result.complete_object_locators = cols.size();
    if (cols.empty()) {
        printf("错误: 未找到 CompleteObjectLocator\n");
        return false;
    }

    // 3. 对每个 COL, 找 vtable + 继承链
    printf("  重建 vtable...\n");
    result.vtables.reserve(cols.size());
    for (const auto& [col_rva, td_rva] : cols) {
        // 获取类名
        std::string class_name;
        auto it = tds.find(td_rva);
        if (it != tds.end()) {
            class_name = it->second.name;
        } else {
            class_name = read_cstr(td_rva + 16);
            if (class_name.empty()) class_name = "Unknown_" + std::to_string(td_rva);
        }

        // 解析继承链 (需要先读 COL 的 pClassDescriptor)
        u32 chd_rva = 0;
        const u8* col_ptr = rva_to_ptr(col_rva);
        if (col_ptr) {
            const CompleteObjectLocator* col = (const CompleteObjectLocator*)col_ptr;
            chd_rva = col->pClassDescriptor;
        }
        std::vector<std::string> bases;
        if (chd_rva) {
            bases = parse_inheritance(chd_rva, tds);
        }

        Vtable vt;
        vt.class_name = class_name;
        vt.col_rva = col_rva;
        vt.bases = bases;
        if (!bases.empty()) {
            result.inheritance_map[class_name] = bases;
            result.inheritance_chains++;
        }

        // 找 vtable
        u32 vt_rva = find_vtable_for_col(col_rva);
        if (vt_rva == 0) {
            result.no_vtable_count++;
            continue;
        }
        vt.vtable_rva = vt_rva;
        vt.funcs = scan_vtable_functions(vt_rva);
        vt.nfunc = vt.funcs.size();
        result.vtables.push_back(std::move(vt));
    }
    result.vtables_found = result.vtables.size();

    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    printf("\n=== 分析结果 ===\n");
    printf("  TypeDescriptor: %zu\n", result.type_descriptors);
    printf("  CompleteObjectLocator: %zu\n", result.complete_object_locators);
    printf("  vtable 重建: %zu\n", result.vtables_found);
    printf("  继承链: %zu\n", result.inheritance_chains);
    printf("  无 vtable 的 COL: %zu\n", result.no_vtable_count);
    printf("  耗时: %.1f ms\n", ms);
    return true;
}

// SDK 头文件生成

// 分类定义
struct CatDef {
    const char* name;
    std::vector<const char*> keywords;
};

static const std::vector<CatDef>& get_cat_defs() {
    static const std::vector<CatDef> cat_defs = {
        {"Attack",   {"Attack", "Atk", "Damage", "Hit", "Weapon", "Arrow", "Bullet", "Projectile"}},
        {"Boss",     {"Boss", "MiniBoss", "BossGroup", "FrostWyrm", "Dragon"}},
        {"Player",   {"Player", "Actor", "Pawn", "Character", "ClientActor", "Mob", "Npc"}},
        {"AI",       {"AI", "Brain", "Behavior", "BTNode", "BehaviorTree"}},
        {"Timeline", {"Timeline", "Track", "Sequence", "Playable", "Animation"}},
        {"Rainbow",  {"Rainbow", "Skin", "Shop", "Item", "Inventory", "Equip"}},
    };
    return cat_defs;
}

// 根据类名分类
static std::string classify(const std::string& raw_name) {
    std::string name = sanitize_class_name(raw_name);
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (const auto& cat : get_cat_defs()) {
        for (const char* kw : cat.keywords) {
            std::string lk = kw;
            std::transform(lk.begin(), lk.end(), lk.begin(), ::tolower);
            if (lower.find(lk) != std::string::npos) return cat.name;
        }
    }
    return "Misc";
}

// 生成各分类的顺序
static const std::vector<std::string>& get_cat_order() {
    static const std::vector<std::string> cat_order = {
        "Attack", "Boss", "Player", "AI", "Timeline", "Rainbow", "Misc"
    };
    return cat_order;
}

// 生成继承链头文件 MiniWorld_SDK_Inheritance.h
static void generate_inheritance_header(const AnalysisResult& result, const std::string& out_path) {
    std::ofstream f(out_path, std::ios::binary);
    if (!f) {
        printf("错误: 无法创建继承链文件 %s\n", out_path.c_str());
        return;
    }
    f << "// MiniWorld SDK - Inheritance Chains (PE RTTI Reconstructed)\n";
    f << "// Total chains: " << result.inheritance_chains << "\n";
    f << "#pragma once\n\n";
    f << "namespace MiniWorld {\n\n";
    f << "// ============ Inheritance Chains ============\n";
    for (const auto& [cls, bases] : result.inheritance_map) {
        std::string cn = sanitize_class_name(cls);
        f << "// chain: " << cn;
        f << " -> ";
        for (size_t i = 0; i < bases.size(); i++) {
            if (i) f << " -> ";
            f << sanitize_class_name(bases[i]);
        }
        f << "\n";
        f << "// struct " << to_c_ident(cn) << " : ";
        for (size_t i = 0; i < bases.size(); i++) {
            if (i) f << ", ";
            f << to_c_ident(sanitize_class_name(bases[i]));
        }
        f << "\n";
    }
    f << "\n} // namespace MiniWorld\n";
}

// 生成单个分类的头文件 MiniWorld_SDK_<Cat>.h
static void generate_category_header(const AnalysisResult& result,
                                     const std::string& cat_name,
                                     const std::vector<const Vtable*>& vts,
                                     const std::string& out_path) {
    std::ofstream f(out_path, std::ios::binary);
    if (!f) {
        printf("错误: 无法创建文件 %s\n", out_path.c_str());
        return;
    }

    size_t total_funcs = 0;
    for (const Vtable* vt : vts) total_funcs += vt->nfunc;

    f << "// MiniWorld SDK - " << cat_name << " Classes (PE RTTI Reconstructed)\n";
    f << "// Classes: " << vts.size() << "  Vfuncs: " << total_funcs << "\n";
    f << "#pragma once\n";
    f << "#include \"MiniWorld_SDK.h\"\n";
    f << "#include \"MiniWorld_SDK_Inheritance.h\"\n\n";
    f << "namespace MiniWorld {\n";
    f << "namespace " << cat_name << " {\n\n";

    for (const Vtable* vt : vts) {
        std::string cn = sanitize_class_name(vt->class_name);
        std::string safe = to_c_ident(cn);
        f << "// Class: " << cn << "\n";
        f << "// vtable RVA: 0x" << std::hex << vt->vtable_rva << std::dec
          << "  funcs: " << vt->nfunc << "\n";
        if (!vt->bases.empty()) {
            f << "// Inheritance: " << cn << " -> ";
            for (size_t i = 0; i < vt->bases.size(); i++) {
                if (i) f << " -> ";
                f << sanitize_class_name(vt->bases[i]);
            }
            f << "\n";
        }
        f << "struct " << safe << "_VTable {\n";
        f << "    void* __rtti_col;  // vtable[-1]\n";
        for (size_t i = 0; i < vt->funcs.size(); i++) {
            const VtableFunc& vf = vt->funcs[i];
            char fn_name[64];
            snprintf(fn_name, sizeof(fn_name), "sub_%llX", (unsigned long long)vf.ea);
            f << "    // [" << i << "] " << fn_name
              << "  RVA 0x" << std::hex << vf.rva
              << "  EA 0x" << vf.ea << std::dec << "\n";
            char buf[256];
            snprintf(buf, sizeof(buf),
                     "    void* vfunc_%zu;   // +0x%zX  sig: __int64 __fastcall()\n",
                     i, i * 8);
            f << buf;
        }
        f << "};\n\n";
    }

    f << "} // namespace " << cat_name << "\n";
    f << "} // namespace MiniWorld\n";
}

// 生成主头文件 MiniWorld_SDK.h (include 所有分类)
static void generate_main_header(const AnalysisResult& result,
                                 const std::unordered_map<std::string, std::vector<const Vtable*>>& categorized,
                                 const std::string& out_path) {
    std::ofstream f(out_path, std::ios::binary);
    if (!f) {
        printf("错误: 无法创建主头文件 %s\n", out_path.c_str());
        return;
    }

    size_t total_funcs = 0;
    for (const auto& vt : result.vtables) total_funcs += vt.nfunc;

    f << "// MiniWorld SDK (PE RTTI Reconstructed) - C++ Standalone Tool\n";
    f << "// No IDA Required, No Python Required\n";
    f << "// TypeDescriptors: " << result.type_descriptors << "\n";
    f << "// CompleteObjectLocators: " << result.complete_object_locators << "\n";
    f << "// vtables rebuilt: " << result.vtables_found << "\n";
    f << "// Inheritance chains: " << result.inheritance_chains << "\n";
    f << "// Total vfuncs: " << total_funcs << "\n";
    f << "#pragma once\n\n";
    f << "// Auto-generated by mw-pe-sdk.exe (PE RTTI analyzer)\n";
    f << "// Include this file to access all SDK categories.\n\n";

    for (const std::string& cat : get_cat_order()) {
        auto it = categorized.find(cat);
        if (it == categorized.end() || it->second.empty()) continue;
        f << "#include \"MiniWorld_SDK_" << cat << ".h\"\n";
    }
    f << "\nnamespace MiniWorld {\n";
    f << "// Total: " << result.vtables_found << " classes, " << total_funcs << " vfuncs\n";
    f << "} // namespace MiniWorld\n";
}

//生成文件 SDK
static void generate_sdk_header(const AnalysisResult& result, const std::string& out_dir) {
    //按分类分组
    std::unordered_map<std::string, std::vector<const Vtable*>> categorized;
    for (const auto& vt : result.vtables) {
        categorized[classify(vt.class_name)].push_back(&vt);
    }

    //分类排序
    for (auto& [cat, vts] : categorized) {
        std::sort(vts.begin(), vts.end(), [](const Vtable* a, const Vtable* b) {
            return sanitize_class_name(a->class_name) < sanitize_class_name(b->class_name);
        });
    }

    //生成主头文件
    std::string main_path = out_dir + "/MiniWorld_SDK.h";
    generate_main_header(result, categorized, main_path);

    //生成继承链头文件
    std::string inh_path = out_dir + "/MiniWorld_SDK_Inheritance.h";
    generate_inheritance_header(result, inh_path);

    //生成各分类头文件
    size_t total_funcs = 0;
    for (const auto& vt : result.vtables) total_funcs += vt.nfunc;

    printf("\n=== 输出文件 (Pro 多文件) ===\n");
    printf("  %s/MiniWorld_SDK.h\n", out_dir.c_str());
    printf("  %s/MiniWorld_SDK_Inheritance.h\n", out_dir.c_str());

    for (const std::string& cat : get_cat_order()) {
        auto it = categorized.find(cat);
        if (it == categorized.end() || it->second.empty()) continue;
        std::string path = out_dir + "/MiniWorld_SDK_" + cat + ".h";
        generate_category_header(result, cat, it->second, path);
        printf("  %s/MiniWorld_SDK_%s.h  (%zu 类)\n",
               out_dir.c_str(), cat.c_str(), it->second.size());
    }

    printf("\n  SDK 头文件: %zu 类, %zu 虚函数\n", result.vtables_found, total_funcs);
}

// JSON 输出
static void write_json(const AnalysisResult& result, const std::string& out_path) {
    std::ofstream f(out_path, std::ios::binary);
    if (!f) return;
    f << "{\n";
    f << "  \"image_base\": \"0x" << std::hex << g_image_base << std::dec << "\",\n";
    f << "  \"type_descriptors\": " << result.type_descriptors << ",\n";
    f << "  \"complete_object_locators\": " << result.complete_object_locators << ",\n";
    f << "  \"total_vtables\": " << result.vtables_found << ",\n";
    f << "  \"inheritance_chains\": " << result.inheritance_chains << ",\n";
    f << "  \"vtables\": [\n";
    for (size_t i = 0; i < result.vtables.size(); i++) {
        const Vtable& vt = result.vtables[i];
        f << "    {\n";
        f << "      \"class\": \"" << vt.class_name << "\",\n";
        f << "      \"vtable_rva\": \"0x" << std::hex << vt.vtable_rva << std::dec << "\",\n";
        f << "      \"nfunc\": " << vt.nfunc << ",\n";
        f << "      \"funcs\": [";
        for (size_t j = 0; j < vt.funcs.size(); j++) {
            if (j) f << ",";
            f << "\n        {\"rva\": \"0x" << std::hex << vt.funcs[j].rva
              << std::dec << "\", \"ea\": \"0x" << std::hex << vt.funcs[j].ea
              << std::dec << "\"}";
        }
        f << "\n      ]\n";
        f << "    }";
        if (i + 1 < result.vtables.size()) f << ",";
        f << "\n";
    }
    f << "  ]\n";
    f << "}\n";
}

static std::wstring select_dll_file() {
    wchar_t path[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = L"PE/DLL Files\0*.dll;*.exe\0All Files\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    ofn.lpstrTitle = L"选择 libsandboxgame.dll (Mini World PE)";
    ofn.lpstrDefExt = L"dll";

    printf("=== 请在弹出的对话框中选择 libsandboxgame.dll ===\n");
    if (GetOpenFileNameW(&ofn)) {
        return std::wstring(path);
    }
    return L"";
}

// 辅助函数
static std::string wstr_to_str(const wchar_t* w) {
    if (!w) return "";
    int len = WideCharToMultiByte(CP_ACP, 0, w, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    std::string s(len - 1, '\0');
    WideCharToMultiByte(CP_ACP, 0, w, -1, &s[0], len, NULL, NULL);
    return s;
}

// 主函数
int wmain(int argc, wchar_t** argv) {
    // 设置控制台为 UTF-8, 避免 GBK 代码页导致中文乱码
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    std::wstring dll_path;
    // 默认输出到 exe 所在目录下的 sdk_out (双击运行时工作目录可能不是 exe 目录)
    char exe_path[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    std::string exe_dir(exe_path);
    size_t pos = exe_dir.find_last_of("\\/");
    std::string out_dir = (pos != std::string::npos ? exe_dir.substr(0, pos) : ".") + "/sdk_out";

    if (argc >= 2) {
        // 命令行模式
        dll_path = argv[1];
        if (argc >= 3) out_dir = wstr_to_str(argv[2]);
    } else {
        // 交互模式: 弹文件选择
        dll_path = select_dll_file();
    }

    if (dll_path.empty()) {
        printf("未选择文件, 退出\n");
        return 1;
    }
    printf("by:MWPDT deobf?. bbb")
    // 转宽字符路径为多字节 (用于 printf)
    char dll_mb[MAX_PATH] = {0};
    WideCharToMultiByte(CP_ACP, 0, dll_path.c_str(), -1, dll_mb, MAX_PATH, NULL, NULL);
    printf("目标: %s\n", dll_mb);
    printf("输出: %s\n\n", out_dir.c_str());

    // 创建输出目录
    CreateDirectoryA(out_dir.c_str(), NULL);

    // 1. 加载 PE
    if (!load_pe(dll_path.c_str())) {
        printf("PE 加载失败\n");
        return 1;
    }

    // 2. 分析
    AnalysisResult result;
    bool ok = analyze(result);

    // 3. 写文件
    if (ok) {
        std::string vt_path = out_dir + "/vtables_pe.json";
        std::string inh_path = out_dir + "/inheritance_pe.json";

        // 生成 Pro 风格的多文件 SDK (主头 + 继承链 + 各分类头)
        generate_sdk_header(result, out_dir);
        write_json(result, vt_path);

        // 写继承链 JSON
        std::ofstream f(inh_path, std::ios::binary);
        if (f) {
            f << "{\n";
            size_t idx = 0;
            for (const auto& [cls, bases] : result.inheritance_map) {
                f << "  \"" << cls << "\": [";
                for (size_t i = 0; i < bases.size(); i++) {
                    if (i) f << ", ";
                    f << "\"" << bases[i] << "\"";
                }
                f << "]";
                if (++idx < result.inheritance_map.size()) f << ",";
                f << "\n";
            }
            f << "}\n";
        }

        printf("\n  %s/vtables_pe.json\n", out_dir.c_str());
        printf("  %s/inheritance_pe.json\n", out_dir.c_str());
    }

    unload_pe();
    printf("\n完成\n");
    return ok ? 0 : 1;
}
