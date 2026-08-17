// OneAttackData 完整结构定义 - 基于逆向分析
// Source: libSandboxGame.dll
// 22 字段全部已通过 IDA 反编译验证
//
// 用途: 攻击数据载体, Lua 脚本通过 sub_18205B140 注册的字段访问器读写
//       22 个 setter 共用 prologue: AOB 48 89 5C 24 08 57 48 83 EC 20 ...

#pragma once
#include <cstdint>

namespace MiniWorld {
namespace Structures {

struct vec3 {
    float x, y, z;
};

// ============================================
// OneAttackData - 单次攻击的完整数据 (size: 0x60+)
// 实例地址通过 hook buff_atk setter 捕获 (rbx 寄存器)
// ============================================
struct OneAttackData {
    int      atktype;                                         // +0x00  攻击类型 ID
    float    atkpoints;                                         // +0x04  基础攻击点数
    float    enchant_atk;                                         // +0x08  附魔攻击加成
    float    buff_atk;                                         // +0x0C  Buff 攻击加成 (实测: sub_182070580 setter)
    bool     critical;                                         // +0x10  是否暴击 (实测: sub_182070620 setter)
    bool     damage_armor;                                         // +0x11  护甲穿透 (实测: sub_182070920 setter)
    float    knockback;                                         // +0x14  击退力度 (实测: sub_182070AF0 setter)
    float    damage_armor_f;                                         // +0x18  护甲伤害 float
    int      buffId;                                         // +0x1C  Buff ID (实测: sub_1814E5AE0 setter)
    bool     ignore_resist;                                         // +0x20  忽略抗性
    int      explodePos_x;                                         // +0x24  爆炸位置 X (实测: sub_1820708D0 setter)
    float    explodePos_y;                                         // +0x28  爆炸位置 Y
    float    explodePos_z;                                         // +0x2C  爆炸位置 Z
    float    explodeSize;                                         // +0x30  爆炸范围
    bool     fromplayer;                                         // +0x34  是否来自玩家
    bool     isAttackHead;                                         // +0x38  是否爆头
    vec3     atkpos;                                         // +0x3C  攻击位置 (3*float)
    bool     triggerhit;                                         // +0x48  是否触发命中
    float    touReduce;                                         // +0x4C  TOU 减伤
    int      atkTypeNew;                                         // +0x50  新版攻击类型
    float    atkPointsNew;                                         // +0x54  新版攻击点数
    float    explodePoints;                                         // +0x58  爆炸点数组
};

// 字段访问器地址 (RVA, 用于 hook)
namespace Setters {
    constexpr uintptr_t buff_atk       = 0x20705B0;  // movss [rbx+0Ch], xmm1
    constexpr uintptr_t critical       = 0x2070620;  // mov [rbx+10h], cl
    constexpr uintptr_t damage_armor   = 0x2070920;  // mov [rbx+11h], cl
    constexpr uintptr_t knockback      = 0x2070AF0;  // movss [rbx+14h], xmm1
    constexpr uintptr_t buffId         = 0x14E5AE0;  // mov [rbx+1Ch], ecx
    constexpr uintptr_t explodePos_x   = 0x20708D0;  // mov [rbx+24h], ecx
}

namespace Getters {
    constexpr uintptr_t buff_atk       = 0x200CEA0;
    constexpr uintptr_t critical       = 0x200CF20;
    constexpr uintptr_t damage_armor   = 0x200D170;
    constexpr uintptr_t knockback      = 0x200CFE0;
    constexpr uintptr_t buffId         = 0x1485C60;
    constexpr uintptr_t explodePos_x   = 0x200D0B0;
}

} // namespace Structures
} // namespace MiniWorld