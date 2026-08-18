# MiniWorld DumpSDK<img src="https://gd-hbimg.huaban.com/259be091fd49ec8f86369a41ac419303cd83bc6422428-jN45an_fw658" alt="mnsj" width="100">

> <img src=".\deobf1.jpg" alt="deobf" width="100"><img src=".\deobf2.jpg" alt="deobf" width="70"><img src=".\deobf3.jpg" alt="deobf" width="70"><img src=".\deobf4.jpg" alt="deobf" width="100">
>
> 交流群1064321413
> RTTI 虚表重建、Hex-Rays 反编译签名、SDK 头文件生成
## 目录结构

```
sdk/
├── MiniWorld_SDK.h                  # 主头文件
├── MiniWorld_SDK_Inheritance.h     # 继承链
├── MiniWorld_SDK_OneAttackData.h    # OneAttackData 结构
├── MiniWorld_SDK_Attack_Pro.h       # 攻击类（含签名）
├── MiniWorld_SDK_Boss_Pro.h         # Boss 类
├── MiniWorld_SDK_Player_Pro.h       # 玩家类
├── MiniWorld_SDK_AI_Pro.h           # AI 类
├── MiniWorld_SDK_Timeline_Pro.h     # 时间线类
├── MiniWorld_SDK_Rainbow_Pro.h      # Rainbow 类
├── MiniWorld_SDK_Misc_Pro.h         # 杂项类
├── _batch_*.json                    # 中间数据（按 500 类分批）
├── _hexrays_full_all.json           # 真实 Hex-Rays 签名（按 EA 索引）
└── _no_sig_full_list.json           # 去重后的无签名函数列表
```

### 格式

每个 `*.h` 文件包含：
```cpp
// MiniWorld SDK - Attack Classes (Full: analyzed+guessed+hexrays signatures)
// Classes: 505
namespace MiniWorld { namespace Attack {

// Class: VAIArrowAttack
// vtable RVA: 0x2DBA988  funcs: 24
// Inheritance: VAIArrowAttack -> VAIAttackBase -> VAttackBase
struct VAIArrowAttack_VTable {
    void* __rtti_col;  // vtable[-1]
    // [0] General_NAtk_01  RVA 0x2DBA988  EA 0x182dba988  [hexrays]
    void* vfunc_0;   // +0x0  sig: __int64 __fastcall(...)
    // [1] sub_182DBA990  RVA 0x2DBA990  EA 0x182dba990  [analyzed]
    void* vfunc_1;   // +0x8  sig: void __fastcall(...)
    ...
};
}} // namespace Attack / MiniWorld
```

### 签名全是 `__int64()`

因为**迷你世界**的无签名函数多数是：
- **thunk**（6 字节 jmp 跳转到导入函数）
- **_purecall**（纯虚函数占位符）


## 为什么可以逆向出完整 SDK

因为迷你世界的垃圾大粪混淆：
1. **RTTI 完整保留**：所有类的 TypeDescriptor、ClassHierarchyDescriptor 全在 .data/.rdata 段
2. **字符串全明文**：函数名、字段名、错误信息都是明文
3. **无控制流混淆**：函数体逻辑清晰，Hex-Rays 可直接反编译
4. **Lua 注册模板高度同构**：ScriptAPI 注册函数有固定模式可批量提取

## 许可

仅供学习和研究使用。请遵守当地法律法规，不要用于破坏游戏公平性或商业用途。
