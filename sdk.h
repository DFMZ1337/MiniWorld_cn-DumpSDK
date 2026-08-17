// MiniWorld SDK - main entry
// Generated: 2026-08-16
#pragma once

#include "MiniWorld_SDK.h"
#include "MiniWorld_SDK_Attack.h"
#include "MiniWorld_SDK_Boss.h"
#include "MiniWorld_SDK_Player.h"
#include "MiniWorld_SDK_AI.h"
#include "MiniWorld_SDK_Timeline.h"
#include "MiniWorld_SDK_Rainbow.h"
#include "MiniWorld_SDK_Misc.h"

/*
Usage:
  1. Get module base: uintptr_t base = (uintptr_t)GetModuleHandleW(L"libSandboxGame.dll");
  2. Get vtable: auto* vtbl = (MiniWorld::Attack::VAIArrowAttack_VTable*)(base + MiniWorld::VTable::VTBL_VAIArrowAttack);
  3. Call vfunc: vtbl->vfunc_0(this_ptr);
*/