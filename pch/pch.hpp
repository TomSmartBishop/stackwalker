#pragma once

#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include <tchar.h>

#if defined(_DEBUG)
#include <assert.h>
#define SW_ASSERT(condition, message) assert((condition) && message)
#endif
#define SW_ASSERT(condition, message)

#include "../DebugHelp.h"
#include "../StackWalker.h"