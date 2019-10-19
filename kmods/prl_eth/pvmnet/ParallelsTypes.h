//////////////////////////////////////////////////////////////////////////
///
/// @file ParallelsTypes.h
///
/// @brief Base Parallels types declarations
///
/// @author maximk, misha
///
/// Ideally, all user - and - kernel space components are
/// supposed to use types, declared in this module.
/// Does not need any additional headers.
///
/// Copyright (c) 1999-2016 Parallels International GmbH. All rights reserved.
///
/// This file is licensed for use in the Linux Kernel under the
/// terms of the GNU General Public License version 2.
///
/// www.parallels.com
///
//////////////////////////////////////////////////////////////////////////

#ifndef __PARALLELS_TYPES_H__
#define __PARALLELS_TYPES_H__

#if defined(__linux__) && defined(__KERNEL__)
/* all from stddef.h + ARRAY_SIZE, container_of */
#include <linux/kernel.h>
/* PAGE_SIZE (FIXME: should go somewhere else) */
#include <asm/page.h>
#elif defined(__APPLE__) && defined(KERNEL)
/* Apple's kext build doesn't give easy access to the compiler's headers, and
 * xnu only provides traditional offsetof() definition which is considered to
 * be non-constant by Apple's gcc, so override it with gcc builtin */
#include <sys/param.h>

#ifdef __GNUC__
#if __GNUC__ >= 4
#undef offsetof
#define offsetof(t, f) __builtin_offsetof(t, f)
#endif
#endif
#else

#ifndef EFIAPI
/* NULL, offsetof, size_t */
	#include <stddef.h>
#else
	#define offsetof(s,m)   ((ULONG_PTR)&(((s *)0)->m))
#endif

#endif

#ifdef _ANDROID_
/* Define __used to prevent warning: "__used" redefined */
	#include <sys/cdefs.h>
/* Define PAGE_SIZE to prevent warning: "PAGE_SIZE" redefined */
	#include <asm/page.h>
#endif

// this is PREfast tool tune parameters (for DDK/WDK PREfast)
#if defined(_WIN_) && (_MSC_VER >= 1000) && !defined(__midl) && defined(_PREFAST_)
typedef int __declspec("SAL_nokernel") __declspec("SAL_nodriver") __prefast_flag_kernel_driver_mode;
#pragma prefast(disable: 28110 28159 28146 28285, "useless noise for UM apps")
#endif

// Force compilation errors if the platform defines are in conflict states
// (e.g. _X86_ is defined for __x86_64__)
#define FORCE_PLATFORM_CHECK

// Determining current architecture
#if defined(__x86_64__) || defined(_M_X64) || defined (_AMD64_) || defined(_WIN64) || defined(_M_AMD64) || defined(_M_IA64)
#ifndef _64BIT_
	#define _64BIT_
#endif
#ifndef _AMD64_
	#define _AMD64_
#endif
#if defined(FORCE_PLATFORM_CHECK) && defined(_X86_)
	#error "Define _X86_ is incompatible with 64-bit platform!"
#endif
#elif defined(_X86_) || defined(__i386__) || defined(_M_IX86)
#ifndef _32BIT_
	#define _32BIT_
#endif
#ifndef _X86_
	#define _X86_
#endif
#if defined(FORCE_PLATFORM_CHECK) && defined(_AMD64_)
	#error "Define _AMD64_ is incompatible with 32-bit platform!"
#endif
#elif defined(__arm__)
#ifndef _32BIT_
	#define _32BIT_
#endif
#ifndef _ARM_
	#define _ARM_
#endif
#ifndef _ARMV_
	#if defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || \
		defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__)
		#define _ARMV_ 7
	#else
		#error Unknown ARM version
	#endif
#endif
#elif defined (__aarch64__)
	#ifndef _64BIT_
		#define _64BIT_
	#endif

	#ifndef _ARM_
		#define _ARM_
	#endif

	#if defined(__ARM64_ARCH_8__)
		#define _ARMV_ 8
	#else
		#error Unknown ARM64 version
	#endif
#else
	#error "Failed to determine processor architecture"
#endif

/**
 * Base types declaration, used by all Parallels software,
 * including user and kernel space components.
 *
 * NOTE: these types are also defined in winnt.h and ntdef.h; we are lucky that
 * MSVC doesn't complain about duplicate typedefs if they are compatible
 * FIXME: stop following this MS braindamage and switch to standard C types
 */

/* Don't declare BOOL for obj-c */
#ifndef OBJC_BOOL_DEFINED
typedef	int				BOOL;
#endif

typedef char			CHAR;
typedef unsigned char	UCHAR;
typedef	unsigned char	BYTE;
typedef	short			SHORT;
typedef	unsigned short	USHORT;
typedef	unsigned short	WORD;
typedef int				INT;
typedef unsigned int	UINT;
#if defined(_X86_) || defined(_WIN_)
typedef long		LONG;
typedef unsigned long	ULONG;
#define PRL_LU          "%lu"
#define PRL_LX          "%lx"
#else
typedef int		LONG;
typedef unsigned int	ULONG;
#define PRL_LU          "%u"
#define PRL_LX          "%x"
#endif
#ifdef _WIN_
typedef	unsigned long	DWORD;
#else
typedef	unsigned int	DWORD;
#endif

#define BITS_PER_UINT	(sizeof(UINT) * 8)



/**
 * There are some differences in 64-bit variables declarations
 * on windows and unix compilers.
 */
#ifdef _WIN_
	typedef __int64            LONG64;
	typedef unsigned __int64   ULONG64;
	#if defined (_32BIT_)
	typedef unsigned long      ULONG_PTR;
	typedef signed long        LONG_PTR;
	#elif defined (_64BIT_)
	typedef ULONG64            ULONG_PTR;
	typedef LONG64             LONG_PTR;
	#endif
#else
	#undef LONG64
	#undef ULONG64
	typedef unsigned long long __int64;
	typedef long long          LONG64;
	typedef unsigned long long ULONG64;
	typedef unsigned long      ULONG_PTR;
	typedef long               LONG_PTR;
#endif

typedef unsigned int           ULONG32;

#if defined (_32BIT_)
	typedef	unsigned long      SIZE_T;
	#define PRL_ZU             "%lu"
#elif defined (_64BIT_)
	typedef	ULONG64            SIZE_T;
	#define PRL_ZU             "%llu"
#endif

/**
 * Declaring pointers to the base classes - we're not sure if
 * this is a good idea to keep this, but many developers already use it.
 */
#define VOID		void

typedef VOID		*PVOID;
typedef VOID		*LPVOID;

typedef BOOL		*PBOOL;
typedef CHAR		*PCHAR;
typedef UCHAR		*PUCHAR;
typedef BYTE		*PBYTE;
typedef SHORT		*PSHORT;
typedef USHORT		*PUSHORT;
typedef WORD		*PWORD;
typedef INT			*PINT;
typedef UINT		*PUINT;
typedef LONG		*PLONG;
typedef	DWORD		*PDWORD;
typedef ULONG		*PULONG;
typedef ULONG32		*PULONG32;
typedef LONG64		*PLONG64;
typedef ULONG64		*PULONG64;
typedef ULONG_PTR	*PULONG_PTR;


#ifndef EFIAPI

typedef UCHAR		UINT8,  *PUINT8;
typedef USHORT		UINT16, *PUINT16;
typedef SHORT		INT16,  *PINT16;
typedef UINT		UINT32, *PUINT32;
typedef INT			INT32,  *PINT32;
typedef ULONG64		UINT64;

#endif // EFIAPI

/* FIXME: this is not a standard type even in windows. Kill it */
typedef UINT64 QWORD;

// Formerly compiler-dependent INT64 format specifier
#define I64X "%#llx"
#define I64D "%lld"
#define I64U "%llu"

/*
 * Formerly compiler-dependent suffixes for 64-bit constants.
 */
#define L64(x)	(x##LL)
#define UL64(x)	(x##ULL)

/**
 * C90 6.3.4, C99 6.3.2.3
 *   Any pointer type may be converted to an integer type. Except as
 *   previously specified, the result is implementation-defined.
 *
 * Most of the compilers will sign-extend the pointer when it is assigned
 * to a native pointer in 64-bit code, not zero-extend the pointer as might
 * be expected.
 *
 * http://gcc.gnu.org/onlinedocs/gcc/Arrays-and-pointers-implementation.html
 * http://msdn.microsoft.com/en-us/library/aa384242
 */
#define PTR_TO_64(ptr) ((ULONG64)(ULONG_PTR)(ptr))


/**
 * Some very common declarations - not sure where to keep them,
 * this place seems to be the best one
 */
#ifndef PAGE_SIZE
	#define PAGE_SIZE	0x1000
#endif

#ifndef BYTES2PAGES
	#define BYTES2PAGES(b)	(((b) + (PAGE_SIZE - 1)) / PAGE_SIZE)
#endif

/* Best definition is in Linux kernel, X86_L1_CACHE_SHIFT:
 *   arch/x86/Kconfig.cpu
 */
#define CACHELINE_SIZE	64

#define CPUMASK_ALL		((UINT)0xFFFFFFFF)
#define CPUMASK_NONE	0

#ifndef TRUE
	#define TRUE	1
#endif

#ifndef FALSE
	#define FALSE	0
#endif

#ifndef MAX
	#define MAX(a,b)	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
	#define MIN(a,b)	(((a) < (b)) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
	#define ARRAY_SIZE(a)	(sizeof(a)/sizeof(a[0]))
#endif

#ifndef ARRAY_AND_SIZE
	#define ARRAY_AND_SIZE(a)	(a), ARRAY_SIZE(a)
#endif

/**
 * For platforms compatibility, we need to to have some
 * very common macros one each platform.
 */
#ifdef __GNUC__

	#define UNUSED			__attribute__((unused))
#ifndef EFIAPI
	#define PACKED			__attribute__((packed))
#endif

	/* force caller to check result, e.g. for error codes... */
#ifndef __must_check
	#define __must_check	 __attribute__((warn_unused_result))
#endif

	/* check types of %x parameters as for printf() in compile time... */
#ifndef __printf
	#define __printf(a,b)	__attribute__((format(printf,a,b)))
#endif

	/* Mark function as used */
#ifndef __used
	#define __used __attribute__((used))
#endif

	/* tell gcc that condition is likely/unlikely always evaluates to true,
	 * so unlikely case will be branched out of main stream of instructions.
	 * Likely case goes w/o jumps and thus faster... */
	#define likely(x)		__builtin_expect(!!(x), 1)
	#define unlikely(x)		__builtin_expect(!!(x), 0)
#ifndef __cold
	#define __cold
#endif

#ifndef __always_inline
	#define __always_inline	inline __attribute__((always_inline))
#endif

	#define _ReturnAddress() __builtin_return_address(0)

	#define NAKED			__attribute__((naked))
	#define NORETURN		__attribute__((noreturn))
	#define DLLEXPORT
	#define V_HIDDEN		__attribute__((visibility("hidden")))
#ifndef PRL_ALIGN
	#define PRL_ALIGN(x)		__attribute__((aligned(x)))
#endif
#ifndef __cdecl
#ifdef _64BIT_
	#define __cdecl
#else
	#define __cdecl			__attribute__((__cdecl__))
#endif
#endif
#ifndef __stdcall
#ifdef _64BIT_
	#define __stdcall
#else
	#define __stdcall		__attribute__((__stdcall__))
#endif
#endif
#ifndef __fastcall
#ifdef _64BIT_
	#define __fastcall
#else
	#define __fastcall		__attribute__((__fastcall__))
#endif
#endif

#else /* All other compilers (MS, Intel) */

	#define UNUSED
	#define PACKED

	#define __must_check
	#define __printf(a,b)
	#define __used

#ifdef __ICL
	 /* tell ICL that condition is likely/unlikely always evaluates to true,
	 * so unlikely case will be branched out of main stream of instructions.
	 * Likely case goes w/o jumps and thus faster... */
	#define likely(x)               __builtin_expect(!!(x), 1)
	#define unlikely(x)             __builtin_expect(!!(x), 0)

#else
	#define likely(x)	x
	#define unlikely(x)	x
#endif

#ifndef __cold
	#define __cold
#endif

	#define __always_inline	__inline

	/* Visual Studio 2005 warnings madness workaround
	   (eliminating "deprecation" warnings) */
	#ifndef _CRT_SECURE_NO_DEPRECATE
		#define _CRT_SECURE_NO_DEPRECATE
	#endif

	#define NAKED			__declspec(naked)
	#define NORETURN		__declspec(noreturn)
	#define DLLEXPORT		__declspec(dllexport)
	#define PRL_ALIGN(x)	__declspec(align(x))
	#define V_HIDDEN

#endif

#ifdef BUILD_BUG_ON
#undef BUILD_BUG_ON
#endif

#define __PRL_UNIQUE_NAME(x,y) x##y
#define PRL_UNIQUE_NAME(x,y) __PRL_UNIQUE_NAME(x,y)

#ifndef __COUNTER__		/* gcc-4.2 or less. cl, icl, clang are OK */
#define __COUNTER__		__LINE__
#endif

// Validate constant condition on compilation stage. If condition is true
// array invalid size error occured
#define BUILD_BUG_ON(condition) \
	extern void UNUSED PRL_UNIQUE_NAME(__build_bug_on_dummy, \
									   __COUNTER__)(char a[1 - 2*!!(condition)])

#define UNUSED_PARAM(x)		(void)x

#ifndef container_of
#ifdef __GNUC__
/* version of container_of with type checking inside */
#ifndef __prl_typeof
#if defined(__cplusplus) && (__cplusplus >= 201103L)
	#define __prl_typeof decltype
#else
	#define __prl_typeof __typeof__
#endif
#endif
#define container_of(ptr, type, member) ({                    \
		const __prl_typeof( ((type *)0)->member ) *__xptr = (ptr);  \
		(type *)( (char *)__xptr - offsetof(type,member) );})
#else
#define container_of(ptr, type, member) \
		((type *)(((char *)(ptr)) - offsetof(type,member)))
#endif
#endif

/**
 * Empty define to mark variables that are frequently accessed.
 */
#ifdef _LIN_
#define __vmexit_hot __attribute__((__section__(".data.hot")))
#else
#define __vmexit_hot
#endif

/**
 * The following 64-bit type should be used in API structures to avoid
 * use of packing and to guarantee the same structure layout across all
 * compilers and architectures.
 */
typedef UINT64 PRL_ALIGN(8) API_UINT64;
/**
 * 32-bit ICL/MSVC emits "error C2719" if passing explicitly aligned variables
 * to variadic argument functions (i.e. print, logging). It seems that
 * the only way is to cast such variables to a naturally aligned type.
 */
static __always_inline UINT64 reset_align(UINT64 f_val) { return f_val; }

#endif // __PARALLELS_TYPES_H__
