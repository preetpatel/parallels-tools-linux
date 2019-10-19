/* NOTE: this works for GCC too! */

#if defined(_MSC_VER)
    #pragma warning(disable:4103)
#elif defined(__clang__) && defined(__has_warning)
	#if __has_warning("-Wpragma-pack")
		#pragma clang diagnostic ignored "-Wpragma-pack"
	#endif
#endif

#ifdef __PRAGMA_PACK_ON
#error "Nested usage of pragma(pack) is prohibited!"
#endif
#define __PRAGMA_PACK_ON

#pragma pack(push,1)
