#ifndef __CC_H__
#define __CC_H__

typedef unsigned   char    u8_t;
typedef signed     char    s8_t;
typedef unsigned   short   u16_t;
typedef signed     short   s16_t;
typedef unsigned   long    u32_t;
typedef signed     long    s32_t;

typedef u32_t mem_ptr_t;

// LW: Supported in at least >=v7.5 r2, but lwIP worked without the "_packed" attribute already
#define PACK_STRUCT_BEGIN _packed
#define PACK_STRUCT_STRUCT
#define PACK_STRUCT_END
#define PACK_STRUCT_FIELD(x) x


#endif /* __CC_H__ */
