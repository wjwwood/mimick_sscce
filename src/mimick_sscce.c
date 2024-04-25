#include "link.h"
#include "stdio.h"

void (*found_vfprintf_)(FILE *, const char *, va_list);

const char *
d_tag_to_string(Elf64_Sxword tag) {
  // from: https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html
  switch (tag) {
    case 0:
      return "DT_NULL";
    case 1:
      return "DT_NEEDED";
    case 2:
      return "DT_PLTRELSZ";
    case 3:
      return "DT_PLTGOT";
    case 4:
      return "DT_HASH";
    case 5:
      return "DT_STRTAB";
    case 6:
      return "DT_SYMTAB";
    case 7:
      return "DT_RELA";
    case 8:
      return "DT_RELASZ";
    case 9:
      return "DT_RELAENT";
    case 10:
      return "DT_STRSZ";
    case 11:
      return "DT_SYMENT";
    case 12:
      return "DT_INIT";
    case 13:
      return "DT_FINI";
    case 14:
      return "DT_SONAME";
    case 15:
      return "DT_RPATH";
    case 16:
      return "DT_SYMBOLIC";
    case 17:
      return "DT_REL";
    case 18:
      return "DT_RELSZ";
    case 19:
      return "DT_RELENT";
    case 20:
      return "DT_PLTREL";
    case 21:
      return "DT_DEBUG";
    case 22:
      return "DT_TEXTREL";
    case 23:
      return "DT_JMPREL";
    case 24:
      return "DT_BIND_NOW";
    case 25:
      return "DT_INIT_ARRAY";
    case 26:
      return "DT_FINI_ARRAY";
    case 27:
      return "DT_INIT_ARRAYSZ";
    case 28:
      return "DT_FINI_ARRAYSZ";
    case 29:
      return "DT_RUNPATH";
    case 30:
      return "DT_FLAGS";
    case 32:
      return "DT_PREINIT_ARRAY";
    case 33:
      return "DT_PREINIT_ARRAYSZ";
    case 34:
      return "DT_MAXPOSTAGS";
    default:
      return "Unknown";
  }
}

// Reference structures:
//
// struct r_debug
// {
//   int r_version;              /* Version number for this protocol.  */
//
//   struct link_map *r_map;     /* Head of the chain of loaded objects.  */
//
//   /* This is the address of a function internal to the run-time linker,
//      that will always be called when the linker begins to map in a
//      library or unmap it, and again when the mapping change is complete.
//      The debugger can set a breakpoint at this address if it wants to
//      notice shared object mapping changes.  */
//   ElfW(Addr) r_brk;
//   enum
//     {
//       /* This state value describes the mapping change taking place when
//          the `r_brk' address is called.  */
//       RT_CONSISTENT,          /* Mapping change is complete.  */
//       RT_ADD,                 /* Beginning to add a new object.  */
//       RT_DELETE               /* Beginning to remove an object mapping.  */
//     } r_state;
//
//   ElfW(Addr) r_ldbase;        /* Base address the linker is loaded at.  */
// };
//
// struct link_map {
//     ElfW(Addr) l_addr;  /* Difference between the
//                            address in the ELF file and
//                            the address in memory */
//     char      *l_name;  /* Absolute pathname where
//                            object was found */
//     ElfW(Dyn) *l_ld;    /* Dynamic section of the
//                            shared object */
//     struct link_map *l_next, *l_prev;
//                         /* Chain of loaded objects */
//
//     /* Plus additional fields private to the
//        implementation */
// };
//
// typedef struct {
//    Elf32_Sword    d_tag;
//    union {
//        Elf32_Word d_val;
//        Elf32_Addr d_ptr;
//    } d_un;
// } Elf32_Dyn;
// extern Elf32_Dyn _DYNAMIC[];
//
// typedef struct {
//    Elf64_Sxword    d_tag;
//    union {
//        Elf64_Xword d_val;
//        Elf64_Addr  d_ptr;
//    } d_un;
// } Elf64_Dyn;
// extern Elf64_Dyn _DYNAMIC[];

#if INTPTR_MAX == INT64_MAX
// 64-bit
#define MY_ADDR_BITS 64
#elif INTPTR_MAX == INT32_MAX
// 32-bit
#define MY_ADDR_BITS 32
#else
#error unknown pointer size or missing size macros
#endif

void *
get_ld_ptr(const ElfW(Addr) * base_addr, const ElfW(Dyn) * ld)
{
  if (ld->d_un.d_ptr >= base_addr && (ld->d_un.d_ptr >> (MY_ADDR_BITS - 8)) ^ 0xff) {
    return (void*) ld->d_un.d_ptr;
  } else {
    return (char*) base_addr + ld->d_un.d_ptr;
  }
}

void
handle_ld(const ElfW(Dyn) * ld, struct link_map * link)
{
  switch (ld->d_tag) {
    case DT_HASH:
      ElfW(Word) * hash_ptr = get_ld_ptr(link->l_addr, ld);
      fprintf(stderr, "         DT_HASH (%p): %d\n", hash_ptr, *hash_ptr);
      break;
    case DT_SYMTAB:
      ElfW(Sym) * symtab_ptr = get_ld_ptr(link->l_addr, ld);
      // TODO(wjwwood): this is a hash and other things, needs special handling to visualize
      fprintf(stderr, "         DT_SYMTAB (%p): ...\n", symtab_ptr);
      break;
    case DT_STRTAB:
      const char * strtab  = (const char*) get_ld_ptr(link->l_addr, ld);
      // TODO(wjwwood): this is an array of strs, it needs to be considered with the symtab contents
      fprintf(stderr, "         DT_STRTAB (%p): '%s'\n", strtab, strtab);
      break;
    default:
      break;
  }
}

void *
locate_function(const char * function_name)
{
  fprintf(stderr, "_r_debug.r_version: %d\n", _r_debug.r_version);

  // fprintf(stderr, "\n");
  fprintf(stderr, "Iterating over _r_debug.r_map:\n");
  size_t link_index = 0;
  for (struct link_map * link = _r_debug.r_map; NULL != link; link = link->l_next) {
    void * l_addr = (void *)link->l_addr;
    fprintf(stderr, "  [%zu] '%s' addr: %p ld: %p\n", link_index, link->l_name, l_addr, link->l_ld);
    size_t ld_index = 0;
    for (const ElfW(Dyn) * ld = link->l_ld; ld->d_tag != DT_NULL; ++ld) {
      fprintf(stderr,
        "       [%zu] d_tag: %s(%ld) d_ptr: %p\n",
        ld_index,
        d_tag_to_string(ld->d_tag),
        ld->d_tag,
        ld->d_un.d_ptr);
      handle_ld(ld, link);
      ld_index++;
    }
    link_index++;
  }

  return NULL;
}

int
main(void)
{
  found_vfprintf_ = locate_function("vfprintf");

  fprintf(stderr, "vfprintf address found: %p\n", found_vfprintf_);

  return 0;
}
