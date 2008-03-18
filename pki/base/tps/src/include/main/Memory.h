/* --- BEGIN COPYRIGHT BLOCK ---
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

#ifndef RA_MEMORY_H
#define RA_MEMORY_H

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

#include "main/MemoryMgr.h"

#ifdef MEM_PROFILING

#ifdef __cplusplus
extern "C"
{
#endif

extern void MEM_init(char *audit_file, char *dump_file);
extern void MEM_shutdown();
extern void MEM_dump_unfree();
extern char *MEM_strdup(const char *, const char *, const char *, const char *, int);
extern void *MEM_malloc(int, const char *, const char *, const char *, int);
extern void MEM_free(void *i, const char *, const char *, const char *, int);

#ifdef __cplusplus
}
#endif


#ifdef malloc
#undef malloc
#endif

#ifdef free
#undef free
#endif

#ifdef strdup
#undef strdup
#endif

#ifdef PL_strdup
#undef PL_strdup
#endif

#ifdef PL_strfree
#undef PL_strfree
#endif


#define strdup(s)          MEM_strdup(s,"strcpy",__FUNCTION__,__FILE__,__LINE__)
#define malloc(size)       MEM_malloc(size,"malloc",__FUNCTION__,__FILE__,__LINE__)
#define free(p)            MEM_free(p,"free",__FUNCTION__,__FILE__,__LINE__)
#define PR_MALLOC(size)    MEM_malloc(size,"PL_MALLOC",__FUNCTION__,__FILE__,__LINE__)
#define PR_Malloc(size)    MEM_malloc(size,"PR_Malloc",__FUNCTION__,__FILE__,__LINE__)
#define PR_Free(p)         MEM_free(p,"free",__FUNCTION__,__FILE__,__LINE__)

#define PL_strdup(s)       MEM_strdup(s,"PL_strdup",__FUNCTION__,__FILE__,__LINE__)
#define PL_strfree(p)      MEM_free(p,"PL_strfree",__FUNCTION__,__FILE__,__LINE__)

#if 0
extern void *operator new(size_t size, const char *func, const char *file, int line);
extern void *operator new[](size_t size, const char *func, const char *file, int line);
#endif
extern void operator delete(void* p);
extern void operator delete[](void* p);

inline void *operator new(size_t size, const char *func, const char *file, int line)
{
	  return MEM_malloc(size, "new", func, file, line);
}

inline void *operator new[](size_t size, const char *func, const char *file, int line)  
{
	  return MEM_malloc(size, "new[]", func, file, line);
}

#if 0
inline void operator delete(void *p)
{
	  MEM_free(p,"delete","", "", 0);
}

inline void operator delete[](void *p)
{
           MEM_free(p,"delete[]","", "", 0);
}
#endif


#ifdef new
#undef new
#endif

#define new                new(__FUNCTION__,__FILE__,__LINE__)

#endif

#endif /* RA_MEMORY_H */
