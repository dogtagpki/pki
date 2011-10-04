// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "prmem.h"
#include "prsystem.h"
#include "plstr.h"
#include "prio.h"
#include "prprf.h"
#include "plhash.h"
#include "pk11func.h"

#include "main/MemoryMgr.h"

#ifdef MEM_PROFILING

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _ref_block
{
	int id;
	void *ptr;
	const char *file;
	const char *func;
	const char *type;
	int line;
	int size;
	int used;
	PRTime time;
} ref_block;

#define MAX_BLOCKS 8096
static ref_block m_rb[MAX_BLOCKS];

static PRLock *m_free_block_lock = NULL;
static PRLock *m_dump_lock = NULL;
static PRLock *m_audit_lock = NULL;

ref_block *get_free_block()
{
	int i;
	PR_Lock(m_free_block_lock);
	for (i = 0; i < MAX_BLOCKS; i++) {
		if (m_rb[i].used == 0) {
			// lock
			m_rb[i].used = 1;
	                m_rb[i].time = PR_Now();
	                PR_Unlock(m_free_block_lock);
			return &m_rb[i];
		}
	}
        PR_Unlock(m_free_block_lock);
	return NULL;
}

ref_block *find_block(void *ptr)
{
	int i;
	for (i = 0; i < MAX_BLOCKS; i++) {
		if (m_rb[i].used == 1 && m_rb[i].ptr == ptr) {
			return &m_rb[i];
		}
	}
	return NULL;
}

void free_block(ref_block *rb)
{
	rb->used = 0;
}

static PRFileDesc *m_audit_f = NULL;
static PRFileDesc *m_dump_f = NULL;

void MEM_init(char *audit_file, char *dump_file)
{
       m_audit_f = PR_Open(audit_file, PR_RDWR|PR_CREATE_FILE|PR_APPEND, 
		       00200|00400);
       m_dump_f = PR_Open(dump_file,  PR_RDWR|PR_CREATE_FILE|PR_APPEND,
		       00200|00400);

       int i;
       for (i = 0; i < MAX_BLOCKS; i++) {
		m_rb[i].id = i;
		m_rb[i].used = 0;
       }
       m_free_block_lock = PR_NewLock();
       m_dump_lock = PR_NewLock();
       m_audit_lock = PR_NewLock();
}

void MEM_shutdown()
{
       PR_DestroyLock(m_free_block_lock);
       PR_DestroyLock(m_dump_lock);
       PR_DestroyLock(m_audit_lock);
       if (m_dump_f != NULL) {
           PR_Close(m_dump_f);
       }
       if (m_audit_f != NULL) {
           PR_Close(m_audit_f);
       }
}

static void MEM_audit_block(ref_block *ref, const char *type, const char *func, const char *file, int line, PRFileDesc *f)
{
       PRTime now;
       const char* time_fmt = "%Y-%m-%d %H:%M:%S";
       char datetime[1024];
       PRExplodedTime time;
       char datetime1[1024];
       PRExplodedTime time1;

       now = PR_Now();
       PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
       PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);

       PR_ExplodeTime(ref->time, PR_LocalTimeParameters, &time1);
       PR_FormatTimeUSEnglish(datetime1, 1024, time_fmt, &time1);

       PR_Lock(m_audit_lock);
       PR_fprintf(f, "[%s] ID='%d' Size='%d' Type='%s' Func='%s' File='%s' Line='%d' Time='%s'\n", 
  	datetime, ref->id, ref->size, type, func, file, line, datetime1);
       PR_Sync(f);
       PR_Unlock(m_audit_lock);
}

void MEM_dump_unfree()
{
       int i;
       PRTime now;
       const char* time_fmt = "%Y-%m-%d %H:%M:%S";
       char datetime[1024];
       PRExplodedTime time;
       char datetime1[1024];
       PRExplodedTime time1;
       int sum_count = 0;
       int sum_mem = 0;

       now = PR_Now();
       PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
       PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);

       PR_Lock(m_dump_lock);
       PR_fprintf(m_dump_f, "--------------------------------------------\n");
       PR_fprintf(m_dump_f, "Memory Report - '%s'\n", datetime);
       PR_fprintf(m_dump_f, "1) Unfree Blocks:\n");
       PR_fprintf(m_dump_f, "\n");
       for (i = 0; i < MAX_BLOCKS; i++) {
	       if (!m_rb[i].used)
		       continue;
               PR_ExplodeTime(m_rb[i].time, PR_LocalTimeParameters, &time1);
               PR_FormatTimeUSEnglish(datetime1, 1024, time_fmt, &time1);
       	       PR_fprintf(m_dump_f, "   ID='%d' Size='%d' Type='%s' Func='%s' File='%s' Line='%d' Time='%s'\n", m_rb[i].id, m_rb[i].size, m_rb[i].type, m_rb[i].func, m_rb[i].file, m_rb[i].line, datetime1);
	       sum_mem += m_rb[i].size;
	       sum_count += 1;
       }
       PR_fprintf(m_dump_f, "\n");
       PR_fprintf(m_dump_f, "2) Total Unfree Memory Size:\n");
       PR_fprintf(m_dump_f, "   %d bytes\n", sum_mem);
       PR_fprintf(m_dump_f, "\n");
       PR_fprintf(m_dump_f, "3) Total Unfree Memory Blocks:\n");
       PR_fprintf(m_dump_f, "   %d\n", sum_count);
       PR_fprintf(m_dump_f, "\n");
       PR_fprintf(m_dump_f, "--------------------------------------------\n");
       PR_Sync(m_dump_f);
       PR_Unlock(m_dump_lock);
}

char *MEM_strdup(const char *s, const char *type, const char *func, const char *file, int line)
{
	ref_block *rb = get_free_block();
	if (rb == NULL)
		return NULL;

	char *buf = strdup(s);

	rb->ptr = buf;
	rb->func = func;
	rb->file = file;
	rb->line = line;
	rb->type = type;
	rb->size = strlen(s) + 1;
        MEM_audit_block(rb, rb->type, rb->func, rb->file, rb->line, m_audit_f);

	return buf;
}

void *MEM_malloc(int size, const char *type, const char *func, const char *file, int line)
{
	ref_block *rb = get_free_block();
	if (rb == NULL)
		return NULL;
	void *buf = malloc(size);

	rb->ptr = buf;
	rb->func = func;
	rb->file = file;
	rb->line = line;
	rb->type = type;
	rb->size = size;
        MEM_audit_block(rb, rb->type, rb->func, rb->file, rb->line, m_audit_f);

	return buf;
}

void MEM_free(void *p, const char *type, const char *func, const char *file, int line)
{
	if (p == NULL)
		return;
	ref_block *rb = find_block(p);
	if (rb == NULL)
		return;
        MEM_audit_block(rb, type, func, file, line, m_audit_f);
        free(p);
        free_block(rb);
}

#ifdef __cplusplus
}
#endif

#if 0
void *operator new(size_t size, const char *func, const char *file, int line)  
{
	      return MEM_malloc(size, func, file, line);
}

void *operator new[](size_t size, const char *func, const char *file, int line)  
{
	      return MEM_malloc(size, func, file, line);
}

#endif
void operator delete(void *p)
{
	      MEM_free(p,"delete","", "", 0);
}

void operator delete[](void *p)
{
	      MEM_free(p,"delete[]","", "", 0);
}

#endif /* MEM_PROFILING */

