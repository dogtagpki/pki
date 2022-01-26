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

#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
//#include <wchar.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "httpd/httpd.h"
#include "prmem.h"
#include "prsystem.h"
#include "plstr.h"
#include "prio.h"
#include "prprf.h"
#include "plhash.h"
#include "pk11func.h"
#include "cert.h"
#include "certt.h"
#include "secerr.h"
#include "base64.h"
#include "secder.h"
#include "nss.h"
#include "nssb64.h"

#ifdef __cplusplus
}
#endif

#include "main/Memory.h"
#include "main/RA_Context.h"
#include "engine/RA.h"
#include "main/Util.h"
#include "main/LogFile.h"

typedef struct
{
    enum
    {
        PW_NONE = 0,
        PW_FROMFILE = 1,
        PW_PLAINTEXT = 2,
        PW_EXTERNAL = 3
    } source;
    char *data;
} secuPWData;


static LogFile* m_debug_log = (LogFile *)NULL; 
static LogFile* m_error_log = (LogFile *)NULL; 

RA_Context *RA::m_ctx = NULL;
PRLock *RA::m_debug_log_lock = NULL;
PRLock *RA::m_error_log_lock = NULL;

PRThread *RA::m_flush_thread = (PRThread *) NULL;
size_t RA::m_bytes_unflushed =0;
size_t RA::m_buffer_size = 512;
int RA::m_flush_interval = 5;

int RA::m_debug_log_level = (int) LL_PER_SERVER;
int RA::m_error_log_level = (int) LL_PER_SERVER;

#define MAX_BODY_LEN 4096

#define MAX_AUTH_LIST_MEMBERS 20

extern void BuildHostPortLists(char *host, char *port, char **hostList, 
  char **portList, int len);

static char *transitionList                  = NULL;

#define MAX_TOKEN_UI_STATE  6

enum token_ui_states  {
    TOKEN_UNINITIALIZED = 0,
    TOKEN_DAMAGED =1,
    TOKEN_PERM_LOST=2,
    TOKEN_TEMP_LOST=3,
    TOKEN_FOUND =4,
    TOKEN_TEMP_LOST_PERM_LOST =5,
    TOKEN_TERMINATED = 6
};

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs a Registration Authority object.
 */
RA::RA ()
{ 
}

/**
 * Destructs a Registration Authority object.
 */
RA::~RA ()
{
}

#define DES2_WORKAROUND
#define MAX_BODY_LEN 4096

TPS_PUBLIC void RA::DebugBuffer(const char *func_name, const char *prefix, Buffer *buf)
{
	RA::DebugBuffer(LL_PER_CONNECTION, func_name, prefix, buf);
}

void RA::DebugBuffer(RA_Log_Level level, const char *func_name, const char *prefix, Buffer *buf)
{
    int i;
    PRTime now;
    const char* time_fmt = "%Y-%m-%d %H:%M:%S";
    char datetime[1024]; 
    PRExplodedTime time;
    BYTE *data = *buf;
    int sum = 0;
	PRThread *ct;

    if ((m_debug_log == NULL) || (!m_debug_log->isOpen())) 
        return;
    if ((int) level >= m_debug_log_level)
		return;
    PR_Lock(m_debug_log_lock);
    now = PR_Now();
    PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
    PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
    ct = PR_GetCurrentThread();
    m_debug_log->printf("[%s] %x %s - ", datetime, ct, func_name);
    m_debug_log->printf("%s (length='%d')", prefix, buf->size());
    m_debug_log->printf("\n");
    m_debug_log->printf("[%s] %x %s - ", datetime, ct, func_name);
    for (i=0; i<(int)buf->size(); i++) {
        m_debug_log->printf("%02x ", (unsigned char)data[i]);
        sum++; 
	if (sum == 10) {
    		m_debug_log->printf("\n");
                m_debug_log->printf("[%s] %x %s - ", datetime, ct, func_name);
                sum = 0;
	}
    }
    m_debug_log->write("\n");
    PR_Unlock(m_debug_log_lock);
}

TPS_PUBLIC void RA::Debug (const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::DebugThis(LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
}

TPS_PUBLIC void RA::Debug (RA_Log_Level level, const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::DebugThis(level, func_name, fmt, ap);
	va_end(ap); 
}



void RA::DebugThis (RA_Log_Level level, const char *func_name, const char *fmt, va_list ap)
{ 
	PRTime now;
        const char* time_fmt = "%Y-%m-%d %H:%M:%S";
        char datetime[1024]; 
        PRExplodedTime time;
	PRThread *ct;

 	if ((m_debug_log == NULL) || (!m_debug_log->isOpen())) 
		return;
	if ((int) level >= m_debug_log_level)
		return;
	PR_Lock(m_debug_log_lock);
	now = PR_Now();
	ct = PR_GetCurrentThread();
        PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
	PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
	m_debug_log->printf("[%s] %x %s - ", datetime, ct, func_name);
	m_debug_log->vfprintf(fmt, ap); 
	m_debug_log->write("\n");
	PR_Unlock(m_debug_log_lock);
}

TPS_PUBLIC void RA::Error (const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::ErrorThis(LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
	va_start(ap, fmt); 
	RA::DebugThis(LL_PER_SERVER, func_name, fmt, ap);
	va_end(ap); 
}

TPS_PUBLIC void RA::Error (RA_Log_Level level, const char *func_name, const char *fmt, ...)
{ 
	va_list ap; 
	va_start(ap, fmt); 
	RA::ErrorThis(level, func_name, fmt, ap);
	va_end(ap); 
	va_start(ap, fmt); 
	RA::DebugThis(level, func_name, fmt, ap);
	va_end(ap); 
}

void RA::ErrorThis (RA_Log_Level level, const char *func_name, const char *fmt, va_list ap)
{ 
	PRTime now;
        const char* time_fmt = "%Y-%m-%d %H:%M:%S";
        char datetime[1024]; 
        PRExplodedTime time;
	PRThread *ct;

 	if ((m_error_log == NULL) || (!m_error_log->isOpen()))
		return;
	if ((int) level >= m_error_log_level)
		return;
	PR_Lock(m_error_log_lock);
	now = PR_Now();
	ct = PR_GetCurrentThread();
        PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
	PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
	m_error_log->printf("[%s] %x %s - ", datetime, ct, func_name);
	m_error_log->vfprintf(fmt, ap); 
	m_error_log->write("\n");
	PR_Unlock(m_error_log_lock);
}
