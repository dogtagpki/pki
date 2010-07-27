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
// Copyright (C) 2010 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <stdio.h>

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

#ifdef __cplusplus
extern "C"
{
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "prmem.h"
#include "prsystem.h"
#include "plstr.h"
#include "prio.h"

#ifdef __cplusplus
}   
#endif

#include "main/ConfigStore.h"
#include "engine/RA.h"
#include "main/LogFile.h"
#include "main/RA_Context.h"
#include "main/Util.h"

//default constructor
LogFile::LogFile():
    m_fd(NULL), 
    m_fname(NULL), 
    m_signed_log(false),
    m_bytes_written(0),
    m_signed(false), 
    m_monitor(NULL),
    m_ctx(NULL) { }

int LogFile::startup(RA_Context *ctx, const char* prefix, const char *fname, bool signed_audit) 
{
    if (ctx == NULL) {
        return PR_FAILURE;
    }

    if (fname == NULL) {
        ctx->LogError("LogFile::startup",
                      __LINE__,
                      "startup error, fname is  NULL");
        return PR_FAILURE;
    }

    m_ctx = ctx;
    m_signed_log = signed_audit;
    m_fname = PL_strdup(fname);
    m_bytes_written =0;
    m_signed = false;
    m_fd = (PRFileDesc*) NULL;
    m_monitor = PR_NewMonitor();

    m_ctx->LogInfo( "LogFile::startup",
                     __LINE__,
                     "thread = 0x%lx: Logfile %s startup complete",
                     PR_GetCurrentThread(), m_fname);
    return PR_SUCCESS;
}

bool LogFile::isOpen()
{
    if (m_fd != NULL) return true;
    return false;
}

void LogFile::shutdown() 
{
    m_ctx->LogInfo( "LogFile::shutdown",
                      __LINE__,
                      "thread = 0x%lx: Logfile %s shutting down",
                      PR_GetCurrentThread(), m_fname);

    PR_EnterMonitor(m_monitor);
    if (m_fd != NULL) {
        close();
        m_fd = (PRFileDesc *) NULL;
    }

    if (m_fname != NULL) {
        PR_Free(m_fname);
        m_fname = NULL;
    }

    PR_ExitMonitor(m_monitor);
    
    if (m_monitor != NULL) {
       PR_DestroyMonitor(m_monitor);
       m_monitor = (PRMonitor *) NULL;
    }
}

int LogFile::open()
{
    PRFileInfo info;
    PR_EnterMonitor(m_monitor);
    if (m_fd == NULL) {
        m_fd = PR_Open(m_fname,  PR_RDWR | PR_CREATE_FILE | PR_APPEND, 440|220);
        if (m_fd == NULL) {
            m_ctx->LogError( "LogFile::open",
                      __LINE__,
                      "Unable to open log file %s",
                      m_fname);

            goto loser;
        }
        PRStatus status = PR_GetOpenFileInfo(m_fd, &info);
        if (status != PR_SUCCESS) { 
            m_ctx->LogError( "LogFile::open",
                      __LINE__,
                      "Unable to get file information for log file %s",
                      m_fname);
            goto loser;
        }

        set_bytes_written(info.size);
    }
    PR_ExitMonitor(m_monitor);
    return PR_SUCCESS;

    loser: 
        if (m_fd != NULL) {
            PR_Close(m_fd);
            m_fd = (PRFileDesc *)NULL;
        }
        set_bytes_written(0);
        PR_ExitMonitor(m_monitor);
        return PR_FAILURE;
}

int LogFile::close() 
{
   PRStatus status;
   PR_EnterMonitor(m_monitor);
   status = PR_Close(m_fd);
   if (status != PR_SUCCESS) {
        m_ctx->LogError( "LogFile::close",
                      __LINE__,
                      "Failed to close log file %s",
                      m_fname);
   }
   PR_ExitMonitor(m_monitor);
   return status;
}

int LogFile::ReadLine(char *buf, int buf_len, int *removed_return)
{
    return Util::ReadLine(m_fd, buf,buf_len, removed_return);
}

int LogFile::printf(const char* fmt, ...)
{
    PRInt32 status;
    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    PR_vsnprintf((char *) msg, 4096, fmt, ap);
    status = this->write(msg);
    va_end(ap);
    return status;
}

int LogFile::write(char *msg_in, size_t n)
{
    char msg[4096];
    PRInt32 status;

    if (n > 4096) {
        m_ctx->LogError("LogFile::write", 
            __LINE__,
            "Trying to write more than 4096 bytes in one write to log file %s. Truncating ...",
            m_fname);
        n=4096;
    }

    PR_snprintf(msg, n, "%s", msg_in);
    status = this->write(msg);
    return status;
}

int LogFile::vfprintf(const char* fmt, va_list ap)
{
    char msg[4096];
    PRInt32 status;

    PR_vsnprintf((char *) msg, 4096, fmt, ap);
    status = this->write(msg);
    return status;
}

int LogFile::write(char * msg)
{
    PRErrorCode error;
    PRInt32 status;
    int len;

    if (msg == NULL) {
        return PR_SUCCESS;
    }

    PR_EnterMonitor(m_monitor);
    len = PL_strlen(msg);
    if (m_fd != NULL) {
        status = PR_Write(m_fd, msg, len);
        if (status != len) {
            m_ctx->LogError( "LogFile::write",
                          __LINE__,
                          "Too few or too many bytes written to log file  %s",
                          m_fname);
            goto loser;
        } else if (status < 0) {
            // write failed
            error = PR_GetError();
            m_ctx->LogError( "LogFile::write",
                          __LINE__,
                          "Write to log file %s failed: code %d",
                          m_fname, error);
            goto loser;
        } else {
            set_bytes_written(get_bytes_written() + len);
        }
    }
    PR_ExitMonitor(m_monitor);
    return PR_SUCCESS; 
    loser: 
        PR_ExitMonitor(m_monitor);
        return PR_FAILURE;
}   

void LogFile::setSigned(bool val) {
    m_signed = val;
}

bool LogFile::getSigned() {
   return m_signed;
}

int LogFile::get_bytes_written() {
    return m_bytes_written;
}

void LogFile::set_bytes_written(int val) {
    if (val >=0) { 
        m_bytes_written = val;
    } else {
        m_ctx->LogError("LogFile::set_bytes_written", 
                        __LINE__, 
                        "Attempt to set m_bytes_written to a negative value. Ignoring");
    }
}

RA_Context * LogFile::get_context() {
    return m_ctx;
}

void LogFile::set_context(RA_Context *ctx) {
    m_ctx = ctx;
}


