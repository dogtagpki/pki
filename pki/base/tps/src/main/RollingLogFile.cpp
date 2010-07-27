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
#include "main/RA_Context.h"
#include "main/LogFile.h"
#include "main/RollingLogFile.h"

const char *RollingLogFile::CFG_MAX_FILE_SIZE=       "maxFileSize";
const char *RollingLogFile::CFG_ROLLOVER_INTERVAL=   "rolloverInterval";
const char *RollingLogFile::CFG_EXPIRATION_INTERVAL= "expirationTime";
const int RollingLogFile::MAX_SLEEP = 21600; /* 6 hours */

RollingLogFile::RollingLogFile() :
    m_max_file_size(2000),
    m_rollover_interval(0), 
    m_expiration_time(0), 
    m_expiration_sleep_time(0),
    m_rotation_needed(false),
    m_rollover_thread(NULL),
    m_expiration_thread(NULL) { }

int RollingLogFile::startup(RA_Context *ctx, const char* prefix, const char *fname, bool signed_audit) 
{
    char configname[256];

    if (ctx == NULL) {
        return PR_FAILURE;
    }

    if (fname == NULL) {
        ctx->LogError("RollingLogFile::startup", 
                      __LINE__, 
                      "startup error, fname is  NULL");
        return PR_FAILURE;
    }

    if (prefix == NULL) {
        ctx->LogError("RollingLogFile::startup", 
                      __LINE__, 
                      "startup error for file %s: prefix is NULL", 
                      fname);
        return PR_FAILURE;
    }

    ConfigStore* store = RA::GetConfigStore();

    if (store == NULL) {
        ctx->LogError("RollingLogFile::startup", 
                      __LINE__,
                      "Error in obtaining config store to set up rolling log for %s",
                      fname);
        return PR_FAILURE;
    }
 
    PR_snprintf((char *)configname, 256, "%s.%s", prefix, CFG_MAX_FILE_SIZE);
    m_max_file_size = store->GetConfigAsInt(configname, 2000); /* 2 MB */

    PR_snprintf((char *)configname, 256, "%s.%s", prefix, CFG_ROLLOVER_INTERVAL);
    m_rollover_interval = store->GetConfigAsInt(configname, 2592000);  /* 30 days */
     
    PR_snprintf((char *)configname, 256, "%s.%s", prefix, CFG_EXPIRATION_INTERVAL);
    m_expiration_time = store->GetConfigAsInt(configname, 0); /* disabled, by default */

    m_rollover_thread = (PRThread *) NULL;
    m_expiration_thread = (PRThread*) NULL;
    m_rotation_needed = false;
    
    LogFile::startup(ctx, prefix, fname, signed_audit);

    m_ctx->LogInfo( "RollingLogFile::startup",
                     __LINE__,
                     "thread = 0x%lx: Rolling log file %s startup complete",
                     PR_GetCurrentThread(), m_fname);
    return PR_SUCCESS; 
}

void RollingLogFile::shutdown()
{
    m_ctx->LogInfo( "RollingLogFile::shutdown",
                     __LINE__,
                     "thread = 0x%lx: Rolling log file %s shutting down",
                     PR_GetCurrentThread(), m_fname);

    // interrupt and join threads

    set_expiration_time(0);
    if (m_expiration_thread != NULL) {
        PR_Interrupt(m_expiration_thread);
        PR_JoinThread(m_expiration_thread);
        m_expiration_thread = (PRThread*) NULL;
    }

    set_rollover_interval(0);
    if (m_rollover_thread != NULL) {
        PR_Interrupt(m_rollover_thread);
        PR_JoinThread(m_rollover_thread);
        m_rollover_thread = (PRThread*) NULL;
    }

    LogFile::shutdown();
}

int RollingLogFile::write(char *msg) {
    int status;
    PR_EnterMonitor(m_monitor);

    if (m_rotation_needed && m_signed && m_signed_log) {
        rotate();
        m_rotation_needed = false;
    }

    status = LogFile::write(msg);
    if ((get_bytes_written() >= (m_max_file_size*1024)) && (m_max_file_size >0)) {
        if (! m_signed_log) {
            rotate();
            m_rotation_needed = false;
        } else {
            m_rotation_needed = true;
        }
    }
    PR_ExitMonitor(m_monitor);
    return status;
}

/* this is always called under a monitor */
void RollingLogFile::rotate() {
    PRTime now;
    const char* time_fmt = "%Y%m%d-%H%M%S";
    char datetime[1024];
    char backup_fname[1024];
    char *first_sig = (char *) NULL;
    PRExplodedTime time;
    int status;

    now = PR_Now();
    PR_ExplodeTime(now, PR_LocalTimeParameters, &time);
    PR_FormatTimeUSEnglish(datetime, 1024, time_fmt, &time);
    PR_snprintf((char *) backup_fname, 1024, "%s.%s", m_fname, datetime);

    /* close the old file */
    status = LogFile::close();
    if (status != PR_SUCCESS) {
         m_ctx->LogError( "RollingLogFile::rotate",
                          __LINE__,
                          "Failed to close log file %s",
                          m_fname);
         goto loser;
    } else {
        m_fd = (PRFileDesc *) NULL;
    }

    status = PR_Rename(m_fname, backup_fname);
    if (status != PR_SUCCESS) {
        m_ctx->LogError( "RollingLogFile::rotate",
                          __LINE__,
                          "Failed to rename %s to %s",
                          m_fname, backup_fname);

        status = LogFile::open(); 
        if (status != PR_SUCCESS) {
            m_ctx->LogError("RollingLogFile::rotate", 
                            __LINE__,
                            "Failed to reopen log file %s",
                            m_fname);
        }
        goto loser;
    }

    /* open the new file */
    m_fd = PR_Open(m_fname,  PR_RDWR | PR_CREATE_FILE | PR_TRUNCATE, 440|220);
    set_bytes_written(0);
    if (m_fd == NULL) {
        m_ctx->LogError( "RollingLogFile::rotate",
                          __LINE__,
                          "Failed to reopen log file %s",
                          m_fname);
    } else {
        if (m_signed_log) {
            first_sig = RA::GetAuditSigningMessage("");
            if (first_sig != NULL) {
                status = LogFile::write(first_sig);
                if (status != PR_SUCCESS) {
                    m_ctx->LogError("RollingLogFile::rotate",
                            __LINE__,
                            "Failed to write signature to new (rotated) log file %s",
                             m_fname);
                } else {
                    status = LogFile::write("\n");
                    if (RA::m_last_audit_signature != NULL) {
                        PR_Free( RA::m_last_audit_signature );
                    }
                    RA::m_last_audit_signature = PL_strdup(first_sig);
                    m_signed = true;
                }
                PR_Free(first_sig);
            } else {
                m_ctx->LogError("RollingLogFile::rotate",
                           __LINE__,
                           "Failed to generate signature for new (rotated) log file %s",
                            m_fname);
            }
        }
    }


    loser: 
        m_rotation_needed = false;
}

void RollingLogFile::child_init()
{
    set_rollover_interval(m_rollover_interval);
    set_expiration_time(m_expiration_time);
}


void RollingLogFile::set_rollover_interval(int interval)
{
    m_rollover_interval = interval;
    if ((m_rollover_interval>0) && (m_rollover_thread == NULL)) {
        m_rollover_thread = PR_CreateThread( PR_USER_THREAD, 
                                 start_rollover_thread, 
                                 (void *) this,
                                 PR_PRIORITY_NORMAL,      /* Priority */
                                 PR_LOCAL_THREAD,   /* Scope */
                                 PR_JOINABLE_THREAD, /* State */
                                 0   /* Stack Size */);

    } else {
        if (m_rollover_thread != NULL) PR_Interrupt(m_rollover_thread);
    }
}

void RollingLogFile::start_rollover_thread(void *args) {
    RollingLogFile *rf;
    if (args != NULL) {
        rf = (RollingLogFile *) args;
        rf->run_rollover_thread();
    }
}
 
void RollingLogFile::run_rollover_thread() {

    m_ctx->LogInfo( "RollingLogFile::run_rollover_thread",
                     __LINE__,
                    "thread = 0x%lx: Rollover thread for %s starting", 
                    PR_GetCurrentThread(), m_fname);

    while (m_rollover_interval > 0) {
        PR_Sleep(PR_SecondsToInterval(m_rollover_interval));

        PR_EnterMonitor(m_monitor);
        if (m_rollover_interval == 0) break;
        if (get_bytes_written()>0) {
            if (! m_signed_log) { 
                rotate();
            } else {
                m_rotation_needed = true;
            }
        }
        PR_ExitMonitor(m_monitor);
    }

    m_ctx->LogInfo( "RollingLogFile::run_rollover_thread",
                    __LINE__,
                    "thread = 0x%lx: Rollover thread for %s ending", 
                    PR_GetCurrentThread(), m_fname);

    PR_ExitMonitor(m_monitor);
}

void RollingLogFile::set_expiration_time(int interval)
{
    m_expiration_time = interval;
    m_expiration_sleep_time = interval;

    if ((interval>0) && (m_expiration_thread == NULL)) {
        m_expiration_thread = PR_CreateThread( PR_USER_THREAD,
                                 start_expiration_thread,
                                 (void *) this,
                                 PR_PRIORITY_NORMAL,      /* Priority */
                                 PR_GLOBAL_THREAD,   /* Scope */
                                 PR_JOINABLE_THREAD, /* State */
                                 0   /* Stack Size */);

    } else {
        if (m_expiration_thread != NULL) PR_Interrupt(m_expiration_thread);
    }
}

void RollingLogFile::start_expiration_thread(void *args) {
    RollingLogFile *rf;
    if (args != NULL) {
        rf = (RollingLogFile *) args;
        rf->run_expiration_thread();
    }
}

/* wait for a bit and then call expire().
   Note that PR_Sleep() requires a small interval 
   (about 6 hrs to prevent overflow) */
void RollingLogFile::run_expiration_thread() {
    int interval;

    m_ctx->LogInfo( "RollingLogFile::run_expiration_thread",
                     __LINE__,
                    "thread = 0x%lx: Expiration thread for %s starting", 
                    PR_GetCurrentThread(), m_fname);

    while (m_expiration_time > 0) {
        expire();
        while (m_expiration_sleep_time > 0) {
            if (m_expiration_sleep_time > MAX_SLEEP) {
                interval = MAX_SLEEP;
            } else {
                interval = m_expiration_sleep_time;
            }

            PR_Sleep(PR_SecondsToInterval(interval));
            m_expiration_sleep_time = m_expiration_sleep_time - interval;

            if (m_expiration_time == 0) break;
        }

        if (m_expiration_time == 0) break;
    }

    m_ctx->LogInfo( "RollingLogFile::run_expiration_thread",
                     __LINE__,
                    "thread = 0x%lx: Expiration thread for %s ending", 
                    PR_GetCurrentThread(), m_fname);
}

/* remove log files that have not been modified in specified time */
void RollingLogFile::expire() {
    char basename[256];
    char dirname[256];
    char searchStr[256];
    char full_search_name[256];
    PRDir *dir;
    PRDirEntry *entry;
    PRFileInfo info;
    PRTime expireTime;
    PRTime now;
    PRTime earliestModTime;
    PRInt64 expiration_interval;
    PRInt64 usec_per_sec;
    PRInt64 tmp, tmp1, tmp2;
    PRStatus status;

    if (m_expiration_time == 0) {
        return;
    }

    if (strrchr(m_fname, '/') != NULL) {
        PR_snprintf((char *) basename, 256, "%s", strrchr(m_fname, '/') +1);
        PR_snprintf((char *) dirname, PL_strlen(m_fname) - PL_strlen(basename), "%s", m_fname);
        PL_strcat(dirname, '\0');
    } else {
        PR_snprintf((char *) basename, 256, "%s", m_fname);
        PR_snprintf((char *) dirname, 256, ".");
    }

    LL_I2L(tmp, m_expiration_time);
    LL_I2L(usec_per_sec, PR_USEC_PER_SEC);
    LL_MUL(expiration_interval, tmp, usec_per_sec);

    now = PR_Now();
    earliestModTime=now;
    LL_SUB(expireTime, now, expiration_interval);

    dir = PR_OpenDir(dirname);

    if (dir == NULL) {
         m_ctx->LogError( "RollingLogFile::expire",
                          __LINE__,
                          "Failed to open log file directory %s",
                          dirname);
        return;
    }

    PR_snprintf(searchStr, 256, "%s.", basename);

    while ((entry=PR_ReadDir(dir, PR_SKIP_BOTH)) != NULL) {
        /* look only for entries of form basename. */

        if (PL_strstr(entry->name, searchStr) != NULL) {
            PR_snprintf(full_search_name, 256, "%s/%s", dirname, entry->name);
            status = PR_GetFileInfo(full_search_name, &info);

            if (status != PR_SUCCESS) {
                 m_ctx->LogError( "RollingLogFile::expire",
                          __LINE__,
                          "Failed to get file info for log file %s",
                          full_search_name);
                // log failure to get file info
            } else {
                if (LL_CMP(info.modifyTime,<, expireTime)) {
                    status = PR_Delete(full_search_name);
                    if (status != PR_SUCCESS) {
                        m_ctx->LogError( "RollingLogFile::expire",
                                   __LINE__,
                                   "Failed to delete expired log file %s",
                                   full_search_name);
                    }  else {
                        RA::Debug("RollingLogFile::expire", "Deleted expired file: %s",
                            full_search_name);
                    }
                } else {
                    if (LL_CMP(info.modifyTime,<,earliestModTime)) {
                        earliestModTime = info.modifyTime;
                    }
                }
            }
        }
    }

    PR_CloseDir(dir);

    /* set next wakeup interval */
    /* A complicated 64-bit way of calculating :
       m_expiration_sleep_time = (earliestModTime + m_expiration_time * 1000000 - PR_Now())/1000000;
    */

    LL_ADD(tmp, earliestModTime, expiration_interval);
    LL_SUB(tmp1, tmp, now);
    LL_DIV(tmp, tmp1, usec_per_sec);
    LL_L2I(m_expiration_sleep_time, tmp);

}

int RollingLogFile::get_rollover_interval() {
   return m_rollover_interval;
}

void RollingLogFile::set_rotation_needed(bool val) {
    m_rotation_needed = val;
}

bool RollingLogFile::get_rotation_needed() {
    return m_rotation_needed;
}

int RollingLogFile::get_expiration_time() {
    return m_expiration_time;
}


