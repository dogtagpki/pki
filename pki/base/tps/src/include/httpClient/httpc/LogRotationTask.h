/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 */
/** BEGIN COPYRIGHT BLOCK
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
 * END COPYRIGHT BLOCK **/

#ifndef __LOG_ROTATION_TASK_H__
#define __LOG_ROTATION_TASK_H__

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

#include "httpClient/httpc/ScheduledTask.h"

/**
 * Log rotation task in Presence Server
 */

class EXPORT_DECL LogRotationTask: public ScheduledTask {
public:
    /**
     * Constructor - creates an initialized task for log rotation
     *
     * @param name Name of task
     * @param fileName Name of file to rotate
     * @param startTime Time when the file is to be rotated
     * @param maxLogs Max logs to keep
     * @param interval Time between rotations
     * @param fp File pointer for log file
     * @param lock Lock for writing to log file
     */
    LogRotationTask( const char *name,
                     const char *fileName,
                     time_t startTime,
                     int maxLogs,
                     int interval,
                     FILE **fp,
                     PRLock *lock );
    /**
     * Destructor
     */
    virtual ~LogRotationTask();
    /**
     * Returns a copy of the task
     *
     * @return A copy of the task
     */
    virtual ScheduledTask *Clone();
    /**
     * Executes the task
     *
     * @return 0 on successfully starting the task
     */
    virtual int Start();

protected:
    /**
     * Composes a file name from a base name and a time value
     *
     * @param filename The base file name (may be a path)
     * @param ltime The time value
     * @param outbuf Returns the composed file name
     * @return 0 on success
     */
    int CreateFilename( const char *filename,
                        time_t ltime,
                        char *outbuf );
    /**
     * Extracts the folder and base name components of a file path
     *
     * @param fileName The full file path to examine
     * @param dirName A buffer in which to place the folder found
     * @param baseName A buffer in which to place the base name found
     */
    static void GetPathComponents( const char *fileName,
                                   char *dirName,
                                   char *baseName );

    /**
     * Counts the number of files with the same initial path as fileName
     * (the same folder and the same base pattern)
     *
     * @param fileName The file name to compare (including a folder)
     * @return The number of matching files
     */
    static int CountFiles( const char *fileName );

    /**
     * Purges (deletes) files with the same initial path as fileName
     * (the same folder and the same base pattern)
     *
     * @param fileName The file name to compare (including a folder)
     * @param maxLogs The number of files to purge to
     * @return The number of files purged
     */
    static int PurgeLogs( const char *fileName, int maxLogs );

    char *m_fileName;
    int m_maxLogs;
    FILE **m_fp;
	PRLock *m_lock;
};

#endif // __LOG_ROTATION_TASK_H__
