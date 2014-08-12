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

#ifndef __LOGGER_H__
#define __LOGGER_H__

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

#include <time.h>

struct PRLock;
class LogRotationTask;

/**
 * A base class for writing to a log
 */
class EXPORT_DECL Logger {

protected:
    /**
     * Constructor
     */
	Logger();

    /**
     * Destructor
     */
	virtual ~Logger();

    /**
     * Parses a time string in HH:MM format into a time_t for the next
     * occurrence of the time
     *
     * @param timeString A time string in HH:MM format
     * @return A time_t for the next occurrence of the time, or -1 if the
     * string is not in a valid format
     */
    time_t ParseTime( const char *timeString );

    /**
     * Creates a time-of-day rotation task
     *
     * @param taskName Name of task
     * @param filename Name of log file
     * @param rotationTime Time of day to rotate at
     * @return Rotation task on success
     */
    LogRotationTask *CreateRotationTask( const char *taskName,
                                         const char *filename,
                                         const char *rotationTime );

public:

    /**
     * Shut down, flushing any buffers and releasing resources
     */
    void Close();
    /**
     * Gets the local time of day
     *
     * @param now The current local time of day
     */
    static void GetLocalTime( struct tm *now );

protected:
	int m_rotationSize;
	time_t m_rotationTime;
	int m_maxLogs;
	char *m_dir;
	FILE *m_fp;
    /**
     * Lock for writing to the file
     */
    PRLock *m_fileLock;
    /**
     * Task that rotates a log file
     */
    LogRotationTask *m_rotator;
    /**
     * True if object has been successfully initialized
     */
    bool m_initialized;
};

#endif // __LOGGER_H__
