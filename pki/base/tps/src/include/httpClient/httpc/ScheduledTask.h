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

#ifndef __SCHEDULED_TASK_H__
#define __SCHEDULED_TASK_H__

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

class TaskList;

/**
 * Base class for scheduled tasks in Presence Server
 */

class EXPORT_DECL ScheduledTask {
    friend class TaskList;
public:
    /**
     * Constructor - creates an empty task
     */
    ScheduledTask();
    /**
     * Constructor - creates an empty task
     *
     * @param name Name of task
     */
    ScheduledTask( const char *name );
    /**
     * Destructor
     */
    virtual ~ScheduledTask();
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
    char *m_name;
    ScheduledTask *m_next;
    ScheduledTask *m_prev;
    time_t m_time;
    int m_interval;
};

#endif // __SCHEDULED_TASK_H__
