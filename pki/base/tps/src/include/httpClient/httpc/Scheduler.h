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

#ifndef __SCHEDULER_H__
#define __SCHEDULER_H__

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

class ScheduledTask;
class TaskList;

/**
 * Base class for scheduled tasks in Presence Server
 */

class EXPORT_DECL Scheduler {
private:
    /**
     * Constructor - creates a scheduler object
     */
    Scheduler();
    /**
     * Destructor
     */
    ~Scheduler();
public:
    /**
     * Returns the single scheduler object
     *
     * @return The single scheduler object
     */
    static Scheduler *GetScheduler();
    /**
     * Starts executing a sleep and check task list loop
     *
     * @return 0 on success
     */
    int Run();
    /**
     * Shuts down the scheduler
     */
    static void Shutdown();
    /**
     * Launches a thread that executes Run()
     *
     * @param interval Interval in seconds between checking for task execution
     * time
     * @return 0 on success
     */
    int Start( int interval );
    /**
     * Adds a task to the list
     *
     * @param task A task to be executed
     */
    void AddTask( ScheduledTask *task );
    /**
     * Removes a task from the list
     *
     * @param taskName Name of a task to be removed
     */
    void RemoveTask( const char *taskName );
private:
    TaskList *m_taskList;
    int m_interval;
    bool m_done;
    bool m_running;
};

#endif /* __SCHEDULER_H__ */

