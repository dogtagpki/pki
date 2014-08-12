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

#ifndef __TASK_LIST_H__
#define __TASK_LIST_H__

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

/**
 * Base class for scheduled tasks in Presence Server
 */

class EXPORT_DECL TaskList {
public:
    /**
     * Constructor - creates an empty task list
     *
     * @param name Name of task list
     */
    TaskList( const char *name );
    /**
     * Destructor - Empties the task list, deleting each entry
     */
    virtual ~TaskList();
    /**
     * Returns true if the task list is empty
     *
     * @return true if the task list is empty
     */
    bool IsEmpty();
    /**
     * Adds a task to the list; the list is sorted by execution time
     *
     * @param node An entry to add
     * @return The added entry
     */
    ScheduledTask *Add( ScheduledTask *node );
    /**
     * Removes a node from the list but does not delete it
     *
     * @param taskName The name of the node to remove
     * @return The node with the name taskName, or NULL if not found
     */
    ScheduledTask *Remove( const char *taskName );
    /**
     * Executes each task for which the time is right in a separate thread;
     * if the task is repeating, a new entry is created for it, otherwise
     * it is removed from the list
     *
     * @return The number of tasks executed
     */
    int ExecuteCurrent();
    /**
     * Dumps the task list to the debug log
     *
     * @param logLevel Lowest debug level for which the log should be dumped
     */
    void Dump( int logLevel );
private:
    /**
     * Removes a node from the list but does not delete it; does not lock
     *
     * @param node The node to remove
     * @return The node
     */
    ScheduledTask *InternalRemove( ScheduledTask *node );
    /**
     * Adds a task to the list; the list is sorted by execution time
     *
     * @param node An entry to add
     * @return The added entry
     */
    ScheduledTask *InternalAdd( ScheduledTask *node );

    char *m_name;
    ScheduledTask *m_next;
    int m_interval;
	PRLock *m_lock;
};

#endif /* __TASK_LIST_H__ */

