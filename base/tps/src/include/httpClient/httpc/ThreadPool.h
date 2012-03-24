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

#ifndef __THREAD_POOL_H
#define __THREAD_POOL_H

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
 * ThreadPool.h	1.000 06/12/2002
 * 
 * A worker thread pool.
 *
 * @author  Surendra Rajam
 * @version 1.000, 06/12/2002
 */

class EXPORT_DECL ThreadPool {
	friend class WorkerThread;
public:
	/**
	 * Constructor - creates the pool with default values
	 *
	 * @param	name	name of the threadpool
	 */
	ThreadPool(const char* name);

	/**
	 * Constructor
	 *
	 * @param	name	name of the threadpool
	 * @param	min		minimum threads in the pool
	 * @param	max		maximum threads that can be created
	 * @param	timeout	timeout for each thread
	 */
	ThreadPool(const char* name, int min, int max, int timeout);
	
	/**
	 * Destructor
	 */
	virtual ~ThreadPool();

public:

	/**
	 * Initializes the thread pool with minimum threads
	 */
	void Init();

	/**
	 * Shutdown the thread pool
	 */
	void Shutdown();

	/**
	 * Adds a task for future execution
	 *
	 * @param	task	a task to execute
	 */
	void AddTask(ScheduledTask* task);	

	/**
	 * Executes the task immediately 
	 *
	 * @param	task	a task to execute
	 */
	void ExecuteTask(ScheduledTask* task);	

	/**
	 * Gets the number of active threads in the pool
	 *
	 * @return	number of active threads
	 */
	int GetThreads();

	/**
	 * Gets the number of pending tasks in the list
	 *
	 * @return	number of pending tasks
	 */
	int GetPendingTasks();

	/**
	 * Function to start a NSPR thread
	 */
	static void StartWorkerThread(void* arg);

private:
	/**
	 * Initializes constructor params
	 */
	void ConstructorInit(const char* name, int min, int max, int timeout);

	/**
	 * Creates a new thread
	 */
	void CreateNewThread();

	/**
	 * Notify one of the threads waiting on a condition
	 */
	void Notify();

private:
	char* m_name;
	TaskList* m_taskList;

	int m_minThreads;
	int m_maxThreads;
	int m_timeout;

	int m_threads;
	int m_activeThreads;

	PRBool m_threadWait;
	PRLock* m_threadLock;
	PRCondVar* m_threadCondVar;

	PRBool m_newThreadInitialized;
	PRLock* m_newThreadLock;
	PRCondVar* m_newThreadCondVar;

	bool m_keepRunning;
};

#endif // __THREAD_POOL_H

