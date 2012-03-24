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

#ifndef __DEBUG_LOGGER_H__
#define __DEBUG_LOGGER_H__

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

struct PLHashTable;

/**
 * The DebugLogger class writes debug log entries conditionally. A single
 * instance can be shared among modules or different modules can have
 * their own instances. In either case, the log level can be changed
 * globally across all instances with a single function call. All instances
 * write through a singleton to ensure coordination in writing to a single
 * file.
 */
class EXPORT_DECL DebugLogger {
public:
private:
	DebugLogger( const char *moduleName );
	virtual ~DebugLogger();

public:
/**
 * Gets a logger object for a particular module. Provide a module name
 * if there will be more than one logger object in use, with each module
 * having its own instance. Pass NULL if a single logger object will be
 * shared throughout the application.
 *
 * @param moduleName Name of a module
 * @return A logger instance
 */
static DebugLogger *GetDebugLogger( const char *moduleName = NULL );

/**
 * Sets global default values for loggers; the values are assigned to
 * DebugLogger objects created after this call returns
 *
 * @param configParams A table of key-value pairs to assign configuration
 * parameters
 */
static void SetDefaults( PLHashTable *configParams );

/**
 * Sets the log level for this object
 *
 * @param logLevel Log level setting for the module
 */
void SetLogLevel( int logLevel );

/**
 * Gets the log level for this object
 *
 * @return logLevel Log level setting for the object
 */
int GetLogLevel();

/**
 * Sets the log level for a particular module or all modules
 * in all debug logger objects
 *
 * @param logLevel Log level setting for the module
 * @param moduleName Name of the module (does not need to be known before
 * this call); if NULL, the level is applied to all modules
 */
static void SetGlobalLogLevel( int logLevel,
                               const char *moduleName = NULL );

/**
 * Gets the log level for a particular module
 *
 * @param moduleName Name of the module
 * @return logLevel Log level setting for the module
 */
static int GetLogLevel( const char *moduleName );

/**
 * Writes a debug log entry if logLevel is equal to or higher than the
 * logLevel setting of the object
 *
 * @param logLevel One of the log levels defined above
 * @param className The name of the class recording the log entry
 * @param methodName The name of the method that is calling this log method
 * @param fmt A sprintf format string for the remaining arguments
 * @param ... A varargs list of things to log
 * @return 0 on success
 */
int Log( int logLevel,
         const char *className,
         const char *methodName,
         const char *fmt, ... );

/**
 * Writes a trace entry if the logLevel setting of the object is FINER or FINEST
 *
 * @param className The name of the class recording the log entry
 * @param methodName The name of the method that is calling this log method
 * @param args An optional descriptive string
 * @return 0 on success
 */
int Entering( const char *className,
              const char *methodName,
              const char *args = NULL );

/**
 * Writes a trace entry if the logLevel setting of the object is FINER or FINEST
 *
 * @param className The name of the class recording the log entry
 * @param methodName The name of the method that is calling this log method
 * @param args An optional descriptive string
 * @return 0 on success
 */
int Exiting( const char *className,
             const char *methodName,
             const char *args = NULL );
/**
 * Shut down, flushing any buffers and releasing resources
 */
void Close();

/**
 * Shut down, flushing any buffers and releasing resources
 */
static void CloseAll();

protected:
/**
 * Sets the log level for a particular module
 *
 * @param logLevel Log level setting for the module
 * @param moduleName Name of the module (does not need to be known before
 * this call)
 */
static void SetOneLogLevel( int logLevel,
                            const char *moduleName );

private:
/**
 * Initializes the object with parameters from the Config Manager
 *
 * @param configName The name of the configuration entry to use
 * @return 0 on success
 */
static int Initialize( const char *configName );

private:
    int m_level;
    char *m_module;
};

#endif // __DEBUG_LOGGER_H__
