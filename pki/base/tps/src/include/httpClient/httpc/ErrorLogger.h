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

#ifndef __ERROR_LOGGER_H__
#define __ERROR_LOGGER_H__

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

#include "httpClient/httpc/Logger.h"

/**
 * A singleton class for writing to an error log
 */
class EXPORT_DECL ErrorLogger : public Logger {
private:
	ErrorLogger();
	virtual ~ErrorLogger();

public:
    /**
     * Gets a logger object with parameters obtained from the
     * configuration manager
     */
    static ErrorLogger *GetErrorLogger();

    /**
     * Writes an error log entry
     *
     * @param level SEVERE, WARNING, or INFO
     * @param errorCode An error code
     * @param fmt A message to be written to the log
     * @return 0 on success
     */
    int Log( int level,
             int errorCode,
             const char *fmt,
             ... );

    /**
     * Initializes the object with parameters from the Config Manager
     *
     * @param configName The name of the configuration entry to use
     * @return 0 on success
     */
    int Initialize( const char *configName );

protected:
    /**
     * Writes the fixed argument part of an error log entry
     *
     * @param fp File pointer to write to
     * @param level SEVERE, WARNING, or INFO
     * @param errorCode An error code
     * @return 0 on success
     */
    int LogProlog( FILE *fp,
                   int level,
                   int errorCode );
};

#endif // __ERROR_LOGGER_H__
