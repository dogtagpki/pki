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

#ifndef __ACCESS_LOGGER_H__
#define __ACCESS_LOGGER_H__

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
 * A singleton class for writing to an access log
 */
class EXPORT_DECL AccessLogger : public Logger {
private:
	AccessLogger();
	virtual ~AccessLogger();

public:
/**
 * Gets a logger object with parameters obtained from the configuration manager
 */
static AccessLogger *GetAccessLogger();

/**
 * Writes an access log entry
 *
 * @param hostName The IP address or host name of the requestor
 * @param userName The authenticated user name; NULL or "" if not authenticated
 * @param requestName The name of the requested function
 * @param status The status returned to the client
 * @param responseLength The number of bytes returned to the client
 * @return 0 on success
 */
int Log( const char *hostName,
		 const char *userName,
		 const char *requestName,
		 int status,
		 int responseLength );

/**
 * Initializes the object with parameters from the Config Manager
 *
 * @param configName The name of the configuration entry to use
 * @return 0 on success
 */
	int Initialize( const char *configName );

/**
 * Flush any unwritten buffers
 */
void Flush();

protected:
/**
 * Gets a formatted timestamp
 *
 * @param now The current time
 * @param buffer Buffer to put time in
 * @return A formatted timestamp
 */
char *GetTimeStamp( struct tm *now, char *buffer );

private:
	char *m_buffer;
	int m_bufferIndex;
	int m_bufferTime;
	int m_bufferSize;
	time_t m_lastWrite;
    char m_gmtOffset[16];
};

#endif // __ACCESS_LOGGER_H__
