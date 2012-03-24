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

#ifndef __PS_SERVER_MANAGER_H__
#define __PS_SERVER_MANAGER_H__

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
 * PSServerManager.h	1.000 05/21/2002
 * 
 * This class manages the server execution. It is responsible for loading
 * of configurations, starting of services and proper shutdown of services. 
 *
 * @author  Surendra Rajam
 * @version 1.000, 05/21/2002
 */
class PSServerManager :
	public PSServerListener
{
private:

/**
 * Constructor - creates an instance of server manager object
 */
PSServerManager();

/**
 * Destructor
 */
virtual ~PSServerManager();

public:

/**
 * Gets an instance of this class.
 */
static PSServerManager* GetServerManager();

public:

/**
 * Loads general configuration into the ConfigManager
 *
 * @return 0 on success, negative error code otherwise
 */
int InitServices();

/**
 * Starts services after server startup. The presence services are 
 * started before anything else and if it fails then no attempt is 
 * made to start other services. 
 * 
 * @return		0 on success, negative error code otherwise
 */
int StartServices();

/**
 * Stops services before server shutdown.
 * 
 * @return		0 on success, negative error code otherwise
 */
int StopServices();

private:

/**
 * Loads one configuration entry
 *
 * @param configdn		The DN of the LDAP entry containing the config
 * @param configName	The name of the config entry
 * @param descr			A description of the config entry
 * @return				0 on success
 */
int LoadOneConfig(const char* configdn, const char* configName, const char* descr);

// PSServerListener interface
public:

/**
 * Callback to notify server upon a service startup
 *
 * @param moduleid	the notifying service id
 * @return			0 on success
 */
int OnStartup(const char* moduleid);

/**
 * Callback to notify server upon a service shutdown
 *
 * @param moduleid	the notifying service id
 * @return			0 on success
 */
int OnShutdown(const char* moduleid);

/**
 * Callback to notify server upon a critical errors. The server immediately
 * shuts down upon receipt of any such notification.
 *
 * @param moduleid		the notifying service id
 * @param errorcode		negative error code
 * @param errorstring	negative error code
 * @return				0 on success
 */
int OnCriticalError(const char* moduleid, int errorcode, const char* errorstring);

private:
	bool m_loadServiceDone;
};

#endif // __PS_SERVER_MANAGER_H__


