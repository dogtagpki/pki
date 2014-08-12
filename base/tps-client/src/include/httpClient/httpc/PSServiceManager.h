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

#ifndef __PS_SERVICE_MANAGER_H__
#define __PS_SERVICE_MANAGER_H__

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
 * PSServiceManager.h	1.000 05/16/2002
 * 
 * A Singleton class to manage presence services. Currently we support 
 * only one service to be loaded.
 *
 * @author  Surendra Rajam
 * @version 1.000, 05/16/2002
 */
class PSServiceManager :
	public PSServiceListener
{
private:

/**
 * Constructor - creates a service manager object
 */
PSServiceManager();

/**
 * Destructor
 */
virtual ~PSServiceManager();

public:

/**
 * Gets an instance of this class.
 */
static PSServiceManager* GetServiceManager();

public:

/**
 * Registers a listener with this class. Only one listener is 
 * allowed to be registered. If an attempt is made to register
 * more than one listener, then an error condition is raised.
 *
 * @param	listener	a server listener
 * @return	0 on success, negative error upon failure
 */
int RegisterListener(PSServerListener* listener);

/**
 * Loads all providers type plugins. 
 *
 * @return	0 for success, negative error code otherwise
 */
int LoadServices();

/**
 * Unloads all providers type plugins. 
 *
 * @return	0 for success, negative error code otherwise
 */
int UnloadServices();

/**
 * Gets the service currently loaded. Only one service can 
 * be configured at a time.
 *
 * @return	an im service 
 */
PSBuddyService* GetService();

// PSServiceListener interface
public:

/**
 * Callback function to notify the manager of a service being started.
 *
 * @param	service		a buddy service
 */
int OnServiceStart(PSBuddyService* service);

/**
 * Callback function to notify the manager of a service error.
 *
 * @param	service		a buddy service
 * @param	errorcode	a negative error code
 * @param	errorstring	an error message
 */
int OnServiceError(PSBuddyService* service, int errorcode, const char* errorstring);

/**
 * Callback function to notify the manager of a service being stopped.
 *
 * @param	service		a buddy service
 */
int OnServiceStop(PSBuddyService* service);

private:
	char* m_serviceDN;
	PSServerListener* m_serverListener;
	PSBuddyService* m_service;

	bool m_servicesLoaded;
};

#endif // __PS_SERVICE_MANAGER_H__





