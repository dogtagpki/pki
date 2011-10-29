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

#ifndef __PS_BUDDY_SERVICE_H__
#define __PS_BUDDY_SERVICE_H__

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
 * PSBuddyService.h	1.000 05/16/2002
 * 
 * A pure virtual class defining Buddy Service interface 
 * to be implemented by the various IM presence service providers. 
 *
 * @author  Surendra Rajam
 * @version 1.000, 05/16/2002
 */
class EXPORT_DECL PSBuddyService {
public:

/**
 * Registers a listener with this class. The listener 
 * is notified of any changes to the buddies being tracked.
 *
 * @param	a buddy service listener
 * @return 0 on success
 */
virtual int RegisterListener(PSListener*) = 0;

/**
 * An entry point to start the service. This function is responsible
 * for authentication with the backend service.
 *
 * @param	config parameters for the service to start
 * @return 0 on success
 */
virtual int SignOn(PSConfig*) = 0;

/**
 * Shutdown of the service.
 *
 * @return 0 on success
 */
virtual int SignOff() = 0;

/**
 * Sets a user name for online status tracking.
 *
 * @param	user name to be tracked
 * @return 0 on success
 */
virtual int WatchBuddy(const char*) = 0;	

/**
 * Sets a number of users for online status tracking
 *
 * @param	number of users to be tracked
 * @param	array of user names
 * @return 0 on success
 */
virtual int WatchBuddies(int, char**) = 0;

/**
 * Unsets a user name from online status tracking.
 *
 * @param	user name to be tracked
 * @return 0 on success
 */
virtual int UnwatchBuddy(const char*) = 0;

/**
 * Unsets a number of users from online status tracking
 *
 * @param	number of users to be tracked
 * @param	array of user names
 * @return 0 on success
 */
virtual int UnwatchBuddies(int, char**) = 0;

/**
 * Gets the service config entry
 *
 * @return config object
 */
virtual PSConfig* GetServiceConfig() = 0;

};

#endif // __PS_BUDDY_SERVICE_H__


