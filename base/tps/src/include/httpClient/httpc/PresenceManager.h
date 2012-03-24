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

#ifndef __PRESENCEMANAGER_H__
#define __PRESENCEMANAGER_H__

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#define AUTOTOOLS_CONFIG_H
#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

#include "httpClient/httpc/PSUser.h"

/**
 * PresenceManager.h	1.000 04/30/2002
 * 
 * Wrapper class around the core buddylist management API. 
 *
 * @author  Rob Weltman
 * @author  Surendra Rajam
 * @version 1.000, 04/30/2002
 */
class EXPORT_DECL PresenceManager {
public:
    PresenceManager();
    virtual ~PresenceManager();

	int GetUserStatus(const char* group, const char* name, int nAttributes, char** attributes, PSUser** user);
	int GetMultipleUserStatus(const char* group,
							  int nUsers,
							  char** names,
							  int nAttributes,
							  char** attributes,
							  PSUser*** users);
	int GetUsersByFilter(const char* group, const char* filter, int nAttributes, char** attributes, PSUser*** users);
	int GetSortedUsersByFilter(const char* group, const char* filter,
							   const char *sortKey, int sortKeyType,
							   int nAttributes, char** attributes, PSUser*** users);
    /** 
     * Gets the number of users who are online or offline in a group
     * 
     * @param group Name of group to query; NULL or empty for all groups
     * @param bOnline true to return the count of online users, false for
     * offline
     * @return Number of users, or a negative error code on failure 
     *
     * Error Code(s):
     * PS_UNKOWN_GROUP 
     */ 
    int GetUserCount( const char* group, int bOnline );
	int AddGroup(const char* group, int nAttributes, char** attributes); 
	int AddUser(const char* group, const char* name, int nAttributes, PSAttribute** attributes);
	int AddUsers(const char* group, int nUsers, PSUser** users);
	int RemoveUser(const char* group, const char* name);
	int RemoveUsers(const char* group, int nUsers, char** names);
	int RemoveGroup(const char* group); 
	int GetAllGroups(char*** groups);
	int GetAllUsers(const char* group, PSUser*** users); 
	int GetSearchableAttributes(const char* group, char*** attributes);

private:    
};

#endif // __PRESENCEMANAGER_H__
