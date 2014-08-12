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

#ifndef __PS_GROUP_H__
#define __PS_GROUP_H__

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

class PSUser;

/**
 * PSGroup.h	1.000 04/30/2002
 * 
 * This class stores information about the users belonging to a group. 
 * All the users must belong to at least one group in the server.
 *
 * @author  Surendra Rajam
 * @version 1.000, 04/30/2002
 */
class PSGroup
{
public:
	PSGroup(const char* name, int nAttributes, char** attributes);
	virtual ~PSGroup();

public:
	char* GetName();
	int GetAttributeCount();
	char** GetAttributes();
	int GetAttributes(int offset, char** & attributes);

	int AddUser(PSUser* user);
	int RemoveUser(const char* name);
	PSUser* GetUser(const char* name);
	bool UserExists(const char* name);

	int GetUserCount();
	int GetAllUsers(int offset, PSUser** & users, int maxcount);
	int GetAllUsers(int offset, char** & names, int maxcount);

	int UpdateStatus(const char* name, bool changeToOnline);
	int GetOnlineUsers(char*** names);
	int GetOfflineUsers(char*** names);
	int GetOnlineCount();
	int GetOfflineCount();

	void ReadLock();
	void Unlock();

private:
	char* m_name;
	int m_count;
	char** m_attributes;

	PRRWLock* m_psOnlineLock;
	PRRWLock* m_psOfflineLock;
	StringList* m_psOnlineUsers;
	StringList* m_psOfflineUsers;

	StringKeyCache* m_users;
};

#endif // __PS_GROUP_H__


