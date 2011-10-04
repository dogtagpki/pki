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

#ifndef __PS_DATA_SOURCE_MANAGER_H__
#define __PS_DATA_SOURCE_MANAGER_H__

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
 * PSDataSourceManager.h	1.000 05/21/2002
 * 
 * This class manages presence server data sources plugins. 
 *
 * @author  Surendra Rajam
 * @version 1.000, 05/21/2002
 */
class PSDataSourceManager :
	public PSDataSourceListener
{
private:

	/**
	 * Constructor - creates a data source manager object
	 */
	PSDataSourceManager();

	/**
	 * Destructor
	 */
	virtual ~PSDataSourceManager();

public:

	/**
	 * Gets an instance of this class.
	 */
	static PSDataSourceManager* GetDataSourceManager();

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
	 * Loads all data source type plugins.
	 *
	 * @return	0 for success, negative error code otherwise
	 */
	int LoadDataSources();

	/**
	 * Unloads all data source type plugins.
	 *
	 * @return	0 for success, negative error code otherwise
	 */
	int UnloadDataSources();

// PSDataSourceListener interface
public:

	/**
	 * Callback function to notify the manager upon data source error.
	 *
	 * @param	sourceid	id of the source calling 
	 * @param	errorcode	error code
	 * @param	errorstring	error string
	 * @return				0 on success
	 * 
	 */
	int OnSourceError(const char* sourceid, int errorcode, const char* errorstring);

	/**
	 * Callback function to notify the manager upon new group.
	 *
	 * @param     group		name of the new group 
	 * @param     nAttrs	number of attributes 
	 * @param     attrs		attributes the group will support 
	 * @return              0 on success
	 * 
	 */
	int OnNewGroup(const char* group, int nAttrs, char** attrs);

	/**
	 * Callback function to notify the manager of new users
	 *
	 * @param	group	name of the group
	 * @param	nUsers	number of users
	 * @param	users	array containing user objects
	 * @return 0 on success, a negative error code on failure 
	 */
	int OnNewUsers(const char* group, int nUsers, PSUser** users); 

	/**
	 * Callback function to notify the manager of changes to a user.
	 * The valid operations are :
	 *		PS_OPERATION_ADD
	 *		PS_OPERATION_REPLACE
	 *		PS_OPERATION_DELETE
	 *
	 * @param	op		operation to be performed
	 * @param	group	name of the group
	 * @param	user	the user object containing modified attributes
	 * @return 0 on success, a negative error code on failure 
	 */
	int OnUserChanged(int op, const char* group, PSUser* user);

private:
	char* m_dataSourceDN;
	PSServerListener* m_serverListener;
	bool m_dataSourcesLoaded;
};

#endif // __PS_DATA_SOURCE_MANAGER_H__
