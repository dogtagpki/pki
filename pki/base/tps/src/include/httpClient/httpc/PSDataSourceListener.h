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

#ifndef __PS_DATA_SOURCE_LISTENER_H__
#define __PS_DATA_SOURCE_LISTENER_H__

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

#include "httpClient/httpc/PSUser.h"

/**
 * PSDataSourceListener.h	1.000 04/30/2002
 * 
 * A listener class for data source type plugins. The plugins 
 * notify the data source service manager through the functions 
 * provided by this interface.
 *
 * @author  Surendra Rajam
 * @version 1.000, 04/30/2002
 */
class EXPORT_DECL PSDataSourceListener :
	public PSListener
{
public:

/**
 * Notifies the listener of any errors encountered by
 * the data sources
 *
 * @param	sourceId	reporting source ID
 * @param	errCode		error code
 * @param	errString	error message
 * @return 0 on success
 */
virtual int OnSourceError( const char* sourceId, 
						   int errCode, 
						   const char* errString) = 0;

/**
 * Notifies the listener of any new group
 *
 * @param	group	name of the group
 * @param	nAttrs	number of attributes
 * @param	attrs	array of attributes supported by the group
 * @return 0 on success
 */
virtual int OnNewGroup( const char* group, int nAttrs, char** attrs ) = 0;

/**
 * Notifies the listener of any new users
 *
 * @param	group	name of the group
 * @param	nUsers	number of users
 * @param	users	array containing user objects
 * @return 0 on success
 */
virtual int OnNewUsers( const char* group, int nUsers, PSUser** users ) = 0;

/**
 * Notifies the listener of any changes to the user being
 * watched
 *
 * @param	op		operation to be performed ( add/replace/remove)
 * @param	group	name of the group
 * @param	user	the user object containing modified attributes
 * @return 0 on success
 */
virtual int OnUserChanged(int op, const char* group, PSUser* user) = 0;

};

#endif	// __PS_DATA_SOURCE_LISTENER_H__


