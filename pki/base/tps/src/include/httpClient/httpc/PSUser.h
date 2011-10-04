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

#ifndef __PSUSER_H__
#define __PSUSER_H__

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

#include "PresenceServer.h"

/**
 * PSUser.h	1.000 04/30/2002
 * 
 * This class represents one attribute of a user.
 *
 * @author  Surendra Rajam
 * @version 1.000, 04/30/2002
 */
class EXPORT_DECL PSAttribute
{
public:

/**
 * Construts a new PSAttribute object.
 *
 * @param	name	name of the attribute
 * @param	value	value of the attribute
 */
PSAttribute(const char* name, const char* value);

/**
 * Destructor
 */
virtual ~PSAttribute();

/**
 * Gets the name of the attribute.
 *
 * @return	name of the attribute
 */
char* GetName();

/**
 * Gets the value of the specified attribute.
 *
 * @return	value of the attribute
 */
char* GetValue();

private:
	char* m_name;
	char* m_value;
};

/**
 * PSUser.h	1.000 04/30/2002
 * 
 * This class represents information about a single user. 
 *
 * @author  Surendra Rajam
 * @version 1.000, 04/30/2002
 */
class EXPORT_DECL PSUser
{
public:

/**
 * Construts a new PSUser object with just one attribute.
 *
 * @param	name		name of the user
 * @param	attribute	a user attribute
 */
PSUser(const char* name, PSAttribute* attribute);

/**
 * Construts a new PSUser object with number of attributes.
 *
 * @param	name		name of the user
 * @param	nAttributes	number of attributes
 * @param	attribute	array containing user attributes
 */
PSUser(const char* name, int nAttributes, PSAttribute** attributes);

/**
 * Destructor
 */
virtual ~PSUser();

/**
 * Gets the name of the user.
 *
 * @return	user name
 */
char* GetName();

/**
 * Get the count of user attributes.
 *
 * @return	count of user attributes
 */
int GetCount();

/**
 * Gets a list of attribute objects for the user.
 *
 * @return	array of attribute objects
 */
PSAttribute** GetAttributes();

/**
 * Gets the user attribute based on the specified attribute name.
 *
 * @return	user attribute object on success, NULL otherwise
 */
PSAttribute* Lookup(char* key);

/**
 * Creates a new copy of the current user object.
 *
 * @return	new user object
 */
void Clone(PSUser** user);

private:
	char* m_name;
	int m_attrCount;
	PSAttribute** m_attributes;
};

#endif


