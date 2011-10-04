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

#ifndef __PS_PLUGIN_MANAGER_H__
#define __PS_PLUGIN_MANAGER_H__

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
 * PSPluginManager.h	1.000 05/21/2002
 * 
 * This class manages loading and unloading of all server plugin modules. 
 *
 * @author  Surendra Rajam
 * @version 1.000, 05/21/2002
 */
class PSPluginManager
{
private:

/**
 * Constructor - creates an instance of Plugin manager object
 */
PSPluginManager();

/**
 * Destructor
 */
virtual ~PSPluginManager();

public:

/**
 * Gets an instance of the class
 */
static PSPluginManager* GetPluginManager();

public:

/**
 * Loads a group of plugins based on the type (dn) specified. If the loading 
 * is successful the specified listener is registered with the plugin and 
 * the plugin is started.
 *
 * @param dn		root DN of the plugins
 * @param listener	listener associated with the specified type of plugins
 * @return 0 on success, negative error code otherwise
 */
int LoadPlugin(const char* dn, PSListener* listener);

/**
 * Unloads a group of plugins based on the type ( dn ) specified. 
 * This function just issues a Stop on all the loaded plugins. 
 * It doesn't attempt to release any allocated data structures.
 *
 * @param dn	root DN of the plugins
 * @return		0 for success or error code for failure
 */
int UnloadPlugin(const char* dn);

private:
	StringKeyCache* m_serverPlugins;
};

#endif // __PS_PLUGIN_MANAGER_H__





