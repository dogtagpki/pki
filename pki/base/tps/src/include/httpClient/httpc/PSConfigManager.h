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

#ifndef __PS_CONFIG_MANAGER_H__
#define __PS_CONFIG_MANAGER_H__

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
 * PSConfigManager.h	1.000 04/30/2002
 * 
 * This class is a singleton that provides access to configuration parameters
 * for the Presence Server.
 *
 * @author  rweltman@netscape.com
 * @version 1.0
 */
class EXPORT_DECL PSConfigManager {
private:
	PSConfigManager();
	virtual ~PSConfigManager();

public:
	static PSConfigManager *GetConfigManager();

public:
	void SetConfigEntry( PSConfig *entry );
	PSConfig *GetConfigEntry( const char *name );

private:
	PLHashTable* m_configEntries;
};

#endif // __PS_CONFIG_MANAGER_H__
