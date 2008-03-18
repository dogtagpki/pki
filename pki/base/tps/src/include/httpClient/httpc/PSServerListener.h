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

#ifndef __PS_SERVER_LISTENER_H__
#define __PS_SERVER_LISTENER_H__

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
 * PSServerListener.h	1.000 04/30/2002
 * 
 * A listener class to report back into the server.
 *
 * @author  Surendra Rajam
 * @version 1.000, 04/30/2002
 */
class EXPORT_DECL PSServerListener :
	public PSListener
{
public:

/**
 * Callback to report startup of a service.
 *
 * @param	reporting module ID
 * @return 0 on success
 */
virtual int OnStartup(const char*) = 0;

/**
 * Callback to report shutdown of a service.
 *
 * @param	reporting module ID
 * @return 0 on success
 */
virtual int OnShutdown(const char*) = 0;

/**
 * Callback to report any errors encountered during service execution.
 *
 * @param	reporting module ID
 * @param	error code
 * @param	error message
 * @return 0 on success
 */
virtual int OnCriticalError(const char*, int, const char*) = 0;

};

#endif	// __PS_SERVER_LISTENER_H__



