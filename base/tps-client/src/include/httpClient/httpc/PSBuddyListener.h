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

#ifndef __PS_BUDDY_LISTENER_H__
#define __PS_BUDDY_LISTENER_H__

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
 * PSBuddyListener.h	1.000 05/15/2002
 * 
 * A listener interface for getting notifications from a buddy service. 
 *
 * @author  Surendra Rajam
 * @version 1.000, 05/15/2002
 */
class PSBuddyListener :
	public PSListener
{
public:

/**
 * Notifies the listener of the buddy status changes
 *
 * @param	the reporting buddy service
 * @param	buddy object containing online status attributes
 * @return 0 on success
 */
virtual int OnBuddyChanged(PSBuddyService*, PSBuddy*) = 0;

/**
 * Notifies the listener of the service to refresh the list 
 * of screen names to the buddy queue 
 *
 * @param	the reporting buddy service
 * @return 0 on success
 */
virtual int OnRefreshList(PSBuddyService*) = 0; 

};

#endif // __PS_BUDDY_LISTENER_H__




