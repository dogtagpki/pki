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

#ifndef __PS_BUDDY_CACHE_H__
#define __PS_BUDDY_CACHE_H__

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
 * PSBuddyCache.h	1.000 04/30/2002
 * 
 * Cache of PSBuddy objects containing online status
 *
 * @author  Surendra Rajam
 * @version 1.000, 04/30/2002
 */
class PSBuddyCache
{
public:

	/**
	 * Constructor - initializes the internal cache
	 */
	PSBuddyCache();

	/**
	 * Destructor
	 */
	virtual ~PSBuddyCache();

	/**
	 * Adds a buddy to the cache. The old entry, if exists, is deleted
	 * from the cache
	 *
	 * @param	name	name of the new buddy
	 * @param	buddy	object containing onlinestatus attributes
	 * @return	0 on success
	 */
	int AddBuddy(const char* name, PSBuddy* buddy);

	/**
	 * Removes a buddy from the cache
	 *
	 * @param	name	name of the buddy to be removed
	 * @return	0 on success
	 */
	int RemoveBuddy(const char* name);

	/**
	 * Gets the buddy object
	 *
	 * @param	name	name of the new buddy
	 * @return	object containing onlinestatus attributes, NULL if not found
	 */
	PSBuddy* GetBuddy(const char* name);

	/**
	 * Gets count of buddies in the cache
	 *
	 * @return	count of buddies
	 */
	int GetBuddyCount();

	/**
	 * Gets all the screen names  
	 *
	 * @param	names	On return, contains array of screen names
	 * @return	number of screen names
	 */
	int GetAllBuddies(char*** names);

	/**
	 * Acquires a read lock on the cache. Multiple threads may simultaneously
	 * have a read lock, but attempts to acquire a read lock will block
	 * if another thread already has a write lock. It is illegal to request
	 * a read lock if the thread already has one.
	 */
	void ReadLock();

	/**
	 * Releases a read lock that the thread has on the cache
	 */
	void Unlock();

private:
	StringKeyCache* m_buddies;
};

#endif // __PS_BUDDY_CACHE_H__


