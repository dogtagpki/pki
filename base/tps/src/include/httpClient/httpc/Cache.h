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

#ifndef _CACHE_H_
#define _CACHE_H_

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

#include "httpClient/httpc/Iterator.h"

/**
 * Simple cache implementation
 */

/**
 * Contains a cache entry and housekeeping info
 */
class CacheEntry {
public:
    /**
     * Constructor
     *
     * @param key  Pointer to the key being cached
     * @param data Pointer to the data being cached
     */
    CacheEntry( const char *key, void *data );
	/**
	 * Destructor
	 */
	virtual ~CacheEntry();

    /**
     * Returns a pointer to the cached key
     *
     * @return A pointer to the cached key
     */
    const char *GetKey();

    /**
     * Returns a pointer to the cached data
     *
     * @return A pointer to the cached data
     */
    void *GetData();
    /**
     * Returns the time when the entry was created
     *
     * @return The time when the entry was created
     */
	long GetStartTime();

private:
	char *m_key;
    void *m_data;
    time_t m_startTime;
};

/**
 * Contains a generic cache; this is currently an abstract base class
 */
class Cache {
protected:
    /**
     * Default constructor
     */
	Cache();

public:
    /**
     * Constructor
     *
     * @param name of the cache
     * @param ttl Time to live of each cache entry
     * @param implicitLock true if the Cached is to do locking internally
     * when required; false if the caller will take responsibility
     */
	Cache( const char *name, int ttl, bool implictLock = false );

    /**
     * Destructor
     */
	virtual ~Cache();

    /**
     * Returns the number of entries in the cache
     *
     * @return The number of entries in the cache
     */
    virtual int GetCount();

    /**
     * Acquires a read lock on the cache. Multiple threads may simultaneously
     * have a read lock, but attempts to acquire a read lock will block
     * if another thread already has a write lock. It is illegal to request
     * a read lock if the thread already has one.
     */
    void ReadLock();

    /**
     * Acquires a write lock on the cache. Only one thread may have a write
     * lock at any given time; attempts to acquire a write lock will block
     * if another thread already has one. It is illegal to request
     * a write lock if the thread already has one.
     */
    void WriteLock();

    /**
     * Releases a read or write lock that the thread has on the cache
     */
    void Unlock();

protected:
    /**
     * Initializes the object - to be called from the constructor
     *
     * @param name of the cache
     * @param ttl Time to live of each cache entry
     * @param implicitLock true if the Cached is to do locking internally
     * when required; false if the caller will take responsibility
     */
	void Initialize( const char *name, int ttl, bool implictLock );

protected:
	const char *m_name;
	int m_ttl;
	PLHashTable* m_cache;
	PRRWLock* m_cacheLock;
    bool m_implicitLock;
};

/**
 * Contains a cache where the keys are strings
 */
class StringKeyCache : public Cache {
public:
    /**
     * Constructor
     *
     * @param name of the cache
     * @param ttl Time to live of each cache entry
     * @param implicitLock true if the Cached is to do locking internally
     * when required; false if the caller will take responsibility
     */
	StringKeyCache( const char *name, int ttl, bool implictLock = false );

    /**
     * Destructor
     */
	virtual ~StringKeyCache();

    /**
     * Returns a cache entry
     *
     * @param key The name of the cache entry
     * @return The corresponding cache entry, or NULL if not found
     */
	CacheEntry *Get( const char *key );

    /**
     * Adds a cache entry
     *
     * @param key The name of the cache entry; an internal copy is made
     * @param value The value of the cache entry
     * @return The corresponding cache entry, or NULL if it couldn't be added
     */
	CacheEntry *Put( const char *key, void *value );

    /**
     * Removes a cache entry; does not free the entry object
     *
     * @param key The name of the cache entry
     * @return The corresponding cache entry, or NULL if not found
     */
	CacheEntry *Remove( const char *key );

    /**
     * Allocates and returns a list of keys in the cache
     *
     * @param keys Returns an array of names; each name and also the
     * array itself are to be freed by the caller with delete
     * @return The number of keys found
     */
    int GetKeys( char ***keys );

    /**
     * Returns an iterator over keys in the cache
     *
     * @return An iterator over keys in the cache
     */
    Iterator *GetKeyIterator();

};

#endif // _CACHE_H_
