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

/**
 * Simple cache implementation
 */
#include <string.h>
#include <time.h>

// NSS includes
#include "pk11func.h"
#include "hasht.h"

// NSPR includes
#include "nspr.h"
#include "plhash.h"
#include "plstr.h"
#include "plbase64.h"

// Always before PSCommonLib.h
#define COMMON_LIB_DLL
#include "httpClient/httpc/PSCommonLib.h"
#include "httpClient/httpc/Defines.h"
//-- #include "httpClient/httpc/PSError.h"
#include "httpClient/httpc/Iterator.h"
#include "httpClient/httpc/Cache.h"
//-- #include "httpClient/httpc/DebugLogger.h"
//-- #include "httpClient/httpc/ErrorLogger.h"

#include "engine/RA.h"
#include "main/Memory.h"

//-- static const char *DEBUG_MODULE = NULL;
//-- static const char *DEBUG_CLASS_NAME = "StringKeyCache";

// From the NSPR implementation of hashtables
/* Compute the number of buckets in ht */
#define NBUCKETS(ht)    (1 << (PL_HASH_BITS - (ht)->shift))


/**
 * Called from the destructor
 */
extern "C" {
static PRIntn onCacheRelease( PLHashEntry* he, PRIntn index, void* arg );
/**
 * Called to allocate and return copies of keys
 */
static PRIntn getKeys( PLHashEntry* he, PRIntn index, void* arg );
}

/**
 * Constructor
 *
 * @param key  Pointer to the key being cached
 * @param data Pointer to the data being cached
 */
CacheEntry::CacheEntry( const char* key, void *data ) {
    if( key != NULL ) {
        m_key = strdup( key );
    } else {
        m_key = NULL; 
    }
    m_data = data;
    // NSPR counts in microseconds
    m_startTime = (time_t)(PR_Now() / 1000000);
}

/**
 * Destructor
 */
CacheEntry::~CacheEntry() {
    if( m_key != NULL ) {
        free( m_key );
        m_key = NULL;
    }
}

/**
 * Returns a pointer to the cached key
 *
 * @return A pointer to the cached key
 */
const char *CacheEntry::GetKey() {
	return m_key;
}

/**
 * Returns a pointer to the cached data
 *
 * @return A pointer to the cached data
 */
void *CacheEntry::GetData() {
    return m_data;
}


/**
 * Returns the time when the entry was created
 *
 * @return The time when the entry was created
 */
long CacheEntry::GetStartTime() {
    return (long)m_startTime;
}


/**
 * Default constructor
 */
Cache::Cache() {
    m_cache = NULL;
    m_cacheLock = NULL;
}

/**
 * Constructor
 *
 * @param name of the cache
 * @param ttl Time to live of each cache entry
 * @param implicitLock true if the Cache is to do locking internally
 * when required; false if the caller will take responsibility
 */
Cache::Cache( const char *name, int ttl, bool implicitLock ) {

    Initialize( name, ttl, implicitLock );
}

/**
 * Destructor
 */
Cache::~Cache() {

    if( m_cacheLock ) {
        PR_DestroyRWLock( m_cacheLock );
        m_cacheLock = NULL;
    }
	if( m_cache ) {
		PL_HashTableEnumerateEntries( m_cache, onCacheRelease, NULL );
		PL_HashTableDestroy( m_cache );
        m_cache = NULL;
	}

}

/**
 * Initializes the object - to be called from the constructor
 *
 * @param name of the cache
 * @param ttl Time to live of each cache entry
 * @param implicitLock true if the Cache is to do locking internally
 * when required; false if the caller will take responsibility
 */
void Cache::Initialize( const char *name, int ttl, bool implicitLock ) {

    if ( !m_cache ) {
        m_implicitLock = implicitLock;
        m_ttl = ttl;
        m_cache = PL_NewHashTable( 0,
                                   PL_HashString,
                                   PL_CompareStrings,
                                   PL_CompareValues,
                                   NULL,
                                   NULL
            );
        m_cacheLock	= PR_NewRWLock( PR_RWLOCK_RANK_NONE, name );
        m_name = name;
    }

}

/**
 * Acquires a read lock on the cache. Multiple threads may simultaneously
 * have a read lock, but attempts to acquire a read lock will block
 * if another thread already has a write lock. It is illegal to request
 * a read lock if the thread already has one.
 */
void Cache::ReadLock() {
	PR_RWLock_Rlock( m_cacheLock );
}

/**
 * Acquires a write lock on the cache. Only one thread may have a write
 * lock at any given time; attempts to acquire a write lock will block
 * if another thread already has one. It is illegal to request
 * a write lock if the thread already has one.
 */
void Cache::WriteLock() {
	PR_RWLock_Wlock( m_cacheLock );
}

/**
 * Releases a read or write lock that the thread has on the cache
 */
void Cache::Unlock() {
	PR_RWLock_Unlock( m_cacheLock );
}

/**
 * Returns the number of entries in the cache
 *
 * @return The number of entries in the cache
 */
int Cache::GetCount() {
    int nKeys = 0;
    if ( m_implicitLock ) {
        ReadLock();
    }
    nKeys = m_cache->nentries;
    if ( m_implicitLock ) {
        Unlock();
    }
    return nKeys;
}

class KeyIterator : public Iterator {
public:
    /**
     * Constructor
     *
     * @param ht A hashtable to iterate on
     * @param cacheLock Lock for accessing the hashtable
     * @param implictLock true if hashtable locking is to be done
     * internally
     */
    KeyIterator( PLHashTable *ht, PRRWLock *cacheLock, bool implicitLock ) {
        m_table = ht;
        m_bucketIndex = 0;
        m_entry = m_table->buckets[m_bucketIndex];
        m_cacheLock = cacheLock;
        m_implicitLock = implicitLock;
    }

    /**
     * Destructor
     */
    virtual ~KeyIterator() {
    }

    /**
     * Returns true if there is at least one more key
     *
     * @return true if there is at least one more key
     */
    bool HasMore() {
        if ( NULL == m_entry ) {
            Next();
        }
        return ( NULL != m_entry );
    }

   /**
     * Returns the next key, if any; the key is deallocated by the Iterator
     * in its destructor
     *
     * @return The next key, if any, or NULL
     */
    void *Next() {
        PLHashEntry *he = m_entry;
        m_entry = (m_entry != NULL) ? m_entry->next : NULL;
        int nBuckets = NBUCKETS(m_table);
        if ( m_implicitLock ) {
            PR_RWLock_Rlock( m_cacheLock );
        }
        while ( (NULL == m_entry) && (m_bucketIndex < (nBuckets-1)) ) {
            m_bucketIndex++;
            m_entry = m_table->buckets[m_bucketIndex];
        }
        if ( m_implicitLock ) {
            PR_RWLock_Unlock( m_cacheLock );
        }
        return ( he != NULL ) ? (void *)he->key : NULL;
    }

private:
    PLHashTable *m_table;
    PLHashEntry *m_entry;
    int m_bucketIndex;
	PRRWLock* m_cacheLock;
    bool m_implicitLock;
};

/**
 * Constructor
 *
 * @param name of the cache
 * @param ttl Time to live of each cache entry
 * @param implicitLock true if the Cache is to do locking internally
 * when required; false if the caller will take responsibility
 */
StringKeyCache::StringKeyCache( const char *name, int ttl,
                                bool implicitLock ) {

    Initialize( name, ttl, implicitLock );

}

/**
 * Destructor
 */
StringKeyCache::~StringKeyCache() {
}

/**
 * Returns a cache entry
 *
 * @param key The name of the cache entry
 * @return The corresponding cache entry, or NULL if not found
 */
CacheEntry *StringKeyCache::Get( const char *key ) {
    // Avoid recursion when the debug log is starting up

    if ( m_implicitLock ) {
        ReadLock();
    }
	CacheEntry *entry =
		(CacheEntry *)PL_HashTableLookupConst( m_cache, key );
    if ( m_implicitLock ) {
        Unlock();
    }
	if ( entry && m_ttl ) {
		// Check if the cache entry has expired
        // NSPR counts in microseconds
        time_t now = (time_t)(PR_Now() / 1000000);
		if ( ((long)now - entry->GetStartTime()) > m_ttl ) {
            if( key != NULL ) {
                Remove( key );
                key = NULL;
            }
            if( entry != NULL ) {
                delete entry;
                entry = NULL;
            }
			 // Avoid recursion when the debug log is starting up
     		if ( PL_strcasecmp( m_name, "DebugLogModuleCache" ) ) {
//--          		DebugLogger *logger = DebugLogger::GetDebugLogger( DEBUG_MODULE );
//--          		logger->Log( LOGLEVEL_FINER, DEBUG_CLASS_NAME,
//--                          "Get",
                   RA::Debug( LL_PER_PDU,
                              "StringKeyCache::Get: ",
                              "Entry %s expired from cache %s",
                              key,
                              m_name ); 
        	}
		}
    }

	return entry;
}

/**
 * Adds a cache entry
 *
 * @param key The name of the cache entry; an internal copy is made
 * @param value The value of the cache entry
 * @return The corresponding cache entry, or NULL if it couldn't be added
 */
CacheEntry *StringKeyCache::Put( const char *key, void *value ) {
	CacheEntry *entry = new CacheEntry( key, value );
    if ( m_implicitLock ) {
        WriteLock();
    }
    PL_HashTableAdd( m_cache, entry->GetKey(), entry );
    if ( m_implicitLock ) {
        Unlock();
    }

	return entry;
}

/**
 * Removes a cache entry; does not free the entry object
 *
 * @param key The name of the cache entry
 * @return The corresponding cache entry, or NULL if not found
 */
CacheEntry *StringKeyCache::Remove( const char *key ) {

    if ( m_implicitLock ) {
        WriteLock();
    }
	CacheEntry *entry =
		(CacheEntry *)PL_HashTableLookupConst( m_cache, key );
	if( entry ) {
		PL_HashTableRemove( m_cache, key );
	}
    if ( m_implicitLock ) {
        Unlock();
    }

	return entry;
}

class KeyArray {
public:
    KeyArray( int nKeys ) {
        m_nKeys = nKeys;
        m_keys = new char *[m_nKeys];
        m_currentKey = 0;
    }
    virtual ~KeyArray() {
    }
    int m_currentKey;
    int m_nKeys;
    char **m_keys;
};

/**
 * Returns an iterator over keys in the cache
 *
 * @return An iterator over keys in the cache
 */
Iterator *StringKeyCache::GetKeyIterator() {
    return new KeyIterator( m_cache, m_cacheLock, m_implicitLock );
}

/**
 * Allocates and returns a list of keys in the cache
 *
 * @param keys Returns an array of names; each name and also the
 * array itself are to be freed by the caller with delete
 * @return The number of keys found
 */
int StringKeyCache::GetKeys( char ***keys ) {

    int nKeys = GetCount();
    if ( m_implicitLock ) {
        ReadLock();
    }
    KeyArray keyArray( nKeys );
    PL_HashTableEnumerateEntries( m_cache, getKeys, &keyArray );
    if ( m_implicitLock ) {
        Unlock();
    }
    if( ( keyArray.m_nKeys < 1 ) && keyArray.m_keys ) {
        delete [] keyArray.m_keys;
        keyArray.m_keys = NULL;
    }
    *keys = keyArray.m_keys;

    return keyArray.m_nKeys;
}

/**
 * Adds cache entry keys to an accumulator
 */
extern "C" {
static PRIntn getKeys( PLHashEntry* he, PRIntn index, void* arg ) {
	PRIntn result = HT_ENUMERATE_NEXT;
	if ( he != NULL ) {
		if ( he->key ) {
            KeyArray *keys = (KeyArray *)arg;
            int len = strlen( (char *)he->key );
            int i = keys->m_currentKey;
            keys->m_keys[i] = new char[len+1];
            strcpy( keys->m_keys[i], (char *)he->key );
            keys->m_currentKey++;
		}
	}
	return result;
}

/**
 * Frees keys of entries in cache; does not free values
 */
static PRIntn onCacheRelease( PLHashEntry* he, PRIntn index, void* arg ) {
    PRIntn result = HT_ENUMERATE_NEXT;
    if( he != NULL ) {
        if( he->key != NULL ) {
            free( (char *) he->key );
            he->key = NULL;
            result = HT_ENUMERATE_REMOVE;
        }
    }
    return result;
}
} // extern "C"
