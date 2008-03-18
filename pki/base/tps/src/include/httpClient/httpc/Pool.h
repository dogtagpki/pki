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

#ifndef __POOL_H__
#define __POOL_H__

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#define AUTOTOOLS_CONFIG_H
#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

/**
 * Utility classes for object pools
 *
 * @author  rweltman@netscape.com
 * @version 1.0
 */

class PoolNode;
class Pool;

typedef int (*PoolEnumerator)(PoolNode *node);

/**
 * A node in a pool
 */
class EXPORT_DECL PoolNode {
    friend class Pool;
public:
    /**
     * Constructor
     *
     * @param data The real data of the node
     */
    PoolNode( void *data );
    /**
     * Destructor
     */
    virtual ~PoolNode();
    /**
     * Returns the real data of the node
     *
     * @return The real data of the node
     */
    void *GetData();
    /**
     * Returns the next entry in the list
     *
     * @return The next entry in the list
     */
    PoolNode *GetNext();
    /**
     * Returns the previous entry in the list
     *
     * @return The previous entry in the list
     */
    PoolNode *GetPrev();
private:
    void *m_data;
    PoolNode *m_next;
    PoolNode *m_prev;
};

/**
 * A generic object pool
 */
class EXPORT_DECL Pool {
public:
    /**
     * Constructor - creates a pool with an internal list of nodes
     *
     * @param name Name of pool
     * @param poolSize Max number of nodes kept
     * @param enumerator Optional enumerator to be called on destruction
     */
    Pool( const char *name, int poolSize, PoolEnumerator enumerator = NULL );
    /**
     * Destructor - Empties the pool
     */
    virtual ~Pool();
    /**
     * Appends an entry to the end of the internal list
     *
     * @param node An entry to add
     * @return The added entry
     */
    PoolNode *Append( PoolNode *node );
    /**
     * Retrieves the head of the internal list and removes it
     *
     * @return The head of the internal list
     */
    PoolNode *RemoveHead();
    /**
     * Returns true if the pool is empty
     *
     * @return true if the pool is empty
     */
    bool IsEmpty();

    /**
     * Returns the number of entries in the pool
     *
     * @return The number of entries in the pool
     */
    int GetCount();

protected:
private:
    PoolNode *m_list;
    char *m_name;
    int m_maxNodes;
    int m_count;
    PoolEnumerator m_enumerator;
	PRRWLock *m_lock;
	PRLock *m_conditionLock;
    PRCondVar *m_condition;
};

#endif // __POOL_H__
