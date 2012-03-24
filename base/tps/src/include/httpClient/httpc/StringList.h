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

#ifndef _STRING_LIST_H
#define _STRING_LIST_H

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
 * Simple String list class using the STL List template
 */

#include <list>
#ifdef HPUX
#include <iostream.h>
#else
#include <iostream>
#endif

#include "httpClient/httpc/Iterator.h"

#ifndef HPUX
using namespace std;
#endif

typedef EXPORT_DECL list<const char *> LISTSTR;

class EXPORT_DECL StringList {
public:
	/**
	 * Constructor
	 */
	StringList();

	/**
	 * Destructor
	 */
	~StringList();

	/**
	 * Appends a string to the end of the list
	 *
	 * @param value The string value to append
	 */
	void Add( const char *value );

    /**
     * Gets the string at a particular index in the list
     *
     * @param index Index of the string to retrieve
     * @return The string at the specified index, or NULL if outside
     * the range of the list
     */
    const char *GetAt( int index );

	/**
	 * Returns the index of a string in the list
	 *
	 * @param matchString The string to match
	 * @param startIndex The index to start searching from
	 * @return The index of the string, or -1 if not found
	 */
	int Find( const char *matchString,
						  int startIndex );

	/**
	 * Returns the number of strings in the list
	 *
	 * @return The number of strings in the list
	 */
	int GetCount();

	/**
	 * Inserts a string before the specified position
	 *
	 * @param index Position to insert the string
	 * @param value The string to insert
	 * @return The index of the string, or -1 if the requested index
	 * is beyond the end of the list
	 */
	int Insert( int index, const char *value );

	/**
	 * Removes a string at the specified position
	 *
	 * @param index Position to remove the string
	 * @return 0 on sucess, or -1 if the requested index
	 * is beyond the end of the list
	 */
	int Remove( int index );

	/**
	 * Removes all strings
	 */
	void RemoveAll();

    /**
     * Returns an iterator over strings in the list
     *
     * @return An iterator over strings in the list
     */
    Iterator *GetIterator();

	EXPORT_DECL friend ostream& operator<< ( ostream& os, StringList& list );

protected:
	/**
	 * Gets the iterator for an indexed element
	 *
	 * @param index Position to get
	 * @return Iterator for the position (could be end())
	 */
	LISTSTR::iterator GetIteratorAt( int index );

private:
	LISTSTR m_list;
};

#endif // _STRING_LIST_H
