// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.dbs;


import java.util.*;
import netscape.ldap.*;
import netscape.ldap.controls.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.logging.*;


/**
 * A interface represents a virtual list of search results.
 * Note that this class must be used with DS4.0.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface IDBVirtualList {

    /**
     * Sets the paging size of this virtual list.
     * The page size here is just a buffer size. A buffer is kept around
     * that is three times as large as the number of visible entries.
     * That way, you can scroll up/down several items(up to a page-full)
     * without refetching entries from the directory.
     * 
     * @param size the page size
     */
    public void setPageSize(int size);

    /**
     * Sets the sort key
     *
     * @param sortKey the attribute to sort by
     * @exception EBaseException failed to set
     */
    public void setSortKey(String sortKey) throws EBaseException;

    /**
     * Sets the sort key
     *
     * @param sortKeys the attributes to sort by
     * @exception EBaseException failed to set
     */
    public void setSortKey(String[] sortKeys) throws EBaseException;

    /**
     * Retrieves the size of this virtual list.
     * Recommend to call getSize() before getElementAt() or getElements() 
     * since you'd better check if the index is out of bound first.
     *
     * @return current size in list
     */
    public int getSize();

    /**
     * Returns current index.
     *
     * @return current index
     */

    public int getSizeBeforeJumpTo();
    public int getSizeAfterJumpTo();

    public int getCurrentIndex();

    /** 
     * Get a page starting at "first" (although we may also fetch
     * some preceding entries)
     * Recommend to call getSize() before getElementAt() or getElements() 
     * since you'd better check if the index is out of bound first.
     *
     * @param first the index of the first entry of the page you want to fetch
     */
    public boolean getPage(int first);

    /** 
     * Called by application to scroll the list with initial letters.
     * Consider text to be an initial substring of the attribute of the
     * primary sorting key(the first one specified in the sort key array)
     * of an entry.
     * If no entries match, the one just before(or after, if none before)
     * will be returned as mSelectedIndex
     *
     * @param text the prefix of the first entry of the page you want to fetch
     */
    public boolean getPage(String text);

    /** 
     * Fetchs data of a single list item
     * Recommend to call getSize() before getElementAt() or getElements() 
     * since you'd better check if the index is out of bound first.
     * If the index is out of range of the virtual list, an exception 
     * will be thrown and return null
     *
     * @param index the index of the element to fetch
     */
    public Object getElementAt(int index);

    /**
     * Retrieves and jumps to element in the given position.
     *
     * @param i position
     * @return object
     */
    public Object getJumpToElementAt(int i);

    /**
     * Processes elements as soon as it arrives. It is
     * more memory-efficient. 
     *
     * @param startidx starting index
     * @param endidx ending index
     * @param ep object to call
     * @exception EBaseException failed to process elements
     */
    public void processElements(int startidx, int endidx, IElementProcessor ep)
        throws EBaseException;

    /** 
     * Gets the virutal selected index
     *
     * @return selected index
     */
    public int getSelectedIndex();

    /** 
     * Gets the top of the buffer
     *
     * @return first index
     */
    public int getFirstIndex();
}
