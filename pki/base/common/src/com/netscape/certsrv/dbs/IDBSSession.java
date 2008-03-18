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
import com.netscape.certsrv.base.*;


/**
 * An interface represents the database session. Operations
 * can be performed with a session.
 *
 * Transaction and Caching support can be integrated 
 * into session.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $ 
 */
public interface IDBSSession {

    /**
     * Returns database subsystem.
     *
     * @return subsystem
     */
    public ISubsystem getDBSubsystem();

    /**
     * Closes this session.
     *
     * @exception EDBException failed to close session
     */
    public void close() throws EDBException;

    /**
     * Adds object to backend database. For example,
     * <PRE>
     *    session.add("cn=123459,o=certificate repository,o=airius.com", 
     * 			certRec);
     * </PRE>
     *
     * @param name name of the object
     * @param obj object to be added
     * @exception EDBException failed to add object
     */
    public void add(String name, IDBObj obj) throws EBaseException;

    /**
     * Reads an object from the database.
     *
     * @param name name of the object that is to be read
     * @return database object
     * @exception EBaseException failed to read object
     */
    public IDBObj read(String name) throws EBaseException;

    /**
     * Reads an object from the database, and only populates
     * the selected attributes.
     *
     * @param name name of the object that is to be read
     * @param attrs selected attributes
     * @return database object
     * @exception EBaseException failed to read object
     */
    public IDBObj read(String name, String attrs[]) 
        throws EBaseException;

    /**
     * Deletes object from database.
     *
     * @param name name of the object that is to be deleted
     * @exception EBaseException failed to delete object
     */
    public void delete(String name) throws EBaseException;

    /**
     * Modify an object in the database.
     *
     * @param name name of the object that is to be modified
     * @param mods modifications
     * @exception EBaseException failed to modify
     */
    public void modify(String name, ModificationSet mods) 
        throws EBaseException;

    /**
     * Searchs for a list of objects that match the 
     * filter.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @return search results
     * @exception EBaseException failed to search
     */
    public IDBSearchResults search(String base, String filter) 
        throws EBaseException;

    /**
     * Searchs for a list of objects that match the 
     * filter.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param maxSize max number of entries
     * @return search results
     * @exception EBaseException failed to search
     */
    public IDBSearchResults search(String base, String filter, int maxSize) 
        throws EBaseException;

    /**
     * Searchs for a list of objects that match the 
     * filter.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param maxSize max number of entries
     * @param timeLimit timeout limit
     * @return search results
     * @exception EBaseException failed to search
     */
    public IDBSearchResults search(String base, String filter, int maxSize, 
        int timeLimit) throws EBaseException;

    /**
     * Retrieves a list of object that satifies the given 
     * filter.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param attrs selected attributes
     * @return search results
     * @exception EBaseException failed to search
     */
    public IDBSearchResults search(String base, String filter, 
        String attrs[]) throws EBaseException;

    /**
     * Retrieves a list of objects.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param attrs selected attributes
     * @return search results in virtual list
     * @exception EBaseException failed to search
     */
    public IDBVirtualList createVirtualList(String base, String filter, 
        String attrs[]) throws EBaseException;

    /**
     * Sets persistent search to retrieve modified
     * certificate records.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param attrs selected attributes
     * @return LDAP search results
     * @exception EBaseException failed to search
     */
    public LDAPSearchResults persistentSearch(String base, String filter,
        String attrs[]) throws EBaseException;

    /**
     * Retrieves a list of objects.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param attrs selected attributes
     * @param sortKey key used to sort the list
     * @param pageSize page size in the virtual list
     * @return search results in virtual list
     * @exception EBaseException failed to search
     */
    public IDBVirtualList createVirtualList(String base, String filter, 
        String attrs[], String sortKey, int pageSize) 
        throws EBaseException;

    /**
     * Retrieves a list of objects.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param attrs selected attributes
     * @param startFrom starting point
     * @param sortKey key used to sort the list
     * @param pageSize page size in the virtual list
     * @return search results in virtual list
     * @exception EBaseException failed to search
     */
    public IDBVirtualList createVirtualList(String base, String filter, 
        String attrs[], String startFrom, 
        String sortKey, int pageSize) 
        throws EBaseException;
}
