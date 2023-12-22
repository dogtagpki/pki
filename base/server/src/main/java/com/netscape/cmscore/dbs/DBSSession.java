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
package com.netscape.cmscore.dbs;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBPagedSearch;
import com.netscape.certsrv.dbs.DBVirtualList;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.ModificationSet;

import netscape.ldap.LDAPSearchResults;

/**
 * An interface represents the database session. Operations
 * can be performed with a session.
 *
 * Transaction and Caching support can be integrated
 * into session.
 */
public class DBSSession implements AutoCloseable {

    /**
     * Closes this session.
     *
     * @exception EDBException failed to close session
     */
    @Override
    public void close() throws EDBException {
    }

    /**
     * Adds object to backend database. For example,
     *
     * <PRE>
     * session.add("cn=123459,o=certificate repository,o=airius.com", record);
     * </PRE>
     *
     * @param name name of the object
     * @param obj object to be added
     * @exception EDBException failed to add object
     */
    public void add(String name, IDBObj obj) throws EBaseException {
    }

    /**
     * Reads an object from the database.
     *
     * @param name name of the object that is to be read
     * @return database object
     * @exception EBaseException failed to read object
     */
    public IDBObj read(String name) throws EBaseException {
        return null;
    }

    /**
     * Reads an object from the database, and only populates
     * the selected attributes.
     *
     * @param name name of the object that is to be read
     * @param attrs selected attributes
     * @return database object
     * @exception EBaseException failed to read object
     */
    public IDBObj read(String name, String[] attrs) throws EBaseException {
        return null;
    }

    /**
     * Deletes object from database.
     *
     * @param name name of the object that is to be deleted
     * @exception EBaseException failed to delete object
     */
    public void delete(String name) throws EBaseException {
    }

    /**
     * Modify an object in the database.
     *
     * @param name name of the object that is to be modified
     * @param mods modifications
     * @exception EBaseException failed to modify
     */
    public void modify(String name, ModificationSet mods) throws EBaseException {
    }

    /**
     * Searchs for a list of objects that match the
     * filter.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @return search results
     * @exception EBaseException failed to search
     */
    public DBSearchResults search(String base, String filter) throws EBaseException {
        return null;
    }

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
    public DBSearchResults search(
            String base,
            String filter,
            int maxSize
            ) throws EBaseException {
        return null;
    }

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
    public DBSearchResults search(
            String base,
            String filter,
            int maxSize,
            int timeLimit
            ) throws EBaseException {
        return null;
    }

    /**
     * Searchs for a list of objects that match the
     * filter.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param maxSize max number of entries
     * @param sortAttribute Field to sort the records on
     * @return search results
     * @exception EBaseException failed to search
     */
    public DBSearchResults search(
            String base,
            String filter,
            int maxSize,
            String sortAttribute
            ) throws EBaseException {
        return null;
    }

    /**
     * Searchs for a list of objects that match the
     * filter.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param maxSize max number of entries
     * @param timeLimit timeout limit
     * @param sortAttribute Field to sort the records on
     * @return search results
     * @exception EBaseException failed to search
     */
    public DBSearchResults search(
            String base,
            String filter,
            int maxSize,
            int timeLimit,
            String sortAttribute
            ) throws EBaseException {
        return null;
    }

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
    public DBSearchResults search(
            String base,
            String filter,
            String[] attrs
            ) throws EBaseException {
        return null;
    }

    /**
     * Retrieves a list of object that satifies the given
     * filter.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param start index of the first element
     * @param size max number of element in the page
     * @return search results
     * @exception EBaseException failed to search
     */
    public DBSearchResults pagedSearch(
            String base,
            String filter,
            int start,
            int size
            ) throws EBaseException {
        return pagedSearch(base, filter, start, size, -1);
    }

    /**
     * Retrieves a list of object that satifies the given
     * filter.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param start index of the first element
     * @param size max number of element in the page
     * @param timeLimit timeout limit
     * @return search results
     * @exception EBaseException failed to search
     */
    public DBSearchResults pagedSearch(
            String base,
            String filter,
            int start,
            int size,
            int timeLimit
            ) throws EBaseException {
        return null;
    }

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
    public LDAPSearchResults persistentSearch(
            String base,
            String filter,
            String[] attrs
            ) throws EBaseException {
        return null;
    }

    /**
     * Retrieves a list of objects.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param attrs selected attributes
     * @return search results in virtual list
     * @exception EBaseException failed to search
     */
    public <T extends IDBObj> DBVirtualList<T> createVirtualList(
            String base,
            String filter,
            String[] attrs
            ) throws EBaseException {
        return null;
    }

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
    public <T extends IDBObj> DBVirtualList<T> createVirtualList(
            String base,
            String filter,
            String[] attrs,
            String sortKey,
            int pageSize
            ) throws EBaseException {
        return null;
    }

    /**
     * Retrieves a list of objects.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param attrs selected attributes
     * @param sortKeys keys used to sort the list
     * @param pageSize page size in the virtual list
     * @return search results in virtual list
     * @exception EBaseException failed to search
     */
    public <T extends IDBObj> DBVirtualList<T> createVirtualList(
            String base,
            String filter,
            String[] attrs,
            String[] sortKeys,
            int pageSize
            ) throws EBaseException {
        return null;
    }

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
    public <T extends IDBObj> DBVirtualList<T> createVirtualList(
            String base,
            String filter,
            String[] attrs,
            String startFrom,
            String sortKey,
            int pageSize
            ) throws EBaseException {
        return null;
    }

    /**
     * Retrieves a paged search of objects.
     *
     * @param base starting point of the search
     * @param filter search filter
     * @param attrs selected attributes
     * @param startFrom starting point
     * @param sortKey key used to sort the list
     * @return search results in virtual list
     * @exception EBaseException failed to search
     */
    public <T extends IDBObj> DBPagedSearch<T> createPagedSearch(String base, String filter, String[] attrs,
            String sortKey)  throws EBaseException {
        return null;
    }

    public void abandon(LDAPSearchResults results) throws EBaseException {
    }
}
