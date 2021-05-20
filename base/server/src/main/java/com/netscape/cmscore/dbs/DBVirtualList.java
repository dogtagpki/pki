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

import java.util.Arrays;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.IDBVirtualList;
import com.netscape.certsrv.dbs.IElementProcessor;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPControl;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPSortKey;
import netscape.ldap.LDAPv2;
import netscape.ldap.controls.LDAPSortControl;
import netscape.ldap.controls.LDAPVirtualListControl;
import netscape.ldap.controls.LDAPVirtualListResponse;

/**
 * A class represents a virtual list of search results.
 * Note that this class must be used with DS4.0.
 *
 * @author thomask
 * @author mzhao
 * @version $Revision$, $Date$
 */
public class DBVirtualList<E extends IDBObj> implements IDBVirtualList<E> {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DBVirtualList.class);

    private DBRegistry mRegistry = null;
    private LDAPConnection mConn = null;
    private String mBase = null;
    private String mFilter = null;
    private String mAttrs[] = null;
    // virtual list size
    private int mSize = -1;

    private Vector<E> mEntries = new Vector<>();
    // mSize is get or not?
    private boolean mInitialized = false;
    private LDAPSortKey[] mKeys;
    private LDAPControl[] mPageControls = null;
    // page buffer size
    private int mPageSize = 10;
    // the top of the buffer
    private int mTop = 0;
    private int mBeforeCount;
    private int mAfterCount;
    // the index of the first entry returned
    private int mSelectedIndex = 0;
    private int mJumpToIndex = 0;
    private int mJumpToInitialIndex = 0; // Initial index hit in jumpto operation
    private int mJumpToDirection = 1; // Do we proceed forward or backwards
    private String mJumpTo = null; // Determines if this is the jumpto case

    /**
     * Constructs a virtual list.
     * Be sure to setPageSize() later if your pageSize is not the default 10
     * Be sure to setSortKey() before fetchs
     *
     * param registry the registry of attribute mappers
     * param c the ldap connection. It has to be version 3 and upper
     * param base the base distinguished name to search from
     * param filter search filter specifying the search criteria
     * param attrs list of attributes that you want returned in the search results
     */
    public DBVirtualList(DBRegistry registry, LDAPConnection c,
            String base, String filter, String attrs[]) throws EBaseException {
        mRegistry = registry;
        mFilter = filter;
        mBase = base;
        mAttrs = attrs;
        logger.debug("In DBVirtualList filter attrs filter: " + filter
                 + " attrs: " + Arrays.toString(attrs));
        mPageControls = new LDAPControl[2];
        try {
            mConn = (LDAPConnection) c.clone();
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED",
                        e.toString()));
        }
    }

    /**
     * Constructs a virtual list.
     * Be sure to setPageSize() later if your pageSize is not the default 10
     *
     * param registry the registry of attribute mappers
     * param c the ldap connection. It has to be version 3 and upper
     * param base the base distinguished name to search from
     * param filter search filter specifying the search criteria
     * param attrs list of attributes that you want returned in the search results
     * param sortKey the attributes to sort by
     */
    public DBVirtualList(DBRegistry registry, LDAPConnection c,
            String base, String filter, String attrs[], String sortKey[])
            throws EBaseException {

        logger.debug("In DBVirtualList filter attrs sotrKey[]  filter: " + filter
                 + " attrs: " + Arrays.toString(attrs));
        mRegistry = registry;
        mFilter = filter;
        try {
            mConn = (LDAPConnection) c.clone();
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED",
                        e.toString()));
        }
        mBase = base;
        mAttrs = attrs;
        mPageControls = new LDAPControl[2];
        setSortKey(sortKey);
    }

    /**
     * Constructs a virtual list.
     * Be sure to setPageSize() later if your pageSize is not the default 10
     *
     * param registry the registry of attribute mappers
     * param c the ldap connection. It has to be version 3 and upper
     * param base the base distinguished name to search from
     * param filter search filter specifying the search criteria
     * param attrs list of attributes that you want returned in the search results
     * param sortKey the attribute to sort by
     */
    public DBVirtualList(DBRegistry registry, LDAPConnection c,
            String base, String filter, String attrs[], String sortKey)
            throws EBaseException {

        logger.debug("In DBVirtualList filter attrs sortKey   filter: " + filter + " attrs: " + Arrays.toString(attrs));
        mRegistry = registry;
        mFilter = filter;
        try {
            mConn = (LDAPConnection) c.clone();
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED",
                        e.toString()));
        }
        mBase = base;
        mAttrs = attrs;
        mPageControls = new LDAPControl[2];
        setSortKey(sortKey);
    }

    /**
     * Constructs a virtual list.
     *
     * param registry the registry of attribute mappers
     * param c the ldap connection. It has to be version 3 and upper
     * param base the base distinguished name to search from
     * param filter search filter specifying the search criteria
     * param attrs list of attributes that you want returned in the search results
     * param sortKey the attributes to sort by
     * param pageSize the size of a page. There is a 3*pageSize buffer maintained so
     * pageUp and pageDown won't invoke fetch from ldap server
     */
    public DBVirtualList(DBRegistry registry, LDAPConnection c,
            String base, String filter, String attrs[], String sortKey[],
            int pageSize) throws EBaseException {

        logger.debug("In DBVirtualList filter attrs sortKey[] pageSize filter: "
                 + filter + " attrs: " + Arrays.toString(attrs)
                 + " pageSize " + pageSize);
        mRegistry = registry;
        mFilter = filter;
        try {
            mConn = (LDAPConnection) c.clone();
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED",
                        e.toString()));
        }
        mBase = base;
        mAttrs = attrs;
        mPageControls = new LDAPControl[2];
        setSortKey(sortKey);
        setPageSize(pageSize);
    }

    /**
     * Constructs a virtual list.
     *
     * param registry the registry of attribute mappers
     * param c the ldap connection. It has to be version 3 and upper
     * param base the base distinguished name to search from
     * param filter search filter specifying the search criteria
     * param attrs list of attributes that you want returned in the search results
     * param sortKey the attribute to sort by
     * param pageSize the size of a page. There is a 3*pageSize buffer maintained so
     * pageUp and pageDown won't invoke fetch from ldap server
     */
    public DBVirtualList(DBRegistry registry, LDAPConnection c,
            String base, String filter, String attrs[], String sortKey,
            int pageSize) throws EBaseException {

        logger.debug("In DBVirtualList filter attrs sortKey pageSize filter: "
                 + filter + " attrs: " + Arrays.toString(attrs)
                 + " pageSize " + pageSize);
        mRegistry = registry;
        mFilter = filter;
        try {
            mConn = (LDAPConnection) c.clone();
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED",
                        e.toString()));
        }
        mBase = base;
        mAttrs = attrs;
        mPageControls = new LDAPControl[2];
        setSortKey(sortKey);
        setPageSize(pageSize);
    }

    public DBVirtualList(DBRegistry registry, LDAPConnection c,
            String base, String filter, String attrs[],
            String startFrom, String sortKey,
            int pageSize) throws EBaseException {

        logger.debug("In DBVirtualList filter attrs startFrom sortKey pageSize "
                 + "filter: " + filter
                 + " attrs: " + Arrays.toString(attrs)
                 + " pageSize " + pageSize + " startFrom " + startFrom);
        mRegistry = registry;
        mFilter = filter;
        try {
            mConn = (LDAPConnection) c.clone();
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED",
                        e.toString()));
        }
        mBase = base;
        mAttrs = attrs;
        mPageControls = new LDAPControl[2];
        mJumpTo = startFrom;
        setSortKey(sortKey);
        // setPageSize(pageSize);

        if (pageSize < 0) {
            mJumpToDirection = -1;
        }
        mPageSize = pageSize;

        mBeforeCount = 0;
        mAfterCount = mPageSize;
    }

    /**
     * Set the paging size of this virtual list.
     * The page size here is just a buffer size. A buffer is kept around
     * that is three times as large as the number of visible entries.
     * That way, you can scroll up/down several items(up to a page-full)
     * without refetching entries from the directory.
     *
     * @param size the page size
     */
    @Override
    public void setPageSize(int size) {

        if (mJumpTo != null) {
            return;
        }

        mPageSize = size;
        mBeforeCount = 0; //mPageSize;
        mAfterCount = mPageSize; // mPageSize + mPageSize;

        //logger.debug("In setPageSize " + size + " mBeforeCount " + mBeforeCount + " mAfterCount " + mAfterCount);
    }

    /**
     * set the sort key
     *
     * @param sortKey the attribute to sort by
     */
    @Override
    public void setSortKey(String sortKey) throws EBaseException {
        String keys[] = new String[1];

        keys[0] = sortKey;
        setSortKey(keys);
    }

    /**
     * set the sort key
     *
     * @param sortKey the attributes to sort by
     */
    @Override
    public void setSortKey(String[] sortKeys) throws EBaseException {

        if (sortKeys == null)
            throw new EBaseException("sort keys cannot be null");

        mKeys = new LDAPSortKey[sortKeys.length];
        String la[] = null;
        synchronized (this) {
            la = mRegistry.getLDAPAttributes(sortKeys);
        }

        if (la == null)
            throw new EBaseException("sort keys cannot be null");

        for (int i = 0; i < sortKeys.length; i++) {
            mKeys[i] = new LDAPSortKey(la[i]);
        }

        // Paged results also require a sort control
        if (mKeys == null) {
            throw new EBaseException("sort keys cannot be null");
        }

        mPageControls[0] = new LDAPSortControl(mKeys, true);
    }

    /**
     * Retrieves the size of this virtual list.
     * Recommend to call getSize() before getElementAt() or getElements()
     * since you'd better check if the index is out of bound first.
     */
    @Override
    public int getSize() {

        //logger.debug("DBVirtualList.getSize()");

        if (!mInitialized) {

            mInitialized = true;
            // Do an initial search to get the virtual list size
            // Keep one page before and one page after the start
            if (mJumpTo == null) {
                mBeforeCount = 0; //mPageSize;
                mAfterCount = mPageSize; //  mPageSize + mPageSize;
            }
            // Create the initial paged results control
            /* Since this one is only used to get the size of the virtual list;
             we don't care about the starting index. If there is no partial
             match, the first one before (or after, if none before) is returned
             as the index entry. Instead of "A", you could use the other
             constructor and specify 0 both for startIndex and for
             contentCount. */
            LDAPVirtualListControl cont = null;

            if (mJumpTo == null) {
                logger.debug("DBVirtualList: searching for entry A");
                cont = new LDAPVirtualListControl("A",
                            mBeforeCount,
                            mAfterCount);

            } else {
                logger.debug("DBVirtualList: searching for entry " + mJumpTo);

                if (mPageSize < 0) {
                    mBeforeCount = mPageSize * -1;
                    mAfterCount = 0;
                }
                cont = new LDAPVirtualListControl(mJumpTo,
                            mBeforeCount,
                            mAfterCount);
            }

            mPageControls[1] = cont;
            getJumpToPage();
        }

        logger.debug("DBVirtualList: size: " + mSize);
        return mSize;
    }

    @Override
    public int getSizeBeforeJumpTo() {

        if (!mInitialized || mJumpTo == null)
            return 0;

        int size = 0;

        if (mJumpToDirection < 0) {
            size = mTop + mEntries.size();
        } else {
            size = mTop;

        }

        return size;

    }

    @Override
    public int getSizeAfterJumpTo() {

        if (!mInitialized || mJumpTo == null)
            return 0;

        int size = mSize - mTop;

        return size;

    }

    private synchronized boolean getEntries() {

        logger.info("DBVirtualList: Searching " + mBase);

        // Specify necessary controls for vlist
        // LDAPSearchConstraints cons = mConn.getSearchConstraints();
        LDAPSearchConstraints cons = new LDAPSearchConstraints();

        cons.setMaxResults(0);
        if (mPageControls != null) {
            cons.setServerControls(mPageControls);
            //System.out.println( "setting vlist control" );
        }

        // Empty the buffer
        mEntries.removeAllElements();

        try {
            //what happen if there is no matching?
            String ldapFilter = mRegistry.getFilter(mFilter);
            logger.info("DBVirtualList: filter: " + ldapFilter);

            String ldapAttrs[] = null;
            LDAPSearchResults result;

            Integer size_limit = (Integer) mConn.getOption(LDAPv2.SIZELIMIT);
            if (size_limit == 0 ||
                    (size_limit > 0 && mPageSize != 0 && Math.abs(mPageSize) < size_limit))
            {
                mConn.setOption(LDAPv2.SIZELIMIT, Math.abs(mPageSize));
            }

            if (mAttrs != null) {
                ldapAttrs = mRegistry.getLDAPAttributes(mAttrs);

                /*
                 LDAPv2.SCOPE_BASE:
                 (search only the base DN)
                 LDAPv2.SCOPE_ONE:
                 (search only entries under the base DN)
                 LDAPv2.SCOPE_SUB:
                 (search the base DN and all entries within its subtree)
                 */
                result = mConn.search(mBase,
                            LDAPConnection.SCOPE_ONE, ldapFilter, ldapAttrs,
                            false, cons);

            } else {
                result = mConn.search(mBase,
                            LDAPConnection.SCOPE_ONE, ldapFilter, null,
                            false, cons);
            }

            if (result == null) {
                return false;
            }

            int damageCounter = 0;

            while (result.hasMoreElements()) {
                LDAPEntry entry = (LDAPEntry) result.nextElement();
                logger.info("DBVirtualList: dn: " + entry.getDN());

                try {
                    LDAPAttributeSet attrs = entry.getAttributeSet();

                    IDBObj record = mRegistry.createObject(attrs);
                    logger.debug("DBVirtualList: record: " + (record == null ? null : record.getClass()));

                    @SuppressWarnings("unchecked")
                    E o = (E) record;

                    mEntries.addElement(o);

                } catch (Exception e) {

                    String message = CMS.getLogMessage("CMSCORE_DBS_VL_ADD", e.getMessage());
                    logger.error(message, e);

                    /*LogDoc
                     *
                     * @phase local ldap search
                     * @reason Failed to get enties.
                     * @message DBVirtualList: <exception thrown>
                     */

                    // #539044
                    damageCounter++;
                    if (damageCounter > 100) {
                        logger.error(CMS.getLogMessage("CMSCORE_DBS_VL_CORRUPTED_ENTRIES", Integer.toString(damageCounter)));
                        return false;
                    }
                }
            }

        } catch (Exception e) {

            /*LogDoc
             *
             * @phase local ldap search
             * @reason Failed to get enties.
             * @message DBVirtualList: <exception thrown>
             */
            String message = CMS.getLogMessage("OPERATION_ERROR", e.getMessage());
            logger.error(message, e);

            throw new RuntimeException(e);
        }

        logger.debug("DBVirtualList: entries: " + mEntries.size());

        return true;
    }

    @Override
    public int getCurrentIndex() {
        return mTop;
    }

    private synchronized boolean getJumpToPage() {
        try {
            // Get the actual entries
            if (!getEntries())
                return false;

            // Check if we have a control returned
            LDAPControl[] c = mConn.getResponseControls();
            LDAPVirtualListResponse nextCont = null;

            if (c != null) {
                for (LDAPControl control : c) {
                    if (control instanceof LDAPVirtualListResponse) {
                        nextCont = (LDAPVirtualListResponse)control;
                        break;
                    }
                }
            }

            if (nextCont != null) {
                mSelectedIndex = nextCont.getFirstPosition() - 1;
                mTop = Math.max(0, mSelectedIndex - mBeforeCount);

                logger.debug("DBVirtualList: top: " + mTop);
                if (mJumpTo != null) {
                    mJumpToInitialIndex = mTop;
                }

                // Now we know the total size of the virtual list box
                mSize = nextCont.getContentCount();
                ((LDAPVirtualListControl) mPageControls[1]).setListSize(mSize);
                mInitialized = true;
                //System.out.println( "Virtual window: " + mTop +
                //       ".." + (mTop+mEntries.size()-1) +
                //      " of " + mSize );
            } else {
                logger.warn(CMS.getLogMessage("CMSCORE_DBS_VL_NULL_RESPONSE"));
            }
            return true;
        } catch (Exception e) {
            // happens when connection is not available
            return false;
        }
    }

    /**
     * Get a page starting at "first" (although we may also fetch
     * some preceding entries)
     * Recommend to call getSize() before getElementAt() or getElements()
     * since you'd better check if the index is out of bound first.
     *
     * @param first the index of the first entry of the page you want to fetch
     */
    @Override
    public boolean getPage(int first) {

        logger.debug("DBVirtualList.getPage(" + first + ")");

        if (!mInitialized) {
            LDAPVirtualListControl cont = new LDAPVirtualListControl(0,
                    mBeforeCount,
                    mAfterCount, 0);

            mPageControls[1] = cont;
        }

        //logger.debug("about to set range first " + first + " mBeforeCount " + mBeforeCount + " mAfterCount " + mAfterCount);
        ((LDAPVirtualListControl) mPageControls[1]).setRange(first, mBeforeCount, mAfterCount);
        return getPage();
    }

    /**
     * Fetch a buffer
     */
    private boolean getPage() {
        // Get the actual entries
        if (!getEntries())
            return false;

        // Check if we have a control returned
        LDAPControl[] c = mConn.getResponseControls();
        LDAPVirtualListResponse nextCont = null;

        if (c != null) {
            for (LDAPControl control : c) {
                if (control instanceof LDAPVirtualListResponse) {
                    nextCont = (LDAPVirtualListResponse)control;
                    break;
                }
            }
        }

        if (nextCont != null) {
            mSelectedIndex = nextCont.getFirstPosition() - 1;
            mTop = Math.max(0, mSelectedIndex - mBeforeCount);
            //logger.debug("New mTop: " + mTop + " mSelectedIndex " + mSelectedIndex);
            // Now we know the total size of the virtual list box
            mSize = nextCont.getContentCount();
            ((LDAPVirtualListControl) mPageControls[1]).setListSize(mSize);
            mInitialized = true;
            //logger.debug( "Virtual window: " + mTop +
            //       ".." + (mTop+mEntries.size()-1) +
            //      " of " + mSize );
        } else {

            /*LogDoc
             *
             * @phase local ldap search
             */
            logger.warn(CMS.getLogMessage("CMSCORE_DBS_VL_NULL_RESPONSE"));
        }
        return true;
    }

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
    @Override
    public boolean getPage(String text) {
        mPageControls[1] =
                new LDAPVirtualListControl(text,
                        mBeforeCount,
                        mAfterCount);
        //System.out.println( "Setting requested start to " +
        //      text + ", -" + mBeforeCount + ", +" +
        //      mAfterCount );
        return getPage();
    }

    /**
     * fetch data of a single list item
     * Recommend to call getSize() before getElementAt() or getElements()
     * since you'd better check if the index is out of bound first.
     * If the index is out of range of the virtual list, an exception will be thrown
     * and return null
     *
     * @param index the index of the element to fetch
     */
    @Override
    public E getElementAt(int index) {

        /* mSize may not be init at this time! Bad !
         * the caller should really check the index is within bound before this
         * but I'll take care of this just in case they are too irresponsible
         */
        if (!mInitialized) {
            mSize = getSize();
        }

        //logger.debug("DBVirtualList: retrieving entry #" + index);

        //System.out.println( "need entry " + index );
        if ((index < 0) || (index >= mSize)) {
            logger.warn("DBVirtualList: returning null");
            return null;
        }

        if (mJumpTo != null) { //Handle the explicit jumpto case

            if (index == 0)
                mJumpToIndex = 0; // Keep a running jumpto index for this page of data
            else
                mJumpToIndex++;

            //logger.debug("getElementAtJT: " + index  +  " mTop " + mTop + " mEntries.size() " + mEntries.size());

            if ((mJumpToDirection > 0) && (mJumpToInitialIndex + index >= mSize)) // out of data in forward paging jumpto case
            {
                logger.warn("mJumpTo virtual list exhausted   mTop " + mTop + " mSize " + mSize);
                return null;
            }

            if (mJumpToIndex >= mEntries.size()) // In jumpto case, page of data has been exhausted
            {
                mJumpToIndex = 0; // new page will be needed reset running count

                if (mJumpToDirection > 0) { //proceed in positive direction past hit point
                    getPage(index + mJumpToInitialIndex + 1);
                } else { //proceed backwards from hit point
                    if (mTop == 0) {
                        getPage(0);
                        logger.warn("asking for a page less than zero in reverse case, return null");
                        return null;
                    }

                    logger.debug("getting page reverse mJumptoIndex  " + mJumpToIndex + " mTop " + mTop);
                    getPage(mTop);

                }

            }

            if (mJumpToDirection > 0) // handle getting entry in forward direction
            {
                return mEntries.elementAt(mJumpToIndex);
            } else { // handle getting entry in reverse direction
                int reverse_index = mEntries.size() - mJumpToIndex - 1;

                //logger.debug("reverse direction getting index " + reverse_index);

                if (reverse_index < 0 || reverse_index >= mEntries.size()) {
                    logger.warn("reverse_index out of range " + reverse_index);
                    return null;
                }
                return mEntries.elementAt(reverse_index);
            }
        }

        //logger.debug("getElementAt noJumpto: " + index);

        if ((index < mTop) || (index >= mTop + mEntries.size())) { // handle the non jumpto case
            //fetch a new page
            //System.out.println( "fetching a page starting at " +
            //        index );
            //   logger.debug("getElementAt noJumpto: getting page index: " + index + " mEntries.size() " + mEntries.size() + " mTop: " + mTop);
            getPage(index);
        }

        int offset = index - mTop;

        if ((offset < 0) || (offset >= mEntries.size()))
            //XXX
            return null; //("No entry at " + index);
        else
            return mEntries.elementAt(offset);
    }

    @Override
    public E getJumpToElementAt(int i) {
        return mEntries.elementAt(i);
    }

    /**
     * This function processes elements as soon as it arrives. It is
     * more memory-efficient.
     */
    @Override
    public void processElements(int startidx, int endidx, IElementProcessor ep)
            throws EBaseException {

        /* mSize may not be init at this time! Bad !
         * the caller should really check the index is within bound before this
         * but I'll take care of this just in case they are too irresponsible
         */
        if (!mInitialized)
            mSize = getSize();

        // short-cut the existing code ... :(
        if (mJumpTo != null) {
            for (int i = startidx; i <= endidx; i++) {
                Object element = getJumpToElementAt(i);

                if (element != null)
                    ep.process(element);
            }
            return;
        }

        //guess this is what you really mean to try to improve performance
        if (startidx >= endidx) {
            throw new EBaseException("startidx must be less than endidx");
        } else {
            setPageSize(endidx - startidx);
            getPage(startidx);
        }

        for (int i = startidx; i <= endidx; i++) {
            Object element = getElementAt(i);

            if (element != null)
                ep.process(element);
        }
    }

    /**
     * get the virutal selected index
     */
    @Override
    public int getSelectedIndex() {
        return mSelectedIndex;
    }

    /**
     * get the top of the buffer
     */
    @Override
    public int getFirstIndex() {
        return mTop;
    }
}
