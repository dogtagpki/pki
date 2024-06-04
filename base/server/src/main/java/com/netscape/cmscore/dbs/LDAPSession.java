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
import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBException;
import com.netscape.certsrv.dbs.DBNotAvailableException;
import com.netscape.certsrv.dbs.DBPagedSearch;
import com.netscape.certsrv.dbs.DBRecordNotFoundException;
import com.netscape.certsrv.dbs.DBVirtualList;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.ldap.LDAPExceptionConverter;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPControl;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPSortKey;
import netscape.ldap.LDAPv3;
import netscape.ldap.controls.LDAPPagedResultsControl;
import netscape.ldap.controls.LDAPPersistSearchControl;
import netscape.ldap.controls.LDAPSortControl;

/**
 * A class represents the database session. Operations
 * can be performed with a session.
 *
 * Transaction and Caching support can be integrated
 * into session.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class LDAPSession extends DBSSession {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LDAPSession.class);

    public static final int MAX_PAGED_SEARCH_SIZE = 500;

    private DBSubsystem dbSubsystem;
    private LDAPConnection mConn = null;

    /**
     * Constructs a database session.
     *
     * @param dbSubsystem the database subsytem
     * @param c the ldap connection
     */
    public LDAPSession(DBSubsystem dbSubsystem, LDAPConnection c) throws DBException {
        this.dbSubsystem = dbSubsystem;
        mConn = c;
        try {
            // no limit
            mConn.setOption(LDAPv3.SIZELIMIT, Integer.valueOf(0));
        } catch (LDAPException e) {
            throw new DBException("Unable to create LDAP session: " + e.getMessage(), e);
        }
    }

    public LDAPConnection getConnection() {
        return mConn;
    }

    /**
     * Closes this session.
     */
    @Override
    public void close() throws DBException {
        // return ldap connection.
        dbSubsystem.returnConn(mConn);
    }

    /**
     * Adds object to backend database. For example,
     *
     * <PRE>
     * session.add(&quot;cn=123459,o=certificate repository,o=airius.com&quot;,
     *             certRec);
     * </PRE>
     *
     * @param name the name of the ldap entry
     * @param obj the DBobj that can be mapped to ldap attrubute set
     */
    @Override
    public void add(String name, IDBObj obj) throws EBaseException {

        logger.info("LDAPSession: Adding " + name);

        try {
            LDAPAttributeSet attrs = dbSubsystem.getRegistry().createLDAPAttributeSet(obj);

            for (Enumeration<LDAPAttribute> e = attrs.getAttributes(); e.hasMoreElements(); ) {
                LDAPAttribute attr = e.nextElement();
                String[] values = attr.getStringValueArray();
                if (values == null) continue;
                logger.debug("LDAPSession: - " + attr.getName());
            }

            LDAPEntry e = new LDAPEntry(name, attrs);

            /*LogDoc
             *
             * @phase local ldap add
             * @message LDAPSession: begin LDAP add <entry>
             */
            mConn.add(e);

        } catch (LDAPException e) {
            throw LDAPExceptionConverter.toDBException(e);
        }
    }

    /**
     * Reads an object from the database.
     * all attributes will be returned
     *
     * @param name the name of the ldap entry
     */
    @Override
    public IDBObj read(String name) throws EBaseException {
        return read(name, null);
    }

    /**
     * Reads an object from the database, and only populates
     * the selected attributes.
     *
     * @param name the name of the ldap entry
     * @param attrs the attributes to be selected
     */
    @Override
    public IDBObj read(String name, String attrs[])
            throws EBaseException {

        try {
            String ldapattrs[] = null;

            if (attrs != null) {
                ldapattrs = dbSubsystem.getRegistry(
                        ).getLDAPAttributes(attrs);
            }

            logger.info("LDAPSession: Retrieving " + name);

            /*LogDoc
             *
             * @phase local ldap read
             * @message LDAPSession: begin LDAP read <entry>
             */
            LDAPSearchResults res = mConn.search(name,
                    LDAPv3.SCOPE_BASE, "(objectclass=*)",
                    ldapattrs, false);
            LDAPEntry entry = res.next();
            LDAPAttributeSet attrSet = entry.getAttributeSet();

            for (Enumeration<LDAPAttribute> e = attrSet.getAttributes(); e.hasMoreElements(); ) {
                LDAPAttribute attr = e.nextElement();
                String[] values = attr.getStringValueArray();
                if (values == null) continue;
                logger.debug("LDAPSession: - " + attr.getName());
            }

            return dbSubsystem.getRegistry().createObject(attrSet);

        } catch (LDAPException e) {
            throw LDAPExceptionConverter.toDBException(e);
        }
    }

    /**
     * Deletes object from database.
     */
    @Override
    public void delete(String name) throws EBaseException {

        logger.info("LDAPSession: Deleting " + name);

        try {
            mConn.delete(name);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new DBNotAvailableException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            throw new DBException("Unable to delete LDAP record: " + e.getMessage(), e);
        }
    }

    /**
     * Modify an object in the database.
     */
    @Override
    public void modify(String name, ModificationSet mods) throws EBaseException {

        logger.info("LDAPSession: Modifying " + name);

        try {
            LDAPModificationSet ldapMods = new LDAPModificationSet();
            Enumeration<?> e = mods.getModifications();

            while (e.hasMoreElements()) {
                Modification mod = (Modification) e.nextElement();
                LDAPAttributeSet attrs = new LDAPAttributeSet();

                dbSubsystem.getRegistry().mapObject(null, mod.getName(), mod.getValue(), attrs);
                Enumeration<LDAPAttribute> e0 = attrs.getAttributes();

                while (e0.hasMoreElements()) {
                    int op = toLdapModOp(mod.getOp());
                    LDAPAttribute attr = e0.nextElement();

                    switch (op) {
                    case LDAPModification.ADD:
                        logger.debug("LDAPSession: - add: " + attr.getName());
                        break;
                    case LDAPModification.DELETE:
                        logger.debug("LDAPSession: - delete: " + attr.getName());
                        break;
                    case LDAPModification.REPLACE:
                        logger.debug("LDAPSession: - replace: " + attr.getName());
                        break;
                    }

                    ldapMods.add(op, attr);
                }
            }

            /*LogDoc
             *
             * @phase local ldap add
             * @message LDAPSession: begin LDAP modify <entry>
             */
            mConn.modify(name, ldapMods);

        } catch (LDAPException e) {

            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                throw new DBNotAvailableException(CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            }

            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                throw new DBRecordNotFoundException(CMS.getUserMessage("CMS_DBS_RECORD_NOT_FOUND"));
            }

            throw new DBException("Unable to modify LDAP record: " + e.getMessage(), e);
        }
    }

    private int toLdapModOp(int modOp) throws EBaseException {
        switch (modOp) {
        case Modification.MOD_ADD:
            return LDAPModification.ADD;

        case Modification.MOD_DELETE:
            return LDAPModification.DELETE;

        case Modification.MOD_REPLACE:
            return LDAPModification.REPLACE;
        }
        throw new EBaseException(CMS.getUserMessage("CMS_DBS_LDAP_OP_FAILURE",
                    Integer.toString(modOp)));
    }

    /**
     * Searchs for a list of objects that match the
     * filter.
     */
    @Override
    public DBSearchResults search(String base, String filter)
            throws EBaseException {
        return search(base, filter, null);
    }

    @Override
    public DBSearchResults search(String base, String filter, int maxSize)
            throws EBaseException {

        try {
            String ldapfilter = dbSubsystem.getRegistry().getFilter(filter);
            logger.info("LDAPSession: Searching " + base + " for " + ldapfilter);

            String ldapattrs[] = null;

            LDAPSearchConstraints cons = new LDAPSearchConstraints();

            cons.setMaxResults(maxSize);

            LDAPSearchResults res = mConn.search(base,
                    LDAPv3.SCOPE_ONE, ldapfilter, ldapattrs, false, cons);

            return new DBSearchResults(dbSubsystem.getRegistry(),
                    res);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new DBNotAvailableException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new DBException("Unable to search LDAP record: " + e.getMessage(), e);
        }
    }

    @Override
    public DBSearchResults search(String base, String filter, int maxSize,String sortAttribute)
            throws EBaseException {

        try {
            String ldapfilter = dbSubsystem.getRegistry().getFilter(filter);
            logger.info("LDAPSession: Searching " + base + " for " + ldapfilter);

            String ldapattrs[] = null;

            LDAPSearchConstraints cons = new LDAPSearchConstraints();

            cons.setMaxResults(maxSize);

            if(sortAttribute != null) {
                LDAPSortKey sortOrder = new LDAPSortKey( sortAttribute );
                LDAPSortControl sortCtrl = new LDAPSortControl(sortOrder,true);
                cons.setServerControls( sortCtrl );
            }

            LDAPSearchResults res = mConn.search(base,
                    LDAPv3.SCOPE_ONE, ldapfilter, ldapattrs, false, cons);

            return new DBSearchResults(dbSubsystem.getRegistry(),
                    res);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new DBNotAvailableException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new DBException("Unable to search LDAP record: " + e.getMessage(), e);
        }
    }

    @Override
    public DBSearchResults search(String base, String filter, int maxSize, int timeLimit)
            throws EBaseException {

        try {
            String ldapfilter = dbSubsystem.getRegistry().getFilter(filter);
            logger.info("LDAPSession: Searching " + base + " for " + ldapfilter);

            String ldapattrs[] = null;

            LDAPSearchConstraints cons = new LDAPSearchConstraints();

            cons.setMaxResults(maxSize);
            cons.setServerTimeLimit(timeLimit);

            LDAPSearchResults res = mConn.search(base,
                    LDAPv3.SCOPE_ONE, ldapfilter, ldapattrs, false, cons);

            return new DBSearchResults(dbSubsystem.getRegistry(),
                    res);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new DBNotAvailableException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new DBException("Unable to search LDAP record: " + e.getMessage(), e);
        }
    }

    @Override
    public DBSearchResults search(String base, String filter, int maxSize,
            int timeLimit, String sortAttribute) throws EBaseException {

        try {
            String ldapfilter = dbSubsystem.getRegistry().getFilter(filter);
            logger.info("LDAPSession: Searching " + base + " for " + ldapfilter);

            String ldapattrs[] = null;

            LDAPSearchConstraints cons = new LDAPSearchConstraints();

            cons.setMaxResults(maxSize);
            cons.setServerTimeLimit(timeLimit);

            if(sortAttribute != null) {
                LDAPSortKey sortOrder = new LDAPSortKey( sortAttribute );
                LDAPSortControl sortCtrl = new LDAPSortControl(sortOrder,true);
                cons.setServerControls( sortCtrl );
            }

            LDAPSearchResults res = mConn.search(base,
                    LDAPv3.SCOPE_ONE, ldapfilter, ldapattrs, false, cons);

            return new DBSearchResults(dbSubsystem.getRegistry(),
                    res);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new DBNotAvailableException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new DBException("Unable to search LDAP record: " + e.getMessage(), e);
        }

    }

    /**
     * Retrieves a list of object that satifies the given
     * filter.
     */
    @Override
    public DBSearchResults search(String base, String filter,
            String attrs[]) throws EBaseException {

        try {
            String ldapfilter = dbSubsystem.getRegistry().getFilter(filter);
            logger.info("LDAPSession: Searching " + base + " for " + ldapfilter);

            String[] ldapattrs = null;
            if (attrs != null) {
                ldapattrs = dbSubsystem.getRegistry().getLDAPAttributes(attrs);
            }

            /*LogDoc
             *
             * @phase local ldap add
             * @message LDAPSession: begin LDAP search <filter>
             */
            LDAPSearchConstraints cons = new LDAPSearchConstraints();

            cons.setMaxResults(0);

            LDAPSearchResults res = mConn.search(base,
                    LDAPv3.SCOPE_ONE, ldapfilter, ldapattrs, false, cons);

            return new DBSearchResults(dbSubsystem.getRegistry(),
                    res);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new DBNotAvailableException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new DBException("Unable to search LDAP record: " + e.getMessage(), e);
        }
    }

    @Override
    public DBSearchResults pagedSearch(String base, String filter, String[] sortKeys, int start, int size, int timeLimit)
            throws EBaseException {
        try {
            String ldapfilter = dbSubsystem.getRegistry().getFilter(filter);
            logger.info("LDAPSession.pagedSearch(): Searching {}  for {}", base, ldapfilter);

            LDAPSearchConstraints cons = new LDAPSearchConstraints();
            if (timeLimit > 0) {
                cons.setServerTimeLimit(timeLimit);
            }
            LDAPPagedResultsControl pagecon;
            LDAPSortControl sortCtrl = generateSortControl(sortKeys);
            LDAPSearchResults res;
            int skipped = 0;
            int pageSize = start > 0 ? Math.min(start, MAX_PAGED_SEARCH_SIZE) : Math.min(size, MAX_PAGED_SEARCH_SIZE);
            byte[] cookie = null;

            pagecon = new LDAPPagedResultsControl(false, pageSize);
            while (start > 0 && skipped < start) {
                if (sortCtrl != null) {
                    LDAPControl[] controls = {sortCtrl, pagecon};
                    cons.setServerControls(controls);
                } else {
                    cons.setServerControls(pagecon);
                }
                res = mConn.search(base,
                        LDAPv3.SCOPE_ONE, ldapfilter, null, false, cons);
                while(res.hasMoreElements())
                        res.next();
                skipped += pageSize;
                for (LDAPControl c: res.getResponseControls()){
                    if(c instanceof LDAPPagedResultsControl resC){
                        cookie = resC.getCookie();
                        if(cookie!=null){
                            pageSize = start - skipped > 0 ? Math.min((start - skipped) , 500) : Math.min(size, MAX_PAGED_SEARCH_SIZE);
                            pagecon = new LDAPPagedResultsControl(false, pageSize, cookie);
                        } else {
                            res =  new LDAPSearchResults();
                            return new DBSearchResults(dbSubsystem.getRegistry(),
                                    res);
                        }
                    }
                }
            }
            if (sortCtrl != null) {
                LDAPControl[] controls = {sortCtrl, pagecon};
                cons.setServerControls(controls);
            } else {
                cons.setServerControls(pagecon);
            }
            res = mConn.search(base,
                    LDAPv3.SCOPE_ONE, ldapfilter, null, false, cons);
            return new DBSearchResults(dbSubsystem.getRegistry(),
                    res);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new DBNotAvailableException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new DBException("Unable to search LDAP record: " + e.getMessage(), e);
        }
    }

    @Override
    public <T extends IDBObj> int countEntries(Class<T> classResults, String base, String filter, int timeLimit)
            throws EBaseException {
        String[] attrs = {"objectclass"};
        DBPagedSearch<T> search = createPagedSearch(classResults,  base, filter, attrs, (String) null);
        RecordPagedList<T> list = new RecordPagedList<>(search);
        int count = 0;
        for(T c: list) {
            count++;
        }

        return count;
    }

    @Override
    public LDAPSearchResults persistentSearch(String base, String filter, String attrs[])
            throws EBaseException {

        try {
            String ldapfilter = dbSubsystem.getRegistry().getFilter(filter);
            logger.info("LDAPSession: Searching " + base + " for " + ldapfilter);

            String ldapattrs[] = null;
            if (attrs != null) {
                ldapattrs = dbSubsystem.getRegistry(
                        ).getLDAPAttributes(attrs);
            }

            Integer version = (Integer) (mConn.getOption(LDAPv3.PROTOCOL_VERSION));

            // Only version 3 protocol supports persistent search.
            if (version.intValue() == 2) {
                mConn.setOption(LDAPv3.PROTOCOL_VERSION, Integer.valueOf(3));
            }

            int op = LDAPPersistSearchControl.MODIFY;

            boolean changesOnly = true;
            boolean returnControls = true;
            boolean isCritical = true;
            LDAPPersistSearchControl persistCtrl = new
                    LDAPPersistSearchControl(op, changesOnly,
                            returnControls, isCritical);

            LDAPSearchConstraints cons = new LDAPSearchConstraints();
            cons.setBatchSize(0);
            cons.setServerControls(persistCtrl);

            LDAPSearchResults res = mConn.search(base,
                    LDAPv3.SCOPE_ONE, ldapfilter, ldapattrs, false, cons);
            return res;
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new DBNotAvailableException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new DBException("Unable to search LDAP record: " + e.getMessage(), e);
        }
    }

    @Override
    public void abandon(LDAPSearchResults results) throws EBaseException {

        logger.debug("LDAPSession: abandon()");

        try {
            mConn.abandon(results);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new DBNotAvailableException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new DBException("Unable to abandon LDAP search result: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves a list of objects.
     */
    @Override
    public <T extends IDBObj> DBVirtualList<T> createVirtualList(String base, String filter,
            String attrs[]) throws EBaseException {

        logger.debug("LDAPSession: createVirtualList(" + base + ", " + filter + ")");

        return new LDAPVirtualList<>(dbSubsystem.getRegistry(), mConn, base,
                filter, attrs);
    }

    /**
     * Retrieves a list of objects.
     */
    public <T extends IDBObj> DBVirtualList<T> createVirtualList(String base, String filter,
            String attrs[], String sortKey[]) throws EBaseException {

        logger.debug("LDAPSession: createVirtualList(" + base + ", " + filter + ")");

        return new LDAPVirtualList<>(dbSubsystem.getRegistry(), mConn, base,
                filter, attrs, sortKey);
    }

    /**
     * Retrieves a list of objects.
     */
    public <T extends IDBObj> DBVirtualList<T> createVirtualList(String base, String filter,
            String attrs[], String sortKey) throws EBaseException {

        logger.debug("LDAPSession: createVirtualList(" + base + ", " + filter + ")");

        return new LDAPVirtualList<>(dbSubsystem.getRegistry(), mConn, base,
                filter, attrs, sortKey);
    }

    /**
     * Retrieves a list of objects.
     */
    @Override
    public <T extends IDBObj> DBVirtualList<T> createVirtualList(String base, String filter,
            String attrs[], String sortKey[], int pageSize) throws EBaseException {

        logger.debug("LDAPSession: createVirtualList(" + base + ", " + filter + ")");

        return new LDAPVirtualList<>(dbSubsystem.getRegistry(), mConn, base,
                filter, attrs, sortKey, pageSize);
    }

    /**
     * Retrieves a list of objects.
     */
    @Override
    public  <T extends IDBObj> DBVirtualList<T> createVirtualList(String base, String filter,
            String attrs[], String sortKey, int pageSize) throws EBaseException {

        logger.debug("LDAPSession: createVirtualList(" + base + ", " + filter + ")");

        return new LDAPVirtualList<>(dbSubsystem.getRegistry(), mConn, base,
                filter, attrs, sortKey, pageSize);
    }

    @Override
    public <T extends IDBObj> DBVirtualList<T> createVirtualList(String base, String filter,
            String attrs[], String startFrom, String sortKey, int pageSize) throws EBaseException {

        logger.debug("LDAPSession: createVirtualList(" + base + ", " + filter + ")");

        return new LDAPVirtualList<>(dbSubsystem.getRegistry(), mConn, base,
                filter, attrs, startFrom, sortKey, pageSize);

    }

    @Override
    public <T extends IDBObj> DBPagedSearch<T> createPagedSearch(Class<T> classResults, String base, String filter,
            String[] attrs, String sortKey) throws EBaseException {
        logger.debug("LDAPSession: createPagedSearch({}, {})", base, filter);

        return new LDAPPagedSearch<>(classResults, dbSubsystem.getRegistry(),mConn, base,
                filter, attrs, sortKey);
    }

    @Override
    public <T extends IDBObj> DBPagedSearch<T> createPagedSearch(Class<T> classResults, String base, String filter,
            String[] attrs, String[] sortKeys) throws EBaseException {
        logger.debug("LDAPSession: createPagedSearch({}, {})", base, filter);

        return new LDAPPagedSearch<>(classResults, dbSubsystem.getRegistry(),mConn, base,
                filter, attrs, sortKeys);
    }

    /**
     * Releases object to this interface. This allows us to
     * use memory more efficiently.
     */
    public void release(Object obj) {
        // not implemented
    }

    private LDAPSortControl generateSortControl(String[] sortKeys) throws EBaseException {

        if (sortKeys == null || sortKeys.length == 0)
            return null;

        LDAPSortKey[] mKeys = new LDAPSortKey[sortKeys.length];
        String[] la = null;
        synchronized (this) {
            la = dbSubsystem.getRegistry().getLDAPAttributes(sortKeys);
        }
        if (la == null) {
            logger.debug("LDAPPagedSearch.generateSortControl: cannot convert search keys {}", Arrays.toString(sortKeys));
            throw new EBaseException("sort keys cannot be null");
        }
        for (int i = 0; i < la.length; i++) {
            mKeys[i] = new LDAPSortKey(la[i]);
        }
        return new LDAPSortControl(mKeys, true);
    }
}
