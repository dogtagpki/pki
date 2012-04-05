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

import java.util.Enumeration;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;
import netscape.ldap.controls.LDAPPersistSearchControl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.EDBNotAvailException;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.IDBVirtualList;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.logging.ILogger;

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
public class DBSSession implements IDBSSession {

    private IDBSubsystem mDBSystem = null;
    private LDAPConnection mConn = null;
    private ILogger mLogger = CMS.getLogger();

    /**
     * Constructs a database session.
     *
     * @param system the database subsytem
     * @param c the ldap connection
     */
    public DBSSession(IDBSubsystem system, LDAPConnection c) {
        mDBSystem = system;
        mConn = c;
        try {
            // no limit
            mConn.setOption(LDAPv2.SIZELIMIT, Integer.valueOf(0));
        } catch (LDAPException e) {
        }
    }

    /**
     * Returns database subsystem.
     */
    public ISubsystem getDBSubsystem() {
        return mDBSystem;
    }

    /**
     * Closes this session.
     */
    public void close() throws EDBException {
        // return ldap connection.
        mDBSystem.returnConn(mConn);
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
    public void add(String name, IDBObj obj) throws EBaseException {
        try {
            LDAPAttributeSet attrs = mDBSystem.getRegistry(
                    ).createLDAPAttributeSet(obj);
            LDAPEntry e = new LDAPEntry(name, attrs);

            /*LogDoc
             *
             * @phase local ldap add
             * @message DBSSession: begin LDAP add <entry>
             */
            mConn.add(e);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new EDBNotAvailException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            throw new EDBException(CMS.getUserMessage("CMS_DBS_LDAP_OP_FAILURE",
                        name + " " + e.toString()));
        }
    }

    /**
     * Reads an object from the database.
     * all attributes will be returned
     *
     * @param name the name of the ldap entry
     */
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
    public IDBObj read(String name, String attrs[])
            throws EBaseException {
        try {
            String ldapattrs[] = null;

            if (attrs != null) {
                ldapattrs = mDBSystem.getRegistry(
                        ).getLDAPAttributes(attrs);
            }

            /*LogDoc
             *
             * @phase local ldap read
             * @message DBSSession: begin LDAP read <entry>
             */
            LDAPSearchResults res = mConn.search(name,
                    LDAPv2.SCOPE_BASE, "(objectclass=*)",
                    ldapattrs, false);
            LDAPEntry entry = (LDAPEntry) res.nextElement();

            return mDBSystem.getRegistry().createObject(
                    entry.getAttributeSet());
        } catch (LDAPException e) {

            /*LogDoc
             *
             * @phase local ldap read
             * @message DBSSession: <exception thrown>
             */
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_DB, ILogger.LL_INFO, "DBSSession: " + e.toString());
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new EDBNotAvailException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT)
                throw new EDBRecordNotFoundException(
                        CMS.getUserMessage("CMS_DBS_RECORD_NOT_FOUND"));
            throw new EDBException(CMS.getUserMessage("CMS_DBS_LDAP_OP_FAILURE",
                        name + " " + e.toString()));
        }
    }

    /**
     * Deletes object from database.
     */
    public void delete(String name) throws EBaseException {
        try {
            mConn.delete(name);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new EDBNotAvailException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            throw new EDBException(CMS.getUserMessage("CMS_DBS_LDAP_OP_FAILURE",
                        name + " " + e.toString()));
        }
    }

    /**
     * Modify an object in the database.
     */
    public void modify(String name, ModificationSet mods)
            throws EBaseException {
        try {
            LDAPModificationSet ldapMods = new
                    LDAPModificationSet();
            Enumeration<?> e = mods.getModifications();

            while (e.hasMoreElements()) {
                Modification mod = (Modification)
                        e.nextElement();
                LDAPAttributeSet attrs = new LDAPAttributeSet();

                mDBSystem.getRegistry().mapObject(null,
                        mod.getName(), mod.getValue(), attrs);
                Enumeration<?> e0 = attrs.getAttributes();

                while (e0.hasMoreElements()) {
                    ldapMods.add(toLdapModOp(mod.getOp()),
                            (LDAPAttribute)
                            e0.nextElement());
                }
            }

            /*LogDoc
             *
             * @phase local ldap add
             * @message DBSSession: begin LDAP modify <entry>
             */
            mConn.modify(name, ldapMods);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new EDBNotAvailException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            throw new EDBException(CMS.getUserMessage("CMS_DBS_LDAP_OP_FAILURE",
                        name + " " + e.toString()));
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
    public IDBSearchResults search(String base, String filter)
            throws EBaseException {
        return search(base, filter, null);
    }

    @SuppressWarnings("unchecked")
    public IDBSearchResults search(String base, String filter, int maxSize)
            throws EBaseException {
        try {
            String ldapattrs[] = null;
            String ldapfilter =
                    mDBSystem.getRegistry().getFilter(filter);

            LDAPSearchConstraints cons = new LDAPSearchConstraints();

            cons.setMaxResults(maxSize);

            LDAPSearchResults res = mConn.search(base,
                    LDAPv2.SCOPE_ONE, ldapfilter, ldapattrs, false, cons);

            return new DBSearchResults(mDBSystem.getRegistry(),
                    res);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new EDBNotAvailException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new EDBException(CMS.getUserMessage("CMS_DBS_LDAP_OP_FAILURE",
                        e.toString()));
        }
    }

    @SuppressWarnings("unchecked")
    public IDBSearchResults search(String base, String filter, int maxSize, int timeLimit)
            throws EBaseException {
        try {
            String ldapattrs[] = null;
            String ldapfilter =
                    mDBSystem.getRegistry().getFilter(filter);

            LDAPSearchConstraints cons = new LDAPSearchConstraints();

            cons.setMaxResults(maxSize);
            cons.setServerTimeLimit(timeLimit);

            LDAPSearchResults res = mConn.search(base,
                    LDAPv2.SCOPE_ONE, ldapfilter, ldapattrs, false, cons);

            return new DBSearchResults(mDBSystem.getRegistry(),
                    res);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new EDBNotAvailException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new EDBException(CMS.getUserMessage("CMS_DBS_LDAP_OP_FAILURE",
                        e.toString()));
        }
    }

    /**
     * Retrieves a list of object that satifies the given
     * filter.
     */
    @SuppressWarnings("unchecked")
    public IDBSearchResults search(String base, String filter,
            String attrs[]) throws EBaseException {
        try {
            String ldapattrs[] = null;

            if (attrs != null) {
                ldapattrs = mDBSystem.getRegistry(
                        ).getLDAPAttributes(attrs);
            }
            String ldapfilter =
                    mDBSystem.getRegistry().getFilter(filter);

            /*LogDoc
             *
             * @phase local ldap add
             * @message DBSSession: begin LDAP search <filter>
             */
            LDAPSearchConstraints cons = new LDAPSearchConstraints();

            cons.setMaxResults(0);

            LDAPSearchResults res = mConn.search(base,
                    LDAPv2.SCOPE_ONE, ldapfilter, ldapattrs, false, cons);

            return new DBSearchResults(mDBSystem.getRegistry(),
                    res);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new EDBNotAvailException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new EDBException(CMS.getUserMessage("CMS_DBS_LDAP_OP_FAILURE",
                        e.toString()));
        }
    }

    public LDAPSearchResults persistentSearch(String base, String filter, String attrs[])
            throws EBaseException {
        try {
            String ldapattrs[] = null;
            if (attrs != null) {
                ldapattrs = mDBSystem.getRegistry(
                        ).getLDAPAttributes(attrs);
            }
            String ldapfilter =
                    mDBSystem.getRegistry().getFilter(filter);

            Integer version = (Integer) (mConn.getOption(LDAPv2.PROTOCOL_VERSION));

            // Only version 3 protocol supports persistent search.
            if (version.intValue() == 2) {
                mConn.setOption(LDAPv2.PROTOCOL_VERSION, Integer.valueOf(3));
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
                    LDAPv2.SCOPE_ONE, ldapfilter, ldapattrs, false, cons);
            return res;
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new EDBNotAvailException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new EDBException(CMS.getUserMessage("CMS_DBS_LDAP_OP_FAILURE",
                        e.toString()));
        }
    }

    public void abandon(LDAPSearchResults results) throws EBaseException {
        try {
            mConn.abandon(results);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE)
                throw new EDBNotAvailException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            // XXX error handling, should not raise exception if
            // entry not found
            throw new EDBException(CMS.getUserMessage("CMS_DBS_LDAP_OP_FAILURE",
                        e.toString()));
        }
    }

    /**
     * Retrieves a list of objects.
     */
    public <T> IDBVirtualList<T> createVirtualList(String base, String filter,
            String attrs[]) throws EBaseException {
        return new DBVirtualList<T>(mDBSystem.getRegistry(), mConn, base,
                filter, attrs);
    }

    /**
     * Retrieves a list of objects.
     */
    public <T> IDBVirtualList<T> createVirtualList(String base, String filter,
            String attrs[], String sortKey[]) throws EBaseException {
        return new DBVirtualList<T>(mDBSystem.getRegistry(), mConn, base,
                filter, attrs, sortKey);
    }

    /**
     * Retrieves a list of objects.
     */
    public IDBVirtualList<?> createVirtualList(String base, String filter,
            String attrs[], String sortKey) throws EBaseException {
        return new DBVirtualList<Object>(mDBSystem.getRegistry(), mConn, base,
                filter, attrs, sortKey);
    }

    /**
     * Retrieves a list of objects.
     */
    public IDBVirtualList<?> createVirtualList(String base, String filter,
            String attrs[], String sortKey[], int pageSize) throws EBaseException {
        return new DBVirtualList<Object>(mDBSystem.getRegistry(), mConn, base,
                filter, attrs, sortKey, pageSize);
    }

    /**
     * Retrieves a list of objects.
     */
    public IDBVirtualList<Object> createVirtualList(String base, String filter,
            String attrs[], String sortKey, int pageSize) throws EBaseException {
        return new DBVirtualList<Object>(mDBSystem.getRegistry(), mConn, base,
                filter, attrs, sortKey, pageSize);
    }

    public IDBVirtualList<Object> createVirtualList(String base, String filter,
            String attrs[], String startFrom, String sortKey, int pageSize) throws EBaseException {
        return new DBVirtualList<Object>(mDBSystem.getRegistry(), mConn, base,
                filter, attrs, startFrom, sortKey, pageSize);

    }

    /**
     * Releases object to this interface. This allows us to
     * use memory more efficiently.
     */
    public void release(Object obj) {
        // not implemented
    }

}
