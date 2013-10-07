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
package com.netscape.cmscore.request;

import java.math.BigInteger;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.cmscore.dbs.Repository;
import com.netscape.cmscore.dbs.RepositoryRecord;

/**
 * TODO: what does this class provide beyond the Repository
 * base class??
 * <p>
 *
 * @author thayes
 * @version $Revision$ $Date$
 */
class RequestRepository
        extends Repository {

    IDBSubsystem mDB = null;
    IRequestQueue mRequestQueue = null;

    /**
     * Create a request repository that uses the LDAP database
     * <p>
     *
     * @param name
     *            the name of the repository. This String is used to
     *            construct the DN for the repository's LDAP entry.
     * @param db
     *            the LDAP database system.
     */
    public RequestRepository(String name, int increment, IDBSubsystem db)
            throws EDBException {
        super(db, increment, "ou=" + name + ",ou=requests," + db.getBaseDN());

        CMS.debug("RequestRepository: constructor 1");
        mBaseDN = "ou=" + name + ",ou=requests," + db.getBaseDN();

        // Let RequestRecord class register its
        // database mapping and object mapping values
        RequestRecord.register(db);
        mDB = db;
    }

    public RequestRepository(String name, int increment, IDBSubsystem db, IRequestQueue requestQueue)
            throws EDBException {
        super(db, increment, "ou=" + name + ",ou=requests," + db.getBaseDN());

        CMS.debug("RequestRepository: constructor2.");
        mRequestQueue = requestQueue;
        mBaseDN = "ou=" + name + ",ou=requests," + db.getBaseDN();

        // Let RequestRecord class register its
        // database mapping and object mapping values
        RequestRecord.register(db);
        mDB = db;
    }

    /**
     * get the LDAP base DN for this repository. This
     * value can be used by the request queue to create the
     * name for the request records themselves.
     * <p>
     *
     * @return
     *         the LDAP base DN.
     */
    public String getBaseDN() {
        return mBaseDN;
    }

    /**
     * Resets serial number.
     */
    public void resetSerialNumber(BigInteger serial) throws EBaseException {
        setTheSerialNumber(serial);
    }

    /**
     * Removes all objects with this repository.
     */
    public void removeAllObjects() throws EBaseException {
        IDBSSession s = mDB.createSession();
        try {
            IDBSearchResults sr = s.search(getBaseDN(),
                               "(" + RequestRecord.ATTR_REQUEST_ID + "=*)");
            while (sr.hasMoreElements()) {
                RequestRecord r = (RequestRecord) sr.nextElement();
                String name = "cn" + "=" +
                        r.getRequestId().toString() + "," + getBaseDN();
                s.delete(name);
            }
        } finally {
            if (s != null)
                s.close();
        }
    }

    public BigInteger getLastSerialNumberInRange(BigInteger min, BigInteger max) {

        CMS.debug("RequestRepository: in getLastSerialNumberInRange: min " + min + " max " + max);

        CMS.debug("RequestRepository: mRequestQueue " + mRequestQueue);

        BigInteger ret = null;

        if (mRequestQueue == null) {

            CMS.debug("RequestRepository:  mRequestQueue is null.");

        } else {

            CMS.debug("RequestRepository: about to call mRequestQueue.getLastRequestIdInRange");
            ret = mRequestQueue.getLastRequestIdInRange(min, max);

        }

        return ret;

    }

    /**
     * the LDAP base DN for this repository
     */
    protected String mBaseDN;

    public String getPublishingStatus() {
        RepositoryRecord record = null;
        Object obj = null;
        IDBSSession dbs = null;
        String status = null;

        try {
            dbs = mDB.createSession();
            obj = dbs.read(mBaseDN);
        } catch (Exception e) {
            CMS.debug("RequestRepository:  getPublishingStatus:  Error: " + e);
            CMS.debugStackTrace();
        } finally {
            // Close session - ignoring errors (UTIL)
            if (dbs != null) {
                try {
                    dbs.close();
                } catch (Exception ex) {
                    CMS.debug("RequestRepository:  getPublishingStatus:  Error: " + ex);
                }
            }
        }

        if (obj != null && (obj instanceof RepositoryRecord)) {
            record = (RepositoryRecord) obj;
            status = record.getPublishingStatus();
        } else {
            CMS.debug("RequestRepository:  obj is NOT instanceof RepositoryRecord");
        }
        CMS.debug("RequestRepository:  getPublishingStatus  mBaseDN: " + mBaseDN +
                  "  status: " + ((status != null) ? status : "null"));

        return status;
    }

    public void setPublishingStatus(String status) {
        IDBSSession dbs = null;

        CMS.debug("RequestRepository:  setPublishingStatus  mBaseDN: " + mBaseDN + "  status: " + status);
        ModificationSet mods = new ModificationSet();

        if (status != null && status.length() > 0) {
            mods.add(IRepositoryRecord.ATTR_PUB_STATUS,
                    Modification.MOD_REPLACE, status);

            try {
                dbs = mDB.createSession();
                dbs.modify(mBaseDN, mods);
            } catch (Exception e) {
                CMS.debug("RequestRepository:  setPublishingStatus:  Error: " + e);
                CMS.debugStackTrace();
            } finally {
                // Close session - ignoring errors (UTIL)
                if (dbs != null) {
                    try {
                        dbs.close();
                    } catch (Exception ex) {
                        CMS.debug("RequestRepository:  setPublishingStatus:  Error: " + ex);
                    }
                }
            }
        }
    }
}
