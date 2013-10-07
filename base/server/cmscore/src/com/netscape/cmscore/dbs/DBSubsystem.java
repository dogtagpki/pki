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

import java.math.BigInteger;
import java.util.Hashtable;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSchema;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPObjectClassSchema;
import netscape.ldap.LDAPSchema;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;
import netscape.security.x509.CertificateValidity;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.EDBNotAvailException;
import com.netscape.certsrv.dbs.IDBRegistry;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.LdapConnInfo;

/**
 * A class represents the database subsystem that manages
 * the backend data storage.
 *
 * This subsystem maintains multiple sessions that allows
 * operations to be performed, and provide a registry
 * where all the schema information is stored.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class DBSubsystem implements IDBSubsystem {

    public static String ID = IDBSubsystem.SUB_ID;

    private IConfigStore mConfig = null;
    private IConfigStore mDBConfig = null;
    private LdapBoundConnFactory mLdapConnFactory = null;
    private DBRegistry mRegistry = null;
    private String mBaseDN = null;
    private ISubsystem mOwner = null;

    private Hashtable<String, String>[] mRepos = null;

    private BigInteger mNextSerialConfig = null;
    private boolean mEnableSerialMgmt = false;

    private static final String PROP_ENABLE_SERIAL_NUMBER_RECOVERY =
            "enableSerialNumberRecovery";
    // This value is only equal to the next Serial number that the CA's
    // going to issue when cms just start up or it's just set from console.
    // It doesn't record the next serial number at other time when cms's
    // runing not to increase overhead when issuing certs.
    private static final String PROP_NEXT_SERIAL_NUMBER =
            "nextSerialNumber";
    private static final String PROP_MIN_SERIAL_NUMBER = "beginSerialNumber";
    private static final String PROP_MAX_SERIAL_NUMBER = "endSerialNumber";
    private static final String PROP_NEXT_MIN_SERIAL_NUMBER = "nextBeginSerialNumber";
    private static final String PROP_NEXT_MAX_SERIAL_NUMBER = "nextEndSerialNumber";
    private static final String PROP_SERIAL_LOW_WATER_MARK = "serialLowWaterMark";
    private static final String PROP_SERIAL_INCREMENT = "serialIncrement";
    private static final String PROP_SERIAL_BASEDN = "serialDN";
    private static final String PROP_SERIAL_RANGE_DN = "serialRangeDN";

    private static final String PROP_MIN_REQUEST_NUMBER = "beginRequestNumber";
    private static final String PROP_MAX_REQUEST_NUMBER = "endRequestNumber";
    private static final String PROP_NEXT_MIN_REQUEST_NUMBER = "nextBeginRequestNumber";
    private static final String PROP_NEXT_MAX_REQUEST_NUMBER = "nextEndRequestNumber";
    private static final String PROP_REQUEST_LOW_WATER_MARK = "requestLowWaterMark";
    private static final String PROP_REQUEST_INCREMENT = "requestIncrement";
    private static final String PROP_REQUEST_BASEDN = "requestDN";
    private static final String PROP_REQUEST_RANGE_DN = "requestRangeDN";

    private static final String PROP_MIN_REPLICA_NUMBER = "beginReplicaNumber";
    private static final String PROP_MAX_REPLICA_NUMBER = "endReplicaNumber";
    private static final String PROP_NEXT_MIN_REPLICA_NUMBER = "nextBeginReplicaNumber";
    private static final String PROP_NEXT_MAX_REPLICA_NUMBER = "nextEndReplicaNumber";
    private static final String PROP_REPLICA_LOW_WATER_MARK = "replicaLowWaterMark";
    private static final String PROP_REPLICA_INCREMENT = "replicaIncrement";
    private static final String PROP_REPLICA_BASEDN = "replicaDN";
    private static final String PROP_REPLICA_RANGE_DN = "replicaRangeDN";

    private static final String PROP_INFINITE_SERIAL_NUMBER = "1000000000";
    private static final String PROP_INFINITE_REQUEST_NUMBER = "1000000000";
    private static final String PROP_INFINITE_REPLICA_NUMBER = "1000";
    private static final String PROP_BASEDN = "basedn";
    private static final String PROP_LDAP = "ldap";
    private static final String PROP_NEXT_RANGE = "nextRange";
    private static final String PROP_ENABLE_SERIAL_MGMT = "enableSerialManagement";

    // hash keys
    private static final String NAME = "name";
    private static final String PROP_MIN = "min";
    private static final String PROP_MIN_NAME = "min_name";
    private static final String PROP_MAX = "max";
    private static final String PROP_MAX_NAME = "max_name";
    private static final String PROP_NEXT_MIN = "next_min";
    private static final String PROP_NEXT_MIN_NAME = "next_min_name";
    private static final String PROP_NEXT_MAX = "next_max";
    private static final String PROP_NEXT_MAX_NAME = "next_max_name";
    private static final String PROP_LOW_WATER_MARK = "lowWaterMark";
    private static final String PROP_LOW_WATER_MARK_NAME = "lowWaterMark_name";
    private static final String PROP_INCREMENT = "increment";
    private static final String PROP_INCREMENT_NAME = "increment_name";
    private static final String PROP_RANGE_DN = "rangeDN";

    private ILogger mLogger = null;

    // singleton enforcement

    private static IDBSubsystem mInstance = new DBSubsystem();

    public static IDBSubsystem getInstance() {
        return mInstance;
    }

    /**
     * This method is used for unit tests. It allows the underlying instance
     * to be stubbed out.
     *
     * @param dbSubsystem The stubbed out subsystem to override with.
     */
    public static void setInstance(IDBSubsystem dbSubsystem) {
        mInstance = dbSubsystem;
    }

    // end singleton enforcement.

    /**
     * Constructs database subsystem.
     */
    private DBSubsystem() {
    }

    /**
     * Retrieves subsystem identifier.
     */
    public String getId() {
        return IDBSubsystem.SUB_ID;
    }

    /**
     * Sets subsystem identifier.
     */
    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
    }

    public boolean enableSerialNumberRecovery() {
        try {
            return mDBConfig.getBoolean(
                    PROP_ENABLE_SERIAL_NUMBER_RECOVERY, true);
        } catch (EBaseException e) {
            // by default
            return true;
        }
    }

    public boolean getEnableSerialMgmt() {
        return mEnableSerialMgmt;
    }

    public void setEnableSerialMgmt(boolean v)
            throws EBaseException {
        if (v) {
            CMS.debug("DBSubsystem: Enabling Serial Number Management");
        } else {
            CMS.debug("DBSubsystem: Disabling Serial Number Management");
        }

        mDBConfig.putBoolean(PROP_ENABLE_SERIAL_MGMT, v);
        IConfigStore rootStore = getOwner().getConfigStore();
        rootStore.commit(false);
        mEnableSerialMgmt = v;
    }

    public BigInteger getNextSerialConfig() {
        return mNextSerialConfig;
    }

    public void setNextSerialConfig(BigInteger serial)
            throws EBaseException {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_DB,
                ILogger.LL_INFO, "DBSubsystem: " +
                        "Setting next serial number: 0x" + serial.toString(16));
        mDBConfig.putString(PROP_NEXT_SERIAL_NUMBER,
                serial.toString(16));
    }

    /**
     * Gets minimum serial number limit in config file
     *
     * @param repo repo identifier
     * @return min serial number
     */
    public String getMinSerialConfig(int repo) {
        return mRepos[repo].get(PROP_MIN);
    }

    /**
     * Gets maximum serial number limit in config file
     *
     * @param repo repo identifier
     * @return max serial number
     */
    public String getMaxSerialConfig(int repo) {
        return mRepos[repo].get(PROP_MAX);
    }

    /**
     * Gets minimum serial number limit in next range in config file
     *
     * @param repo repo identifier
     * @return min serial number in next range
     */
    public String getNextMinSerialConfig(int repo) {
        String ret = mRepos[repo].get(PROP_NEXT_MIN);
        if (ret.equals("-1")) {
            return null;
        } else {
            return ret;
        }
    }

    /**
     * Gets maximum serial number limit in next range in config file
     *
     * @param repo repo identifier
     * @return max serial number in next range
     */
    public String getNextMaxSerialConfig(int repo) {
        String ret = mRepos[repo].get(PROP_NEXT_MAX);
        if (ret.equals("-1")) {
            return null;
        } else {
            return ret;
        }
    }

    /**
     * Gets low water mark limit in config file
     *
     * @param repo repo identifier
     * @return low water mark
     */
    public String getLowWaterMarkConfig(int repo) {
        return mRepos[repo].get(PROP_LOW_WATER_MARK);
    }

    /**
     * Gets range increment for next range in config file
     *
     * @param repo repo identifier
     * @return range increment
     */
    public String getIncrementConfig(int repo) {
        return mRepos[repo].get(PROP_INCREMENT);
    }

    /**
     * Sets maximum serial number limit in config file
     *
     * @param repo repo identifier
     * @param serial max serial number
     * @exception EBaseException failed to set
     */
    public void setMaxSerialConfig(int repo, String serial)
            throws EBaseException {
        Hashtable<String, String> h = mRepos[repo];
        CMS.debug("DBSubsystem: Setting max serial number for " + h.get(NAME) + ": " + serial);

        //persist to file
        mDBConfig.putString(h.get(PROP_MAX_NAME), serial);
        IConfigStore rootStore = getOwner().getConfigStore();
        rootStore.commit(false);

        h.put(PROP_MAX, serial);
        mRepos[repo] = h;
    }

    /**
     * Sets minimum serial number limit in config file
     *
     * @param repo repo identifier
     * @param serial min serial number
     * @exception EBaseException failed to set
     */
    public void setMinSerialConfig(int repo, String serial)
            throws EBaseException {
        Hashtable<String, String> h = mRepos[repo];
        CMS.debug("DBSubsystem: Setting min serial number for " + h.get(NAME) + ": " + serial);

        //persist to file
        mDBConfig.putString(h.get(PROP_MIN_NAME), serial);
        IConfigStore rootStore = getOwner().getConfigStore();
        rootStore.commit(false);

        h.put(PROP_MIN, serial);
        mRepos[repo] = h;
    }

    /**
     * Sets maximum serial number limit for next range in config file
     *
     * @param repo repo identifier
     * @param serial max serial number for next range
     * @exception EBaseException failed to set
     */
    public void setNextMaxSerialConfig(int repo, String serial)
            throws EBaseException {
        Hashtable<String, String> h = mRepos[repo];
        if (serial == null) {
            CMS.debug("DBSubsystem: Removing next max " + h.get(NAME) + " number");
            mDBConfig.remove(h.get(PROP_NEXT_MAX_NAME));
        } else {
            CMS.debug("DBSubsystem: Setting next max " + h.get(NAME) + " number: " + serial);
            mDBConfig.putString(h.get(PROP_NEXT_MAX_NAME), serial);
        }
        IConfigStore rootStore = getOwner().getConfigStore();
        rootStore.commit(false);
        if (serial == null) {
            h.remove(PROP_NEXT_MAX);
        } else {
            h.put(PROP_NEXT_MAX, serial);
        }
        mRepos[repo] = h;
    }

    /**
     * Sets minimum serial number limit for next range in config file
     *
     * @param repo repo identifier
     * @param serial min serial number for next range
     * @exception EBaseException failed to set
     */
    public void setNextMinSerialConfig(int repo, String serial)
            throws EBaseException {
        Hashtable<String, String> h = mRepos[repo];
        if (serial == null) {
            CMS.debug("DBSubsystem: Removing next min " + h.get(NAME) + " number");
            mDBConfig.remove(h.get(PROP_NEXT_MIN_NAME));
        } else {
            CMS.debug("DBSubsystem: Setting next min " + h.get(NAME) + " number: " + serial);
            mDBConfig.putString(h.get(PROP_NEXT_MIN_NAME), serial);
        }
        IConfigStore rootStore = getOwner().getConfigStore();
        rootStore.commit(false);
        if (serial == null) {
            h.remove(PROP_NEXT_MIN);
        } else {
            h.put(PROP_NEXT_MIN, serial);
        }
        mRepos[repo] = h;
    }

    /**
     * Gets start of next range from database.
     * Increments the nextRange attribute and allocates
     * this range to the current instance by creating a pkiRange object.
     *
     * @param repo repo identifier
     * @return start of next range
     */
    public String getNextRange(int repo) {
        LDAPConnection conn = null;
        String nextRange = null;
        try {
            Hashtable<String, String> h = mRepos[repo];
            conn = mLdapConnFactory.getConn();
            String dn = h.get(PROP_BASEDN) + "," + mBaseDN;
            String rangeDN = h.get(PROP_RANGE_DN) + "," + mBaseDN;

            LDAPEntry entry = conn.read(dn);
            LDAPAttribute attr = entry.getAttribute(PROP_NEXT_RANGE);
            if (attr == null) {
                throw new Exception("Missing Attribute" + PROP_NEXT_RANGE + "in Entry " + dn);
            }
            nextRange = (String) attr.getStringValues().nextElement();

            BigInteger nextRangeNo = new BigInteger(nextRange);
            BigInteger incrementNo = new BigInteger(h.get(PROP_INCREMENT));
            // To make sure attrNextRange always increments, first delete the current value and then
            // increment.  Two operations in the same transaction
            LDAPAttribute attrNextRange = new LDAPAttribute(PROP_NEXT_RANGE, nextRangeNo.add(incrementNo).toString());
            LDAPModification[] mods = {
                    new LDAPModification(LDAPModification.DELETE, attr),
                    new LDAPModification(LDAPModification.ADD, attrNextRange) };
            conn.modify(dn, mods);

            // Add new range object
            String endRange = nextRangeNo.add(incrementNo).subtract(BigInteger.ONE).toString();
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectClass", "top"));
            attrs.add(new LDAPAttribute("objectClass", "pkiRange"));
            attrs.add(new LDAPAttribute("beginRange", nextRange));
            attrs.add(new LDAPAttribute("endRange", endRange));
            attrs.add(new LDAPAttribute("cn", nextRange));
            attrs.add(new LDAPAttribute("host", CMS.getEESSLHost()));
            attrs.add(new LDAPAttribute("securePort", CMS.getEESSLPort()));
            String dn2 = "cn=" + nextRange + "," + rangeDN;
            LDAPEntry rangeEntry = new LDAPEntry(dn2, attrs);
            conn.add(rangeEntry);
            CMS.debug("DBSubsystem: getNextRange  Next range has been added: " +
                      nextRange + " - " + endRange);
        } catch (Exception e) {
            CMS.debug("DBSubsystem: getNextRange. Unable to provide next range :" + e);
            e.printStackTrace();
            nextRange = null;
        } finally {
            try {
                if ((conn != null) && (mLdapConnFactory != null)) {
                    CMS.debug("Releasing ldap connection");
                    mLdapConnFactory.returnConn(conn);
                }
            } catch (Exception e) {
                CMS.debug("Error releasing the ldap connection" + e.toString());
            }
        }
        return nextRange;
    }

    /**
     * Determines if a range conflict has been observed in database.
     * If so, delete the conflict entry and remove the next range.
     * When the next number is requested, if the number of certs is still
     * below the low water mark, then a new range will be requested.
     *
     * @param repo repo identifier
     * @return true if range conflict, false otherwise
     */
    public boolean hasRangeConflict(int repo) {
        LDAPConnection conn = null;
        boolean conflict = false;
        try {
            String nextRangeStart = getNextMinSerialConfig(repo);
            if (nextRangeStart == null) {
                return false;
            }
            Hashtable<String, String> h = mRepos[repo];
            conn = mLdapConnFactory.getConn();
            String rangedn = h.get(PROP_RANGE_DN) + "," + mBaseDN;
            String filter = "(&(nsds5ReplConflict=*)(objectClass=pkiRange)(host= " +
                    CMS.getEESSLHost() + ")(SecurePort=" + CMS.getEESSLPort() +
                    ")(beginRange=" + nextRangeStart + "))";
            LDAPSearchResults results = conn.search(rangedn, LDAPv3.SCOPE_SUB,
                    filter, null, false);

            while (results.hasMoreElements()) {
                conflict = true;
                LDAPEntry entry = results.next();
                String dn = entry.getDN();
                CMS.debug("Deleting conflict entry:" + dn);
                conn.delete(dn);
            }
        } catch (Exception e) {
            CMS.debug("DBSubsystem: hasRangeConflict. Error while checking next range." + e);
            e.printStackTrace();
        } finally {
            try {
                if ((conn != null) && (mLdapConnFactory != null)) {
                    CMS.debug("Releasing ldap connection");
                    mLdapConnFactory.returnConn(conn);
                }
            } catch (Exception e) {
                CMS.debug("Error releasing the ldap connection" + e.toString());
            }
        }
        return conflict;
    }

    public ISubsystem getOwner() {
        return mOwner;
    }

    /**
     * Initializes the internal registery. Connects to the
     * data source, and create a pool of connection of which
     * applications can use. Optionally, check the integrity
     * of the database.
     */
    @SuppressWarnings("unchecked")
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {

        mLogger = CMS.getLogger();
        mDBConfig = config;
        mRepos = new Hashtable[IDBSubsystem.NUM_REPOS];

        mConfig = config.getSubStore(PROP_LDAP);
        IConfigStore tmpConfig = null;
        try {
            mBaseDN = mConfig.getString(PROP_BASEDN, "o=NetscapeCertificateServer");

            mOwner = owner;

            mNextSerialConfig = new BigInteger(mDBConfig.getString(
                    PROP_NEXT_SERIAL_NUMBER, "0"), 16);

            mEnableSerialMgmt = mDBConfig.getBoolean(PROP_ENABLE_SERIAL_MGMT, false);
            CMS.debug("DBSubsystem: init()  mEnableSerialMgmt="+mEnableSerialMgmt);

            // populate the certs hash entry
            Hashtable<String, String> certs = new Hashtable<String, String>();
            certs.put(NAME, "certs");
            certs.put(PROP_BASEDN, mDBConfig.getString(PROP_SERIAL_BASEDN, ""));
            certs.put(PROP_RANGE_DN, mDBConfig.getString(PROP_SERIAL_RANGE_DN, ""));

            certs.put(PROP_MIN_NAME, PROP_MIN_SERIAL_NUMBER);
            certs.put(PROP_MIN, mDBConfig.getString(
                    PROP_MIN_SERIAL_NUMBER, "0"));

            certs.put(PROP_MAX_NAME, PROP_MAX_SERIAL_NUMBER);
            certs.put(PROP_MAX, mDBConfig.getString(
                    PROP_MAX_SERIAL_NUMBER, PROP_INFINITE_SERIAL_NUMBER));

            certs.put(PROP_NEXT_MIN_NAME, PROP_NEXT_MIN_SERIAL_NUMBER);
            certs.put(PROP_NEXT_MIN, mDBConfig.getString(
                    PROP_NEXT_MIN_SERIAL_NUMBER, "-1"));

            certs.put(PROP_NEXT_MAX_NAME, PROP_NEXT_MAX_SERIAL_NUMBER);
            certs.put(PROP_NEXT_MAX, mDBConfig.getString(
                    PROP_NEXT_MAX_SERIAL_NUMBER, "-1"));

            certs.put(PROP_LOW_WATER_MARK_NAME, PROP_SERIAL_LOW_WATER_MARK);
            certs.put(PROP_LOW_WATER_MARK, mDBConfig.getString(
                    PROP_SERIAL_LOW_WATER_MARK, "5000"));

            certs.put(PROP_INCREMENT_NAME, PROP_SERIAL_INCREMENT);
            certs.put(PROP_INCREMENT, mDBConfig.getString(
                    PROP_SERIAL_INCREMENT, PROP_INFINITE_SERIAL_NUMBER));

            mRepos[CERTS] = certs;

            // populate the requests hash entry
            Hashtable<String, String> requests = new Hashtable<String, String>();
            requests.put(NAME, "requests");
            requests.put(PROP_BASEDN, mDBConfig.getString(PROP_REQUEST_BASEDN, ""));
            requests.put(PROP_RANGE_DN, mDBConfig.getString(PROP_REQUEST_RANGE_DN, ""));

            requests.put(PROP_MIN_NAME, PROP_MIN_REQUEST_NUMBER);
            requests.put(PROP_MIN, mDBConfig.getString(
                    PROP_MIN_REQUEST_NUMBER, "0"));

            requests.put(PROP_MAX_NAME, PROP_MAX_REQUEST_NUMBER);
            requests.put(PROP_MAX, mDBConfig.getString(
                    PROP_MAX_REQUEST_NUMBER, PROP_INFINITE_REQUEST_NUMBER));

            requests.put(PROP_NEXT_MIN_NAME, PROP_NEXT_MIN_REQUEST_NUMBER);
            requests.put(PROP_NEXT_MIN, mDBConfig.getString(
                    PROP_NEXT_MIN_REQUEST_NUMBER, "-1"));

            requests.put(PROP_NEXT_MAX_NAME, PROP_NEXT_MAX_REQUEST_NUMBER);
            requests.put(PROP_NEXT_MAX, mDBConfig.getString(
                    PROP_NEXT_MAX_REQUEST_NUMBER, "-1"));

            requests.put(PROP_LOW_WATER_MARK_NAME, PROP_REQUEST_LOW_WATER_MARK);
            requests.put(PROP_LOW_WATER_MARK, mDBConfig.getString(
                    PROP_REQUEST_LOW_WATER_MARK, "5000"));

            requests.put(PROP_INCREMENT_NAME, PROP_REQUEST_INCREMENT);
            requests.put(PROP_INCREMENT, mDBConfig.getString(
                    PROP_REQUEST_INCREMENT, PROP_INFINITE_REQUEST_NUMBER));

            mRepos[REQUESTS] = requests;

            // populate replica ID hash entry
            Hashtable<String, String> replicaID = new Hashtable<String, String>();
            replicaID.put(NAME, "requests");
            replicaID.put(PROP_BASEDN, mDBConfig.getString(PROP_REPLICA_BASEDN, ""));
            replicaID.put(PROP_RANGE_DN, mDBConfig.getString(PROP_REPLICA_RANGE_DN, ""));

            replicaID.put(PROP_MIN_NAME, PROP_MIN_REPLICA_NUMBER);
            replicaID.put(PROP_MIN, mDBConfig.getString(
                    PROP_MIN_REPLICA_NUMBER, "1"));

            replicaID.put(PROP_MAX_NAME, PROP_MAX_REPLICA_NUMBER);
            replicaID.put(PROP_MAX, mDBConfig.getString(
                    PROP_MAX_REPLICA_NUMBER, PROP_INFINITE_REPLICA_NUMBER));

            replicaID.put(PROP_NEXT_MIN_NAME, PROP_NEXT_MIN_REPLICA_NUMBER);
            replicaID.put(PROP_NEXT_MIN, mDBConfig.getString(
                    PROP_NEXT_MIN_REPLICA_NUMBER, "-1"));

            replicaID.put(PROP_NEXT_MAX_NAME, PROP_NEXT_MAX_REPLICA_NUMBER);
            replicaID.put(PROP_NEXT_MAX, mDBConfig.getString(
                    PROP_NEXT_MAX_REPLICA_NUMBER, "-1"));

            replicaID.put(PROP_LOW_WATER_MARK_NAME, PROP_REPLICA_LOW_WATER_MARK);
            replicaID.put(PROP_LOW_WATER_MARK, mDBConfig.getString(
                    PROP_REPLICA_LOW_WATER_MARK, "10"));

            replicaID.put(PROP_INCREMENT_NAME, PROP_REPLICA_INCREMENT);
            replicaID.put(PROP_INCREMENT, mDBConfig.getString(
                    PROP_REPLICA_INCREMENT, PROP_INFINITE_REPLICA_NUMBER));

            mRepos[REPLICA_ID] = replicaID;

            // initialize registry
            mRegistry = new DBRegistry();
            mRegistry.init(this, null);

            // initialize LDAP connection factory
            // by default return error if server is down at startup time.
            mLdapConnFactory = new LdapBoundConnFactory(true);
            tmpConfig = (IConfigStore) (((PropConfigStore) mConfig).clone());

            tmpConfig.putString(PROP_BASEDN, mBaseDN);
        } catch (EBaseException e) {
            if (CMS.isPreOpMode())
                return;
            throw e;
        }

        try {
            mLdapConnFactory.init(tmpConfig);
        } catch (ELdapServerDownException e) {
            if (CMS.isPreOpMode())
                return;
            throw new EDBNotAvailException(
                    CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
        } catch (ELdapException ex) {
            if (CMS.isPreOpMode())
                return;
            throw new EDBException(CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_ERROR", ex.toString()));
        } catch (EBaseException e) {
            if (CMS.isPreOpMode())
                return;
            throw e;
        }

        try {
            // registers CMS database attributes
            IDBRegistry reg = getRegistry();

            String certRecordOC[] = new String[2];

            certRecordOC[0] = CertDBSchema.LDAP_OC_TOP;
            certRecordOC[1] = CertDBSchema.LDAP_OC_CERT_RECORD;

            if (!reg.isObjectClassRegistered(CertRecord.class.getName())) {
                reg.registerObjectClass(CertRecord.class.getName(),
                        certRecordOC);
            }
            if (!reg.isAttributeRegistered(CertRecord.ATTR_ID)) {
                reg.registerAttribute(CertRecord.ATTR_ID, new
                        BigIntegerMapper(CertDBSchema.LDAP_ATTR_SERIALNO));
            }
            if (!reg.isAttributeRegistered(CertRecord.ATTR_META_INFO)) {
                reg.registerAttribute(CertRecord.ATTR_META_INFO, new
                        MetaInfoMapper(CertDBSchema.LDAP_ATTR_META_INFO));
            }
            if (!reg.isAttributeRegistered(CertRecord.ATTR_REVO_INFO)) {
                reg.registerAttribute(CertRecord.ATTR_REVO_INFO, new
                        RevocationInfoMapper());
            }
            if (!reg.isAttributeRegistered(CertRecord.ATTR_X509CERT)) {
                reg.registerAttribute(CertRecord.ATTR_X509CERT, new
                        X509CertImplMapper());
            }
            if (!reg.isAttributeRegistered(CertRecord.ATTR_CERT_STATUS)) {
                reg.registerAttribute(CertRecord.ATTR_CERT_STATUS, new
                        StringMapper(CertDBSchema.LDAP_ATTR_CERT_STATUS));
            }
            if (!reg.isAttributeRegistered(CertRecord.ATTR_AUTO_RENEW)) {
                reg.registerAttribute(CertRecord.ATTR_AUTO_RENEW, new
                        StringMapper(CertDBSchema.LDAP_ATTR_AUTO_RENEW));
            }
            if (!reg.isAttributeRegistered(CertRecord.ATTR_CREATE_TIME)) {
                reg.registerAttribute(CertRecord.ATTR_CREATE_TIME, new
                        DateMapper(CertDBSchema.LDAP_ATTR_CREATE_TIME));
            }
            if (!reg.isAttributeRegistered(CertRecord.ATTR_MODIFY_TIME)) {
                reg.registerAttribute(CertRecord.ATTR_MODIFY_TIME, new
                        DateMapper(CertDBSchema.LDAP_ATTR_MODIFY_TIME));
            }
            if (!reg.isAttributeRegistered(CertRecord.ATTR_ISSUED_BY)) {
                reg.registerAttribute(CertRecord.ATTR_ISSUED_BY, new
                        StringMapper(CertDBSchema.LDAP_ATTR_ISSUED_BY));
            }
            if (!reg.isAttributeRegistered(CertRecord.ATTR_REVOKED_BY)) {
                reg.registerAttribute(CertRecord.ATTR_REVOKED_BY, new
                        StringMapper(CertDBSchema.LDAP_ATTR_REVOKED_BY));
            }
            if (!reg.isAttributeRegistered(CertRecord.ATTR_REVOKED_ON)) {
                reg.registerAttribute(CertRecord.ATTR_REVOKED_ON, new
                        DateMapper(CertDBSchema.LDAP_ATTR_REVOKED_ON));
            }

            if (!reg.isAttributeRegistered(CertificateValidity.NOT_AFTER)) {
                reg.registerAttribute(CertificateValidity.NOT_AFTER, new
                        DateMapper(CertDBSchema.LDAP_ATTR_NOT_AFTER));
            }

            if (!reg.isAttributeRegistered(CertificateValidity.NOT_BEFORE)) {
                reg.registerAttribute(CertificateValidity.NOT_BEFORE, new
                        DateMapper(CertDBSchema.LDAP_ATTR_NOT_BEFORE));
            }

            String crlRecordOC[] = new String[2];

            crlRecordOC[0] = CRLDBSchema.LDAP_OC_TOP;
            crlRecordOC[1] = CRLDBSchema.LDAP_OC_CRL_RECORD;
            reg.registerObjectClass(CRLIssuingPointRecord.class.getName(),
                    crlRecordOC);
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_ID, new
                    StringMapper(CRLDBSchema.LDAP_ATTR_CRL_ID));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_CRL_NUMBER, new
                    BigIntegerMapper(CRLDBSchema.LDAP_ATTR_CRL_NUMBER));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_DELTA_NUMBER, new
                    BigIntegerMapper(CRLDBSchema.LDAP_ATTR_DELTA_NUMBER));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_CRL_SIZE, new
                    LongMapper(CRLDBSchema.LDAP_ATTR_CRL_SIZE));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_DELTA_SIZE, new
                    LongMapper(CRLDBSchema.LDAP_ATTR_DELTA_SIZE));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_THIS_UPDATE, new
                    DateMapper(CRLDBSchema.LDAP_ATTR_THIS_UPDATE));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_NEXT_UPDATE, new
                    DateMapper(CRLDBSchema.LDAP_ATTR_NEXT_UPDATE));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_FIRST_UNSAVED, new
                    StringMapper(CRLDBSchema.LDAP_ATTR_FIRST_UNSAVED));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_CRL, new
                    ByteArrayMapper(CRLDBSchema.LDAP_ATTR_CRL));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_DELTA_CRL, new
                    ByteArrayMapper(CRLDBSchema.LDAP_ATTR_DELTA_CRL));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_CA_CERT, new
                    ByteArrayMapper(CRLDBSchema.LDAP_ATTR_CA_CERT));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_CRL_CACHE, new
                    ObjectStreamMapper(CRLDBSchema.LDAP_ATTR_CRL_CACHE));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_REVOKED_CERTS, new
                    ObjectStreamMapper(CRLDBSchema.LDAP_ATTR_REVOKED_CERTS));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_UNREVOKED_CERTS, new
                    ObjectStreamMapper(CRLDBSchema.LDAP_ATTR_UNREVOKED_CERTS));
            reg.registerAttribute(ICRLIssuingPointRecord.ATTR_EXPIRED_CERTS, new
                    ObjectStreamMapper(CRLDBSchema.LDAP_ATTR_EXPIRED_CERTS));

            if (!reg.isObjectClassRegistered(
                    RepositoryRecord.class.getName())) {
                String repRecordOC[] = new String[2];

                repRecordOC[0] = RepositorySchema.LDAP_OC_TOP;
                repRecordOC[1] = RepositorySchema.LDAP_OC_REPOSITORY;
                reg.registerObjectClass(
                        RepositoryRecord.class.getName(), repRecordOC);
            }
            if (!reg.isAttributeRegistered(IRepositoryRecord.ATTR_SERIALNO)) {
                reg.registerAttribute(IRepositoryRecord.ATTR_SERIALNO,
                        new BigIntegerMapper(RepositorySchema.LDAP_ATTR_SERIALNO));
            }
            if (!reg.isAttributeRegistered(IRepositoryRecord.ATTR_PUB_STATUS)) {
                reg.registerAttribute(IRepositoryRecord.ATTR_PUB_STATUS,
                        new StringMapper(RepositorySchema.LDAP_ATTR_PUB_STATUS));
            }
            if (!reg.isAttributeRegistered(IRepositoryRecord.ATTR_DESCRIPTION)) {
                reg.registerAttribute(IRepositoryRecord.ATTR_DESCRIPTION,
                        new StringMapper(RepositorySchema.LDAP_ATTR_DESCRIPTION));
            }

        } catch (EBaseException e) {
            if (CMS.isPreOpMode())
                return;
            throw e;
        }
    }

    public String getEntryAttribute(String dn, String attrName,
                                    String defaultValue, String errorValue) {
        LDAPConnection conn = null;
        String attrValue = null;
        try {
            conn = mLdapConnFactory.getConn();
            String[] attrs = { attrName };
            LDAPEntry entry = conn.read(dn, attrs);
            if (entry != null) {
                LDAPAttribute attr =  entry.getAttribute(attrName);
                if (attr != null) {
                    attrValue = (String) attr.getStringValues().nextElement();
                } else {
                    attrValue = defaultValue;
                }
            } else {
                attrValue = errorValue;
            }
        } catch (LDAPException e) {
            CMS.debug("DBSubsystem: getEntryAttribute  LDAPException  code="+e.getLDAPResultCode());
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                attrValue = defaultValue;
            }
        } catch (Exception e) {
            CMS.debug("DBSubsystem: getEntryAttribute. Unable to retrieve '"+attrName+"': "+ e);
            attrValue = errorValue;
        } finally {
            try {
                if ((conn != null) && (mLdapConnFactory != null)) {
                    CMS.debug("Releasing ldap connection");
                    mLdapConnFactory.returnConn(conn);
                }
            } catch (Exception e) {
                CMS.debug("Error releasing the ldap connection" + e.toString());
            }
        }
        CMS.debug("DBSubsystem: getEntryAttribute:  dn="+dn+"  attr="+attrName+":"+attrValue+";");

        return attrValue;
    }

    /**
     * Starts up this service.
     */
    public void startup() throws EBaseException {
    }

    /**
     * Retrieves internal DB configuration store.
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Retrieves DB subsystem configuration store.
     */
    public IConfigStore getDBConfigStore() {
        return mDBConfig;
    }

    /**
     * Retrieves base DN of backend database.
     */
    public String getBaseDN() {
        return mBaseDN;
    }

    /**
     * Retrieves LDAP connection info (host, port, secure)
     */
    public LdapConnInfo getLdapConnInfo() {
        if (mLdapConnFactory != null)
            return mLdapConnFactory.getConnInfo();
        return null;
    }

    public LdapAuthInfo getLdapAuthInfo() {
        if (mLdapConnFactory != null)
            return mLdapConnFactory.getAuthInfo();
        return null;
    }

    /**
     * Shutdowns this subsystem gracefully.
     */
    public void shutdown() {
        try {
            if (mLdapConnFactory != null) {
                mLdapConnFactory.reset();
            }
        } catch (ELdapException e) {

            /*LogDoc
             *
             * @phase shutdown server
             * @reason shutdown db subsystem
             * @message DBSubsystem: <exception thrown>
             */
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_DB,
                    ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", e.toString()));
        }
        if (mRegistry != null)
            mRegistry.shutdown();
    }

    /**
     * Retrieves the registry.
     */
    public IDBRegistry getRegistry() {
        return mRegistry;
    }

    /**
     * Creates a database session.
     */
    public IDBSSession createSession() throws EDBException {
        LDAPConnection conn = null;

        try {
            conn = mLdapConnFactory.getConn();

            String schemaAdded = mDBConfig.getString("newSchemaEntryAdded", "");

            if (schemaAdded.equals("")) {
                LDAPSchema dirSchema = new LDAPSchema();

                // create new attribute: userType
                dirSchema.fetchSchema(conn);
                LDAPAttributeSchema userType = dirSchema.getAttribute("usertype");

                if (userType == null) {
                    userType = new LDAPAttributeSchema("usertype", "usertype-oid",
                                "Distinguish whether the user is administrator, agent or subsystem.",
                                LDAPAttributeSchema.cis, false);
                    userType.add(conn);
                }

                // create new objectclass: cmsuser
                dirSchema.fetchSchema(conn);
                LDAPObjectClassSchema newObjClass = dirSchema.getObjectClass("cmsuser");
                String[] requiredAttrs = { "usertype" };
                String[] optionalAttrs = new String[0];

                if (newObjClass == null) {
                    newObjClass = new LDAPObjectClassSchema("cmsuser", "cmsuser-oid",
                                "top", "CMS User", requiredAttrs, optionalAttrs);
                    newObjClass.add(conn);
                }
                mDBConfig.putString("newSchemaEntryAdded", "true");
                IConfigStore rootStore = getOwner().getConfigStore();

                rootStore.commit(false);
            }
        } catch (ELdapException e) {
            if (e instanceof ELdapServerDownException) {
                throw new EDBNotAvailException(
                        CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"));
            }

            /*LogDoc
             *
             * @phase create db session
             */
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_DB, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_DBS_CONN_ERROR", e.toString()));
            throw new EDBException(
                    CMS.getUserMessage("CMS_DBS_CONNECT_LDAP_FAILED", e.toString()));
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() != 20) {
                mLogger.log(ILogger.EV_SYSTEM, ILogger.S_DB, ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_DBS_SCHEMA_ERROR", e.toString()));
                throw new EDBException(
                        CMS.getUserMessage("CMS_DBS_ADD_ENTRY_FAILED", e.toString()));
            }
        } catch (EBaseException e) {
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_DB, ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_DBS_CONF_ERROR",
                            e.toString()));
        }
        return new DBSSession(this, conn);
    }

    public void returnConn(LDAPConnection conn) {
        mLdapConnFactory.returnConn(conn);
    }

}
