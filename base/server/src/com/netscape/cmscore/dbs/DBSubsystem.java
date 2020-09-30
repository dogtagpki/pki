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

import org.mozilla.jss.netscape.security.x509.CertificateValidity;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotDefined;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.EDBNotAvailException;
import com.netscape.certsrv.dbs.IDBRegistry;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;

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
public class DBSubsystem implements ISubsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DBSubsystem.class);

    public final static String ID = "dbs";
    public final static int CERTS = 0;
    public final static int REQUESTS = 1;
    public final static int REPLICA_ID = 2;
    public final static int NUM_REPOS = 3;

    private LDAPConfig mConfig;
    private DatabaseConfig mDBConfig;
    private LdapBoundConnFactory mLdapConnFactory = null;
    private DBRegistry mRegistry = null;
    private String mBaseDN = null;

    private Hashtable<String, String>[] mRepos = null;

    private BigInteger mNextSerialConfig = null;
    private boolean mEnableSerialMgmt = false;

    public static final String PROP_ENABLE_SERIAL_NUMBER_RECOVERY =
            "enableSerialNumberRecovery";
    // This value is only equal to the next Serial number that the CA's
    // going to issue when cms just start up or it's just set from console.
    // It doesn't record the next serial number at other time when cms's
    // runing not to increase overhead when issuing certs.
    public static final String PROP_NEXT_SERIAL_NUMBER =
            "nextSerialNumber";
    public static final String PROP_MIN_SERIAL_NUMBER = "beginSerialNumber";
    public static final String PROP_MAX_SERIAL_NUMBER = "endSerialNumber";
    public static final String PROP_NEXT_MIN_SERIAL_NUMBER = "nextBeginSerialNumber";
    public static final String PROP_NEXT_MAX_SERIAL_NUMBER = "nextEndSerialNumber";
    public static final String PROP_SERIAL_LOW_WATER_MARK = "serialLowWaterMark";
    public static final String PROP_SERIAL_INCREMENT = "serialIncrement";
    public static final String PROP_SERIAL_BASEDN = "serialDN";
    public static final String PROP_SERIAL_RANGE_DN = "serialRangeDN";

    public static final String PROP_MIN_REQUEST_NUMBER = "beginRequestNumber";
    public static final String PROP_MAX_REQUEST_NUMBER = "endRequestNumber";
    public static final String PROP_NEXT_MIN_REQUEST_NUMBER = "nextBeginRequestNumber";
    public static final String PROP_NEXT_MAX_REQUEST_NUMBER = "nextEndRequestNumber";
    public static final String PROP_REQUEST_LOW_WATER_MARK = "requestLowWaterMark";
    public static final String PROP_REQUEST_INCREMENT = "requestIncrement";
    public static final String PROP_REQUEST_BASEDN = "requestDN";
    public static final String PROP_REQUEST_RANGE_DN = "requestRangeDN";

    public static final String PROP_MIN_REPLICA_NUMBER = "beginReplicaNumber";
    public static final String PROP_MAX_REPLICA_NUMBER = "endReplicaNumber";
    public static final String PROP_NEXT_MIN_REPLICA_NUMBER = "nextBeginReplicaNumber";
    public static final String PROP_NEXT_MAX_REPLICA_NUMBER = "nextEndReplicaNumber";
    public static final String PROP_REPLICA_LOW_WATER_MARK = "replicaLowWaterMark";
    public static final String PROP_REPLICA_INCREMENT = "replicaIncrement";
    public static final String PROP_REPLICA_BASEDN = "replicaDN";
    public static final String PROP_REPLICA_RANGE_DN = "replicaRangeDN";

    public static final String PROP_INFINITE_SERIAL_NUMBER = "1000000000";
    public static final String PROP_INFINITE_REQUEST_NUMBER = "1000000000";
    public static final String PROP_INFINITE_REPLICA_NUMBER = "1000";
    private static final String PROP_BASEDN = "basedn";
    private static final String PROP_LDAP = "ldap";
    private static final String PROP_NEXT_RANGE = "nextRange";
    public static final String PROP_ENABLE_SERIAL_MGMT = "enableSerialManagement";

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

    // singleton enforcement

    private static DBSubsystem mInstance = new DBSubsystem();

    public static DBSubsystem getInstance() {
        return mInstance;
    }

    /**
     * This method is used for unit tests. It allows the underlying instance
     * to be stubbed out.
     *
     * @param dbSubsystem The stubbed out subsystem to override with.
     */
    public static void setInstance(DBSubsystem dbSubsystem) {
        mInstance = dbSubsystem;
    }

    // end singleton enforcement.

    /**
     * Constructs database subsystem.
     */
    public DBSubsystem() {
    }

    /**
     * Retrieves subsystem identifier.
     */
    public String getId() {
        return ID;
    }

    /**
     * Sets subsystem identifier.
     */
    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
    }

    public boolean enableSerialNumberRecovery() {
        try {
            return mDBConfig.getEnableSerialNumberRecovery();
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

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        if (v) {
            logger.debug("DBSubsystem: Enabling Serial Number Management");
        } else {
            logger.debug("DBSubsystem: Disabling Serial Number Management");
        }

        mDBConfig.setEnableSerialManagement(v);
        cs.commit(false);
        mEnableSerialMgmt = v;
    }

    public BigInteger getNextSerialConfig() {
        return mNextSerialConfig;
    }

    public void setNextSerialConfig(BigInteger serial)
            throws EBaseException {
        logger.info("DBSubsystem: Setting next serial number: 0x" + serial.toString(16));
        mDBConfig.setNextSerialNumber(serial.toString(16));
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

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        Hashtable<String, String> h = mRepos[repo];
        logger.debug("DBSubsystem: Setting max serial number for " + h.get(NAME) + ": " + serial);

        //persist to file
        mDBConfig.putString(h.get(PROP_MAX_NAME), serial);
        cs.commit(false);

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

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        Hashtable<String, String> h = mRepos[repo];
        logger.debug("DBSubsystem: Setting min serial number for " + h.get(NAME) + ": " + serial);

        //persist to file
        mDBConfig.putString(h.get(PROP_MIN_NAME), serial);
        cs.commit(false);

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

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        Hashtable<String, String> h = mRepos[repo];
        if (serial == null) {
            logger.debug("DBSubsystem: Removing next max " + h.get(NAME) + " number");
            mDBConfig.remove(h.get(PROP_NEXT_MAX_NAME));
        } else {
            logger.debug("DBSubsystem: Setting next max " + h.get(NAME) + " number: " + serial);
            mDBConfig.putString(h.get(PROP_NEXT_MAX_NAME), serial);
        }

        cs.commit(false);

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

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        Hashtable<String, String> h = mRepos[repo];
        if (serial == null) {
            logger.debug("DBSubsystem: Removing next min " + h.get(NAME) + " number");
            mDBConfig.remove(h.get(PROP_NEXT_MIN_NAME));
        } else {
            logger.debug("DBSubsystem: Setting next min " + h.get(NAME) + " number: " + serial);
            mDBConfig.putString(h.get(PROP_NEXT_MIN_NAME), serial);
        }

        cs.commit(false);

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

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        LDAPConnection conn = null;
        String nextRange = null;
        try {
            Hashtable<String, String> h = mRepos[repo];
            conn = mLdapConnFactory.getConn();
            String dn = h.get(PROP_BASEDN) + "," + mBaseDN;
            String rangeDN = h.get(PROP_RANGE_DN) + "," + mBaseDN;

            logger.debug("DBSubsystem: retrieving " + dn);
            LDAPEntry entry = conn.read(dn);

            LDAPAttribute attr = entry.getAttribute(PROP_NEXT_RANGE);
            if (attr == null) {
                throw new Exception("Missing Attribute" + PROP_NEXT_RANGE + "in Entry " + dn);
            }
            nextRange = attr.getStringValues().nextElement();

            BigInteger nextRangeNo = new BigInteger(nextRange);
            BigInteger incrementNo = new BigInteger(h.get(PROP_INCREMENT));
            String newNextRange = nextRangeNo.add(incrementNo).toString();

            // To make sure attrNextRange always increments, first delete the current value and then
            // increment.  Two operations in the same transaction
            LDAPAttribute attrNextRange = new LDAPAttribute(PROP_NEXT_RANGE, newNextRange);
            LDAPModification[] mods = {
                    new LDAPModification(LDAPModification.DELETE, attr),
                    new LDAPModification(LDAPModification.ADD, attrNextRange) };

            logger.debug("DBSubsystem: updating " + PROP_NEXT_RANGE + " from " + nextRange + " to " + newNextRange);

            conn.modify(dn, mods);

            // Add new range object
            String endRange = nextRangeNo.add(incrementNo).subtract(BigInteger.ONE).toString();
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectClass", "top"));
            attrs.add(new LDAPAttribute("objectClass", "pkiRange"));
            attrs.add(new LDAPAttribute("beginRange", nextRange));
            attrs.add(new LDAPAttribute("endRange", endRange));
            attrs.add(new LDAPAttribute("cn", nextRange));
            attrs.add(new LDAPAttribute("host", cs.getHostname()));
            attrs.add(new LDAPAttribute("securePort", engine.getEESSLPort()));
            String dn2 = "cn=" + nextRange + "," + rangeDN;
            LDAPEntry rangeEntry = new LDAPEntry(dn2, attrs);

            logger.debug("DBSubsystem: adding new range object: " + dn2);

            conn.add(rangeEntry);

            logger.debug("DBSubsystem: getNextRange  Next range has been added: " +
                      nextRange + " - " + endRange);

        } catch (Exception e) {
            logger.warn("DBSubsystem: Unable to get next range: " + e.getMessage(), e);
            nextRange = null;

        } finally {
            try {
                if ((conn != null) && (mLdapConnFactory != null)) {
                    logger.debug("Releasing ldap connection");
                    mLdapConnFactory.returnConn(conn);
                }
            } catch (Exception e) {
                logger.warn("Error releasing the ldap connection: " + e.getMessage(), e);
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

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

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
                    cs.getHostname() + ")(SecurePort=" + engine.getEESSLPort() +
                    ")(beginRange=" + nextRangeStart + "))";
            LDAPSearchResults results = conn.search(rangedn, LDAPv3.SCOPE_SUB,
                    filter, null, false);

            while (results.hasMoreElements()) {
                conflict = true;
                LDAPEntry entry = results.next();
                String dn = entry.getDN();
                logger.debug("Deleting conflict entry:" + dn);
                conn.delete(dn);
            }
        } catch (Exception e) {
            logger.warn("DBSubsystem: Error while checking next range: " + e.getMessage(), e);
        } finally {
            try {
                if ((conn != null) && (mLdapConnFactory != null)) {
                    logger.debug("Releasing ldap connection");
                    mLdapConnFactory.returnConn(conn);
                }
            } catch (Exception e) {
                logger.warn("Error releasing the ldap connection" + e.getMessage(), e);
            }
        }

        return conflict;
    }

    /**
     * Initializes the internal registery. Connects to the
     * data source, and create a pool of connection of which
     * applications can use. Optionally, check the integrity
     * of the database.
     */
    @SuppressWarnings("unchecked")
    public void init(IConfigStore config)
            throws EBaseException {

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        mDBConfig = cs.getDatabaseConfig();
        mRepos = new Hashtable[DBSubsystem.NUM_REPOS];

        mConfig = config.getSubStore(PROP_LDAP, LDAPConfig.class);
        try {
            mBaseDN = mConfig.getBaseDN("o=NetscapeCertificateServer");

            mNextSerialConfig = new BigInteger(mDBConfig.getNextSerialNumber(), 16);

            mEnableSerialMgmt = mDBConfig.getEnableSerialManagement();
            logger.debug("DBSubsystem: init()  mEnableSerialMgmt="+mEnableSerialMgmt);

            // populate the certs hash entry
            Hashtable<String, String> certs = new Hashtable<String, String>();
            certs.put(NAME, "certs");
            certs.put(PROP_BASEDN, mDBConfig.getSerialDN());
            certs.put(PROP_RANGE_DN, mDBConfig.getSerialRangeDN());

            certs.put(PROP_MIN_NAME, PROP_MIN_SERIAL_NUMBER);
            certs.put(PROP_MIN, mDBConfig.getBeginSerialNumber());

            certs.put(PROP_MAX_NAME, PROP_MAX_SERIAL_NUMBER);
            certs.put(PROP_MAX, mDBConfig.getEndSerialNumber());

            certs.put(PROP_NEXT_MIN_NAME, PROP_NEXT_MIN_SERIAL_NUMBER);
            certs.put(PROP_NEXT_MIN, mDBConfig.getNextBeginSerialNumber());

            certs.put(PROP_NEXT_MAX_NAME, PROP_NEXT_MAX_SERIAL_NUMBER);
            certs.put(PROP_NEXT_MAX, mDBConfig.getNextEndSerialNumber());

            certs.put(PROP_LOW_WATER_MARK_NAME, PROP_SERIAL_LOW_WATER_MARK);
            certs.put(PROP_LOW_WATER_MARK, mDBConfig.getSerialLowWaterMark());

            certs.put(PROP_INCREMENT_NAME, PROP_SERIAL_INCREMENT);
            certs.put(PROP_INCREMENT, mDBConfig.getSerialIncrement());

            mRepos[CERTS] = certs;

            // populate the requests hash entry
            Hashtable<String, String> requests = new Hashtable<String, String>();
            requests.put(NAME, "requests");
            requests.put(PROP_BASEDN, mDBConfig.getRequestDN());
            requests.put(PROP_RANGE_DN, mDBConfig.getRequestRangeDN());

            requests.put(PROP_MIN_NAME, PROP_MIN_REQUEST_NUMBER);
            requests.put(PROP_MIN, mDBConfig.getBeginRequestNumber());

            requests.put(PROP_MAX_NAME, PROP_MAX_REQUEST_NUMBER);
            requests.put(PROP_MAX, mDBConfig.getEndRequestNumber());

            requests.put(PROP_NEXT_MIN_NAME, PROP_NEXT_MIN_REQUEST_NUMBER);
            requests.put(PROP_NEXT_MIN, mDBConfig.getNextBeginRequestNumber());

            requests.put(PROP_NEXT_MAX_NAME, PROP_NEXT_MAX_REQUEST_NUMBER);
            requests.put(PROP_NEXT_MAX, mDBConfig.getNextEndRequestNumber());

            requests.put(PROP_LOW_WATER_MARK_NAME, PROP_REQUEST_LOW_WATER_MARK);
            requests.put(PROP_LOW_WATER_MARK, mDBConfig.getRequestLowWaterMark());

            requests.put(PROP_INCREMENT_NAME, PROP_REQUEST_INCREMENT);
            requests.put(PROP_INCREMENT, mDBConfig.getRequestIncrement());

            mRepos[REQUESTS] = requests;

            // populate replica ID hash entry
            Hashtable<String, String> replicaID = new Hashtable<String, String>();
            replicaID.put(NAME, "requests");
            replicaID.put(PROP_BASEDN, mDBConfig.getReplicaDN());
            replicaID.put(PROP_RANGE_DN, mDBConfig.getReplicaRangeDN());

            replicaID.put(PROP_MIN_NAME, PROP_MIN_REPLICA_NUMBER);
            replicaID.put(PROP_MIN, mDBConfig.getBeginReplicaNumber());

            replicaID.put(PROP_MAX_NAME, PROP_MAX_REPLICA_NUMBER);
            replicaID.put(PROP_MAX, mDBConfig.getEndReplicaNumber());

            replicaID.put(PROP_NEXT_MIN_NAME, PROP_NEXT_MIN_REPLICA_NUMBER);
            replicaID.put(PROP_NEXT_MIN, mDBConfig.getNextBeginReplicaNumber());

            replicaID.put(PROP_NEXT_MAX_NAME, PROP_NEXT_MAX_REPLICA_NUMBER);
            replicaID.put(PROP_NEXT_MAX, mDBConfig.getNextEndReplicaNumber());

            replicaID.put(PROP_LOW_WATER_MARK_NAME, PROP_REPLICA_LOW_WATER_MARK);
            replicaID.put(PROP_LOW_WATER_MARK, mDBConfig.getReplicaLowWaterMark());

            replicaID.put(PROP_INCREMENT_NAME, PROP_REPLICA_INCREMENT);
            replicaID.put(PROP_INCREMENT, mDBConfig.getReplicaIncrement());

            mRepos[REPLICA_ID] = replicaID;

            // initialize registry
            mRegistry = new DBRegistry();
            mRegistry.init(null);

            // initialize LDAP connection factory
            // by default return error if server is down at startup time.
            mLdapConnFactory = new LdapBoundConnFactory("DBSubsystem", true);

        } catch (EBaseException e) {
            logger.error("DBSubsystem: initialization failed: " + e.getMessage(), e);
            throw e;
        }

        try {
            PKISocketConfig socketConfig = cs.getSocketConfig();
            LDAPConfig tmpConfig = (LDAPConfig) mConfig.clone();
            tmpConfig.setBaseDN(mBaseDN);

            mLdapConnFactory.init(socketConfig, tmpConfig, engine.getPasswordStore());

        } catch (EPropertyNotDefined e) {
            logger.error("DBSubsystem: initialization failed: " + e.getMessage(), e);
            throw e;

        } catch (ELdapServerDownException e) {
            logger.error("DBSubsystem: initialization failed: " + e.getMessage(), e);
            throw new EDBNotAvailException(
                CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_UNAVAILABLE"), e);

        } catch (ELdapException e) {
            logger.error("DBSubsystem: initialization failed: " + e.getMessage(), e);
            throw new EDBException(CMS.getUserMessage("CMS_DBS_INTERNAL_DIR_ERROR", e.toString()), e);

        } catch (EBaseException e) {
            logger.error("DBSubsystem: initialization failed: " + e.getMessage(), e);
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

            boolean registered = reg.isObjectClassRegistered(RepositoryRecord.class.getName());
            logger.debug("registered: " + registered);
            if (!registered) {
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
            logger.error("DBSubsystem: initialization failed: " + e.getMessage(), e);
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
                    attrValue = attr.getStringValues().nextElement();
                } else {
                    attrValue = defaultValue;
                }
            } else {
                attrValue = errorValue;
            }
        } catch (LDAPException e) {
            logger.warn("DBSubsystem: getEntryAttribute  LDAPException  code="+e.getLDAPResultCode());
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                attrValue = defaultValue;
            }
        } catch (Exception e) {
            logger.warn("DBSubsystem: getEntryAttribute. Unable to retrieve '"+attrName+"': "+ e);
            attrValue = errorValue;
        } finally {
            try {
                if ((conn != null) && (mLdapConnFactory != null)) {
                    logger.debug("Releasing ldap connection");
                    mLdapConnFactory.returnConn(conn);
                }
            } catch (Exception e) {
                logger.warn("Error releasing the ldap connection: " + e.getMessage(), e);
            }
        }

        logger.debug("DBSubsystem: getEntryAttribute:  dn="+dn+"  attr="+attrName+":"+attrValue+";");

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
    public LDAPConfig getConfigStore() {
        return mConfig;
    }

    /**
     * Retrieves DB subsystem configuration store.
     */
    public DatabaseConfig getDBConfigStore() {
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
                mLdapConnFactory.shutdown();
            }
        } catch (ELdapException e) {

            /*LogDoc
             *
             * @phase shutdown server
             * @reason shutdown db subsystem
             * @message DBSubsystem: <exception thrown>
             */
            logger.warn("DBSubsystem: "+ CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
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

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();

        LDAPConnection conn = null;

        try {
            conn = mLdapConnFactory.getConn();

            String schemaAdded = mDBConfig.getNewSchemaEntryAdded();

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
                mDBConfig.setNewSchemaEntryAdded("true");

                cs.commit(false);
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
            logger.error("DBSubsystem: "+ CMS.getLogMessage("CMSCORE_DBS_CONN_ERROR", e.toString()), e);
            throw new EDBException(
                    CMS.getUserMessage("CMS_DBS_CONNECT_LDAP_FAILED", e.toString()));
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() != 20) {
                logger.error("DBSubsystem: "+ CMS.getLogMessage("CMSCORE_DBS_SCHEMA_ERROR", e.toString()), e);
                throw new EDBException(
                        CMS.getUserMessage("CMS_DBS_ADD_ENTRY_FAILED", e.toString()));
            }
        } catch (EBaseException e) {
            logger.warn("DBSubsystem: "+ CMS.getLogMessage("CMSCORE_DBS_CONF_ERROR", e.toString()), e);
        }
        return new DBSSession(this, conn);
    }

    public void returnConn(LDAPConnection conn) {
        mLdapConnFactory.returnConn(conn);
    }

}
