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


import java.math.*;
import java.io.*;
import java.util.*;
import netscape.ldap.*;
import netscape.ldap.util.*;
import netscape.security.x509.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.keydb.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.certsrv.dbs.repository.*;
import com.netscape.certsrv.apps.*;
import com.netscape.cmscore.base.*;
import com.netscape.cmscore.ldapconn.*;
import com.netscape.cmscore.cert.*;


/**
 * A class represents the database subsystem that manages
 * the backend data storage.
 *
 * This subsystem maintains multiple sessions that allows
 * operations to be performed, and provide a registry
 * where all the schema information is stored.
 *
 * @author thomask
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $ 
 */
public class DBSubsystem implements IDBSubsystem {

    public static String ID = IDBSubsystem.SUB_ID;

    private IConfigStore mConfig = null;
    private IConfigStore mDBConfig = null;
    private LdapBoundConnFactory mLdapConnFactory = null;
    private DBRegistry mRegistry = null;
    private String mBaseDN = null;
    private ISubsystem mOwner = null;
    private BigInteger mNextSerialConfig = null;
    private String mMaxSerialConfig = null;
    private String mMinSerialConfig = null;

    private String mMinRequestConfig=null;
    private String mMaxRequestConfig=null;
    private static final String PEOPLE_DN = "ou=people";
    private static final String GROUPS_DN = "ou=groups";
    private static final String REQUESTS_DN = "ou=requests";
    private static final String XCERTS_DN = "cn=crossCerts";
    private static final String BASEDN = "o=netscapeCertificateServer";
    private static final String DEFAULT_DATABASE = "userRoot";
    private static final String AT_OC = "objectclass";
    private static final String AT_O = "o";
    private static final String AT_OU = "ou";
    private static final String CA_DN = "ou=ca";
    private static final String CR_DN = "ou=certificateRepository, ou=ca";
    private static final String CRL_DN = "ou=crlIssuingPoints, ou=ca";
    private static final String CA_REQUESTS_DN = "ou=ca, ou=requests";
    private static final String KRA_DN = "ou=kra";
    private static final String KR_DN = "ou=keyRepository, ou=kra";
    private static final String KRA_REQUESTS_DN = "ou=kra, ou=requests";
    private static final String PROP_ENABLE_SERIAL_NUMBER_RECOVERY = 
        "enableSerialNumberRecovery";
    // This value is only equal to the next Serial number that the CA's
    // going to issue when cms just start up or it's just set from console.
    // It doesn't record the next serial number at other time when cms's
    // runing not to increase overhead when issuing certs.
    private static final String PROP_NEXT_SERIAL_NUMBER = 
        "nextSerialNumber";
    private static final String PROP_MIN_SERIAL_NUMBER="beginSerialNumber";

    private static final String PROP_MAX_SERIAL_NUMBER = 
        "endSerialNumber";

    private static final String PROP_MIN_REQUEST_NUMBER="beginRequestNumber";
    private static final String PROP_MAX_REQUEST_NUMBER="endRequestNumber";

    private static final String PROP_INFINITE_SERIAL_NUMBER = "1000000000";
    private static final String PROP_INFINITE_REQUEST_NUMBER = "1000000000";
    private static final String PROP_BASEDN = "basedn";
    private static final String PROP_LDAP = "ldap";
    private ILogger mLogger = null;
 
    // singleton enforcement

    private static IDBSubsystem mInstance = new DBSubsystem();

    public static IDBSubsystem getInstance() {
        return mInstance;
    }

    /**
     * This method is used for unit tests.  It allows the underlying instance
     * to be stubbed out.
     * @param dbSubsystem  The stubbed out subsystem to override with.
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

    public String getMinSerialConfig()
    {
        return mMinSerialConfig;
    }
    public String getMaxSerialConfig() {
        return mMaxSerialConfig;
    }

    public String getMinRequestConfig()
    {
        return mMinRequestConfig;
    }

    public String getMaxRequestConfig()
    {
        return mMaxRequestConfig;
    }

    public void setMaxSerialConfig(String serial) 
        throws EBaseException {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_DB,
            ILogger.LL_INFO, "DBSubsystem: " +
            "Setting max serial number: 0x" + serial);
        mDBConfig.putString(PROP_MAX_SERIAL_NUMBER,
            serial);
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
    public void init(ISubsystem owner, IConfigStore config) 
        throws EBaseException {

        mLogger = CMS.getLogger();
        mDBConfig = config;

        mConfig = config.getSubStore(PROP_LDAP);
        IConfigStore tmpConfig = null;
        try {
            mBaseDN = mConfig.getString(PROP_BASEDN, "o=NetscapeCertificateServer");

            mOwner = owner; 
            mNextSerialConfig = new BigInteger(mDBConfig.getString(
                        PROP_NEXT_SERIAL_NUMBER, "0"), 16);

            mMinSerialConfig = mDBConfig.getString(
                   PROP_MIN_SERIAL_NUMBER,null);

            if(mMinSerialConfig == null)
            {
                mMinSerialConfig = "0";
            }


            mMaxSerialConfig = mDBConfig.getString(
                    PROP_MAX_SERIAL_NUMBER,null );

            if(mMaxSerialConfig == null)
            {
                mMaxSerialConfig = PROP_INFINITE_SERIAL_NUMBER;
            }

            CMS.debug("DBSubsystem:  mMinSerialConfig: " + mMinSerialConfig + " mMaxSerialConfig: " + mMaxSerialConfig);

            mMinRequestConfig = mDBConfig.getString(PROP_MIN_REQUEST_NUMBER,null);

            if(mMinRequestConfig == null)
            {
                CMS.debug("DBSubsystem: missing mMinSerialConfig value!");
                mMinRequestConfig = "0";
            }

            mMaxRequestConfig = mDBConfig.getString(PROP_MAX_REQUEST_NUMBER,null);

            if(mMaxRequestConfig == null)
            {
                CMS.debug("DBSubsystem: missing mMaxSerialConfig value!");
                mMaxRequestConfig = PROP_INFINITE_REQUEST_NUMBER;

            }

            CMS.debug("DBSubsystem:  mMinRequestConfig: " + mMinRequestConfig + " mMaxRequestConfig: " + mMaxRequestConfig);
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
            if (!reg.isAttributeRegistered(RepositoryRecord.ATTR_SERIALNO)) {
                reg.registerAttribute(RepositoryRecord.ATTR_SERIALNO,
                    new BigIntegerMapper(RepositorySchema.LDAP_ATTR_SERIALNO));
            }
        } catch (EBaseException e) {
            if (CMS.isPreOpMode())
                return;
            throw e;
        }
    }

    /**
     * Starts up this service.
     */
    public void startup() throws EBaseException {
    }
	
    /**
     * Retrieves configuration store.
     */
    public IConfigStore getConfigStore() {
        return mConfig;
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
                mLdapConnFactory = null;
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
                String[] requiredAttrs = {"usertype"};
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
