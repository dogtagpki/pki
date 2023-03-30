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
import java.util.Set;

import org.mozilla.jss.netscape.security.x509.CertificateValidity;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotDefined;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.EDBNotAvailException;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmsutil.password.PasswordStore;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSchema;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPObjectClassSchema;
import netscape.ldap.LDAPSchema;

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
public class DBSubsystem {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DBSubsystem.class);

    public static final String ID = "dbs";

    public static final String PROP_NEXT_RANGE = "nextRange";
    public static final Set<String> DEFAULT_EXCLUDED_LDAP_ATTRS = Set.of(
            "req_x509info",
            "publickey",
            "req_extensions",
            "cert_request",
            "req_archive_options",
            "req_key"
    );

    protected EngineConfig engineConfig;
    private DatabaseConfig mDBConfig;
    private LDAPConfig ldapConfig;
    private LdapBoundConnFactory mLdapConnFactory;
    private DBRegistry mRegistry;
    private String mBaseDN;

    private boolean mEnableSerialMgmt;

    protected Set<String> excludedLdapAttrs;

    /**
     * Constructs database subsystem.
     */
    public DBSubsystem() {
    }

    public EngineConfig getEngineConfig() {
        return engineConfig;
    }

    public void setEngineConfig(EngineConfig engineConfig) {
        this.engineConfig = engineConfig;
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

        if (v) {
            logger.debug("DBSubsystem: Enabling Serial Number Management");
        } else {
            logger.debug("DBSubsystem: Disabling Serial Number Management");
        }

        mDBConfig.setEnableSerialManagement(v);
        engineConfig.commit(false);
        mEnableSerialMgmt = v;
    }

    public void setNextSerialConfig(BigInteger serial)
            throws EBaseException {
        logger.info("DBSubsystem: Setting next serial number: 0x" + serial.toString(16));
        mDBConfig.setNextSerialNumber(serial.toString(16));
    }

    public Set<String> getExcludedLdapAttr() {
        return excludedLdapAttrs;
    }

    /**
     * Configure LDAP attributes that need to be excluded from enrollment records.
     *
     * Default config:
     *   excludedLdapAttrs.enabled=false;
     *   (excludedLdapAttrs.attrs unspecified to take default)
     */
    public void configureExcludedLdapAttrs() throws EBaseException {

        String id = engineConfig.getType().toLowerCase();
        if (!id.equals("ca") && !id.equals("kra")) {
            // excludedLdapAttrs is null
            return;
        }

        logger.info("DBSubsystem: Configuring excluded LDAP attributes");

        boolean enabled = engineConfig.getBoolean("excludedLdapAttrs.enabled", false);
        logger.debug("DBSubsystem: excludedLdapAttrs.enabled: " + enabled);

        if (!enabled) {
            // excludedLdapAttrs is null
            return;
        }

        String attrs = engineConfig.getString("excludedLdapAttrs.attrs", "");
        logger.debug("DBSubsystem: excludedLdapAttrs.attrs: " + attrs);

        if (attrs.equals("")) {
            excludedLdapAttrs = DEFAULT_EXCLUDED_LDAP_ATTRS;
        } else {
            excludedLdapAttrs = Set.of(attrs.split(","));
        }
    }

    /**
     * Initializes the internal registry. Connects to the
     * data source, and create a pool of connection of which
     * applications can use. Optionally, check the integrity
     * of the database.
     */
    public void init(
            DatabaseConfig dbConfig,
            LDAPConfig ldapConfig,
            PKISocketConfig socketConfig,
            PasswordStore passwordStore)
            throws EBaseException {

        this.mDBConfig = dbConfig;
        this.ldapConfig = ldapConfig;

        try {
            mBaseDN = ldapConfig.getBaseDN("o=NetscapeCertificateServer");

            mEnableSerialMgmt = mDBConfig.getEnableSerialManagement();
            logger.debug("DBSubsystem: init()  mEnableSerialMgmt="+mEnableSerialMgmt);

            // initialize registry
            mRegistry = new LDAPRegistry();
            mRegistry.init(null);

            // initialize LDAP connection factory
            // by default return error if server is down at startup time.
            mLdapConnFactory = new LdapBoundConnFactory("DBSubsystem", true);

        } catch (EBaseException e) {
            logger.error("DBSubsystem: initialization failed: " + e.getMessage(), e);
            throw e;
        }

        try {
            LDAPConfig tmpConfig = (LDAPConfig) ldapConfig.clone();
            tmpConfig.setBaseDN(mBaseDN);

            mLdapConnFactory.init(socketConfig, tmpConfig, passwordStore);

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
            DBRegistry reg = getRegistry();

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
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_ID, new
                    StringMapper(CRLDBSchema.LDAP_ATTR_CRL_ID));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_CRL_NUMBER, new
                    BigIntegerMapper(CRLDBSchema.LDAP_ATTR_CRL_NUMBER));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_DELTA_NUMBER, new
                    BigIntegerMapper(CRLDBSchema.LDAP_ATTR_DELTA_NUMBER));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_CRL_SIZE, new
                    LongMapper(CRLDBSchema.LDAP_ATTR_CRL_SIZE));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_DELTA_SIZE, new
                    LongMapper(CRLDBSchema.LDAP_ATTR_DELTA_SIZE));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_THIS_UPDATE, new
                    DateMapper(CRLDBSchema.LDAP_ATTR_THIS_UPDATE));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_NEXT_UPDATE, new
                    DateMapper(CRLDBSchema.LDAP_ATTR_NEXT_UPDATE));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_FIRST_UNSAVED, new
                    StringMapper(CRLDBSchema.LDAP_ATTR_FIRST_UNSAVED));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_CRL, new
                    ByteArrayMapper(CRLDBSchema.LDAP_ATTR_CRL));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_DELTA_CRL, new
                    ByteArrayMapper(CRLDBSchema.LDAP_ATTR_DELTA_CRL));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_CA_CERT, new
                    ByteArrayMapper(CRLDBSchema.LDAP_ATTR_CA_CERT));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_CRL_CACHE, new
                    ObjectStreamMapper(CRLDBSchema.LDAP_ATTR_CRL_CACHE));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_REVOKED_CERTS, new
                    ObjectStreamMapper(CRLDBSchema.LDAP_ATTR_REVOKED_CERTS));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_UNREVOKED_CERTS, new
                    ObjectStreamMapper(CRLDBSchema.LDAP_ATTR_UNREVOKED_CERTS));
            reg.registerAttribute(CRLIssuingPointRecord.ATTR_EXPIRED_CERTS, new
                    ObjectStreamMapper(CRLDBSchema.LDAP_ATTR_EXPIRED_CERTS));

            boolean registered = reg.isObjectClassRegistered(RepositoryRecord.class.getName());
            logger.debug("registered: " + registered);
            if (!registered) {
                String repRecordOC[] = new String[2];

                repRecordOC[0] = RepositorySchema.LDAP_OC_TOP;
                repRecordOC[1] = RepositorySchema.LDAP_OC_REPOSITORY;
                reg.registerObjectClass(RepositoryRecord.class.getName(), repRecordOC);
            }

            if (!reg.isAttributeRegistered(RepositoryRecord.ATTR_SERIALNO)) {
                reg.registerAttribute(RepositoryRecord.ATTR_SERIALNO,
                        new BigIntegerMapper(RepositorySchema.LDAP_ATTR_SERIALNO));
            }
            if (!reg.isAttributeRegistered(RepositoryRecord.ATTR_PUB_STATUS)) {
                reg.registerAttribute(RepositoryRecord.ATTR_PUB_STATUS,
                        new StringMapper(RepositorySchema.LDAP_ATTR_PUB_STATUS));
            }
            if (!reg.isAttributeRegistered(RepositoryRecord.ATTR_DESCRIPTION)) {
                reg.registerAttribute(RepositoryRecord.ATTR_DESCRIPTION,
                        new StringMapper(RepositorySchema.LDAP_ATTR_DESCRIPTION));
            }

        } catch (EBaseException e) {
            logger.error("DBSubsystem: initialization failed: " + e.getMessage(), e);
            throw e;
        }

        configureExcludedLdapAttrs();
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
     * Retrieves internal DB configuration store.
     */
    public LDAPConfig getLDAPConfig() {
        return ldapConfig;
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
    public DBRegistry getRegistry() {
        return mRegistry;
    }

    /**
     * Creates a database session.
     */
    public DBSSession createSession() throws EDBException {

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

                engineConfig.commit(false);
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
        return new LDAPSession(this, conn);
    }

    public void returnConn(LDAPConnection conn) {
        mLdapConnFactory.returnConn(conn);
    }

}
