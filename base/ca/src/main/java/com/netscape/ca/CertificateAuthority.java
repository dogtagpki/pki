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
package com.netscape.ca;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAConfig;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NicknameConflictException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.UserCertConflictException;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.GeneralizedTime;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X500Signer;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkix.cert.Extension;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CADisabledException;
import com.netscape.certsrv.ca.CAEnabledException;
import com.netscape.certsrv.ca.CAMissingCertException;
import com.netscape.certsrv.ca.CAMissingKeyException;
import com.netscape.certsrv.ca.CANotLeafException;
import com.netscape.certsrv.ca.CATypeException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.CRLSigningInfoEvent;
import com.netscape.certsrv.logging.event.CertSigningInfoEvent;
import com.netscape.certsrv.logging.event.OCSPSigningInfoEvent;
import com.netscape.certsrv.ocsp.IOCSPService;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.security.SigningUnitConfig;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.cert.CertEnrollmentRequestFactory;
import com.netscape.cms.servlet.cert.EnrollmentProcessor;
import com.netscape.cms.servlet.cert.RenewalProcessor;
import com.netscape.cms.servlet.cert.RevocationProcessor;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.util.StatsSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.CertID;
import com.netscape.cmsutil.ocsp.CertStatus;
import com.netscape.cmsutil.ocsp.GoodInfo;
import com.netscape.cmsutil.ocsp.KeyHashID;
import com.netscape.cmsutil.ocsp.NameID;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.OCSPResponseStatus;
import com.netscape.cmsutil.ocsp.Request;
import com.netscape.cmsutil.ocsp.ResponderID;
import com.netscape.cmsutil.ocsp.ResponseBytes;
import com.netscape.cmsutil.ocsp.ResponseData;
import com.netscape.cmsutil.ocsp.RevokedInfo;
import com.netscape.cmsutil.ocsp.SingleResponse;
import com.netscape.cmsutil.ocsp.TBSRequest;
import com.netscape.cmsutil.ocsp.UnknownInfo;


/**
 * A class represents a Certificate Authority that is
 * responsible for certificate specific operations.
 * <P>
 *
 * @author lhsiao
 * @version $Revision$, $Date$
 */
public class CertificateAuthority extends Subsystem implements IAuthority, IOCSPService {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertificateAuthority.class);

    public static final String ID = "ca";

    public static final String PROP_REGISTRATION = "Registration";
    public static final String PROP_POLICY = "Policy";
    public static final String PROP_GATEWAY = "gateway";
    public static final String PROP_CLASS = "class";
    public static final String PROP_TYPE = "type";
    public static final String PROP_IMPL = "impl";
    public static final String PROP_PLUGIN = "plugin";
    public static final String PROP_INSTANCE = "instance";
    public static final String PROP_LISTENER_SUBSTORE = "listener";
    public static final String PROP_LDAP_PUBLISH_SUBSTORE = "ldappublish";
    public static final String PROP_ENABLE_PUBLISH = "enablePublish";
    public static final String PROP_ENABLE_LDAP_PUBLISH = "enableLdapPublish";

    public static final String PROP_X509CERT_VERSION = "X509CertVersion";
    public static final String PROP_ENABLE_PAST_CATIME = "enablePastCATime";
    public static final String PROP_ENABLE_PAST_CATIME_CACERT = "enablePastCATime_caCert";
    public static final String PROP_DEF_VALIDITY = "DefaultIssueValidity";
    public static final String PROP_FAST_SIGNING = "fastSigning";
    public static final String PROP_ENABLE_ADMIN_ENROLL = "enableAdminEnroll";

    // make this public so agent gateway can access for now.
    public static final String PROP_MASTER_CRL = "MasterCRL";

    public static final String PROP_NOTIFY_SUBSTORE = "notification";
    public static final String PROP_CERT_ISSUED_SUBSTORE = "certIssued";
    public static final String PROP_CERT_REVOKED_SUBSTORE = "certRevoked";
    public static final String PROP_REQ_IN_Q_SUBSTORE = "requestInQ";
    public static final String PROP_PUB_QUEUE_SUBSTORE = "publishingQueue";

    public static final String PROP_ISSUER_NAME = "name";
    public static final String PROP_CA_NAMES = "CAs";

    public static final String PROP_ENABLE_OCSP = "ocsp";
    public static final String PROP_ID = "id";

    public static final String OFFICIAL_NAME = "Certificate Manager";

    public static final OBJECT_IDENTIFIER OCSP_NONCE = new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.48.1.2");

    public static final int FASTSIGNING_DISABLED = 0;
    public static final int FASTSIGNING_ENABLED = 1;

    public static final long SECOND = 1000; // 1000 milliseconds
    public static final long MINUTE = 60 * SECOND;
    public static final long HOUR = 60 * MINUTE;
    public static final long DAY = 24 * HOUR;
    public static final long YEAR = DAY * 365;

    protected boolean hostCA;
    protected AuthorityID authorityID = null;
    protected AuthorityID authorityParentID = null;
    protected BigInteger authoritySerial = null;
    protected String authorityDescription = null;
    protected Collection<String> authorityKeyHosts = null;
    protected boolean authorityEnabled = true;
    private boolean hasKeys = false;
    ECAException signingUnitException = null;

    protected CAConfig mConfig;

    protected CASigningUnit mSigningUnit;
    protected CASigningUnit mOCSPSigningUnit;
    protected CASigningUnit mCRLSigningUnit;

    protected CertificateIssuerName mIssuerObj = null;
    protected CertificateSubjectName mSubjectObj = null;
    protected X500Name mName = null;
    protected String mNickname = null; // nickname of CA signing cert.
    protected long mCertSerialNumberCounter = System.currentTimeMillis();
    protected long mRequestID = System.currentTimeMillis();

    protected String[] mAllowedSignAlgors = null;

    protected String[] mCASigningAlgorithms = null;

    protected long mNumOCSPRequest = 0;
    protected long mTotalTime = 0;
    protected long mTotalData = 0;
    protected long mSignTime = 0;
    protected long mLookupTime = 0;

    /* cache responder ID for performance */
    private ResponderID mResponderIDByName = null;
    private ResponderID mResponderIDByHash = null;

    /**
     * Internal constants
     */

    private String mId = null;

    /**
     * Constructs a CA subsystem.
     */
    public CertificateAuthority() {
        hostCA = true;
    }

    /**
     * Construct and initialise a lightweight authority
     */
    public CertificateAuthority(
            X500Name dn,
            AuthorityID aid,
            AuthorityID parentAID,
            BigInteger serial,
            String signingKeyNickname,
            Collection<String> authorityKeyHosts,
            String authorityDescription,
            boolean authorityEnabled
            ) throws EBaseException {

        this.mId = CertificateAuthority.ID;
        this.hostCA = false;

        // cert and key may not have been replicated to local nssdb
        // yet, so set DN based on data from LDAP
        this.mName = dn;

        this.authorityID = aid;
        this.authorityParentID = parentAID;
        this.authoritySerial = serial;
        this.authorityDescription = authorityDescription;
        this.authorityEnabled = authorityEnabled;
        this.authorityKeyHosts = authorityKeyHosts;

        this.mNickname = signingKeyNickname;
    }

    /**
     * Return whether this CA is the host authority (not a
     * lightweight authority).
     */
    public boolean isHostAuthority() {
        return hostCA;
    }

    /**
     * Throw an exception if CA is not ready to perform signing operations.
     */
    public void ensureReady()
            throws ECAException {
        if (!authorityEnabled)
            throw new CADisabledException("Authority is disabled");
        if (!isReady()) {
            if (signingUnitException == null) {
                throw new CAMissingKeyException("Authority does not yet have signing key and cert in local NSSDB");
            }
            throw signingUnitException;
        }
    }

    /**
     * Return whether CA is ready to perform signing operations.
     */
    public boolean isReady() {
        return hasKeys;
    }

    /**
     * Return whether CA is enabled.
     */
    public boolean getAuthorityEnabled() {
        return authorityEnabled;
    }

    public void setAuthorityEnabled(boolean authorityEnabled) {
        this.authorityEnabled = authorityEnabled;
    }

    /**
     * Retrieves subsystem identifier.
     */
    @Override
    public String getId() {
        return mId;
    }

    /**
     * Sets subsystem identifier.
     */
    @Override
    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * Initializes this CA subsystem.
     *
     * @param config Subsystem configuration
     * @exception Exception Unable to initialize subsystem
     */
    @Override
    public void init(ConfigStore config) throws Exception {

        logger.info("CertificateAuthority: Initializing " +
                (authorityID == null ? "host CA" : "authority " + authorityID));

        CAEngine caEngine = (CAEngine) engine;
        CAEngineConfig cs = caEngine.getConfig();

        mConfig = cs.getCAConfig();

        // init signing unit & CA cert.

        try {
            initCertSigningUnit();
            initCRLSigningUnit();
            initOCSPSigningUnit();

            // try to update the cert once we have the cert and key
            checkForNewerCert();

        } catch (CAMissingCertException | CAMissingKeyException e) {
            logger.warn("CertificateAuthority: CA signing key and cert not (yet) present in NSS database");
            signingUnitException = e;
            caEngine.startKeyRetriever(this);

        } catch (Exception e) {
            throw new EBaseException(e);
        }
    }

    private void checkForNewerCert() throws EBaseException {

        logger.info("CertificateAuthority: Checking for newer CA cert");
        logger.info("CertificateAuthority: serial number: " + authoritySerial);

        if (authoritySerial == null) {
            return;
        }

        X509CertImpl caCertImpl = mSigningUnit.getCertImpl();
        if (authoritySerial.equals(caCertImpl.getSerialNumber())) {
            return;
        }

        // The authoritySerial recorded in LDAP differs from the
        // certificate in NSSDB.  Import the newer cert.
        //
        // Note that the new serial number need not be greater,
        // e.g. if random serial numbers are enabled.
        //
        logger.info("CertificateAuthority: Updating CA cert");
        logger.info("CertificateAuthority: serial number: " + authoritySerial);

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();

        try {
            X509Certificate oldCert = mSigningUnit.getCert();
            CryptoManager manager = CryptoManager.getInstance();

            // add new cert
            X509CertImpl newCert = certificateRepository.getX509Certificate(authoritySerial);
            manager.importUserCACertPackage(newCert.getEncoded(), mNickname);

            // delete old cert
            manager.getInternalKeyStorageToken().getCryptoStore()
                .deleteCert(oldCert);

            logger.info("CertificateAuthority: Reinitializing signing units after new certificate");
            initCertSigningUnit();
            initCRLSigningUnit();
            initOCSPSigningUnit();

        } catch (CAMissingCertException e) {
            logger.warn("CertificateAuthority: CA signing cert not (yet) present in NSS database");
            signingUnitException = e;

        } catch (CAMissingKeyException e) {
            logger.warn("CertificateAuthority: CA signing key not (yet) present in NSS database");
            signingUnitException = e;

        } catch (CertificateException e) {
            throw new ECAException("Failed to update certificate", e);
        } catch (NotInitializedException e) {
            throw new ECAException("CryptoManager not initialized", e);
        } catch (NicknameConflictException e) {
            throw new ECAException("Failed to update certificate; nickname conflict", e);
        } catch (UserCertConflictException e) {
            throw new ECAException("Failed to update certificate; user cert conflict", e);
        } catch (TokenException | NoSuchItemOnTokenException e) {
            // really shouldn't happen
            throw new ECAException("Failed to update certificate", e);

        } catch (Exception e) {
            throw new EBaseException(e);
        }
    }

    /**
     * Is this a clone CA?
     *
     * @return true if this is a clone CA
     */
    public boolean isClone() {
        return CAService.mCLAConnector != null;
    }

    /**
     * Starts up this subsystem.
     */
    @Override
    public void startup() throws EBaseException {
    }

    /**
     * Shutdowns this subsystem.
     * <P>
     */
    @Override
    public void shutdown() {
    }

    /**
     * Retrieves the configuration store of this subsystem.
     * <P>
     */
    @Override
    public CAConfig getConfigStore() {
        return mConfig;
    }

    public CAConfig getConfig() {
        return mConfig;
    }

    public void setConfig(CAConfig config) {
        mConfig = config;
    }

    /**
     * Retrieves the default signature algorithm of this certificate authority.
     *
     * @return the default signature algorithm of this CA
     */
    public SignatureAlgorithm getDefaultSignatureAlgorithm() {
        return mSigningUnit.getDefaultSignatureAlgorithm();
    }

    /**
     * Retrieves the default signing algorithm of this certificate authority.
     *
     * @return the default signing algorithm of this CA
     */
    public String getDefaultAlgorithm() {
        return mSigningUnit.getDefaultAlgorithm();
    }

    /**
     * Sets the default signing algorithm of this certificate authority.
     *
     * @param algorithm new default signing algorithm
     * @exception EBaseException failed to set the default signing algorithm
     */
    public void setDefaultAlgorithm(String algorithm) throws EBaseException {
        mSigningUnit.setDefaultAlgorithm(algorithm);
    }

    /**
     * Adds CRL issuing point with the given identifier and description.
     *
     * @param crlConfig sub-store with all CRL issuing points
     * @param id CRL issuing point id
     * @param description CRL issuing point description
     * @return true if CRL issuing point was successfully added
     */
    public boolean addCRLIssuingPoint(CRLConfig crlConfig, String id,
                                      boolean enable, String description) {

        CAEngine engine = CAEngine.getInstance();

        crlConfig.makeSubStore(id);
        CRLIssuingPointConfig ipConfig = crlConfig.getCRLIssuingPointConfig(id);

        if (ipConfig != null) {
            ipConfig.setAllowExtensions(true);
            ipConfig.setAlwaysUpdate(false);
            ipConfig.setAutoUpdateInterval(240);
            ipConfig.setCACertsOnly(false);
            ipConfig.setCacheUpdateInterval(15);
            ipConfig.setClassName("com.netscape.ca.CRLIssuingPoint");
            ipConfig.setDailyUpdates("3:45");
            ipConfig.setDescription(description);
            ipConfig.setEnable(enable);
            ipConfig.setEnableCRLCache(true);
            ipConfig.setEnableCRLUpdates(true);
            ipConfig.setEnableCacheTesting(false);
            ipConfig.setEnableCacheRecovery(true);
            ipConfig.setEnableDailyUpdates(false);
            ipConfig.setEnableUpdateInterval(true);
            ipConfig.setExtendedNextUpdate(true);
            ipConfig.setIncludeExpiredCerts(false);
            ipConfig.setMinUpdateInterval(0);
            ipConfig.setNextUpdateGracePeriod(0);
            ipConfig.setPublishOnStart(false);
            ipConfig.setSaveMemory(false);
            ipConfig.setSigningAlgorithm("SHA256withRSA");
            ipConfig.setUpdateSchema(1);

            // crl extensions
            CRLExtensionsConfig extsConfig = ipConfig.getExtensionsConfig();

            // AuthorityInformationAccess
            CRLExtensionConfig extConfig = extsConfig.getExtensionConfig("AuthorityInformationAccess");
            extConfig.putString("enable", "false");
            extConfig.putString("critical", "false");
            extConfig.putString("type", "CRLExtension");
            extConfig.putString("class", "com.netscape.cms.crl.CMSAuthInfoAccessExtension");
            extConfig.putString("numberOfAccessDescriptions", "1");
            extConfig.putString("accessMethod0", "caIssuers");
            extConfig.putString("accessLocationType0", "URI");
            extConfig.putString("accessLocation0", "");

            // AuthorityKeyIdentifier
            extConfig = extsConfig.getExtensionConfig("AuthorityKeyIdentifier");
            extConfig.putString("enable", "false");
            extConfig.putString("critical", "false");
            extConfig.putString("type", "CRLExtension");
            extConfig.putString("class", "com.netscape.cms.crl.CMSAuthorityKeyIdentifierExtension");

            // IssuerAlternativeName
            extConfig = extsConfig.getExtensionConfig("IssuerAlternativeName");
            extConfig.putString("enable", "false");
            extConfig.putString("critical", "false");
            extConfig.putString("type", "CRLExtension");
            extConfig.putString("class", "com.netscape.cms.crl.CMSIssuerAlternativeNameExtension");
            extConfig.putString("numNames", "0");
            extConfig.putString("nameType0", "");
            extConfig.putString("name0", "");

            // CRLNumber
            extConfig = extsConfig.getExtensionConfig("CRLNumber");
            extConfig.putString("enable", "true");
            extConfig.putString("critical", "false");
            extConfig.putString("type", "CRLExtension");
            extConfig.putString("class", "com.netscape.cms.crl.CMSCRLNumberExtension");

            // DeltaCRLIndicator
            extConfig = extsConfig.getExtensionConfig("DeltaCRLIndicator");
            extConfig.putString("enable", "false");
            extConfig.putString("critical", "true");
            extConfig.putString("type", "CRLExtension");
            extConfig.putString("class", "com.netscape.cms.crl.CMSDeltaCRLIndicatorExtension");

            // IssuingDistributionPoint
            extConfig = extsConfig.getExtensionConfig("IssuingDistributionPoint");
            extConfig.putString("enable", "false");
            extConfig.putString("critical", "true");
            extConfig.putString("type", "CRLExtension");
            extConfig.putString("class", "com.netscape.cms.crl.CMSIssuingDistributionPointExtension");
            extConfig.putString("pointType", "");
            extConfig.putString("pointName", "");
            extConfig.putString("onlyContainsUserCerts", "false");
            extConfig.putString("onlyContainsCACerts", "false");
            extConfig.putString("onlySomeReasons", "");
            //"keyCompromise,cACompromise,affiliationChanged,superseded,cessationOfOperation,certificateHold");
            extConfig.putString("indirectCRL", "false");

            // CRLReason
            extConfig = extsConfig.getExtensionConfig("CRLReason");
            extConfig.putString("enable", "true");
            extConfig.putString("critical", "false");
            extConfig.putString("type", "CRLEntryExtension");
            extConfig.putString("class", "com.netscape.cms.crl.CMSCRLReasonExtension");

            // HoldInstruction - removed by RFC 5280
            // extConfig = extsConfig.getExtensionConfig("HoldInstruction");
            // extConfig.putString("enable", "false");
            // extConfig.putString("critical", "false");
            // extConfig.putString("type", "CRLEntryExtension");
            // extConfig.putString("class", "com.netscape.cms.crl.CMSHoldInstructionExtension");
            // extConfig.putString("instruction", "none");

            // InvalidityDate
            extConfig = extsConfig.getExtensionConfig("InvalidityDate");
            extConfig.putString("enable", "true");
            extConfig.putString("critical", "false");
            extConfig.putString("type", "CRLEntryExtension");
            extConfig.putString("class", "com.netscape.cms.crl.CMSInvalidityDateExtension");

            // CertificateIssuer
            // extConfig = extsConfig.getExtensionConfig("CertificateIssuer");
            // extConfig.putString("enable", "false");
            // extConfig.putString("critical", "true");
            // extConfig.putString("type", "CRLEntryExtension");
            // extConfig.putString("class", "com.netscape.cms.crl.CMSCertificateIssuerExtension");
            // extConfig.putString("numNames", "0");
            // extConfig.putString("nameType0", "");
            // extConfig.putString("name0", "");

            // FreshestCRL
            extConfig = extsConfig.getExtensionConfig("FreshestCRL");
            extConfig.putString("enable", "false");
            extConfig.putString("critical", "false");
            extConfig.putString("type", "CRLExtension");
            extConfig.putString("class", "com.netscape.cms.crl.CMSFreshestCRLExtension");
            extConfig.putString("numPoints", "0");
            extConfig.putString("pointType0", "");
            extConfig.putString("pointName0", "");

            String issuingPointClassName = null;
            Class<CRLIssuingPoint> issuingPointClass = null;
            CRLIssuingPoint issuingPoint = null;

            try {
                issuingPointClassName = ipConfig.getClassName();
                issuingPointClass = (Class<CRLIssuingPoint>) Class.forName(issuingPointClassName);
                issuingPoint = issuingPointClass.getDeclaredConstructor().newInstance();
                issuingPoint.init(this, id, ipConfig);

                engine.addCRLIssuingPoint(id, issuingPoint);

            } catch (Exception e) {
                logger.error("CertificateAuthority: " + e.getMessage(), e);
                crlConfig.removeSubStore(id);
                return false;
            }
        }
        return true;
    }

    /**
     * Deletes CRL issuing point with the given identifier.
     *
     * @param crlConfig sub-store with all CRL issuing points
     * @param id CRL issuing point id
     */
    public void deleteCRLIssuingPoint(CRLConfig crlConfig, String id) {

        CAEngine engine = CAEngine.getInstance();
        CRLIssuingPoint ip = engine.removeCRLIssuingPoint(id);

        if (ip != null) {
            ip.shutdown();
            ip = null;
            crlConfig.removeSubStore(id);
            try {
                engine.getCRLRepository().deleteCRLIssuingPointRecord(id);
            } catch (EBaseException e) {
                logger.warn(CMS.getLogMessage("FAILED_REMOVING_CRL_IP_2", id, e.toString()), e);
            }
        }
    }

    /**
     * Retrieves the issuer name of this certificate authority.
     *
     * @return the issuer name of this certificate authority
     */
    public X500Name getX500Name() {
        return mName;
    }

    public CertificateIssuerName getIssuerObj() {
       return mIssuerObj;
    }

    public CertificateSubjectName getSubjectObj() {
       return mSubjectObj;
    }

    /**
     * Retrieves the issuer name of this certificate authority issuing point.
     *
     * @return the issuer name of this certificate authority issuing point
     */
    public X500Name getCRLX500Name() {
        X509CertImpl crlCertImpl = mCRLSigningUnit.getCertImpl();
        return crlCertImpl.getSubjectName();
    }

    public X500Name getOCSPX500Name() {
        X509CertImpl certImpl = mOCSPSigningUnit.getCertImpl();
        return certImpl.getSubjectName();
    }

    /**
     * Returns nickname of CA's signing cert.
     * <p>
     *
     * @return CA signing cert nickname.
     */
    @Override
    public String getNickname() {
        return mNickname;
    }

    /**
     * Retrieves the signing unit that manages the CA signing key for
     * signing certificates.
     *
     * @return the CA signing unit for certificates
     */
    public CASigningUnit getSigningUnit() {
        return mSigningUnit;
    }

    /**
     * Retrieves the signing unit that manages the CA signing key for
     * signing CRL.
     *
     * @return the CA signing unit for CRLs
     */
    public CASigningUnit getCRLSigningUnit() {
        return mCRLSigningUnit;
    }

    /**
     * Retrieves the signing unit that manages the CA signing key for
     * signing OCSP response.
     *
     * @return the CA signing unit for OCSP responses
     */
    public CASigningUnit getOCSPSigningUnit() {
        return mOCSPSigningUnit;
    }

    /**
     * Sets the maximium path length in the basic constraint extension.
     *
     * @param num the maximium path length
     */
    public void setBasicConstraintMaxLen(int num) {
        mConfig.putString("Policy.rule.BasicConstraintsExt.maxPathLen", "" + num);
    }

    /**
     * Signs CRL using the specified signature algorithm.
     * If no algorithm is specified the CA's default signing algorithm
     * is used.
     *
     * @param crl the CRL to be signed.
     * @param algname the algorithm name to use. This is a JCA name such
     *            as MD5withRSA, etc. If set to null the default signing algorithm
     *            is used.
     * @return the signed CRL
     * @exception EBaseException failed to sign CRL
     */
    public X509CRLImpl sign(X509CRLImpl crl, String algname)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        ensureReady();
        X509CRLImpl signedcrl = null;

        StatsSubsystem statsSub = (StatsSubsystem) engine.getSubsystem(StatsSubsystem.ID);
        if (statsSub != null) {
            statsSub.startTiming("signing");
        }

        try (DerOutputStream out = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            if (algname == null) {
                algname = mSigningUnit.getDefaultAlgorithm();
            }

            crl.encodeInfo(tmp);
            AlgorithmId.get(algname).encode(tmp);

            byte[] tbsCertList = crl.getTBSCertList();

            byte[] signature = mCRLSigningUnit.sign(tbsCertList, algname);

            if (crl.setSignature(signature)) {
                tmp.putBitString(signature);
                out.write(DerValue.tag_Sequence, tmp);

                if (crl.setSignedCRL(out.toByteArray())) {
                    signedcrl = crl;
                    // signedcrl = new X509CRLImpl(out.toByteArray());
                } else {
                    logger.warn("Failed to add signed-CRL to CRL object.");
                }
            } else {
                logger.warn("Failed to add signature to CRL object.");
            }

        } catch (CRLException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CRL", e.toString(), e.getMessage()), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CRL_FAILED", e.getMessage()), e);

        } catch (X509ExtensionException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CRL", e.toString(), e.getMessage()), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CRL_FAILED", e.getMessage()), e);

        } catch (NoSuchAlgorithmException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CRL", e.toString(), e.getMessage()), e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_SIGNING_CRL_FAILED", e.getMessage()), e);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CRL", e.toString(), e.getMessage()), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CRL_FAILED", e.getMessage()), e);

        } catch (SignatureException e) {
            logger.error(CMS.getUserMessage("CMS_CA_SIGNING_OPERATION_FAILED", e.toString()), e);
            engine.checkForAndAutoShutdown();
            throw new EBaseException(e);

        } catch (Exception e) {
            logger.error("Unable to sign data: " + e.getMessage(), e);
            throw new EBaseException(e);

        } finally {
            if (statsSub != null) {
                statsSub.endTiming("signing");
            }
        }

        return signedcrl;
    }

    /**
     * Signs the given certificate info using specified signing algorithm
     * If no algorithm is specified the CA's default algorithm is used.
     *
     * @param certInfo the certificate info to be signed.
     * @param algname the signing algorithm to use. These are names defined
     *            in JCA, such as MD5withRSA, etc. If null the CA's default
     *            signing algorithm will be used.
     * @return signed certificate
     * @exception EBaseException failed to sign certificate
     */
    public X509CertImpl sign(X509CertInfo certInfo, String algname)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        ensureReady();

        X509CertImpl signedcert = null;

        StatsSubsystem statsSub = (StatsSubsystem) engine.getSubsystem(StatsSubsystem.ID);
        if (statsSub != null) {
            statsSub.startTiming("signing");
        }

        try (DerOutputStream out = new DerOutputStream();
                DerOutputStream tmp = new DerOutputStream()) {

            if (certInfo == null) {
                logger.warn(CMS.getLogMessage("CMSCORE_CA_CA_NO_CERTINFO"));
                return null;
            }

            if (algname == null) {
                algname = mSigningUnit.getDefaultAlgorithm();
            }

            logger.debug("sign cert get algorithm");
            AlgorithmId alg = AlgorithmId.get(algname);

            // encode certificate info
            logger.debug("sign cert encoding cert");
            certInfo.encode(tmp);
            byte[] rawCert = tmp.toByteArray();

            // encode algorithm identifier
            logger.debug("sign cert encoding algorithm");
            alg.encode(tmp);

            logger.debug("CA cert signing: signing cert");
            byte[] signature = mSigningUnit.sign(rawCert, algname);

            tmp.putBitString(signature);

            // Wrap the signed data in a SEQUENCE { data, algorithm, sig }
            out.write(DerValue.tag_Sequence, tmp);
            //logger.info("CertificateAuthority: done signing");

            switch (engine.getFastSigning()) {
            case FASTSIGNING_DISABLED:
                signedcert = new X509CertImpl(out.toByteArray());
                break;

            case FASTSIGNING_ENABLED:
                signedcert = new X509CertImpl(out.toByteArray(), certInfo);
                break;

            default:
                break;
            }

        } catch (NoSuchAlgorithmException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CERT", e.toString(), e.getMessage()), e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_SIGNING_CERT_FAILED", e.getMessage()), e);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CERT", e.toString(), e.getMessage()), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CERT_FAILED", e.getMessage()), e);

        } catch (CertificateException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CERT", e.toString(), e.getMessage()), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CERT_FAILED", e.getMessage()), e);


        } catch (SignatureException e) {
            logger.error(CMS.getUserMessage("CMS_CA_SIGNING_OPERATION_FAILED", e.toString()), e);
            engine.checkForAndAutoShutdown();
            throw new EBaseException(e);

        } catch (Exception e) {
            logger.error("Unable to sign data: " + e.getMessage(), e);
            throw new EBaseException(e);

        } finally {
            if (statsSub != null) {
                statsSub.endTiming("signing");
            }
        }
        return signedcert;
    }

    /**
     * Sign a byte array using the specified algorithm.
     * If algorithm is null the CA's default algorithm is used.
     * <p>
     *
     * @param data the data to be signed in a byte array.
     * @param algname the algorithm to use.
     * @return the signature in a byte array.
     */
    public byte[] sign(byte[] data, String algname)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        ensureReady();

        try {
            return mSigningUnit.sign(data, algname);

        } catch (NoSuchAlgorithmException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_SIGNING_ALGOR_NOT_SUPPORTED", algname), e);

        } catch (SignatureException e) {
            logger.error(CMS.getUserMessage("CMS_CA_SIGNING_OPERATION_FAILED", e.toString()), e);
            engine.checkForAndAutoShutdown();
            throw new EBaseException(e);

        } catch (Exception e) {
            logger.error("Unable to sign data: " + e.getMessage(), e);
            throw new EBaseException(e);
        }
    }

    /**
     * Logs a message to this certificate authority.
     *
     * @param level the debug level.
     * @param msg the message to debug.
     */
    public void log(int level, String msg) {
    }

    /**
     * Retrieves the CA certificate chain.
     *
     * @return the CA certificate chain
     */
    public CertificateChain getCACertChain() {
        return mSigningUnit.getCertChain();
    }

    /**
     * Retrieves the CA certificate.
     *
     * @return the CA certificate
     */
    public X509CertImpl getCACert() throws EBaseException {

        X509CertImpl caCertImpl = mSigningUnit.getCertImpl();
        if (caCertImpl != null) {
            return caCertImpl;
        }

        String certName = mConfig.getString("signing.certnickname");
        String tokenName = mConfig.getString("signing.tokenname");

        if(!CryptoUtil.isInternalToken(tokenName)) {
            certName = tokenName + ":" + certName;
        }

        logger.debug("CertificateAuthority: Getting CA signing cert: " + certName);

        CryptoManager manager;
        X509Certificate caCert;
        try {
            manager= CryptoManager.getInstance();
            caCert = manager.findCertByNickname(certName);
        } catch (ObjectNotFoundException | NotInitializedException | TokenException e) {
            logger.error("CertificateAuthority: Unable to find CA signing certificate: " + e.getMessage(), e);
            throw new EBaseException("Unable to find CA signing certificate: " + e.getMessage(), e);
        }

        try {

            return new X509CertImpl(caCert.getEncoded());

        } catch (CertificateException e) {
            logger.error("Unable to parse CA signing cert: " + e.getMessage(), e);
            throw new EBaseException(e);
        }
    }

    /**
     * Retrieves the CA certificate.
     *
     * @return the CA certificate
     */
    public org.mozilla.jss.crypto.X509Certificate getCaX509Cert() {
        return mSigningUnit.getCert();
    }

    /**
     * Retrieves the supported signing algorithms of this certificate authority.
     *
     * @return the supported signing algorithms of this CA
     */
    public String[] getCASigningAlgorithms() {

        if (mCASigningAlgorithms != null)
            return mCASigningAlgorithms;

        X509CertImpl caCertImpl = mSigningUnit.getCertImpl();
        if (caCertImpl == null)
            return null; // CA not inited yet.

        X509Key caPubKey = null;
        try {
            caPubKey = (X509Key) caCertImpl.get(X509CertImpl.PUBLIC_KEY);
        } catch (CertificateParsingException e) {
        }

        if (caPubKey == null)
            return null; // something seriously wrong.

        AlgorithmId alg = caPubKey.getAlgorithmId();

        if (alg == null)
            return null; // something seriously wrong.
        mCASigningAlgorithms = AlgorithmId.getSigningAlgorithms(alg);
        if (mCASigningAlgorithms == null) {
            logger.warn(
                    "CA - no signing algorithms for " + alg.getName());
        } else {
            logger.debug(
                    "CA First signing algorithm is " + mCASigningAlgorithms[0]);
        }

        return mCASigningAlgorithms;
    }

    //////////
    // Initialization routines.
    //

    public synchronized void initCertSigningUnit() throws Exception {

        logger.info("CertificateAuthority: Initializing cert signing unit");

        SigningUnitConfig caSigningCfg = mConfig.getSigningUnitConfig();

        mSigningUnit = new CASigningUnit();
        mSigningUnit.init(caSigningCfg, mNickname);

        hasKeys = true;
        signingUnitException = null;

        mNickname = mSigningUnit.getNickname();

        X509Certificate caCert = mSigningUnit.getCert();
        logger.info("CertificateAuthority: - nickname: " + caCert.getNickname());

        X509CertImpl caCertImpl = mSigningUnit.getCertImpl();
        mName = caCertImpl.getSubjectName();

        getCASigningAlgorithms();

        // This ensures the isserDN and subjectDN have the same encoding
        // as that of the CA signing cert.
        mSubjectObj = caCertImpl.getSubjectObj();
        logger.debug("CertificateAuthority: - subject DN: " + mSubjectObj);

        // The mIssuerObj is the "issuerDN" object for the certs issued by this CA,
        // not the isserDN object of the CA signing cert unless the it is self-signed.
        X500Name issuerName = (X500Name) mSubjectObj.get(CertificateIssuerName.DN_NAME);
        mIssuerObj = new CertificateIssuerName(issuerName);
        logger.debug("CertificateAuthority: - issuer DN: " + mIssuerObj);

        String certSigningSKI = CryptoUtil.getSKIString(caCertImpl);

        Auditor auditor = engine.getAuditor();

        if (hostCA) {
            // generate cert info without authority ID
            auditor.log(CertSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, certSigningSKI));

        } else {
            // generate cert signing info with authority ID
            auditor.log(CertSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, certSigningSKI, authorityID));
        }
    }


    public synchronized void initCRLSigningUnit() throws Exception {

        logger.info("CertificateAuthority: Initializing CRL signing unit");

        SigningUnitConfig crlSigningConfig = mConfig.getCRLSigningUnitConfig();

        if (hostCA && crlSigningConfig != null && crlSigningConfig.size() > 0) {
            mCRLSigningUnit = new CASigningUnit();
            mCRLSigningUnit.init(crlSigningConfig, null);
        } else {
            mCRLSigningUnit = mSigningUnit;
        }

        X509Certificate crlCert = mCRLSigningUnit.getCert();
        logger.info("CertificateAuthority: - nickname: " + crlCert.getNickname());

        X509CertImpl crlCertImpl = mCRLSigningUnit.getCertImpl();
        String crlSigningSKI = CryptoUtil.getSKIString(crlCertImpl);

        Auditor auditor = engine.getAuditor();

        if (hostCA) {
            // generate CRL signing info without authority ID
            auditor.log(CRLSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, crlSigningSKI));

        } else {
            // don't generate CRL signing info since LWCA doesn't support CRL
        }
    }

    public synchronized void initOCSPSigningUnit() throws Exception {

        logger.info("CertificateAuthority: Initializing OCSP signing unit");

        SigningUnitConfig ocspSigningConfig = mConfig.getOCSPSigningUnitConfig();

        if (hostCA && ocspSigningConfig != null && ocspSigningConfig.size() > 0) {
            mOCSPSigningUnit = new CASigningUnit();
            mOCSPSigningUnit.init(ocspSigningConfig, null);
        } else {
            mOCSPSigningUnit = mSigningUnit;
        }

        X509Certificate ocspCert = mOCSPSigningUnit.getCert();
        logger.info("CertificateAuthority: - nickname: " + ocspCert.getNickname());

        X509CertImpl ocspCertImpl = mOCSPSigningUnit.getCertImpl();
        String ocspSigningSKI = CryptoUtil.getSKIString(ocspCertImpl);

        Auditor auditor = engine.getAuditor();

        if (hostCA) {
            // generate OCSP signing info without authority ID
            auditor.log(OCSPSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, ocspSigningSKI));
        } else {
            // generate OCSP signing info with authority ID
            auditor.log(OCSPSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, ocspSigningSKI, authorityID));
        }
    }

    /**
     * read ca cert from path, converts and bytes
     */
    byte[] getCertFromFile(String path)
            throws FileNotFoundException, IOException {

        File file = new File(path);
        Long l = Long.valueOf(file.length());
        byte[] b = new byte[l.intValue()];
        FileInputStream in = null;
        try {
            in = new FileInputStream(path);
            in.read(b);
        } finally {
            if (in != null)
                in.close();
        }
        return b;
    }

    /*
     private void startCRL()
     throws EBaseException
     {
     Enumeration e = mCRLIssuePoints.keys();
     while (e.hasMoreElements()) {
     CRLIssuingPoint cp = (CRLIssuingPoint)
     mCRLIssuePoints.get(e.nextElement());
     cp.startup();
     }
     }
     */

    @Override
    public String getOfficialName() {
        return OFFICIAL_NAME;
    }

    /**
     * Returns the in-memory count of the processed OCSP requests.
     *
     * @return number of processed OCSP requests in memory
     */
    public long getNumOCSPRequest() {
        return mNumOCSPRequest;
    }

    /**
     * Returns the in-memory time (in mini-second) of
     * the processed time for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPRequestTotalTime() {
        return mTotalTime;
    }

    /**
     * Returns the total data signed
     * for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPTotalData() {
        return mTotalData;
    }

    /**
     * Returns the in-memory time (in mini-second) of
     * the signing time for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPTotalSignTime() {
        return mSignTime;
    }

    @Override
    public long getOCSPTotalLookupTime() {
        return mLookupTime;
    }

    public ResponderID getResponderIDByName() {
        try {
            X500Name name = getOCSPX500Name();
            Name.Template nameTemplate = new Name.Template();

            return new NameID((Name) nameTemplate.decode(
                        new ByteArrayInputStream(name.getEncoded())));
        } catch (IOException e) {
            return null;
        } catch (InvalidBERException e) {
            return null;
        }
    }

    public ResponderID getResponderIDByHash() {

        /*
         KeyHash ::= OCTET STRING --SHA-1 hash of responder's public key
         --(excluding the tag and length fields)
         */
        PublicKey publicKey = getOCSPSigningUnit().getPublicKey();
        MessageDigest md = null;

        try {
            md = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        md.update(publicKey.getEncoded());
        byte digested[] = md.digest();

        return new KeyHashID(new OCTET_STRING(digested));
    }

    /**
     * Process OCSPRequest.
     */
    @Override
    public OCSPResponse validate(OCSPRequest request)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        if (!engine.getEnableOCSP()) {
            logger.debug("CertificateAuthority: OCSP service disabled");
            throw new EBaseException("OCSP service disabled");
        }

        TBSRequest tbsReq = request.getTBSRequest();
        if (tbsReq.getRequestCount() == 0) {
            logger.error(CMS.getLogMessage("OCSP_REQUEST_FAILURE", "No Request Found"));
            throw new EBaseException("OCSP request is empty");
        }

        /* An OCSP request can contain CertIDs for certificates
         * issued by different CAs, but each SingleResponse is valid
         * only if the combined response was signed by its issuer or
         * an authorised OCSP signing delegate.
         *
         * Even though it is silly to send an OCSP request
         * asking about certs issued by different CAs, we must
         * employ some heuristic to deal with this case. Our
         * heuristic is:
         *
         * 0. If CAEngine has no CAs, then lightweight CAs are not
         *    enabled.  There is only one CA, and 'this' is it.  Go
         *    straight to validation.
         *
         * 1. Find the issuer of the cert identified by the first
         *    CertID in the request.
         *
         * 2. If this CA is *not* the issuer, look up the issuer
         *    by its DN in CAEngine. If found, dispatch to its 'validate'
         *    method. Otherwise continue.
         *
         * 3. If this CA is NOT the issuing CA, we locate the
         *    issuing CA and dispatch to its 'validate' method.
         *    Otherwise, we move forward to generate and sign the
         *    aggregate OCSP response.
         */
        for (CertificateAuthority ocspCA: engine.getCAs()) {
            Request req = tbsReq.getRequestAt(0);
            CertID cid = req.getCertID();
            byte[] nameHash = null;
            String digestName = cid.getDigestName();
            if (digestName != null) {
                try {
                    MessageDigest md = MessageDigest.getInstance(digestName);
                    nameHash = md.digest(ocspCA.getSubjectObj().getX500Name().getEncoded());
                } catch (NoSuchAlgorithmException | IOException e) {
                    logger.warn("CertificateAuthority: OCSP request hash algorithm " + digestName + " not recognised: " + e.getMessage(), e);
                }
            }
            if(Arrays.equals(nameHash, cid.getIssuerNameHash().toByteArray())) {
                if(ocspCA != this) {
                    return ((IOCSPService) ocspCA).validate(request);
                }
                break;
            }
        }


        logger.debug("CertificateAuthority: validating OCSP request");

        mNumOCSPRequest++;
        StatsSubsystem statsSub = (StatsSubsystem) engine.getSubsystem(StatsSubsystem.ID);
        long startTime = new Date().getTime();

        try {
            //logger.info("start OCSP request");

            // (3) look into database to check the
            //     certificate's status
            Vector<SingleResponse> singleResponses = new Vector<>();

            if (statsSub != null) {
                statsSub.startTiming("lookup");
            }

            long lookupStartTime = new Date().getTime();

            for (int i = 0; i < tbsReq.getRequestCount(); i++) {
                Request req = tbsReq.getRequestAt(i);
                SingleResponse sr = processRequest(req);
                singleResponses.addElement(sr);
            }

            long lookupEndTime = new Date().getTime();
            mLookupTime += lookupEndTime - lookupStartTime;

            if (statsSub != null) {
                statsSub.endTiming("lookup");
            }

            if (statsSub != null) {
                statsSub.startTiming("build_response");
            }

            SingleResponse res[] = new SingleResponse[singleResponses.size()];
            singleResponses.copyInto(res);

            ResponderID rid = null;

            if (engine.getOCSPResponderByName()) {
                if (mResponderIDByName == null) {
                    mResponderIDByName = getResponderIDByName();
                }
                rid = mResponderIDByName;
            } else {
                if (mResponderIDByHash == null) {
                    mResponderIDByHash = getResponderIDByHash();
                }
                rid = mResponderIDByHash;
            }

            Extension nonce[] = null;

            for (int j = 0; j < tbsReq.getExtensionsCount(); j++) {
                Extension thisExt = tbsReq.getRequestExtensionAt(j);

                if (thisExt.getExtnId().equals(OCSP_NONCE)) {
                    nonce = new Extension[1];
                    nonce[0] = thisExt;
                }
            }

            ResponseData rd = new ResponseData(rid,
                    new GeneralizedTime(new Date()), res, nonce);

            if (statsSub != null) {
                statsSub.endTiming("build_response");
            }

            if (statsSub != null) {
                statsSub.startTiming("signing");
            }

            long signStartTime = new Date().getTime();

            BasicOCSPResponse basicRes = sign(rd);

            long signEndTime = new Date().getTime();
            mSignTime += signEndTime - signStartTime;

            if (statsSub != null) {
                statsSub.endTiming("signing");
            }

            OCSPResponse response = new OCSPResponse(
                    OCSPResponseStatus.SUCCESSFUL,
                    new ResponseBytes(ResponseBytes.OCSP_BASIC,
                            new OCTET_STRING(ASN1Util.encode(basicRes))));

            //logger.info("done OCSP request");
            long endTime = new Date().getTime();
            mTotalTime += endTime - startTime;

            return response;

        } catch (EBaseException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_OCSP_REQUEST", e.toString()), e);
            throw e;
        }
    }

    private BasicOCSPResponse sign(ResponseData rd) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        ensureReady();

        String algname = mOCSPSigningUnit.getDefaultAlgorithm();

        try (DerOutputStream out = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            byte rd_data[] = ASN1Util.encode(rd);
            if (rd_data != null) {
                mTotalData += rd_data.length;
            }
            rd.encode(tmp);
            AlgorithmId.get(algname).encode(tmp);
            logger.debug("adding signature");
            byte[] signature = mOCSPSigningUnit.sign(rd_data, algname);

            tmp.putBitString(signature);
            // optional, put the certificate chains in also

            DerOutputStream tmpChain = new DerOutputStream();
            DerOutputStream tmp1 = new DerOutputStream();
            java.security.cert.X509Certificate chains[] = mOCSPSigningUnit.getCertChain().getChain();

            for (int i = 0; i < chains.length; i++) {
                tmpChain.putDerValue(new DerValue(chains[i].getEncoded()));
            }
            tmp1.write(DerValue.tag_Sequence, tmpChain);
            tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0),
                    tmp1);

            out.write(DerValue.tag_Sequence, tmp);

            BasicOCSPResponse response = new BasicOCSPResponse(out.toByteArray());

            return response;

        } catch (NoSuchAlgorithmException e) {
            logger.error(CMS.getLogMessage("OPERATION_ERROR", e.toString()), e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_SIGNING_ALGOR_NOT_SUPPORTED", algname), e);

        } catch (SignatureException e) {
            logger.error(CMS.getUserMessage("CMS_CA_SIGNING_OPERATION_FAILED", e.toString()), e);
            engine.checkForAndAutoShutdown();
            throw new EBaseException(e);

        } catch (Exception e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_OCSP_SIGN", e.toString()), e);
            throw new EBaseException(e);
        }
    }

    public SingleResponse processRequest(Request req) throws EBaseException {

        String name = "CertificateAuthority: processRequest: ";
        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();

        X509CertImpl caCert = mSigningUnit.getCertImpl();
        X509Key key = (X509Key) caCert.getPublicKey();

        CertID cid = req.getCertID();
        INTEGER serialNo = cid.getSerialNumber();
        logger.debug( name + "for cert 0x" + serialNo.toString(16));

        CertStatus certStatus = null;
        GeneralizedTime thisUpdate = new GeneralizedTime(new Date());

        byte[] nameHash = null;
        byte[] keyHash = null;
        String digestName = cid.getDigestName();
        if (digestName != null) {
            try {
                MessageDigest md = MessageDigest.getInstance(digestName);
                nameHash = md.digest(mName.getEncoded());
                keyHash = md.digest(key.getKey());
            } catch (NoSuchAlgorithmException | IOException e) {
                logger.warn("CertificateAuthority: OCSP request hash algorithm " + digestName + " not recognised: " + e.getMessage(), e);
            }
        }
        if (!Arrays.equals(cid.getIssuerNameHash().toByteArray(), nameHash) ||
                !Arrays.equals(cid.getIssuerKeyHash().toByteArray(), keyHash)) {
            // issuer of cert is not this CA (or we couldn't work
            // out whether it is or not due to unknown hash alg);
            // do not return status information for this cert
            return new SingleResponse(cid, new UnknownInfo(), thisUpdate, null);
        }

        boolean ocspUseCache = mConfig.getOCSPUseCache();

        if (ocspUseCache) {
            String issuingPointId = mConfig.getOCSPUseCacheIssuingPointId();
            CRLIssuingPoint point = engine.getCRLIssuingPoint(issuingPointId);

            /* set nextUpdate to the nextUpdate time of the CRL */
            GeneralizedTime nextUpdate = null;
            Date crlNextUpdate = point.getNextUpdate();
            if (crlNextUpdate != null)
                nextUpdate = new GeneralizedTime(crlNextUpdate);

            if (point.isCRLCacheEnabled()) {
                // only do this if cache is enabled
                BigInteger sno = new BigInteger(serialNo.toString());
                boolean checkDeltaCache = mConfig.getOSPUseCacheCheckDeltaCache();
                boolean includeExpiredCerts = mConfig.getOCSPUseCacheIncludeExpiredCerts();

                Date revokedOn = point.getRevocationDateFromCache(
                        sno, checkDeltaCache, includeExpiredCerts);

                if (revokedOn == null) {
                    certStatus = new GoodInfo();
                } else {
                    certStatus = new RevokedInfo(new GeneralizedTime(revokedOn));
                }
                return new SingleResponse(cid, certStatus, thisUpdate, nextUpdate);
            }
        }

        try {
            CertRecord rec = certificateRepository.readCertificateRecord(serialNo);
            String status = rec.getStatus();

            if (status == null) {
                certStatus = new UnknownInfo();
            } else if (status.equals(CertRecord.STATUS_VALID)) {
                certStatus = new GoodInfo();
            } else if (status.equals(CertRecord.STATUS_INVALID)) {
                // not yet valid
                certStatus = new UnknownInfo();
            } else if (status.equals(CertRecord.STATUS_REVOKED)) {
                certStatus = new RevokedInfo(new GeneralizedTime(rec.getRevokedOn()));
            } else if (status.equals(CertRecord.STATUS_EXPIRED)) {
                certStatus = new UnknownInfo();
            } else if (status.equals(CertRecord.STATUS_REVOKED_EXPIRED)) {
                certStatus = new RevokedInfo(new GeneralizedTime(rec.getRevokedOn()));
            } else {
                certStatus = new UnknownInfo();
            }
        } catch (EDBRecordNotFoundException e) {
            logger.debug("{} cert record not found", name);
            certStatus = new UnknownInfo(); // not issued by this CA
        } catch (Exception e) {
            // internal error
            logger.error(name + " Unable to retrieve certificate record: " + e.getMessage(), e);
            certStatus = new UnknownInfo();
        }

        return new SingleResponse(
            cid, certStatus, thisUpdate,
            /* We are not using a CRL cache for generating OCSP
             * responses, so there is no reasonable value for
             * nextUpdate. */
            null /* nextUpdate */);
    }

    /**
     * Get the AuthorityID of this CA.
     */
    public AuthorityID getAuthorityID() {
        return authorityID;
    }

    public void setAuthorityID(AuthorityID aid) {
        authorityID = aid;
    }

    /**
     * Get the AuthorityID of this CA's parent CA, if available.
     */
    public AuthorityID getAuthorityParentID() {
        return authorityParentID;
    }

    /**
     * Return CA description.  May be null.
     */
    public String getAuthorityDescription() {
        return authorityDescription;
    }

    public void setAuthorityDescription(String desc) {
        authorityDescription = desc;
    }

    public Collection<String> getAuthorityKeyHosts() {
        return authorityKeyHosts;
    }

    public X509CertImpl generateSigningCert(
            X500Name subjectX500Name,
            AuthToken authToken)
            throws Exception {

        CryptoManager cryptoManager = CryptoManager.getInstance();

        // TODO: read PROP_TOKEN_NAME config
        CryptoToken token = cryptoManager.getInternalKeyStorageToken();

        logger.info("CertificateAuthority: generating RSA key");

        // Key size of sub-CA shall be key size of this CA.
        // If the key is not RSA (e.g. EC) default to 3072 bits.
        // TODO: key generation parameters
        KeyPairGenerator gen = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);
        int keySize = 3072;
        PublicKey thisPub = mSigningUnit.getPublicKey();
        if (thisPub instanceof RSAKey) {
            keySize = ((RSAKey) thisPub).getModulus().bitLength();
        }
        gen.initialize(keySize);

        KeyPair keypair = gen.genKeyPair();
        PublicKey pub = keypair.getPublic();
        X509Key x509key = CryptoUtil.createX509Key(pub);

        logger.info("CertificateAuthority: creating PKCS #10 request");

        PKCS10 pkcs10 = new PKCS10(x509key);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keypair.getPrivate());
        pkcs10.encodeAndSign(new X500Signer(signature, subjectX500Name));
        String pkcs10String = CertUtil.toPEM(pkcs10);

        logger.info("CertificateAuthority: signing certificate");

        CAEngine engine = CAEngine.getInstance();
        ProfileSubsystem ps = engine.getProfileSubsystem();
        String profileId = "caCACert";
        Profile profile = ps.getProfile(profileId);

        ArgBlock argBlock = new ArgBlock();
        argBlock.set("cert_request_type", "pkcs10");
        argBlock.set("cert_request", pkcs10String);

        Locale locale = Locale.getDefault();
        CertEnrollmentRequest certRequest =
            CertEnrollmentRequestFactory.create(argBlock, profile, locale);

        EnrollmentProcessor processor = new EnrollmentProcessor("createSubCA", locale);
        processor.setCMSEngine(engine);
        processor.init();

        Map<String, Object> resultMap = processor.processEnrollment(
            certRequest, null, authorityID, null, authToken);

        com.netscape.cmscore.request.Request[] requests = (com.netscape.cmscore.request.Request[]) resultMap.get(CAProcessor.ARG_REQUESTS);
        com.netscape.cmscore.request.Request request = requests[0];

        Integer result = request.getExtDataInInteger(com.netscape.cmscore.request.Request.RESULT);
        if (result != null && !result.equals(com.netscape.cmscore.request.Request.RES_SUCCESS)) {
            throw new EBaseException("Unable to generate signing certificate: " + result);
        }

        RequestStatus requestStatus = request.getRequestStatus();
        if (requestStatus != RequestStatus.COMPLETE) {
            // The request did not complete.  Inference: something
            // incorrect in the request (e.g. profile constraint
            // violated).
            String msg = "Unable to generate signing certificate: " + requestStatus;
            String errorMsg = request.getExtDataInString(com.netscape.cmscore.request.Request.ERROR);
            if (errorMsg != null) {
                msg += ": " + errorMsg;
            }
            throw new BadRequestDataException(msg);
        }

        return request.getExtDataInCert(com.netscape.cmscore.request.Request.REQUEST_ISSUED_CERT);
    }

    /**
     * Renew certificate of this CA.
     */
    public void renewAuthority(HttpServletRequest httpReq) throws Exception {

        CAEngine engine = CAEngine.getInstance();

        if (
            authorityParentID != null
            && !authorityParentID.equals(authorityID)
        ) {
            CertificateAuthority issuer = engine.getCA(authorityParentID);
            issuer.ensureReady();
        }

        ProfileSubsystem ps = engine.getProfileSubsystem();
        /* NOTE: hard-coding the profile to use for Lightweight CA renewal
         * might be OK, but caManualRenewal was not the right one to use.
         * As a consequence, we have an undesirable special case in
         * RenewalProcessor.processRenewal().
         *
         * We should introduce a new profile specifically for LWCA renewal,
         * with an authenticator and ACLs to match the authz requirements
         * for the renewAuthority REST resource itself.  Then we can use
         * it here, and remove the workaround from RenewalProcessor.
         */
        Profile profile = ps.getProfile("caManualRenewal");
        CertEnrollmentRequest req = CertEnrollmentRequestFactory.create(
            new ArgBlock(), profile, httpReq.getLocale());

        X509CertImpl caCertImpl = mSigningUnit.getCertImpl();
        req.setSerialNum(new CertId(caCertImpl.getSerialNumber()));

        RenewalProcessor processor = new RenewalProcessor("renewAuthority", httpReq.getLocale());
        processor.setCMSEngine(engine);
        processor.init();

        Map<String, Object> resultMap =
            processor.processRenewal(req, httpReq, null);
        com.netscape.cmscore.request.Request requests[] = (com.netscape.cmscore.request.Request[]) resultMap.get(CAProcessor.ARG_REQUESTS);
        com.netscape.cmscore.request.Request request = requests[0];
        Integer result = request.getExtDataInInteger(com.netscape.cmscore.request.Request.RESULT);
        if (result != null && !result.equals(com.netscape.cmscore.request.Request.RES_SUCCESS))
            throw new EBaseException("renewAuthority: certificate renewal submission resulted in error: " + result);
        RequestStatus requestStatus = request.getRequestStatus();
        if (requestStatus != RequestStatus.COMPLETE)
            throw new EBaseException("renewAuthority: certificate renewal did not complete; status: " + requestStatus);
        X509CertImpl cert = request.getExtDataInCert(com.netscape.cmscore.request.Request.REQUEST_ISSUED_CERT);
        authoritySerial = cert.getSerialNumber();

        engine.updateAuthoritySerialNumber(authorityID, authoritySerial);

        // update cert in NSSDB
        checkForNewerCert();
    }

    /**
     * Delete this lightweight CA.
     */
    public synchronized void deleteAuthority(HttpServletRequest httpReq)
            throws EBaseException {
        if (hostCA)
            throw new CATypeException("Cannot delete the host CA");

        if (authorityEnabled)
            throw new CAEnabledException("Must disable CA before deletion");

        CAEngine engine = CAEngine.getInstance();
        boolean hasSubCAs = false;

        for (CertificateAuthority ca : engine.getCAs()) {
            AuthorityID parentAID = ca.getAuthorityParentID();
            if (parentAID != null && parentAID.equals(this.authorityID)) {
                hasSubCAs = true;
                break;
            }
        }

        if (hasSubCAs)
            throw new CANotLeafException("CA with sub-CAs cannot be deleted (delete sub-CAs first)");

        revokeAuthority(httpReq);
        engine.deleteAuthorityEntry(authorityID);
        deleteAuthorityNSSDB();
    }

    /** Revoke the authority's certificate
     *
     * TODO: revocation reason, invalidity date parameters
     */
    private void revokeAuthority(HttpServletRequest httpReq)
            throws EBaseException {

        logger.debug("revokeAuthority: checking serial " + authoritySerial);

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();

        CertRecord certRecord = certificateRepository.readCertificateRecord(authoritySerial);
        String curStatus = certRecord.getStatus();
        logger.debug("revokeAuthority: current cert status: " + curStatus);
        if (curStatus.equals(CertRecord.STATUS_REVOKED)
                || curStatus.equals(CertRecord.STATUS_REVOKED_EXPIRED)) {
            return;  // already revoked
        }

        logger.debug("revokeAuthority: revoking cert");
        RevocationProcessor processor = new RevocationProcessor(
                "CertificateAuthority.revokeAuthority", httpReq.getLocale());
        processor.setCMSEngine(engine);
        processor.init();

        processor.setSerialNumber(new CertId(authoritySerial));
        processor.setRevocationReason(RevocationReason.UNSPECIFIED);
        processor.setAuthority(this);
        try {
            processor.createCRLExtension();
        } catch (IOException e) {
            throw new ECAException("Unable to create CRL extensions", e);
        }

        X509CertImpl caCertImpl = mSigningUnit.getCertImpl();
        processor.addCertificateToRevoke(caCertImpl);

        processor.createRevocationRequest();
        processor.auditChangeRequest(ILogger.SUCCESS);
        processor.processRevocationRequest();
        processor.auditChangeRequestProcessed(ILogger.SUCCESS);
    }

    /** Delete keys and certs of this authority from NSSDB.
     */
    void deleteAuthorityNSSDB() throws ECAException {
        if (hostCA) {
            String msg = "Attempt to delete host authority signing key; not proceeding";
            logger.warn(msg);
            return;
        }

        CryptoManager cryptoManager;
        try {
            cryptoManager = CryptoManager.getInstance();
        } catch (NotInitializedException e) {
            // can't happen
            throw new ECAException("CryptoManager not initialized");
        }

        // NOTE: PK11Store.deleteCert deletes the cert AND the
        // private key (which is what we want).  A subsequent call
        // to PK11Store.deletePrivateKey() is not necessary and
        // indeed would throw an exception.
        //
        CryptoStore cryptoStore =
            cryptoManager.getInternalKeyStorageToken().getCryptoStore();
        try {
            cryptoStore.deleteCert(mSigningUnit.getCert());
        } catch (NoSuchItemOnTokenException e) {
            logger.warn("deleteAuthority: cert is not on token: " + e);
            // if the cert isn't there, never mind
        } catch (TokenException e) {
            logger.error("deleteAuthority: TokenExcepetion while deleting cert: " + e.getMessage(), e);
            throw new ECAException("TokenException while deleting cert: " + e);
        }
    }
}
