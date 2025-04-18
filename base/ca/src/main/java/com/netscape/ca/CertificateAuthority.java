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
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Vector;

import org.dogtagpki.server.ca.CAConfig;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
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
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X500Signer;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkix.cert.Extension;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CADisabledException;
import com.netscape.certsrv.ca.CAMissingCertException;
import com.netscape.certsrv.ca.CAMissingKeyException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.dbs.DBRecordNotFoundException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.CRLSigningInfoEvent;
import com.netscape.certsrv.logging.event.CertSigningInfoEvent;
import com.netscape.certsrv.logging.event.OCSPSigningInfoEvent;
import com.netscape.certsrv.ocsp.IOCSPService;
import com.netscape.certsrv.security.SigningUnitConfig;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.util.StatsSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.CertID;
import com.netscape.cmsutil.ocsp.CertStatus;
import com.netscape.cmsutil.ocsp.GoodInfo;
import com.netscape.cmsutil.ocsp.KeyHashID;
import com.netscape.cmsutil.ocsp.NameID;
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
    protected int fastSigning;
    protected boolean ocspResponderByName;

    protected CertificateRepository certRepository;

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

    private KeyRetrieverRunner keyRetrieverRunner;

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

    public ECAException getSigningUnitException() {
        return signingUnitException;
    }

    public void setSigningUnitException(ECAException e) {
        signingUnitException = e;
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

    public int getFastSigning() {
        return fastSigning;
    }

    public void setFastSigning(int fastSigning) {
        this.fastSigning = fastSigning;
    }

    public boolean getOCSPResponderByName() {
        return ocspResponderByName;
    }

    public void setOCSPResponderByName(boolean ocspResponderByName) {
        this.ocspResponderByName = ocspResponderByName;
    }

    public CertificateRepository getCertRepository() {
        return certRepository;
    }

    public void setCertRepository(CertificateRepository certRepository) {
        this.certRepository = certRepository;
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

    public synchronized void setCertSigningUnit(CASigningUnit certSigningUnit) throws Exception {

        mSigningUnit = certSigningUnit;

        hasKeys = true;
        signingUnitException = null;

        mNickname = certSigningUnit.getNickname();

        X509CertImpl caCertImpl = certSigningUnit.getCertImpl();
        mName = caCertImpl.getSubjectName();

        getCASigningAlgorithms();

        // This ensures the isserDN and subjectDN have the same encoding
        // as that of the CA signing cert.
        mSubjectObj = caCertImpl.getSubjectObj();

        // The mIssuerObj is the "issuerDN" object for the certs issued by this CA,
        // not the isserDN object of the CA signing cert unless the it is self-signed.
        X500Name issuerName = (X500Name) mSubjectObj.get(CertificateIssuerName.DN_NAME);
        mIssuerObj = new CertificateIssuerName(issuerName);
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

    public synchronized void setCRLSigningUnit(CASigningUnit crlSigningUnit) {
        mCRLSigningUnit = crlSigningUnit;
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

    public synchronized void setOCSPSigningUnit(CASigningUnit ocspSigningUnit) {
        mOCSPSigningUnit = ocspSigningUnit;
    }

    public void init(ConfigStore config) throws Exception {
        super.init(config);

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig caEngineConfig = engine.getConfig();
        CAConfig caConfig = caEngineConfig.getCAConfig();

        setConfig(caConfig);
        setCertRepository(engine.getCertificateRepository());
        setFastSigning(engine.getFastSigning());
        setOCSPResponderByName(engine.getOCSPResponderByName());
    }

    /**
     * Sets the maximium path length in the basic constraint extension.
     *
     * @param num the maximium path length
     */
    public void setBasicConstraintMaxLen(int num) {
        mConfig.putString("Policy.rule.BasicConstraintsExt.maxPathLen", "" + num);
    }

    public void initCertSigningUnit() throws Exception {

        logger.info("CertificateAuthority: Initializing cert signing unit for authority {}", authorityID);

        SigningUnitConfig caSigningCfg = mConfig.getSigningUnitConfig();

        CASigningUnit certSigningUnit = new CASigningUnit();
        certSigningUnit.init(caSigningCfg, mNickname);

        setCertSigningUnit(certSigningUnit);

        X509Certificate caCert = certSigningUnit.getCert();
        logger.debug("CertificateAuthority: - nickname: " + caCert.getNickname());

        logger.debug("CertificateAuthority: - subject: " + mSubjectObj);
        logger.debug("CertificateAuthority: - issuer: " + mIssuerObj);

        X509CertImpl caCertImpl = certSigningUnit.getCertImpl();
        String certSigningSKI = CryptoUtil.getSKIString(caCertImpl);

        CAEngine engine = CAEngine.getInstance();
        Auditor auditor = engine.getAuditor();

        if (hostCA) {
            // generate cert info without authority ID
            auditor.log(CertSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, certSigningSKI));

        } else {
            // generate cert signing info with authority ID
            auditor.log(CertSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, certSigningSKI, authorityID));
        }
    }

    public void initCRLSigningUnit() throws Exception {

        logger.info("CertificateAuthority: Initializing CRL signing unit for authority {}", authorityID);

        SigningUnitConfig crlSigningConfig = mConfig.getCRLSigningUnitConfig();
        CASigningUnit crlSigningUnit;

        if (hostCA && crlSigningConfig != null && crlSigningConfig.size() > 0) {
            crlSigningUnit = new CASigningUnit();
            crlSigningUnit.init(crlSigningConfig, null);

        } else {
            crlSigningUnit = getSigningUnit();
        }

        setCRLSigningUnit(crlSigningUnit);

        X509Certificate crlCert = crlSigningUnit.getCert();
        logger.debug("CertificateAuthority: - nickname: " + crlCert.getNickname());

        X509CertImpl crlCertImpl = crlSigningUnit.getCertImpl();
        String crlSigningSKI = CryptoUtil.getSKIString(crlCertImpl);

        CAEngine engine = CAEngine.getInstance();
        Auditor auditor = engine.getAuditor();

        if (hostCA) {
            // generate CRL signing info without authority ID
            auditor.log(CRLSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, crlSigningSKI));

        } else {
            // don't generate CRL signing info since LWCA doesn't support CRL
        }
    }

    public void initOCSPSigningUnit() throws Exception {

        logger.info("CertificateAuthority: Initializing OCSP signing unit for authority {}", authorityID);

        SigningUnitConfig ocspSigningConfig = mConfig.getOCSPSigningUnitConfig();
        CASigningUnit ocspSigningUnit;

        if (hostCA && ocspSigningConfig != null && ocspSigningConfig.size() > 0) {
            ocspSigningUnit = new CASigningUnit();
            ocspSigningUnit.init(ocspSigningConfig, null);

        } else {
            ocspSigningUnit = getSigningUnit();
        }

        setOCSPSigningUnit(ocspSigningUnit);

        X509Certificate ocspCert = ocspSigningUnit.getCert();
        logger.debug("CertificateAuthority: - nickname: " + ocspCert.getNickname());

        X509CertImpl ocspCertImpl = ocspSigningUnit.getCertImpl();
        String ocspSigningSKI = CryptoUtil.getSKIString(ocspCertImpl);

        CAEngine engine = CAEngine.getInstance();
        Auditor auditor = engine.getAuditor();

        if (hostCA) {
            // generate OCSP signing info without authority ID
            auditor.log(OCSPSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, ocspSigningSKI));

        } else {
            // generate OCSP signing info with authority ID
            auditor.log(OCSPSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, ocspSigningSKI, authorityID));
        }
    }

    public synchronized void startKeyRetriever() throws EBaseException {

        if (authorityID == null) {
            // Only the host authority should ever see a
            // null authorityID, e.g. during two-step
            // installation of externally-signed CA.
            logger.info("CertificateAuthority: Do not start KeyRetriever for host CA");
            return;
        }

        if (keyRetrieverRunner != null) {
            logger.info("CertificateAuthority: KeyRetriever already running for authority " + authorityID);
            return;
        }

        logger.info("CertificateAuthority: Starting KeyRetriever for authority " + authorityID);

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig engineConfig = engine.getConfig();

        String className = engineConfig.getString("features.authority.keyRetrieverClass", null);
        if (className == null) {
            logger.info("CertificateAuthority: Key retriever not configured");
            return;
        }

        ConfigStore keyRetrieverConfig = engineConfig.getSubStore("features.authority.keyRetrieverConfig", ConfigStore.class);

        KeyRetriever keyRetriever;
        try {
            Class<? extends KeyRetriever> clazz = Class.forName(className).asSubclass(KeyRetriever.class);

            // If there is an accessible constructor that takes
            // a ConfigStore, invoke that; otherwise invoke
            // the nullary constructor.

            try {
                keyRetriever = clazz.getDeclaredConstructor(ConfigStore.class).newInstance(keyRetrieverConfig);

            } catch (NoSuchMethodException | SecurityException | IllegalAccessException e) {
                keyRetriever = clazz.getDeclaredConstructor().newInstance();
            }

        } catch (Exception e) {
            logger.error("Unable to create key retriever: " + e.getMessage(), e);
            throw new EBaseException(e);
        }

        // Use a synchronous KeyRetriever to ensure that the LWCA has
        // the signing key before it can be used.
        // https://github.com/dogtagpki/pki/issues/4677

        keyRetrieverRunner = new KeyRetrieverRunner(keyRetriever, this);
        keyRetrieverRunner.run();
    }

    public synchronized void removeKeyRetriever() {
        keyRetrieverRunner = null;
    }

    public void initSigningUnits() throws Exception {

        logger.info("CertificateAuthority: Initializing " + (authorityID == null ? "host CA" : "authority " + authorityID));

        try {
            initCertSigningUnit();
            initCRLSigningUnit();
            initOCSPSigningUnit();

        } catch (CAMissingCertException | CAMissingKeyException e) {
            logger.warn("CertificateAuthority: CA signing key and cert not (yet) present in NSS database");
            signingUnitException = e;
            startKeyRetriever();

        } catch (Exception e) {
            throw new EBaseException(e);
        }
    }

    public void checkForNewerCert() throws EBaseException {

        logger.info("CertificateAuthority: Checking new CA cert for authority {}", authorityID);

        logger.debug("CertificateAuthority: - new serial number: {}", authoritySerial == null ? null : "0x" + authoritySerial.toString(16));

        if (authoritySerial == null) {
            return;
        }

        X509CertImpl caCertImpl = mSigningUnit.getCertImpl();
        logger.debug("CertificateAuthority: - old serial number: 0x{}", caCertImpl.getSerialNumber().toString(16));

        if (authoritySerial.equals(caCertImpl.getSerialNumber())) {
            return;
        }

        // The authoritySerial recorded in LDAP differs from the
        // certificate in NSSDB.  Import the newer cert.
        //
        // Note that the new serial number need not be greater,
        // e.g. if random serial numbers are enabled.

        logger.info("CertificateAuthority: Updating CA cert for authority {}", authorityID);

        try {
            org.mozilla.jss.crypto.X509Certificate oldCert = mSigningUnit.getCert();
            CryptoManager manager = CryptoManager.getInstance();

            // add new cert
            X509CertImpl newCert = certRepository.getX509Certificate(authoritySerial);
            manager.importUserCACertPackage(newCert.getEncoded(), mNickname);

            // delete old cert
            manager.getInternalKeyStorageToken().getCryptoStore().deleteCert(oldCert);

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
     * Starts up this subsystem.
     */
    @Override
    public void startup() throws EBaseException {
    }

    public X509CRLImpl sign(X509CRLImpl crl, String algname) throws Exception {

        X509CRLImpl signedcrl = null;

        try (DerOutputStream out = new DerOutputStream();
                DerOutputStream tmp = new DerOutputStream()) {

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
        }

        return signedcrl;
    }

    public X509CertImpl sign(X509CertInfo certInfo, String algname) throws Exception {

        X509CertImpl signedcert = null;

        try (DerOutputStream out = new DerOutputStream();
                DerOutputStream tmp = new DerOutputStream()) {

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

            switch (fastSigning) {
            case FASTSIGNING_DISABLED:
                signedcert = new X509CertImpl(out.toByteArray());
                break;

            case FASTSIGNING_ENABLED:
                signedcert = new X509CertImpl(out.toByteArray(), certInfo);
                break;

            default:
                break;
            }
        }

        return signedcert;
    }

    public byte[] sign(byte[] data, String algname) throws Exception {
        return mSigningUnit.sign(data, algname);
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
        X509Key key = new X509Key();
        try {
            key.decode(publicKey.getEncoded());
        } catch (InvalidKeyException e) {
            logger.error("CA - OCSP signing key not accessible");
            return null;
        }
        byte[] digested = CryptoUtil.generateKeyIdentifier(key.getKey());
        return new KeyHashID(new OCTET_STRING(digested));
    }

    public OCSPResponse validate(TBSRequest tbsReq)throws EBaseException {

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
                CertID certID = req.getCertID();
                logger.info("CertificateAuthority: Checking cert 0x{} status", certID.getSerialNumber().toString(16));

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

            if (ocspResponderByName) {
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

            logger.info("CertificateAuthority: Signing OCSP response");
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

    public SingleResponse getCertStatusFromDB(Request request) {

        CertID certID = request.getCertID();
        INTEGER serialNumber = certID.getSerialNumber();
        CertStatus certStatus = null;

        try {
            CertRecord rec = certRepository.readCertificateRecord(serialNumber);
            String status = rec.getStatus();

            if (status == null) {
                certStatus = new UnknownInfo();

            } else if (status.equals(CertRecord.STATUS_VALID)) {
                certStatus = new GoodInfo();

            } else if (status.equals(CertRecord.STATUS_INVALID)) {  // not yet valid
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

        } catch (DBRecordNotFoundException e) {
            logger.info("CertificateAuthority: Cert record {} not found", serialNumber);
            certStatus = new UnknownInfo(); // not issued by this CA

        } catch (Exception e) {
            // internal error
            logger.error("CertificateAuthority: Unable to retrieve cert record: " + e.getMessage(), e);
            certStatus = new UnknownInfo();
        }

        GeneralizedTime thisUpdate = new GeneralizedTime(new Date());
        // We are not using a CRL cache for generating OCSP
        // responses, so there is no reasonable value for nextUpdate.
        return new SingleResponse(certID, certStatus, thisUpdate, null);
    }

    public SingleResponse getCertStatusFromCRL(Request request) throws EBaseException {

        boolean ocspUseCache = mConfig.getOCSPUseCache();

        if (!ocspUseCache) {
            return null;
        }

        CAEngine engine = CAEngine.getInstance();
        String issuingPointId = mConfig.getOCSPUseCacheIssuingPointId();
        CRLIssuingPoint crlIssuingPoint = engine.getCRLIssuingPoint(issuingPointId);

        if (!crlIssuingPoint.isCRLCacheEnabled()) {
            return null;
        }

        // only do this if cache is enabled

        CertID certID = request.getCertID();
        INTEGER serialNumber = certID.getSerialNumber();
        CertStatus certStatus = null;

        BigInteger sno = new BigInteger(serialNumber.toString());
        boolean checkDeltaCache = mConfig.getOSPUseCacheCheckDeltaCache();
        boolean includeExpiredCerts = mConfig.getOCSPUseCacheIncludeExpiredCerts();

        Date revokedOn = crlIssuingPoint.getRevocationDateFromCache(
                sno, checkDeltaCache, includeExpiredCerts);

        if (revokedOn == null) {
            certStatus = new GoodInfo();
        } else {
            certStatus = new RevokedInfo(new GeneralizedTime(revokedOn));
        }

        GeneralizedTime thisUpdate = new GeneralizedTime(new Date());

        /* set nextUpdate to the nextUpdate time of the CRL */
        GeneralizedTime nextUpdate = null;
        Date crlNextUpdate = crlIssuingPoint.getNextUpdate();
        if (crlNextUpdate != null) {
            nextUpdate = new GeneralizedTime(crlNextUpdate);
        }

        return new SingleResponse(certID, certStatus, thisUpdate, nextUpdate);
    }

    public SingleResponse processRequest(Request req) throws EBaseException {

        String name = "CertificateAuthority: processRequest: ";

        X509CertImpl caCert = mSigningUnit.getCertImpl();
        X509Key key = (X509Key) caCert.getPublicKey();

        CertID cid = req.getCertID();
        INTEGER serialNo = cid.getSerialNumber();
        logger.debug( name + "for cert 0x" + serialNo.toString(16));

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

            GeneralizedTime thisUpdate = new GeneralizedTime(new Date());
            return new SingleResponse(cid, new UnknownInfo(), thisUpdate, null);
        }

        SingleResponse response = getCertStatusFromCRL(req);

        if (response != null) {
            return response;
        }

        return getCertStatusFromDB(req);
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

    public BigInteger getAuthoritySerial() {
        return authoritySerial;
    }

    public void setAuthoritySerial(BigInteger serial) {
        authoritySerial = serial;
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

    public KeyPair generateKeyPair(CryptoToken token) throws Exception {

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

        return gen.genKeyPair();
    }

    public PKCS10 generateCertRequest(
            KeyPair keypair,
            X500Name subjectX500Name) throws Exception {

        logger.info("CertificateAuthority: creating PKCS #10 request");

        PublicKey pub = keypair.getPublic();
        X509Key x509key = CryptoUtil.createX509Key(pub);

        PKCS10 pkcs10 = new PKCS10(x509key);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keypair.getPrivate());
        pkcs10.encodeAndSign(new X500Signer(signature, subjectX500Name));

        return pkcs10;
    }

    /** Delete keys and certs of this authority from NSSDB.
     */
    public void deleteAuthorityNSSDB() throws ECAException {

        X509Certificate cert = mSigningUnit.getCert();
        logger.info("CertificateAuthority: Removing cert " + cert.getNickname());

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
            cryptoStore.deleteCert(cert);
        } catch (NoSuchItemOnTokenException e) {
            logger.warn("deleteAuthority: cert is not on token: " + e);
            // if the cert isn't there, never mind
        } catch (TokenException e) {
            logger.error("deleteAuthority: TokenExcepetion while deleting cert: " + e.getMessage(), e);
            throw new ECAException("TokenException while deleting cert: " + e);
        }
    }

    /**
     * Shutdowns this subsystem.
     * <P>
     */
    @Override
    public void shutdown() {
    }
}
