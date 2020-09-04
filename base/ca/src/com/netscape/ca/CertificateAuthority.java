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
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.dogtag.util.cert.CertUtil;
import org.dogtagpki.legacy.policy.IPolicyProcessor;
import org.dogtagpki.server.ca.CAConfig;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.server.ca.ICRLIssuingPoint;
import org.dogtagpki.server.ca.ICertificateAuthority;
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
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.Utils;
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

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.Nonces;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CADisabledException;
import com.netscape.certsrv.ca.CAEnabledException;
import com.netscape.certsrv.ca.CAMissingCertException;
import com.netscape.certsrv.ca.CAMissingKeyException;
import com.netscape.certsrv.ca.CANotFoundException;
import com.netscape.certsrv.ca.CANotLeafException;
import com.netscape.certsrv.ca.CATypeException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.ca.IssuerUnavailableException;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.dbs.crldb.ICRLRepository;
import com.netscape.certsrv.dbs.replicadb.IReplicaIDRepository;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.CRLSigningInfoEvent;
import com.netscape.certsrv.logging.event.CertSigningInfoEvent;
import com.netscape.certsrv.logging.event.OCSPSigningInfoEvent;
import com.netscape.certsrv.ocsp.IOCSPService;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestNotifier;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.security.ISigningUnit;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.cert.CertEnrollmentRequestFactory;
import com.netscape.cms.servlet.cert.EnrollmentProcessor;
import com.netscape.cms.servlet.cert.RenewalProcessor;
import com.netscape.cms.servlet.cert.RevocationProcessor;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.ldap.PublisherProcessor;
import com.netscape.cmscore.profile.ProfileSubsystem;
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
public class CertificateAuthority
        implements ICertificateAuthority, ICertAuthority, IOCSPService {

    public final static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertificateAuthority.class);

    private static final Logger signedAuditLogger = SignedAuditLogger.getLogger();

    public static final String OFFICIAL_NAME = "Certificate Manager";

    public final static OBJECT_IDENTIFIER OCSP_NONCE = new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.48.1.2");

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

    protected SigningUnit mSigningUnit;
    protected SigningUnit mOCSPSigningUnit;
    protected SigningUnit mCRLSigningUnit;

    protected CertificateIssuerName mIssuerObj = null;
    protected CertificateSubjectName mSubjectObj = null;
    protected X500Name mName = null;
    protected X500Name mCRLName = null;
    protected X500Name mOCSPName = null;
    protected String mNickname = null; // nickname of CA signing cert.
    protected String mOCSPNickname = null; // nickname of OCSP signing cert.
    protected long mCertSerialNumberCounter = System.currentTimeMillis();
    protected long mRequestID = System.currentTimeMillis();

    protected String[] mAllowedSignAlgors = null;

    protected CertificateChain mCACertChain = null;
    protected CertificateChain mOCSPCertChain = null;
    protected X509CertImpl mCRLCert = null;
    protected org.mozilla.jss.crypto.X509Certificate mCRLX509Cert = null;
    protected X509CertImpl mCaCert = null;
    protected org.mozilla.jss.crypto.X509Certificate mCaX509Cert = null;
    protected X509CertImpl mOCSPCert = null;
    protected org.mozilla.jss.crypto.X509Certificate mOCSPX509Cert = null;
    protected String[] mCASigningAlgorithms = null;

    protected long mNumOCSPRequest = 0;
    protected long mTotalTime = 0;
    protected long mTotalData = 0;
    protected long mSignTime = 0;
    protected long mLookupTime = 0;

    public final static int FASTSIGNING_DISABLED = 0;
    public final static int FASTSIGNING_ENABLED = 1;

    protected static final long SECOND = 1000; // 1000 milliseconds
    protected static final long MINUTE = 60 * SECOND;
    protected static final long HOUR = 60 * MINUTE;
    public final static long DAY = 24 * HOUR;
    protected static final long YEAR = DAY * 365;

    // for the notification listeners

    /**
     * Package constants
     */

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

    public boolean isHostAuthority() {
        return hostCA;
    }

    public void ensureReady()
            throws ECAException {
        if (!authorityEnabled)
            throw new CADisabledException("Authority is disabled");
        if (!isReady()) {
            if (signingUnitException != null)
                throw signingUnitException;
            else
                throw new CAMissingKeyException("Authority does not yet have signing key and cert in local NSSDB");
        }
    }

    public boolean isReady() {
        return hasKeys;
    }

    public boolean getAuthorityEnabled() {
        return authorityEnabled;
    }

    public void setAuthorityEnabled(boolean authorityEnabled) {
        this.authorityEnabled = authorityEnabled;
    }

    /**
     * Retrieves subsystem identifier.
     */
    public String getId() {
        return mId;
    }

    /**
     * Sets subsystem identifier.
     */
    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * updates the Master CRL now
     */
    public void updateCRLNow() throws EBaseException {
        CAEngine engine = CAEngine.getInstance();
        CRLIssuingPoint masterCRLIssuingPoint = (CRLIssuingPoint) engine.getMasterCRLIssuingPoint();
        if (masterCRLIssuingPoint == null) return;
        masterCRLIssuingPoint.updateCRLNow();
    }

    public void publishCRLNow() throws EBaseException {
        CAEngine engine = CAEngine.getInstance();
        CRLIssuingPoint masterCRLIssuingPoint = (CRLIssuingPoint) engine.getMasterCRLIssuingPoint();
        if (masterCRLIssuingPoint == null) return;
        masterCRLIssuingPoint.publishCRL();
    }

    public IPolicyProcessor getPolicyProcessor() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getCAPolicy().getPolicyProcessor();
    }

    public boolean noncesEnabled() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getEnableNonces();
    }

    public Map<Object, Long> getNonces(HttpServletRequest request, String name) {

        // Create a new session or use an existing one.
        HttpSession session = request.getSession(true);
        if (session == null) {
            throw new PKIException("Unable to create session.");
        }

        CAEngine engine = CAEngine.getInstance();

        // Lock the session to prevent concurrent access.
        // http://yet-another-dev.blogspot.com/2009/08/synchronizing-httpsession.html

        Object lock = request.getSession().getId().intern();
        synchronized (lock) {

            // Find the existing storage in the session.
            @SuppressWarnings("unchecked")
            Map<Object, Long> nonces = (Map<Object, Long>)session.getAttribute("nonces-"+name);

            if (nonces == null) {
                // If not present, create a new storage.
                nonces = Collections.synchronizedMap(new Nonces(engine.getMaxNonces()));

                // Put the storage in the session.
                session.setAttribute("nonces-"+name, nonces);
            }

            return nonces;
        }
    }

    /**
     * Initializes this CA subsystem.
     * <P>
     * @param config configuration of this subsystem
     *
     * @exception EBaseException failed to initialize this CA
     */
    public void init(IConfigStore config) throws
            EBaseException {

        logger.info("CertificateAuthority: Initializing " +
                (authorityID == null ? "host CA" : "authority " + authorityID));

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();

        mConfig = cs.getCAConfig();

        // init signing unit & CA cert.
        boolean initSigUnitSucceeded = false;

        try {
            initCertSigningUnit();
            initCRLSigningUnit();
            initOCSPSigningUnit();
            initSigUnitSucceeded = true;

        } catch (CAMissingCertException | CAMissingKeyException e) {
            logger.warn("CertificateAuthority: CA signing key and cert not (yet) present in NSS database");
            signingUnitException = e;
            engine.startKeyRetriever(this);

        } catch (Exception e) {
            throw new EBaseException(e);
        }

        /* Don't try to update the cert unless we already have
         * the cert and key. */
        if (initSigUnitSucceeded) {
            logger.info("CertificateAuthority: Checking for newer cert");
            checkForNewerCert();
        }
    }

    public PublicKey getIssuanceProtPubKey() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getIssuanceProtectionPublicKey();
    }

    public PrivateKey getIssuanceProtPrivKey() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getIssuanceProtectionPrivateKey();
    }

    public X509Certificate getIssuanceProtCert() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getIssuanceProtectionCert();
    }

    private void checkForNewerCert() throws EBaseException {
        if (authoritySerial == null)
            return;
        if (authoritySerial.equals(mCaCert.getSerialNumber()))
            return;

        // The authoritySerial recorded in LDAP differs from the
        // certificate in NSSDB.  Import the newer cert.
        //
        // Note that the new serial number need not be greater,
        // e.g. if random serial numbers are enabled.
        //
        logger.debug(
            "CertificateAuthority: Updating certificate in NSSDB; new serial number: "
            + authoritySerial);

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();

        try {
            X509Certificate oldCert = mCaX509Cert;
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
     * return CA's request queue processor
     */
    public IRequestQueue getRequestQueue() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getRequestQueue();
    }

    /**
     * registers listener
     */
    public void registerRequestListener(IRequestListener listener) {
        CAEngine engine = CAEngine.getInstance();
        engine.getRequestNotifier().registerListener(listener);
    }

    /**
     * registers listener with a name.
     */
    public void registerRequestListener(String name, IRequestListener listener) {
        CAEngine engine = CAEngine.getInstance();
        engine.getRequestNotifier().registerListener(name, listener);
    }

    /**
     * removes listener
     */
    public void removeRequestListener(IRequestListener listener) {
        CAEngine engine = CAEngine.getInstance();
        engine.getRequestNotifier().removeListener(listener);
    }

    /**
     * removes listener with a name.
     */
    public void removeRequestListener(String name) {
        CAEngine engine = CAEngine.getInstance();
        engine.getRequestNotifier().removeListener(name);
    }

    /**
     * register listener for pending requests
     */
    public void registerPendingListener(IRequestListener listener) {
        CAEngine engine = CAEngine.getInstance();
        engine.getPendingNotifier().registerListener(listener);
    }

    /**
     * register listener for pending requests with a name.
     */
    public void registerPendingListener(String name, IRequestListener listener) {
        CAEngine engine = CAEngine.getInstance();
        engine.getPendingNotifier().registerListener(name, listener);
    }

    /**
     * get listener from listener list
     */
    public IRequestListener getRequestListener(String name) {
        CAEngine engine = CAEngine.getInstance();
        return engine.getRequestNotifier().getListener(name);
    }

    /**
     * get notifiers registered by CA
     */
    public IRequestNotifier getRequestNotifier() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getRequestNotifier();
    }

    /**
     * get listener from listener list
     */
    public IRequestListener getPendingListener(String name) {
        CAEngine engine = CAEngine.getInstance();
        return engine.getPendingNotifier().getListener(name);
    }

    public Enumeration<String> getRequestListenerNames() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getRequestNotifier().getListenerNames();
    }

    /**
     * return CA's request queue service object.
     */
    public IService getCAService() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getCAService();
    }

    /**
     * check if the ca is a clone.
     */
    public boolean isClone() {
        if (CAService.mCLAConnector != null)
            return true;
        else
            return false;
    }

    /**
     * Starts up this subsystem.
     */
    public void startup() throws EBaseException {
    }

    /**
     * Shutdowns this subsystem.
     * <P>
     */
    public void shutdown() {
    }

    /**
     * Retrieves the configuration store of this subsystem.
     * <P>
     */
    public CAConfig getConfigStore() {
        return mConfig;
    }

    public void setConfig(CAConfig config) {
        mConfig = config;
    }

    public long getDefaultValidity() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getDefaultCertValidity();
    }

    public SignatureAlgorithm getDefaultSignatureAlgorithm() {
        return mSigningUnit.getDefaultSignatureAlgorithm();
    }

    public String getDefaultAlgorithm() {
        return mSigningUnit.getDefaultAlgorithm();
    }

    public void setDefaultAlgorithm(String algorithm) throws EBaseException {
        mSigningUnit.setDefaultAlgorithm(algorithm);
    }

    public String getStartSerial() {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();

        try {
            BigInteger serial = certificateRepository.peekNextSerialNumber();

            if (serial == null)
                return "";
            else
                return serial.toString(16);
        } catch (EBaseException e) {
            // shouldn't get here.
            return "";
        }
    }

    public void setStartSerial(String serial) throws EBaseException {
        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();
        certificateRepository.setTheSerialNumber(new BigInteger(serial));
    }

    public String getMaxSerial() {
        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();
        String serial = certificateRepository.getMaxSerial();

        if (serial != null)
            return serial;
        else
            return "";
    }

    public void setMaxSerial(String serial) throws EBaseException {
        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();
        certificateRepository.setMaxSerial(serial);
    }

    /**
     * Retrieves certificate repository.
     * <P>
     *
     * @return certificate repository
     */
    public ICertificateRepository getCertificateRepository() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getCertificateRepository();
    }

    /**
     * Retrieves replica repository.
     * <P>
     *
     * @return replica repository
     */
    public IReplicaIDRepository getReplicaRepository() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getReplicaIDRepository();
    }

    /**
     * Retrieves CRL repository.
     */
    public ICRLRepository getCRLRepository() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getCRLRepository();
    }

    public PublisherProcessor getPublisherProcessor() {
        CAEngine engine = CAEngine.getInstance();
        return engine.getPublisherProcessor();
    }

    /**
     * Retrieves the CRL issuing point by id.
     * <P>
     *
     * @param id string id of the CRL issuing point
     * @return CRL issuing point
     */
    public ICRLIssuingPoint getCRLIssuingPoint(String id) {
        CAEngine engine = CAEngine.getInstance();
        return engine.getCRLIssuingPoint(id);
    }

    /**
     * Enumerates CRL issuing points
     * <P>
     *
     * @return security service
     */
    public Enumeration<ICRLIssuingPoint> getCRLIssuingPoints() {
        CAEngine engine = CAEngine.getInstance();
        return Collections.enumeration(engine.getCRLIssuingPoints());
    }

    /**
     * Adds CRL issuing point with the given identifier and description.
     */
    @SuppressWarnings("unchecked")
    public boolean addCRLIssuingPoint(IConfigStore crlSubStore, String id,
                                      boolean enable, String description) {

        CAEngine engine = CAEngine.getInstance();

        crlSubStore.makeSubStore(id);
        CRLIssuingPointConfig c = crlSubStore.getSubStore(id, CRLIssuingPointConfig.class);

        if (c != null) {
            c.setAllowExtensions(true);
            c.setAlwaysUpdate(false);
            c.setAutoUpdateInterval(240);
            c.setCACertsOnly(false);
            c.setCacheUpdateInterval(15);
            c.setClassName("com.netscape.ca.CRLIssuingPoint");
            c.setDailyUpdates("3:45");
            c.setDescription(description);
            c.setEnable(enable);
            c.setEnableCRLCache(true);
            c.setEnableCRLUpdates(true);
            c.setEnableCacheTesting(false);
            c.setEnableCacheRecovery(true);
            c.setEnableDailyUpdates(false);
            c.setEnableUpdateInterval(true);
            c.setExtendedNextUpdate(true);
            c.setIncludeExpiredCerts(false);
            c.setMinUpdateInterval(0);
            c.setNextUpdateGracePeriod(0);
            c.setPublishOnStart(false);
            c.setSaveMemory(false);
            c.setSigningAlgorithm("SHA256withRSA");
            c.setUpdateSchema(1);

            // crl extensions
            // AuthorityInformationAccess
            c.putString("extension.AuthorityInformationAccess.enable", "false");
            c.putString("extension.AuthorityInformationAccess.critical", "false");
            c.putString("extension.AuthorityInformationAccess.type", "CRLExtension");
            c.putString("extension.AuthorityInformationAccess.class",
                    "com.netscape.cms.crl.CMSAuthInfoAccessExtension");
            c.putString("extension.AuthorityInformationAccess.numberOfAccessDescriptions", "1");
            c.putString("extension.AuthorityInformationAccess.accessMethod0", "caIssuers");
            c.putString("extension.AuthorityInformationAccess.accessLocationType0", "URI");
            c.putString("extension.AuthorityInformationAccess.accessLocation0", "");
            // AuthorityKeyIdentifier
            c.putString("extension.AuthorityKeyIdentifier.enable", "false");
            c.putString("extension.AuthorityKeyIdentifier.critical", "false");
            c.putString("extension.AuthorityKeyIdentifier.type", "CRLExtension");
            c.putString("extension.AuthorityKeyIdentifier.class",
                    "com.netscape.cms.crl.CMSAuthorityKeyIdentifierExtension");
            // IssuerAlternativeName
            c.putString("extension.IssuerAlternativeName.enable", "false");
            c.putString("extension.IssuerAlternativeName.critical", "false");
            c.putString("extension.IssuerAlternativeName.type", "CRLExtension");
            c.putString("extension.IssuerAlternativeName.class",
                    "com.netscape.cms.crl.CMSIssuerAlternativeNameExtension");
            c.putString("extension.IssuerAlternativeName.numNames", "0");
            c.putString("extension.IssuerAlternativeName.nameType0", "");
            c.putString("extension.IssuerAlternativeName.name0", "");
            // CRLNumber
            c.putString("extension.CRLNumber.enable", "true");
            c.putString("extension.CRLNumber.critical", "false");
            c.putString("extension.CRLNumber.type", "CRLExtension");
            c.putString("extension.CRLNumber.class",
                    "com.netscape.cms.crl.CMSCRLNumberExtension");
            // DeltaCRLIndicator
            c.putString("extension.DeltaCRLIndicator.enable", "false");
            c.putString("extension.DeltaCRLIndicator.critical", "true");
            c.putString("extension.DeltaCRLIndicator.type", "CRLExtension");
            c.putString("extension.DeltaCRLIndicator.class",
                    "com.netscape.cms.crl.CMSDeltaCRLIndicatorExtension");
            // IssuingDistributionPoint
            c.putString("extension.IssuingDistributionPoint.enable", "false");
            c.putString("extension.IssuingDistributionPoint.critical", "true");
            c.putString("extension.IssuingDistributionPoint.type", "CRLExtension");
            c.putString("extension.IssuingDistributionPoint.class",
                    "com.netscape.cms.crl.CMSIssuingDistributionPointExtension");
            c.putString("extension.IssuingDistributionPoint.pointType", "");
            c.putString("extension.IssuingDistributionPoint.pointName", "");
            c.putString("extension.IssuingDistributionPoint.onlyContainsUserCerts", "false");
            c.putString("extension.IssuingDistributionPoint.onlyContainsCACerts", "false");
            c.putString("extension.IssuingDistributionPoint.onlySomeReasons", "");
            //"keyCompromise,cACompromise,affiliationChanged,superseded,cessationOfOperation,certificateHold");
            c.putString("extension.IssuingDistributionPoint.indirectCRL", "false");
            // CRLReason
            c.putString("extension.CRLReason.enable", "true");
            c.putString("extension.CRLReason.critical", "false");
            c.putString("extension.CRLReason.type", "CRLEntryExtension");
            c.putString("extension.CRLReason.class",
                    "com.netscape.cms.crl.CMSCRLReasonExtension");
            // HoldInstruction - removed by RFC 5280
            // c.putString("extension.HoldInstruction.enable", "false");
            // c.putString("extension.HoldInstruction.critical", "false");
            // c.putString("extension.HoldInstruction.type", "CRLEntryExtension");
            // c.putString("extension.HoldInstruction.class",
            //     "com.netscape.cms.crl.CMSHoldInstructionExtension");
            // c.putString("extension.HoldInstruction.instruction", "none");
            // InvalidityDate
            c.putString("extension.InvalidityDate.enable", "true");
            c.putString("extension.InvalidityDate.critical", "false");
            c.putString("extension.InvalidityDate.type", "CRLEntryExtension");
            c.putString("extension.InvalidityDate.class",
                    "com.netscape.cms.crl.CMSInvalidityDateExtension");
            // CertificateIssuer
            /*
             c.putString("extension.CertificateIssuer.enable", "false");
             c.putString("extension.CertificateIssuer.critical", "true");
             c.putString("extension.CertificateIssuer.type", "CRLEntryExtension");
             c.putString("extension.CertificateIssuer.class",
             "com.netscape.cms.crl.CMSCertificateIssuerExtension");
             c.putString("extension.CertificateIssuer.numNames", "0");
             c.putString("extension.CertificateIssuer.nameType0", "");
             c.putString("extension.CertificateIssuer.name0", "");
             */
            // FreshestCRL
            c.putString("extension.FreshestCRL.enable", "false");
            c.putString("extension.FreshestCRL.critical", "false");
            c.putString("extension.FreshestCRL.type", "CRLExtension");
            c.putString("extension.FreshestCRL.class",
                    "com.netscape.cms.crl.CMSFreshestCRLExtension");
            c.putString("extension.FreshestCRL.numPoints", "0");
            c.putString("extension.FreshestCRL.pointType0", "");
            c.putString("extension.FreshestCRL.pointName0", "");

            String issuingPointClassName = null;
            Class<CRLIssuingPoint> issuingPointClass = null;
            CRLIssuingPoint issuingPoint = null;

            try {
                issuingPointClassName = c.getClassName();
                issuingPointClass = (Class<CRLIssuingPoint>) Class.forName(issuingPointClassName);
                issuingPoint = issuingPointClass.newInstance();
                issuingPoint.init(this, id, c);

                engine.addCRLIssuingPoint(id, issuingPoint);

            } catch (EPropertyNotFound e) {
                crlSubStore.removeSubStore(id);
                return false;
            } catch (EBaseException e) {
                crlSubStore.removeSubStore(id);
                return false;
            } catch (ClassNotFoundException e) {
                crlSubStore.removeSubStore(id);
                return false;
            } catch (InstantiationException e) {
                crlSubStore.removeSubStore(id);
                return false;
            } catch (IllegalAccessException e) {
                crlSubStore.removeSubStore(id);
                return false;
            }
        }
        return true;
    }

    /**
     * Deletes CRL issuing point with the given identifier.
     */
    public void deleteCRLIssuingPoint(IConfigStore crlSubStore, String id) {

        CAEngine engine = CAEngine.getInstance();
        CRLIssuingPoint ip = (CRLIssuingPoint) engine.removeCRLIssuingPoint(id);

        if (ip != null) {
            ip.shutdown();
            ip = null;
            crlSubStore.removeSubStore(id);
            try {
                engine.getCRLRepository().deleteCRLIssuingPointRecord(id);
            } catch (EBaseException e) {
                logger.warn(CMS.getLogMessage("FAILED_REMOVING_CRL_IP_2", id, e.toString()), e);
            }
        }
    }

    /**
     * Returns X500 name of the Certificate Authority
     * <P>
     *
     * @return CA name
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

    public X500Name getCRLX500Name() {
        return mCRLName;
    }

    public X500Name getOCSPX500Name() {
        return mOCSPName;
    }

    /**
     * Returns nickname of CA's signing cert.
     * <p>
     *
     * @return CA signing cert nickname.
     */
    public String getNickname() {
        return mNickname;
    }

    /**
     * Returns nickname of OCSP's signing cert.
     * <p>
     *
     * @return OCSP signing cert nickname.
     */
    public String getOCSPNickname() {
        return mOCSPNickname;
    }

    /**
     * Returns default signing unit used by this CA
     * <P>
     *
     * @return request identifier
     */
    public ISigningUnit getSigningUnit() {
        return mSigningUnit;
    }

    public ISigningUnit getCRLSigningUnit() {
        return mCRLSigningUnit;
    }

    public ISigningUnit getOCSPSigningUnit() {
        return mOCSPSigningUnit;
    }

    public void setBasicConstraintMaxLen(int num) {
        mConfig.putString("Policy.rule.BasicConstraintsExt.maxPathLen", "" + num);
    }

    /**
     * Signs CRL using the specified signature algorithm.
     * If no algorithm is specified the CA's default signing algorithm
     * is used.
     * <P>
     *
     * @param crl the CRL to be signed.
     * @param algname the algorithm name to use. This is a JCA name such
     *            as MD5withRSA, etc. If set to null the default signing algorithm
     *            is used.
     *
     * @return the signed CRL
     */
    public X509CRLImpl sign(X509CRLImpl crl, String algname)
            throws EBaseException {

        CMSEngine engine = CMS.getCMSEngine();
        ensureReady();
        X509CRLImpl signedcrl = null;

        IStatsSubsystem statsSub = (IStatsSubsystem) engine.getSubsystem(IStatsSubsystem.ID);
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
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CRL_FAILED", e.getMessage()), e);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CRL", e.toString(), e.getMessage()), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CRL_FAILED", e.getMessage()), e);

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
     * <P>
     *
     * @param certInfo the certificate info to be signed.
     * @param algname the signing algorithm to use. These are names defined
     *            in JCA, such as MD5withRSA, etc. If null the CA's default
     *            signing algorithm will be used.
     * @return signed certificate
     */
    public X509CertImpl sign(X509CertInfo certInfo, String algname)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        ensureReady();

        X509CertImpl signedcert = null;

        IStatsSubsystem statsSub = (IStatsSubsystem) engine.getSubsystem(IStatsSubsystem.ID);
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
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CERT_FAILED", e.getMessage()), e);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CERT", e.toString(), e.getMessage()), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CERT_FAILED", e.getMessage()), e);

        } catch (CertificateException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CERT", e.toString(), e.getMessage()), e);
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CERT_FAILED", e.getMessage()), e);

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
        ensureReady();
        return mSigningUnit.sign(data, algname);
    }

    /**
     * logs a message in the CA area.
     *
     * @param level the debug level.
     * @param msg the message to debug.
     */
    public void log(int level, String msg) {
    }

    /**
     * Retrieves certificate chains of this CA.
     *
     * @return this CA's cert chain.
     */
    public CertificateChain getCACertChain() {
        return mCACertChain;
    }

    public X509CertImpl getCACert() throws EBaseException {

        if (mCaCert != null) {
            return mCaCert;
        }

        String cert = mConfig.getString("signing.cert");
        logger.debug("CertificateAuthority: CA signing cert: " + cert);

        if (StringUtils.isEmpty(cert)) {
            logger.error("CertificateAuthority: Missing CA signing certificate");
            throw new EBaseException("Missing CA signing certificate");
        }

        byte[] bytes = Utils.base64decode(cert);
        logger.debug("CertificateAuthority: size: " + bytes.length + " bytes");

        try {
            return new X509CertImpl(bytes);

        } catch (CertificateException e) {
            logger.error("Unable to parse CA signing cert: " + e.getMessage(), e);
            throw new EBaseException(e);
        }
    }

    public org.mozilla.jss.crypto.X509Certificate getCaX509Cert() {
        return mCaX509Cert;
    }

    public String[] getCASigningAlgorithms() {
        if (mCASigningAlgorithms != null)
            return mCASigningAlgorithms;

        if (mCaCert == null)
            return null; // CA not inited yet.
        X509Key caPubKey = null;

        try {
            caPubKey = (X509Key) mCaCert.get(X509CertImpl.PUBLIC_KEY);
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

    public CertificateChain getCertChain(org.mozilla.jss.crypto.X509Certificate cert)
            throws NotInitializedException, CertificateException, TokenException {

        logger.debug("CertificateAuthority: cert chain:");

        CryptoManager manager = CryptoManager.getInstance();
        org.mozilla.jss.crypto.X509Certificate[] chain = manager.buildCertificateChain(cert);

        java.security.cert.X509Certificate[] certs = new java.security.cert.X509Certificate[chain.length];

        for (int i = 0; i < chain.length; i++) {
            certs[i] = new X509CertImpl(chain[i].getEncoded());
            logger.debug("CertificateAuthority: - " + certs[i].getSubjectDN());
        }

        return new CertificateChain(certs);
    }

    public synchronized void initCertSigningUnit() throws Exception {

        logger.info("CertificateAuthority: Initializing cert signing unit");

        IConfigStore caSigningCfg = mConfig.getSubStore(PROP_SIGNING_SUBSTORE);

        String caSigningCertStr = caSigningCfg.getString("cert", "");
        if (!caSigningCertStr.equals("")) {

            byte[] bytes = Utils.base64decode(caSigningCertStr);
            mCaCert = new X509CertImpl(bytes);

            // this ensures the isserDN and subjectDN have the same encoding
            // as that of the CA signing cert
            mSubjectObj = mCaCert.getSubjectObj();
            logger.debug("CertificateAuthority: - subject DN: " + mSubjectObj);

            // The mIssuerObj is the "issuerDN" object for the certs issued by this CA,
            // not the isserDN object of the CA signing cert unless the it is self-signed.
            mIssuerObj = new CertificateIssuerName((X500Name)mSubjectObj.get(CertificateIssuerName.DN_NAME));
            logger.debug("CertificateAuthority: - issuer DN: " + mIssuerObj);
        }

        mSigningUnit = new SigningUnit();
        mSigningUnit.init(caSigningCfg, mNickname);

        hasKeys = true;
        signingUnitException = null;

        mNickname = mSigningUnit.getNickname();

        mCaX509Cert = mSigningUnit.getCert();
        logger.info("CertificateAuthority: - nickname: " + mCaX509Cert.getNickname());

        mCaCert = mSigningUnit.getCertImpl();
        mName = (X500Name) mCaCert.getSubjectDN();

        mCACertChain = getCertChain(mCaX509Cert);

        getCASigningAlgorithms();

        // This ensures the isserDN and subjectDN have the same encoding
        // as that of the CA signing cert.
        mSubjectObj = mCaCert.getSubjectObj();

        if (mSubjectObj != null) {
            // The mIssuerObj is the "issuerDN" object for the certs issued by this CA,
            // not the isserDN object of the CA signing cert unless the it is self-signed.

            X500Name issuerName = (X500Name) mSubjectObj.get(CertificateIssuerName.DN_NAME);
            mIssuerObj = new CertificateIssuerName(issuerName);
        }

        String certSigningSKI = CryptoUtil.getSKIString(mCaCert);

        if (hostCA) {
            // generate cert info without authority ID
            signedAuditLogger.log(CertSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, certSigningSKI));

        } else {
            // generate cert signing info with authority ID
            signedAuditLogger.log(CertSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, certSigningSKI, authorityID));
        }
    }


    public synchronized void initCRLSigningUnit() throws Exception {

        logger.info("CertificateAuthority: Initializing CRL signing unit");

        IConfigStore crlSigningConfig = mConfig.getSubStore(PROP_CRL_SIGNING_SUBSTORE);

        if (hostCA && crlSigningConfig != null && crlSigningConfig.size() > 0) {
            mCRLSigningUnit = new SigningUnit();
            mCRLSigningUnit.init(crlSigningConfig, null);
        } else {
            mCRLSigningUnit = mSigningUnit;
        }

        mCRLX509Cert = mCRLSigningUnit.getCert();
        logger.info("CertificateAuthority: - nickname: " + mCRLX509Cert.getNickname());

        mCRLCert = mCRLSigningUnit.getCertImpl();
        mCRLName = (X500Name) mCRLCert.getSubjectDN();

        String crlSigningSKI = CryptoUtil.getSKIString(mCRLCert);

        if (hostCA) {
            // generate CRL signing info without authority ID
            signedAuditLogger.log(CRLSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, crlSigningSKI));

        } else {
            // don't generate CRL signing info since LWCA doesn't support CRL
        }
    }

    public synchronized void initOCSPSigningUnit() throws Exception {

        logger.info("CertificateAuthority: Initializing OCSP signing unit");

        IConfigStore ocspSigningConfig = mConfig.getSubStore(PROP_OCSP_SIGNING_SUBSTORE);

        if (hostCA && ocspSigningConfig != null && ocspSigningConfig.size() > 0) {
            mOCSPSigningUnit = new SigningUnit();
            mOCSPSigningUnit.init(ocspSigningConfig, null);
        } else {
            mOCSPSigningUnit = mSigningUnit;
        }

        mOCSPNickname = mOCSPSigningUnit.getNickname();
        mOCSPX509Cert = mOCSPSigningUnit.getCert();
        logger.info("CertificateAuthority: - nickname: " + mOCSPX509Cert.getNickname());

        mOCSPCert = mOCSPSigningUnit.getCertImpl();
        mOCSPName = (X500Name) mOCSPCert.getSubjectDN();

        mOCSPCertChain = getCertChain(mOCSPX509Cert);

        String ocspSigningSKI = CryptoUtil.getSKIString(mOCSPCert);

        if (hostCA) {
            // generate OCSP signing info without authority ID
            signedAuditLogger.log(OCSPSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, ocspSigningSKI));
        } else {
            // generate OCSP signing info with authority ID
            signedAuditLogger.log(OCSPSigningInfoEvent.createSuccessEvent(ILogger.SYSTEM_UID, ocspSigningSKI, authorityID));
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

    public String getOfficialName() {
        return OFFICIAL_NAME;
    }

    public long getNumOCSPRequest() {
        return mNumOCSPRequest;
    }

    public long getOCSPRequestTotalTime() {
        return mTotalTime;
    }

    public long getOCSPTotalData() {
        return mTotalData;
    }

    public long getOCSPTotalSignTime() {
        return mSignTime;
    }

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
         *    by its DN in CAEngine.  If not found, fail.  If
         *    found, dispatch to its 'validate' method.  Otherwise
         *    continue.
         *
         * 3. If this CA is NOT the issuing CA, we locate the
         *    issuing CA and dispatch to its 'validate' method.
         *    Otherwise, we move forward to generate and sign the
         *    aggregate OCSP response.
         */
        CertificateAuthority ocspCA = this;
        if (engine.getCAs().size() > 0 && tbsReq.getRequestCount() > 0) {
            Request req = tbsReq.getRequestAt(0);
            BigInteger serialNo = req.getCertID().getSerialNumber();

            CertificateRepository certificateRepository = engine.getCertificateRepository();
            X509CertImpl cert = certificateRepository.getX509Certificate(serialNo);

            X500Name certIssuerDN = (X500Name) cert.getIssuerDN();
            ocspCA = engine.getCA(certIssuerDN);
        }

        if (ocspCA == null) {
            logger.error("CertificateAuthority: Could not locate issuing CA");
            throw new CANotFoundException("Could not locate issuing CA");
        }

        if (ocspCA != this)
            return ((IOCSPService) ocspCA).validate(request);

        logger.debug("CertificateAuthority: validating OCSP request");

        mNumOCSPRequest++;
        IStatsSubsystem statsSub = (IStatsSubsystem) engine.getSubsystem(IStatsSubsystem.ID);
        long startTime = new Date().getTime();

        try {
            //logger.info("start OCSP request");

            // (3) look into database to check the
            //     certificate's status
            Vector<SingleResponse> singleResponses = new Vector<SingleResponse>();

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
        ensureReady();
        try (DerOutputStream out = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            String algname = mOCSPSigningUnit.getDefaultAlgorithm();

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
            java.security.cert.X509Certificate chains[] =
                    mOCSPCertChain.getChain();

            for (int i = 0; i < chains.length; i++) {
                tmpChain.putDerValue(new DerValue(chains[i].getEncoded()));
            }
            tmp1.write(DerValue.tag_Sequence, tmpChain);
            tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0),
                    tmp1);

            out.write(DerValue.tag_Sequence, tmp);

            BasicOCSPResponse response = new BasicOCSPResponse(out.toByteArray());

            return response;
        } catch (Exception e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CA_OCSP_SIGN", e.toString()), e);
            throw new EBaseException(e.toString());
        }
    }

    private SingleResponse processRequest(Request req) {

        CertID cid = req.getCertID();
        INTEGER serialNo = cid.getSerialNumber();
        logger.debug("CertificateAuthority: processing request for cert 0x" + serialNo.toString(16));

        CertStatus certStatus = null;
        GeneralizedTime thisUpdate = new GeneralizedTime(new Date());

        byte[] nameHash = null;
        String digestName = cid.getDigestName();
        if (digestName != null) {
            try {
                MessageDigest md = MessageDigest.getInstance(digestName);
                nameHash = md.digest(mName.getEncoded());
            } catch (NoSuchAlgorithmException | IOException e) {
            }
        }
        if (!Arrays.equals(cid.getIssuerNameHash().toByteArray(), nameHash)) {
            // issuer of cert is not this CA (or we couldn't work
            // out whether it is or not due to unknown hash alg);
            // do not return status information for this cert
            return new SingleResponse(cid, new UnknownInfo(), thisUpdate, null);
        }

        boolean ocspUseCache = true;

        try {
            /* enable OCSP cache by default */
            ocspUseCache = mConfig.getBoolean("ocspUseCache", false);
        } catch (EBaseException e) {
        }

        if (ocspUseCache) {
            String issuingPointId = PROP_MASTER_CRL;

            try {
                issuingPointId = mConfig.getString(
                            "ocspUseCacheIssuingPointId", PROP_MASTER_CRL);

            } catch (EBaseException e) {
            }
            CRLIssuingPoint point = (CRLIssuingPoint)
                    getCRLIssuingPoint(issuingPointId);

            /* set nextUpdate to the nextUpdate time of the CRL */
            GeneralizedTime nextUpdate = null;
            Date crlNextUpdate = point.getNextUpdate();
            if (crlNextUpdate != null)
                nextUpdate = new GeneralizedTime(crlNextUpdate);

            if (point.isCRLCacheEnabled()) {
                // only do this if cache is enabled
                BigInteger sno = new BigInteger(serialNo.toString());
                boolean checkDeltaCache = false;
                boolean includeExpiredCerts = false;

                try {
                    checkDeltaCache = mConfig.getBoolean("ocspUseCacheCheckDeltaCache", false);
                } catch (EBaseException e) {
                }
                try {
                    includeExpiredCerts = mConfig.getBoolean("ocspUseCacheIncludeExpiredCerts", false);
                } catch (EBaseException e) {
                }
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

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certificateRepository = engine.getCertificateRepository();

        try {
            ICertRecord rec = certificateRepository.readCertificateRecord(serialNo);
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
        } catch (Exception e) {
            // not found
            certStatus = new UnknownInfo(); // not issued not all
        }

        return new SingleResponse(
            cid, certStatus, thisUpdate,
            /* We are not using a CRL cache for generating OCSP
             * responses, so there is no reasonable value for
             * nextUpdate. */
            null /* nextUpdate */);
    }

    public AuthorityID getAuthorityID() {
        return authorityID;
    }

    public void setAuthorityID(AuthorityID aid) {
        authorityID = aid;
    }

    public AuthorityID getAuthorityParentID() {
        return authorityParentID;
    }

    public String getAuthorityDescription() {
        return authorityDescription;
    }

    public void setAuthorityDescription(String desc) {
        authorityDescription = desc;
    }

    public Collection<String> getAuthorityKeyHosts() {
        return authorityKeyHosts;
    }

    public void ensureAuthorityDNAvailable(X500Name dn)
            throws IssuerUnavailableException {

        CAEngine engine = CAEngine.getInstance();
        for (CertificateAuthority ca : engine.getCAs()) {
            if (ca.getX500Name().equals(dn))
                throw new IssuerUnavailableException(
                    "DN '" + dn + "' is used by an existing authority");
        }
    }

    public X509CertImpl generateSigningCert(
            X500Name subjectX500Name,
            IAuthToken authToken)
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

        Map<String, Object> resultMap = processor.processEnrollment(
            certRequest, null, authorityID, null, authToken);

        IRequest[] requests = (IRequest[]) resultMap.get(CAProcessor.ARG_REQUESTS);
        IRequest request = requests[0];

        Integer result = request.getExtDataInInteger(IRequest.RESULT);
        if (result != null && !result.equals(IRequest.RES_SUCCESS)) {
            throw new EBaseException("Unable to generate signing certificate: " + result);
        }

        RequestStatus requestStatus = request.getRequestStatus();
        if (requestStatus != RequestStatus.COMPLETE) {
            // The request did not complete.  Inference: something
            // incorrect in the request (e.g. profile constraint
            // violated).
            String msg = "Unable to generate signing certificate: " + requestStatus;
            String errorMsg = request.getExtDataInString(IRequest.ERROR);
            if (errorMsg != null) {
                msg += ": " + errorMsg;
            }
            throw new BadRequestDataException(msg);
        }

        return request.getExtDataInCert(EnrollProfile.REQUEST_ISSUED_CERT);
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
        Profile profile = ps.getProfile("caManualRenewal");
        CertEnrollmentRequest req = CertEnrollmentRequestFactory.create(
            new ArgBlock(), profile, httpReq.getLocale());
        req.setSerialNum(new CertId(mCaCert.getSerialNumber()));
        RenewalProcessor processor =
            new RenewalProcessor("renewAuthority", httpReq.getLocale());
        Map<String, Object> resultMap =
            processor.processRenewal(req, httpReq, null);
        IRequest requests[] = (IRequest[]) resultMap.get(CAProcessor.ARG_REQUESTS);
        IRequest request = requests[0];
        Integer result = request.getExtDataInInteger(IRequest.RESULT);
        if (result != null && !result.equals(IRequest.RES_SUCCESS))
            throw new EBaseException("renewAuthority: certificate renewal submission resulted in error: " + result);
        RequestStatus requestStatus = request.getRequestStatus();
        if (requestStatus != RequestStatus.COMPLETE)
            throw new EBaseException("renewAuthority: certificate renewal did not complete; status: " + requestStatus);
        X509CertImpl cert = request.getExtDataInCert(EnrollProfile.REQUEST_ISSUED_CERT);
        authoritySerial = cert.getSerialNumber();

        engine.updateAuthoritySerialNumber(authorityID, authoritySerial);

        // update cert in NSSDB
        checkForNewerCert();
    }

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
        ICertRecord certRecord = certificateRepository.readCertificateRecord(authoritySerial);
        String curStatus = certRecord.getStatus();
        logger.debug("revokeAuthority: current cert status: " + curStatus);
        if (curStatus.equals(CertRecord.STATUS_REVOKED)
                || curStatus.equals(CertRecord.STATUS_REVOKED_EXPIRED)) {
            return;  // already revoked
        }

        logger.debug("revokeAuthority: revoking cert");
        RevocationProcessor processor = new RevocationProcessor(
                "CertificateAuthority.revokeAuthority", httpReq.getLocale());
        processor.setSerialNumber(new CertId(authoritySerial));
        processor.setRevocationReason(RevocationReason.UNSPECIFIED);
        processor.setAuthority(this);
        try {
            processor.createCRLExtension();
        } catch (IOException e) {
            throw new ECAException("Unable to create CRL extensions", e);
        }
        processor.addCertificateToRevoke(mCaCert);
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
            cryptoStore.deleteCert(mCaX509Cert);
        } catch (NoSuchItemOnTokenException e) {
            logger.warn("deleteAuthority: cert is not on token: " + e);
            // if the cert isn't there, never mind
        } catch (TokenException e) {
            logger.error("deleteAuthority: TokenExcepetion while deleting cert: " + e.getMessage(), e);
            throw new ECAException("TokenException while deleting cert: " + e);
        }
    }
}
