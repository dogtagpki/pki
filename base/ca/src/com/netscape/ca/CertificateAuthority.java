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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Vector;
import java.util.concurrent.CountDownLatch;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.mozilla.jss.CryptoManager;
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
import org.mozilla.jss.pkix.cert.Extension;
import org.mozilla.jss.pkix.primitive.Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
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
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.ca.IssuerUnavailableException;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.dbs.crldb.ICRLRepository;
import com.netscape.certsrv.dbs.replicadb.IReplicaIDRepository;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.ocsp.IOCSPService;
import com.netscape.certsrv.policy.IPolicyProcessor;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.publish.ICRLPublisher;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.certsrv.request.ARequestNotifier;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestNotifier;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.IRequestScheduler;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.security.ISigningUnit;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cms.servlet.cert.CertEnrollmentRequestFactory;
import com.netscape.cms.servlet.cert.EnrollmentProcessor;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.dbs.CRLRepository;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.ReplicaIDRepository;
import com.netscape.cmscore.ldap.PublisherProcessor;
import com.netscape.cmscore.listeners.ListenerPlugin;
import com.netscape.cmscore.request.RequestSubsystem;
import com.netscape.cmscore.security.KeyCertUtil;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.ldap.LDAPPostReadControl;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.CertID;
import com.netscape.cmsutil.ocsp.CertStatus;
import com.netscape.cmsutil.ocsp.GoodInfo;
import com.netscape.cmsutil.ocsp.KeyHashID;
import com.netscape.cmsutil.ocsp.NameID;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.OCSPResponseStatus;
import com.netscape.cmsutil.ocsp.ResponderID;
import com.netscape.cmsutil.ocsp.ResponseBytes;
import com.netscape.cmsutil.ocsp.ResponseData;
import com.netscape.cmsutil.ocsp.RevokedInfo;
import com.netscape.cmsutil.ocsp.SingleResponse;
import com.netscape.cmsutil.ocsp.TBSRequest;
import com.netscape.cmsutil.ocsp.UnknownInfo;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPConstraints;
import netscape.ldap.LDAPControl;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.controls.LDAPEntryChangeControl;
import netscape.ldap.controls.LDAPPersistSearchControl;
import netscape.ldap.util.DN;
import netscape.security.pkcs.PKCS10;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.CertificateIssuerName;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.X500Name;
import netscape.security.x509.X500Signer;
import netscape.security.x509.X509CRLImpl;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509ExtensionException;
import netscape.security.x509.X509Key;


/**
 * A class represents a Certificate Authority that is
 * responsible for certificate specific operations.
 * <P>
 *
 * @author lhsiao
 * @version $Revision$, $Date$
 */
public class CertificateAuthority
        implements ICertificateAuthority, ICertAuthority, IOCSPService, Runnable {
    public static final String OFFICIAL_NAME = "Certificate Manager";

    public final static OBJECT_IDENTIFIER OCSP_NONCE = new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.48.1.2");

    /* The static conn factory is initialised by the host authority's
     * 'init' method, before any lightweight CAs are instantiated
     */
    private static ILdapConnFactory dbFactory = null;

    private static final Map<AuthorityID, ICertificateAuthority> caMap =
        Collections.synchronizedSortedMap(new TreeMap<AuthorityID, ICertificateAuthority>());
    private static final Map<AuthorityID, Thread> keyRetrieverThreads =
        Collections.synchronizedSortedMap(new TreeMap<AuthorityID, Thread>());
    protected CertificateAuthority hostCA = null;
    protected AuthorityID authorityID = null;
    protected AuthorityID authorityParentID = null;
    protected String authorityDescription = null;
    protected Collection<String> authorityKeyHosts = null;
    protected boolean authorityEnabled = true;
    private boolean hasKeys = false;
    private ECAException signingUnitException = null;

    protected ISubsystem mOwner = null;
    protected IConfigStore mConfig = null;
    protected ILogger mLogger = CMS.getLogger();
    protected Hashtable<String, ICRLIssuingPoint> mCRLIssuePoints = new Hashtable<String, ICRLIssuingPoint>();
    protected CRLIssuingPoint mMasterCRLIssuePoint = null; // the complete crl.
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

    protected CertificateRepository mCertRepot = null;
    protected CRLRepository mCRLRepot = null;
    protected ReplicaIDRepository mReplicaRepot = null;

    protected CertificateChain mCACertChain = null;
    protected CertificateChain mOCSPCertChain = null;
    protected X509CertImpl mCRLCert = null;
    protected org.mozilla.jss.crypto.X509Certificate mCRLX509Cert = null;
    protected X509CertImpl mCaCert = null;
    protected org.mozilla.jss.crypto.X509Certificate mCaX509Cert = null;
    protected X509CertImpl mOCSPCert = null;
    protected org.mozilla.jss.crypto.X509Certificate mOCSPX509Cert = null;
    protected String[] mCASigningAlgorithms = null;

    protected PublisherProcessor mPublisherProcessor = null;
    protected IRequestQueue mRequestQueue = null;
    protected CAPolicy mPolicy = null;
    protected CAService mService = null;
    protected IRequestNotifier mNotify = null;
    protected IRequestNotifier mPNotify = null;
    protected long mNumOCSPRequest = 0;
    protected long mTotalTime = 0;
    protected long mTotalData = 0;
    protected long mSignTime = 0;
    protected long mLookupTime = 0;

    protected static final int FASTSIGNING_DISABLED = 0;
    protected static final int FASTSIGNING_ENABLED = 1;

    protected CertificateVersion mDefaultCertVersion;
    protected long mDefaultValidity;
    protected boolean mEnablePastCATime;
    protected boolean mEnableOCSP;
    protected int mFastSigning = FASTSIGNING_DISABLED;

    protected static final long SECOND = 1000; // 1000 milliseconds
    protected static final long MINUTE = 60 * SECOND;
    protected static final long HOUR = 60 * MINUTE;
    protected static final long DAY = 24 * HOUR;
    protected static final long YEAR = DAY * 365;

    protected static final String PROP_CERT_REPOS_DN = "CertificateRepositoryDN";
    protected static final String PROP_REPOS_DN = "RepositoryDN";
    protected static final String PROP_REPLICAID_DN = "dbs.replicadn";

    // for the notification listeners

    /**
     * Package constants
     */

    public IRequestListener mCertIssuedListener = null;
    public IRequestListener mCertRevokedListener = null;
    public IRequestListener mReqInQListener = null;

    /* cache responder ID for performance */
    private ResponderID mResponderIDByName = null;
    private ResponderID mResponderIDByHash = null;

    protected Hashtable<String, ListenerPlugin> mListenerPlugins = null;

    /**
     * Internal constants
     */

    protected ICRLPublisher mCRLPublisher = null;
    private String mId = null;

    private boolean mByName = true;

    private boolean mUseNonces = true;
    private int mMaxNonces = 100;

    /* Variables to manage loading and tracking of lightweight CAs
     *
     * The initialLoadDone latch causes the host authority's 'init'
     * method to block until the monitor thread has finished the
     * initial loading of lightweight CAs.
     *
     * In other words: the "server startup" cannot complete until
     * all the lightweight CAs that exist at start time are loaded.
     */
    private static boolean stopped = false;
    private static boolean foundHostAuthority = false;
    private static Integer initialNumAuthorities = null;
    private static int numAuthoritiesLoaded = 0;
    private static CountDownLatch initialLoadDone = new CountDownLatch(1);

    /* Maps and sets of entryUSNs and nsUniqueIds for avoiding race
     * conditions and unnecessary reloads related to replication */
    private static TreeMap<AuthorityID,Integer> entryUSNs = new TreeMap<>();
    private static TreeMap<AuthorityID,String> nsUniqueIds = new TreeMap<>();
    private static TreeSet<String> deletedNsUniqueIds = new TreeSet<>();

    /**
     * Constructs a CA subsystem.
     */
    public CertificateAuthority() {
        hostCA = this;
    }

    /**
     * Construct and initialise a lightweight authority
     */
    private CertificateAuthority(
            CertificateAuthority hostCA,
            X500Name dn,
            AuthorityID aid,
            AuthorityID parentAID,
            String signingKeyNickname,
            Collection<String> authorityKeyHosts,
            String authorityDescription,
            boolean authorityEnabled
            ) throws EBaseException {
        setId(hostCA.getId());
        this.hostCA = hostCA;

        // cert and key may not have been replicated to local nssdb
        // yet, so set DN based on data from LDAP
        this.mName = dn;

        this.authorityID = aid;
        this.authorityParentID = parentAID;
        this.authorityDescription = authorityDescription;
        this.authorityEnabled = authorityEnabled;
        mNickname = signingKeyNickname;
        this.authorityKeyHosts = authorityKeyHosts;
        init(hostCA.mOwner, hostCA.mConfig);
    }

    public boolean isHostAuthority() {
        return hostCA == this;
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

    /**
     * Retrieves subsystem identifier.
     */
    public String getId() {
        return mId;
    }

    public CertificateVersion getDefaultCertVersion() {
        return mDefaultCertVersion;
    }

    public boolean isEnablePastCATime() {
        return mEnablePastCATime;
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
        if (mMasterCRLIssuePoint != null) {
            mMasterCRLIssuePoint.updateCRLNow();
        }
    }

    public void publishCRLNow() throws EBaseException {
        if (mMasterCRLIssuePoint != null) {
            mMasterCRLIssuePoint.publishCRL();
        }
    }

    public ICRLPublisher getCRLPublisher() {
        return mCRLPublisher;
    }

    /**
     * @deprecated
     */
    public IPolicyProcessor getPolicyProcessor() {
        return mPolicy.getPolicyProcessor();
    }

    public boolean noncesEnabled() {
        return mUseNonces;
    }

    public Map<Object, Long> getNonces(HttpServletRequest request, String name) {

        // Create a new session or use an existing one.
        HttpSession session = request.getSession(true);
        if (session == null) {
            throw new PKIException("Unable to create session.");
        }

        // Lock the session to prevent concurrent access.
        // http://yet-another-dev.blogspot.com/2009/08/synchronizing-httpsession.html

        Object lock = request.getSession().getId().intern();
        synchronized (lock) {

            // Find the existing storage in the session.
            @SuppressWarnings("unchecked")
            Map<Object, Long> nonces = (Map<Object, Long>)session.getAttribute("nonces-"+name);

            if (nonces == null) {
                // If not present, create a new storage.
                nonces = Collections.synchronizedMap(new Nonces(mMaxNonces));

                // Put the storage in the session.
                session.setAttribute("nonces-"+name, nonces);
            }

            return nonces;
        }
    }

    /**
     * Initializes this CA subsystem.
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration of this subsystem
     * @exception EBaseException failed to initialize this CA
     */
    public void init(ISubsystem owner, IConfigStore config) throws
            EBaseException {

        try {
            CMS.debug("CertificateAuthority init ");
            mOwner = owner;
            mConfig = config;

            if (isHostAuthority()) {
                dbFactory = CMS.getLdapBoundConnFactory("CertificateAuthority");
                dbFactory.init(CMS.getConfigStore().getSubStore("internaldb"));
            }

            // init cert & crl database
            initCertDatabase();
            initCrlDatabase();

            // init replica id repository
            if (isHostAuthority()) {
                String replicaReposDN = mConfig.getString(PROP_REPLICAID_DN, null);
                if (replicaReposDN == null) {
                    replicaReposDN = "ou=Replica," + getDBSubsystem().getBaseDN();
                }
                mReplicaRepot = new ReplicaIDRepository(
                        DBSubsystem.getInstance(), 1, replicaReposDN);
                CMS.debug("Replica Repot inited");
            } else {
                mReplicaRepot = hostCA.mReplicaRepot;
            }

            // init signing unit & CA cert.
            try {
                initSigUnit(/* retrieveKeys */ true);
                // init default CA attributes like cert version, validity.
                initDefCaAttrs();

            } catch (EBaseException e) {
                CMS.debug(e);
                if (CMS.isPreOpMode()) {
                    CMS.debug("CertificateAuthority.init(): Swallow exception in pre-op mode");
                } else {
                    throw e;
                }
            }

            mUseNonces = mConfig.getBoolean("enableNonces", true);
            mMaxNonces = mConfig.getInteger("maxNumberOfNonces", 100);

            // init request queue and related modules.
            CMS.debug("CertificateAuthority init: initRequestQueue");
            initRequestQueue();
            if (CMS.isPreOpMode()) {
                CMS.debug("CertificateAuthority.init(): Abort in pre-op mode");
                return;
            }

            /* The host CA owns these resources so skip these
             * steps for lightweight CAs.
             */
            if (isHostAuthority()) {
                /* These methods configure and start threads related to
                 * CertificateRepository.  Ideally all of the config would
                 * be pushed into CertificateRepository constructor and a
                 * single 'start' method would start the threads.
                 */
                // set certificate status to 10 minutes
                mCertRepot.setCertStatusUpdateInterval(
                    mRequestQueue.getRequestRepository(),
                    mConfig.getInteger("certStatusUpdateInterval", 10 * 60),
                    mConfig.getBoolean("listenToCloneModifications", false));
                mCertRepot.setConsistencyCheck(
                    mConfig.getBoolean("ConsistencyCheck", false));
                mCertRepot.setSkipIfInConsistent(
                    mConfig.getBoolean("SkipIfInConsistent", false));

                // set serial number update task to run every 10 minutes
                mCertRepot.setSerialNumberUpdateInterval(
                    mRequestQueue.getRequestRepository(),
                    mConfig.getInteger("serialNumberUpdateInterval", 10 * 60));

                mService.init(config.getSubStore("connector"));

                initMiscellaneousListeners();
            }

            initCRLPublisher();

            // initialize publisher processor (publish remote admin
            // rely on this subsystem, so it has to be initialized)
            initPublish();

            // Initialize CRL issuing points.
            // note CRL framework depends on DBS, CRYPTO and PUBLISHING
            // being functional.
            initCRL();

            if (isHostAuthority() && haveLightweightCAsContainer()) {
                new Thread(this, "authorityMonitor").start();
                try {
                    initialLoadDone.await();
                } catch (InterruptedException e) {
                    CMS.debug("CertificateAuthority: caught InterruptedException "
                            + "while waiting for initial load of authorities.");
                }

                if (!foundHostAuthority) {
                    CMS.debug("loadLightweightCAs: no entry for host authority");
                    CMS.debug("loadLightweightCAs: adding entry for host authority");
                    caMap.put(addHostAuthorityEntry(), this);
                }

                CMS.debug("CertificateAuthority: finished init of host authority");
            }
        } catch (EBaseException e) {
            CMS.debug(e);
            if (CMS.isPreOpMode()) {
                CMS.debug("CertificateAuthority.init(): Swallow exception in pre-op mode");
                return;
            }
            throw e;
        }
    }

    private String authorityBaseDN() {
        return "ou=authorities,ou=" + getId()
            + "," + getDBSubsystem().getBaseDN();
    }

    private boolean haveLightweightCAsContainer() throws ELdapException {
        LDAPConnection conn = dbFactory.getConn();
        try {
            LDAPSearchResults results = conn.search(
                authorityBaseDN(), LDAPConnection.SCOPE_BASE, null, null, false);
            return results != null;
        } catch (LDAPException e) {
            return false;
        } finally {
            dbFactory.returnConn(conn);
        }
    }

    private void initCRLPublisher() throws EBaseException {
        // instantiate CRL publisher
        if (!isHostAuthority()) {
            mByName = hostCA.mByName;
            mCRLPublisher = hostCA.mCRLPublisher;
            return;
        }

        mByName = mConfig.getBoolean("byName", true);
        IConfigStore cpStore = mConfig.getSubStore("crlPublisher");
        if (cpStore != null && cpStore.size() > 0) {
            String publisherClass = cpStore.getString("class");

            if (publisherClass != null) {
                try {
                    @SuppressWarnings("unchecked")
                    Class<ICRLPublisher> pc = (Class<ICRLPublisher>) Class.forName(publisherClass);

                    mCRLPublisher = pc.newInstance();
                    mCRLPublisher.init(this, cpStore);
                } catch (ClassNotFoundException ee) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_NO_PUBLISHER", ee.toString()));
                } catch (IllegalAccessException ee) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_NO_PUBLISHER", ee.toString()));
                } catch (InstantiationException ee) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_NO_PUBLISHER", ee.toString()));
                }
            }
        }
    }

    /**
     * return CA's request queue processor
     */
    public IRequestQueue getRequestQueue() {
        return mRequestQueue;
    }

    /**
     * registers listener
     */
    public void registerRequestListener(IRequestListener listener) {
        mNotify.registerListener(listener);
    }

    /**
     * registers listener with a name.
     */
    public void registerRequestListener(String name, IRequestListener listener) {
        mNotify.registerListener(name, listener);
    }

    /**
     * removes listener
     */
    public void removeRequestListener(IRequestListener listener) {
        mNotify.removeListener(listener);
    }

    /**
     * removes listener with a name.
     */
    public void removeRequestListener(String name) {
        mNotify.removeListener(name);
    }

    /**
     * register listener for pending requests
     */
    public void registerPendingListener(IRequestListener listener) {
        mPNotify.registerListener(listener);
    }

    /**
     * register listener for pending requests with a name.
     */
    public void registerPendingListener(String name, IRequestListener listener) {
        mPNotify.registerListener(name, listener);
    }

    /**
     * get listener from listener list
     */
    public IRequestListener getRequestListener(String name) {
        return mNotify.getListener(name);
    }

    /**
     * get notifiers registered by CA
     */
    public IRequestNotifier getRequestNotifier() {
        return mNotify;
    }

    /**
     * get listener from listener list
     */
    public IRequestListener getPendingListener(String name) {
        return mPNotify.getListener(name);
    }

    public Enumeration<String> getRequestListenerNames() {
        return mNotify.getListenerNames();
    }

    public IRequestListener getRequestInQListener() {
        return mReqInQListener;
    }

    public IRequestListener getCertIssuedListener() {
        return mCertIssuedListener;
    }

    public IRequestListener getCertRevokedListener() {
        return mCertRevokedListener;
    }

    /**
     * return CA's policy processor.
     */
    public IPolicy getCAPolicy() {
        return mPolicy;
    }

    /**
     * return CA's request queue service object.
     */
    public IService getCAService() {
        return mService;
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
        if (CMS.isPreOpMode()) {
            CMS.debug("CertificateAuthority.startup(): Do not start CA in pre-op mode");
            return;
        }
        mService.startup();
        mRequestQueue.recover();

        if (isHostAuthority()) {
            // setup Admin operations
            initNotificationListeners();
            startPublish();
        }
    }

    /**
     * Shutdowns this subsystem.
     * <P>
     */
    public void shutdown() {
        // lightweight authorities don't own these resources
        if (!isHostAuthority())
            return;

        Enumeration<ICRLIssuingPoint> enums = mCRLIssuePoints.elements();
        while (enums.hasMoreElements()) {
            CRLIssuingPoint point = (CRLIssuingPoint) enums.nextElement();
            point.shutdown();
        }
        mCRLIssuePoints.clear();

        if (mMasterCRLIssuePoint != null) {
            mMasterCRLIssuePoint.shutdown();
        }

        if (mCertRepot != null) {
            mCertRepot.shutdown();
        }

        if (mPublisherProcessor != null) {
            mPublisherProcessor.shutdown();
        }

        /* Stop the activityMonitor thread
         *
         * dbFactory.reset() will disconnect all connections,
         * causing the current conn.search() to throw.
         * The search will not be restarted because 'stopped' has
         * set, and the monitor thread will exit.
         */
        stopped = true;
        try {
            dbFactory.reset();
        } catch (ELdapException e) {
            CMS.debug("CertificateAuthority.shutdown: failed to reset "
                    + "dbFactory: " + e);
            // not much else we can do here.
        }
    }

    /**
     * Retrieves the configuration store of this subsystem.
     * <P>
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Retrieves logger.
     */
    public ILogger getLogger() {
        return CMS.getLogger();
    }

    /**
     * Retrieves database services.
     */
    public IDBSubsystem getDBSubsystem() {
        return DBSubsystem.getInstance();
    }

    public void setValidity(String enableCAPast) throws EBaseException {
        if (enableCAPast.equals("true"))
            mEnablePastCATime = true;
        else
            mEnablePastCATime = false;
        mConfig.putString(PROP_ENABLE_PAST_CATIME, enableCAPast);
    }

    public long getDefaultValidity() {
        return mDefaultValidity;
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
        try {
            BigInteger serial =
                    mCertRepot.getTheSerialNumber();

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
        mCertRepot.setTheSerialNumber(new BigInteger(serial));
    }

    public String getMaxSerial() {
        String serial = mCertRepot.getMaxSerial();

        if (serial != null)
            return serial;
        else
            return "";
    }

    public void setMaxSerial(String serial) throws EBaseException {
        mCertRepot.setMaxSerial(serial);
    }

    /**
     * Retrieves certificate repository.
     * <P>
     *
     * @return certificate repository
     */
    public ICertificateRepository getCertificateRepository() {
        return mCertRepot;
    }

    /**
     * Retrieves replica repository.
     * <P>
     *
     * @return replica repository
     */
    public IReplicaIDRepository getReplicaRepository() {
        return mReplicaRepot;
    }

    /**
     * Retrieves CRL repository.
     */
    public ICRLRepository getCRLRepository() {
        return mCRLRepot;
    }

    public IPublisherProcessor getPublisherProcessor() {
        return mPublisherProcessor;
    }

    /**
     * Retrieves the CRL issuing point by id.
     * <P>
     *
     * @param id string id of the CRL issuing point
     * @return CRL issuing point
     */
    public ICRLIssuingPoint getCRLIssuingPoint(String id) {
        return mCRLIssuePoints.get(id);
    }

    /**
     * Enumerates CRL issuing points
     * <P>
     *
     * @return security service
     */
    public Enumeration<ICRLIssuingPoint> getCRLIssuingPoints() {
        return mCRLIssuePoints.elements();
    }

    public int getCRLIssuingPointsSize() {
        return mCRLIssuePoints.size();
    }

    /**
     * Adds CRL issuing point with the given identifier and description.
     */
    @SuppressWarnings("unchecked")
    public boolean addCRLIssuingPoint(IConfigStore crlSubStore, String id,
                                      boolean enable, String description) {
        crlSubStore.makeSubStore(id);
        IConfigStore c = crlSubStore.getSubStore(id);

        if (c != null) {
            c.putString("allowExtensions", "true");
            c.putString("alwaysUpdate", "false");
            c.putString("autoUpdateInterval", "240");
            c.putString("caCertsOnly", "false");
            c.putString("cacheUpdateInterval", "15");
            c.putString("class", "com.netscape.ca.CRLIssuingPoint");
            c.putString("dailyUpdates", "3:45");
            c.putString("description", description);
            c.putBoolean("enable", enable);
            c.putString("enableCRLCache", "true");
            c.putString("enableCRLUpdates", "true");
            c.putString("enableCacheTesting", "false");
            c.putString("enableCacheRecovery", "true");
            c.putString("enableDailyUpdates", "false");
            c.putString("enableUpdateInterval", "true");
            c.putString("extendedNextUpdate", "true");
            c.putString("includeExpiredCerts", "false");
            c.putString("minUpdateInterval", "0");
            c.putString("nextUpdateGracePeriod", "0");
            c.putString("publishOnStart", "false");
            c.putString("saveMemory", "false");
            c.putString("signingAlgorithm", "SHA256withRSA");
            c.putString("updateSchema", "1");

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
                issuingPointClassName = c.getString(PROP_CLASS);
                issuingPointClass = (Class<CRLIssuingPoint>) Class.forName(issuingPointClassName);
                issuingPoint = issuingPointClass.newInstance();
                issuingPoint.init(this, id, c);
                mCRLIssuePoints.put(id, issuingPoint);
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
        CRLIssuingPoint ip = (CRLIssuingPoint) mCRLIssuePoints.get(id);

        if (ip != null) {
            ip.shutdown();
            mCRLIssuePoints.remove(id);
            ip = null;
            crlSubStore.removeSubStore(id);
            try {
                mCRLRepot.deleteCRLIssuingPointRecord(id);
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("FAILED_REMOVING_CRL_IP_2", id, e.toString()));
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
        ensureReady();
        X509CRLImpl signedcrl = null;

        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
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
                    CMS.debug("Failed to add signed-CRL to CRL object.");
                }
            } else {
                CMS.debug("Failed to add signature to CRL object.");
            }
        } catch (CRLException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CRL", e.toString(), e.getMessage()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CRL_FAILED", e.getMessage()));
        } catch (X509ExtensionException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CRL", e.toString(), e.getMessage()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CRL_FAILED", e.getMessage()));
        } catch (NoSuchAlgorithmException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CRL", e.toString(), e.getMessage()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CRL_FAILED", e.getMessage()));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CRL", e.toString(), e.getMessage()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CRL_FAILED", e.getMessage()));
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
        ensureReady();

        X509CertImpl signedcert = null;

        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        if (statsSub != null) {
            statsSub.startTiming("signing");
        }

        try (DerOutputStream out = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            if (certInfo == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_NO_CERTINFO"));
                return null;
            }

            if (algname == null) {
                algname = mSigningUnit.getDefaultAlgorithm();
            }

            CMS.debug("sign cert get algorithm");
            AlgorithmId alg = AlgorithmId.get(algname);

            // encode certificate info
            CMS.debug("sign cert encoding cert");
            certInfo.encode(tmp);
            byte[] rawCert = tmp.toByteArray();

            // encode algorithm identifier
            CMS.debug("sign cert encoding algorithm");
            alg.encode(tmp);

            CMS.debug("CA cert signing: signing cert");
            byte[] signature = mSigningUnit.sign(rawCert, algname);

            tmp.putBitString(signature);

            // Wrap the signed data in a SEQUENCE { data, algorithm, sig }
            out.write(DerValue.tag_Sequence, tmp);
            //log(ILogger.LL_INFO, "CertificateAuthority: done signing");

            switch (mFastSigning) {
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
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CERT", e.toString(), e.getMessage()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CERT_FAILED", e.getMessage()));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CERT", e.toString(), e.getMessage()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CERT_FAILED", e.getMessage()));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_SIGN_CERT", e.toString(), e.getMessage()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_SIGNING_CERT_FAILED", e.getMessage()));
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
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_CA,
                level, msg);
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
        // during configuration
        try {
            String cert = mConfig.getString("signing.cert", null);
            if (cert != null) {
                return new X509CertImpl(CMS.AtoB(cert));
            }

        } catch (EBaseException e) {
            CMS.debug(e);
            throw e;

        } catch (CertificateException e) {
            throw new EBaseException(e);
        }

        return null;
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
            CMS.debug(
                    "CA - no signing algorithms for " + alg.getName());
        } else {
            CMS.debug(
                    "CA First signing algorithm is " + mCASigningAlgorithms[0]);
        }

        return mCASigningAlgorithms;
    }

    //////////
    // Initialization routines.
    //

    /**
     * init CA signing unit & cert chain.
     */
    private synchronized boolean initSigUnit(boolean retrieveKeys)
            throws EBaseException {
        try {
            // init signing unit
            mSigningUnit = new SigningUnit();
            IConfigStore caSigningCfg =
                    mConfig.getSubStore(PROP_SIGNING_SUBSTORE);

            String caSigningCertStr = caSigningCfg.getString("cert", "");
            if (caSigningCertStr.equals("")) {
                CMS.debug("CertificateAuthority:initSigUnit: ca.signing.cert not found");
            } else { //ca cert found
                CMS.debug("CertificateAuthority:initSigUnit: ca cert found");
                mCaCert = new X509CertImpl(CMS.AtoB(caSigningCertStr));
                // this ensures the isserDN and subjectDN have the same encoding
                // as that of the CA signing cert
                CMS.debug("CertificateAuthority: initSigUnit 1- setting mIssuerObj and mSubjectObj");
                mSubjectObj = mCaCert.getSubjectObj();
                // this mIssuerObj is the "issuerDN" obj for the certs this CA
                // issues, NOT necessarily the isserDN obj of the CA signing cert
                mIssuerObj = new CertificateIssuerName((X500Name)mSubjectObj.get(CertificateIssuerName.DN_NAME));
            }

            try {
                mSigningUnit.init(this, caSigningCfg, mNickname);
                hasKeys = true;
                signingUnitException = null;
            } catch (CAMissingCertException | CAMissingKeyException e) {
                CMS.debug("CA signing key and cert not (yet) present in NSSDB");
                signingUnitException = e;
                if (retrieveKeys == true) {
                    if (!keyRetrieverThreads.containsKey(authorityID)) {
                        CMS.debug("Starting KeyRetrieverRunner thread");
                        Thread t = new Thread(
                            new KeyRetrieverRunner(authorityID, mNickname, authorityKeyHosts),
                            "KeyRetrieverRunner-" + authorityID);
                        t.start();
                        keyRetrieverThreads.put(authorityID, t);
                    } else {
                        CMS.debug("KeyRetriever thread already running for authority " + authorityID);
                    }
                }
                return false;
            }
            CMS.debug("CA signing unit inited");

            // for identrus
            IConfigStore CrlStore = mConfig.getSubStore(PROP_CRL_SIGNING_SUBSTORE);

            if (isHostAuthority() && CrlStore != null && CrlStore.size() > 0) {
                mCRLSigningUnit = new SigningUnit();
                mCRLSigningUnit.init(this, mConfig.getSubStore(PROP_CRL_SIGNING_SUBSTORE));
            } else {
                mCRLSigningUnit = mSigningUnit;
            }

            // init cert chain
            CryptoManager manager = CryptoManager.getInstance();

            int caChainNum =
                    caSigningCfg.getInteger(PROP_CA_CHAIN_NUM, 0);

            CMS.debug("cachainNum= " + caChainNum);
            if (caChainNum > 0) {
                // custom build chain (for cross cert chain)
                // audit here ***
                IConfigStore chainStore =
                        caSigningCfg.getSubStore(PROP_CA_CHAIN);

                if (chainStore == null) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_CA_OCSP_CHAIN",
                                    "ca cert chain config error"));
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_BUILD_CA_CHAIN_FAILED",
                                    "ca cert chain config error"));
                }

                java.security.cert.X509Certificate[] implchain =
                        new java.security.cert.X509Certificate[caChainNum];

                for (int i = 0; i < caChainNum; i++) {
                    String subtreeName = PROP_CA_CERT + i;
                    // cert file name must be full path
                    String certFileName =
                            chainStore.getString(subtreeName, null);

                    if ((certFileName == null) || certFileName.equals("")) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_OCSP_CHAIN", "cert file config error"));
                        throw new ECAException(
                                CMS.getUserMessage("CMS_CA_BUILD_CA_CHAIN_FAILED",
                                        "cert file config error"));
                    }
                    byte[] b64Bytes = getCertFromFile(certFileName);
                    String b64String = new String(b64Bytes);
                    byte[] certBytes = KeyCertUtil.convertB64EToByteArray(b64String);

                    implchain[i] = new X509CertImpl(certBytes);
                } // for

                mCACertChain = new CertificateChain(implchain);
                CMS.debug("in init - custom built CA cert chain.");
            } else {
                // build ca chain the traditional way
                org.mozilla.jss.crypto.X509Certificate[] chain =
                        manager.buildCertificateChain(mSigningUnit.getCert());
                // do this in case other subsyss expect a X509CertImpl
                java.security.cert.X509Certificate[] implchain =
                        new java.security.cert.X509Certificate[chain.length];

                for (int i = 0; i < chain.length; i++) {
                    implchain[i] = new X509CertImpl(chain[i].getEncoded());
                }
                mCACertChain = new CertificateChain(implchain);
                CMS.debug("in init - got CA chain from JSS.");
            }

            IConfigStore OCSPStore = mConfig.getSubStore(PROP_OCSP_SIGNING_SUBSTORE);

            if (isHostAuthority() && OCSPStore != null && OCSPStore.size() > 0) {
                mOCSPSigningUnit = new SigningUnit();
                mOCSPSigningUnit.init(this, mConfig.getSubStore(PROP_OCSP_SIGNING_SUBSTORE));
                CMS.debug("Separate OCSP signing unit inited");
            } else {
                mOCSPSigningUnit = mSigningUnit;
                CMS.debug("Shared OCSP signing unit inited");
            }

            org.mozilla.jss.crypto.X509Certificate[] ocspChain =
                    manager.buildCertificateChain(mOCSPSigningUnit.getCert());
            // do this in case other subsyss expect a X509CertImpl
            java.security.cert.X509Certificate[] ocspImplchain =
                    new java.security.cert.X509Certificate[ocspChain.length];

            for (int i = 0; i < ocspChain.length; i++) {
                ocspImplchain[i] = new X509CertImpl(ocspChain[i].getEncoded());
            }
            mOCSPCertChain = new CertificateChain(ocspImplchain);
            CMS.debug("in init - got OCSP chain from JSS.");

            mCaX509Cert = mSigningUnit.getCert();
            mCaCert = new X509CertImpl(mCaX509Cert.getEncoded());
            getCASigningAlgorithms();
            mSubjectObj = mCaCert.getSubjectObj();
            if (mSubjectObj != null) {
                // this ensures the isserDN and subjectDN have the same encoding
                // as that of the CA signing cert
                CMS.debug("CertificateAuthority: initSigUnit - setting mIssuerObj and mSubjectObj");
                // this mIssuerObj is the "issuerDN" obj for the certs this CA
                // issues, NOT necessarily the isserDN obj of the CA signing cert
                // unless the CA is self-signed
                mIssuerObj =
                        new CertificateIssuerName((X500Name)mSubjectObj.get(CertificateIssuerName.DN_NAME));
            }
            mName = (X500Name) mCaCert.getSubjectDN();

            mCRLX509Cert = mCRLSigningUnit.getCert();
            mCRLCert = new X509CertImpl(mCRLX509Cert.getEncoded());
            mCRLName = (X500Name) mCRLCert.getSubjectDN();

            mOCSPX509Cert = mOCSPSigningUnit.getCert();
            mOCSPNickname = mOCSPSigningUnit.getNickname();
            mOCSPCert = new X509CertImpl(mOCSPX509Cert.getEncoded());
            mOCSPName = (X500Name) mOCSPCert.getSubjectDN();
            mNickname = mSigningUnit.getNickname();
            CMS.debug("in init - got CA name " + mName);

            return true;

        } catch (CryptoManager.NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_OCSP_SIGNING", e.toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_CRYPTO_NOT_INITIALIZED"));
        } catch (CertificateException e) {
            if (Debug.ON)
                e.printStackTrace();
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_OCSP_CHAIN", e.toString()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_BUILD_CA_CHAIN_FAILED", e.toString()));
        } catch (FileNotFoundException e) {
            if (Debug.ON)
                e.printStackTrace();
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_OCSP_CHAIN", e.toString()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_BUILD_CA_CHAIN_FAILED", e.toString()));
        } catch (IOException e) {
            if (Debug.ON)
                e.printStackTrace();
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_OCSP_CHAIN", e.toString()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_BUILD_CA_CHAIN_FAILED", e.toString()));
        } catch (TokenException e) {
            if (Debug.ON)
                e.printStackTrace();
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_OCSP_CHAIN", e.toString()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_BUILD_CA_CHAIN_FAILED", e.toString()));
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

    /**
     * init default cert attributes.
     */
    private void initDefCaAttrs()
            throws EBaseException {
        int version = mConfig.getInteger(PROP_X509CERT_VERSION,
                CertificateVersion.V3);

        if (version != CertificateVersion.V1 &&
                version != CertificateVersion.V3) {
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_X509CERT_VERSION_NOT_SUPPORTED"));
        }
        try {
            mDefaultCertVersion = new CertificateVersion(version - 1);
        } catch (IOException e) {
            // should never occur.
        }

        int validity_in_days = mConfig.getInteger(PROP_DEF_VALIDITY, 2 * 365);

        mDefaultValidity = validity_in_days * DAY; // days in config file.

        mEnablePastCATime =
                mConfig.getBoolean(PROP_ENABLE_PAST_CATIME, false);
        mEnableOCSP =
                mConfig.getBoolean(PROP_ENABLE_OCSP, true);

        String fs = mConfig.getString(PROP_FAST_SIGNING, "");

        if (fs.equals("enabled") || fs.equals("enable")) {
            mFastSigning = FASTSIGNING_ENABLED;
        } else {
            mFastSigning = FASTSIGNING_DISABLED;
        }

    }

    /**
     * init cert & crl database
     */
    private void initCertDatabase()
            throws EBaseException {
        if (!isHostAuthority()) {
            mCertRepot = hostCA.mCertRepot;
            return;
        }

        int certdb_inc = mConfig.getInteger(PROP_CERTDB_INC, 5);

        String certReposDN = mConfig.getString(PROP_CERT_REPOS_DN, null);

        if (certReposDN == null) {
            certReposDN = "ou=certificateRepository, ou=" + getId() +
                    ", " + getDBSubsystem().getBaseDN();
        }
        String reposDN = mConfig.getString(PROP_REPOS_DN, null);

        if (reposDN == null) {
            reposDN = "ou=certificateRepository, ou=" + getId() +
                    ", " + getDBSubsystem().getBaseDN();
        }

        int transitMaxRecords = mConfig.getInteger(PROP_CERTDB_TRANS_MAXRECORDS, 1000000);
        int transitRecordPageSize = mConfig.getInteger(PROP_CERTDB_TRANS_PAGESIZE, 200);

        mCertRepot = new CertificateRepository(
                    DBSubsystem.getInstance(),
                    certReposDN, certdb_inc, reposDN);

        mCertRepot.setTransitMaxRecords(transitMaxRecords);
        mCertRepot.setTransitRecordPageSize(transitRecordPageSize);

        CMS.debug("Cert Repot inited");
    }

    /**
     * init cert & crl database
     */
    private void initCrlDatabase()
            throws EBaseException {
        if (!isHostAuthority()) {
            mCRLRepot = hostCA.mCRLRepot;
            return;
        }

        int crldb_inc = mConfig.getInteger(PROP_CRLDB_INC, 5);

        mCRLRepot = new CRLRepository(
                    DBSubsystem.getInstance(),
                    crldb_inc,
                    "ou=crlIssuingPoints, ou=" + getId() + ", " +
                            getDBSubsystem().getBaseDN());
        CMS.debug("CRL Repot inited");
    }

    private void startPublish()
            throws EBaseException {
        //xxx Note that CMS411 only support ca cert publishing to ldap
        // if ldap publishing is not enabled while publishing isenabled
        // there will be a lot of problem.
        try {
            if (mPublisherProcessor.isCertPublishingEnabled()) {
                mPublisherProcessor.publishCACert(mCaCert);
                CMS.debug("published ca cert");
            }
        } catch (ELdapException e) {
            // exception not thrown - not seen as a fatal error.
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_PUBLISH", e.toString()));
        }
    }

    /**
     * init publishing
     */
    private void initPublish()
            throws EBaseException {
        if (!isHostAuthority()) {
            mPublisherProcessor = hostCA.mPublisherProcessor;
            return;
        }

        IConfigStore c = null;

        try {
            c = mConfig.getSubStore(PROP_PUBLISH_SUBSTORE);
            if (c != null && c.size() > 0) {
                mPublisherProcessor = new PublisherProcessor(
                            getId() + "pp");
                mPublisherProcessor.init(this, c);
                CMS.debug("Publishing inited");
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_NO_PUBLISH"));
                throw new ECAException(
                        CMS.getUserMessage("CMS_CA_INIT_PUBLISH_MODULE_FAILED"));
            }

        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_ERROR_PUBLISH_MODULE", e.toString()));
            //throw new ECAException(
            //	CAResources.INIT_PUBLISH_MODULE_FAILED, e);
        }
    }

    private void initMiscellaneousListeners() {
        IConfigStore lc = null;
        IConfigStore implc = null;
        IConfigStore instc = null;

        mListenerPlugins = new Hashtable<String, ListenerPlugin>();
        try {
            // Get list of listener implementations
            lc = mConfig.getSubStore(PROP_LISTENER_SUBSTORE);
            if (lc != null) {

                implc = lc.getSubStore(PROP_IMPL);
                Enumeration<String> names = implc.getSubStoreNames();

                while (names.hasMoreElements()) {
                    String id = names.nextElement();

                    if (Debug.ON)
                        Debug.trace("registering listener impl: " + id);
                    String cl = implc.getString(id + "." + PROP_CLASS);

                    ListenerPlugin plugin = new ListenerPlugin(id, cl);

                    mListenerPlugins.put(id, plugin);
                }

                instc = lc.getSubStore(PROP_INSTANCE);
                Enumeration<String> instances = instc.getSubStoreNames();

                while (instances.hasMoreElements()) {
                    String id = instances.nextElement();

                    if (Debug.ON)
                        Debug.trace("registering listener instance: " + id);
                    IConfigStore iConfig = instc.getSubStore(id);
                    String implName = instc.getString(id + "." + PROP_PLUGIN);
                    ListenerPlugin plugin = mListenerPlugins.get(implName);

                    if (plugin == null) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_ERROR_LISTENER", implName));
                        throw new Exception("Cannot initialize");
                    }
                    String className = plugin.getClassPath();

                    try {
                        IRequestListener listener = null;

                        listener = (IRequestListener)
                                Class.forName(className).newInstance();

                        //listener.init(id, implName, iConfig);
                        listener.init(this, iConfig);
                        // registerRequestListener(id, (IRequestListener) listener);
                        //log(ILogger.LL_INFO,
                        //   "Listener instance " + id + " added");

                    } catch (Exception e) {
                        if (Debug.ON) {
                            e.printStackTrace();
                        }
                        Debug.trace("failed to add listener instance");
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_INIT_LISTENER", id, e.toString()));
                        throw e;
                    }
                }

            }

        } catch (Exception e) {
            log(ILogger.LL_INFO, CMS.getLogMessage("CMSCORE_CA_CA_FAILED_LISTENER", e.toString()));
        }

    }

    /**
     * init notification related listeners
     */
    private void initNotificationListeners() {
        IConfigStore nc = null;

        try {
            nc = mConfig.getSubStore(PROP_NOTIFY_SUBSTORE);
            if (nc != null && nc.size() > 0) {
                // Initialize Certificate Issued notification listener

                String certificateIssuedListenerClassName =
                        nc.getString("certificateIssuedListenerClassName",
                                "com.netscape.cms.listeners.CertificateIssuedListener");

                try {
                    mCertIssuedListener =
                            (IRequestListener) Class.forName(certificateIssuedListenerClassName).newInstance();
                    mCertIssuedListener.init(this, nc);
                } catch (Exception e1) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_CA_REGISTER_LISTENER", certificateIssuedListenerClassName));
                }

                // Initialize Revoke Request notification listener

                String certificateRevokedListenerClassName =
                        nc.getString("certificateIssuedListenerClassName",
                                "com.netscape.cms.listeners.CertificateRevokedListener");

                try {
                    mCertRevokedListener =
                            (IRequestListener) Class.forName(certificateRevokedListenerClassName).newInstance();
                    mCertRevokedListener.init(this, nc);
                } catch (Exception e1) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_CA_REGISTER_LISTENER", certificateRevokedListenerClassName));
                }

                // Initialize Request In Queue notification listener
                String requestInQListenerClassName =
                        nc.getString("certificateIssuedListenerClassName",
                                "com.netscape.cms.listeners.RequestInQListener");

                try {
                    mReqInQListener = (IRequestListener) Class.forName(requestInQListenerClassName).newInstance();
                    mReqInQListener.init(this, nc);
                } catch (Exception e1) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_CA_REGISTER_REQ_LISTENER", requestInQListenerClassName));
                }

            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_NOTIFY_NONE"));
            }
        } catch (Exception e) {
            e.printStackTrace();
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_NOTIFY_FAILED"));
            //			throw e;
        }
    }

    /**
     * initialize request queue components
     */
    private void initRequestQueue()
            throws EBaseException {
        if (!isHostAuthority()) {
            mPolicy = hostCA.mPolicy;
            mService = hostCA.mService;
            mNotify = hostCA.mNotify;
            mPNotify = hostCA.mPNotify;
            mRequestQueue = hostCA.mRequestQueue;
            return;
        }

        mPolicy = new CAPolicy();
        mPolicy.init(this, mConfig.getSubStore(PROP_POLICY));
        CMS.debug("CA policy inited");
        mService = new CAService(this);
        CMS.debug("CA service inited");

        mNotify = new ARequestNotifier(this);
        CMS.debug("CA notifier inited");
        mPNotify = new ARequestNotifier();
        CMS.debug("CA pending notifier inited");

        // instantiate CA request queue.
        try {
            int reqdb_inc = mConfig.getInteger("reqdbInc", 5);

            mRequestQueue =
                    RequestSubsystem.getInstance().getRequestQueue(
                            getId(), reqdb_inc, mPolicy, mService, mNotify, mPNotify);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_QUEUE_FAILED", e.toString()));
            throw e;
        }

        // init request scheduler if configured
        String schedulerClass =
                mConfig.getString("requestSchedulerClass", null);

        if (schedulerClass != null) {
            try {
                IRequestScheduler scheduler = (IRequestScheduler)
                        Class.forName(schedulerClass).newInstance();

                mRequestQueue.setRequestScheduler(scheduler);
            } catch (Exception e) {
                // do nothing here
            }
        }
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

    /**
     * initialize CRL
     */
    @SuppressWarnings("unchecked")
    private void initCRL()
            throws EBaseException {
        if (!isHostAuthority()) {
            mCRLIssuePoints = hostCA.mCRLIssuePoints;
            mMasterCRLIssuePoint = hostCA.mMasterCRLIssuePoint;
            return;
        }
        IConfigStore crlConfig = mConfig.getSubStore(PROP_CRL_SUBSTORE);

        if ((crlConfig == null) || (crlConfig.size() <= 0)) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_NO_MASTER_CRL"));
            //throw new ECAException(CAResources.NO_CONFIG_FOR_MASTER_CRL);
            return;
        }
        Enumeration<String> issuePointIdEnum = crlConfig.getSubStoreNames();

        if (issuePointIdEnum == null || !issuePointIdEnum.hasMoreElements()) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_NO_MASTER_CRL_SUBSTORE"));
            //throw new ECAException(CAResources.NO_CONFIG_FOR_MASTER_CRL);
            return;
        }

        // a Master/full crl must exist.
        CRLIssuingPoint masterCRLIssuePoint = null;

        while (issuePointIdEnum.hasMoreElements()) {
            String issuePointId = issuePointIdEnum.nextElement();

            CMS.debug("initializing crl issue point " + issuePointId);
            IConfigStore issuePointConfig = null;
            String issuePointClassName = null;
            Class<CRLIssuingPoint> issuePointClass = null;
            CRLIssuingPoint issuePoint = null;

            try {
                issuePointConfig = crlConfig.getSubStore(issuePointId);
                issuePointClassName = issuePointConfig.getString(PROP_CLASS);
                issuePointClass = (Class<CRLIssuingPoint>) Class.forName(issuePointClassName);
                issuePoint = issuePointClass.newInstance();
                issuePoint.init(this, issuePointId, issuePointConfig);
                mCRLIssuePoints.put(issuePointId, issuePoint);

                if (masterCRLIssuePoint == null &&
                        issuePointId.equals(PROP_MASTER_CRL))
                    masterCRLIssuePoint = issuePoint;

            } catch (ClassNotFoundException e) {
                throw new ECAException(
                        CMS.getUserMessage("CMS_CA_CRL_ISSUING_POINT_INIT_FAILED",
                                issuePointId, e.toString()));
            } catch (InstantiationException e) {
                throw new ECAException(
                        CMS.getUserMessage("CMS_CA_CRL_ISSUING_POINT_INIT_FAILED",
                                issuePointId, e.toString()));
            } catch (IllegalAccessException e) {
                throw new ECAException(
                        CMS.getUserMessage("CMS_CA_CRL_ISSUING_POINT_INIT_FAILED",
                                issuePointId, e.toString()));
            }
        }

        mMasterCRLIssuePoint = masterCRLIssuePoint;

        /*
         if (mMasterCRLIssuePoint == null) {
         log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_NO_FULL_CRL", PROP_MASTER_CRL));
         throw new ECAException(CAResources.NO_CONFIG_FOR_MASTER_CRL);
         }
         */
        log(ILogger.LL_INFO, "CRL Issuing Points inited");
    }

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

        if (!mEnableOCSP) {
            CMS.debug("Local ocsp service is disable.");
            return null;
        }

        TBSRequest tbsReq = request.getTBSRequest();

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
         * 1. Find the issuer of the cert identified by the first
         *    CertID in the request.
         *
         * 2. If this CA is *not* the issuer, look up the issuer
         *    by its DN in the caMap.  If not found, fail.  If
         *    found, dispatch to its 'validate' method.  Otherwise
         *    continue.
         *
         * 3. If this CA is NOT the issuing CA, we locate the
         *    issuing CA and dispatch to its 'validate' method.
         *    Otherwise, we move forward to generate and sign the
         *    aggregate OCSP response.
         */
        ICertificateAuthority ocspCA = this;
        if (tbsReq.getRequestCount() > 0) {
            com.netscape.cmsutil.ocsp.Request req = tbsReq.getRequestAt(0);
            BigInteger serialNo = req.getCertID().getSerialNumber();
            X509CertImpl cert = mCertRepot.getX509Certificate(serialNo);
            X500Name certIssuerDN = (X500Name) cert.getIssuerDN();
            ocspCA = getCA(certIssuerDN);
        }
        if (ocspCA == null)
            throw new CANotFoundException("Could not locate issuing CA");
        if (ocspCA != this)
            return ((IOCSPService) ocspCA).validate(request);

        mNumOCSPRequest++;
        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        long startTime = CMS.getCurrentDate().getTime();
        try {
            //log(ILogger.LL_INFO, "start OCSP request");

            // (3) look into database to check the
            //     certificate's status
            Vector<SingleResponse> singleResponses = new Vector<SingleResponse>();
            if (statsSub != null) {
                statsSub.startTiming("lookup");
            }

            long lookupStartTime = CMS.getCurrentDate().getTime();
            for (int i = 0; i < tbsReq.getRequestCount(); i++) {
                com.netscape.cmsutil.ocsp.Request req =
                        tbsReq.getRequestAt(i);
                CertID cid = req.getCertID();
                SingleResponse sr = processRequest(cid);

                singleResponses.addElement(sr);
            }
            long lookupEndTime = CMS.getCurrentDate().getTime();
            if (statsSub != null) {
                statsSub.endTiming("lookup");
            }
            mLookupTime += lookupEndTime - lookupStartTime;

            if (statsSub != null) {
                statsSub.startTiming("build_response");
            }
            SingleResponse res[] = new SingleResponse[singleResponses.size()];

            singleResponses.copyInto(res);

            ResponderID rid = null;
            if (mByName) {
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
                    new GeneralizedTime(CMS.getCurrentDate()), res, nonce);
            if (statsSub != null) {
                statsSub.endTiming("build_response");
            }

            if (statsSub != null) {
                statsSub.startTiming("signing");
            }
            long signStartTime = CMS.getCurrentDate().getTime();
            BasicOCSPResponse basicRes = sign(rd);
            long signEndTime = CMS.getCurrentDate().getTime();
            mSignTime += signEndTime - signStartTime;
            if (statsSub != null) {
                statsSub.endTiming("signing");
            }

            OCSPResponse response = new OCSPResponse(
                    OCSPResponseStatus.SUCCESSFUL,
                    new ResponseBytes(ResponseBytes.OCSP_BASIC,
                            new OCTET_STRING(ASN1Util.encode(basicRes))));

            //log(ILogger.LL_INFO, "done OCSP request");
            long endTime = CMS.getCurrentDate().getTime();
            mTotalTime += endTime - startTime;
            return response;
        } catch (Exception e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_OCSP_REQUEST", e.toString()));
            throw new EBaseException(e.toString(), e);
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
            CMS.debug("adding signature");
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
            e.printStackTrace();
            // error e
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_CA_OCSP_SIGN", e.toString()));
            throw new EBaseException(e.toString());
        }
    }

    private SingleResponse processRequest(CertID cid) {
        INTEGER serialNo = cid.getSerialNumber();

        CMS.debug("process request " + serialNo);
        CertStatus certStatus = null;
        GeneralizedTime thisUpdate = new GeneralizedTime(CMS.getCurrentDate());
        GeneralizedTime nextUpdate = null;

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

        try {
            ICertRecord rec = mCertRepot.readCertificateRecord(serialNo);
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

        return new SingleResponse(cid, certStatus, thisUpdate, nextUpdate);
    }

    /**
     * Enumerate all authorities (including host authority)
     */
    public List<ICertificateAuthority> getCAs() {
        List<ICertificateAuthority> cas = new ArrayList<>();
        synchronized (caMap) {
            for (ICertificateAuthority ca : caMap.values()) {
                cas.add(ca);
            }
        }
        return cas;
    }

    /**
     * Get authority by ID.
     *
     * @param aid The ID of the CA to retrieve, or null
     *             to retreive the host authority.
     *
     * @return the authority, or null if not found
     */
    public ICertificateAuthority getCA(AuthorityID aid) {
        return aid == null ? hostCA : caMap.get(aid);
    }

    public ICertificateAuthority getCA(X500Name dn) {
        for (ICertificateAuthority ca : getCAs()) {
            if (ca.getX500Name().equals(dn))
                return ca;
        }
        return null;
    }

    public AuthorityID getAuthorityID() {
        return authorityID;
    }

    public AuthorityID getAuthorityParentID() {
        return authorityParentID;
    }

    public String getAuthorityDescription() {
        return authorityDescription;
    }

    /**
     * Create a new lightweight authority.
     *
     * @param subjectDN Subject DN for new CA
     * @param parentAID ID of parent CA
     * @param description Optional string description of CA
     */
    public ICertificateAuthority createCA(
            IAuthToken authToken,
            String subjectDN, AuthorityID parentAID,
            String description)
            throws EBaseException {
        ICertificateAuthority parentCA = getCA(parentAID);
        if (parentCA == null)
            throw new CANotFoundException(
                "Parent CA \"" + parentAID + "\" does not exist");

        ICertificateAuthority ca = parentCA.createSubCA(
                authToken, subjectDN, description);
        caMap.put(ca.getAuthorityID(), ca);
        return ca;
    }

    private void ensureAuthorityDNAvailable(X500Name dn)
            throws IssuerUnavailableException {
        for (ICertificateAuthority ca : getCAs()) {
            if (ca.getX500Name().equals(dn))
                throw new IssuerUnavailableException(
                    "DN '" + dn + "' is used by an existing authority");
        }
    }

    /**
     * Create a new lightweight authority signed by this authority.
     *
     * This method DOES NOT add the new CA to caMap; it is the
     * caller's responsibility.
     */
    public ICertificateAuthority createSubCA(
            IAuthToken authToken,
            String subjectDN, String description)
            throws EBaseException {

        ensureReady();

        // check requested DN
        X500Name subjectX500Name = null;
        try {
            subjectX500Name = new X500Name(subjectDN);
        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Invalid Subject DN: " + subjectDN);
        }
        ensureAuthorityDNAvailable(subjectX500Name);

        // generate authority ID and nickname
        AuthorityID aid = new AuthorityID();
        String aidString = aid.toString();
        String nickname = hostCA.getNickname() + " " + aidString;

        // build database entry
        String dn = "cn=" + aidString + "," + authorityBaseDN();
        CMS.debug("createSubCA: DN = " + dn);
        String parentDNString = null;
        try {
            parentDNString = mName.toLdapDNString();
        } catch (IOException e) {
            throw new EBaseException("Failed to convert issuer DN to string: " + e);
        }

        String thisClone = CMS.getEEHost() + ":" + CMS.getEESSLPort();

        LDAPAttribute[] attrs = {
            new LDAPAttribute("objectclass", "authority"),
            new LDAPAttribute("cn", aidString),
            new LDAPAttribute("authorityID", aidString),
            new LDAPAttribute("authorityKeyNickname", nickname),
            new LDAPAttribute("authorityKeyHost", thisClone),
            new LDAPAttribute("authorityEnabled", "TRUE"),
            new LDAPAttribute("authorityDN", subjectDN),
            new LDAPAttribute("authorityParentDN", parentDNString)
        };
        LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);
        if (this.authorityID != null)
            attrSet.add(new LDAPAttribute(
                "authorityParentID", this.authorityID.toString()));
        if (description != null)
            attrSet.add(new LDAPAttribute("description", description));
        LDAPEntry ldapEntry = new LDAPEntry(dn, attrSet);

        addAuthorityEntry(aid, ldapEntry);

        try {
            // Generate signing key
            CryptoManager cryptoManager = CryptoManager.getInstance();
            // TODO read PROP_TOKEN_NAME config
            CryptoToken token = cryptoManager.getInternalKeyStorageToken();
            // TODO algorithm parameter
            KeyPairGenerator gen = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);
            gen.initialize(2048);
            KeyPair keypair = gen.genKeyPair();
            PublicKey pub = keypair.getPublic();
            X509Key x509key = CryptoUtil.convertPublicKeyToX509Key(pub);

            // Create pkcs10 request
            CMS.debug("createSubCA: creating pkcs10 request");
            PKCS10 pkcs10 = new PKCS10(x509key);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(keypair.getPrivate());
            pkcs10.encodeAndSign(
                new X500Signer(signature, subjectX500Name));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            pkcs10.print(new PrintStream(out));
            String pkcs10String = out.toString();

            // Sign certificate
            Locale locale = Locale.getDefault();
            String profileId = "caCACert";
            IProfileSubsystem ps = (IProfileSubsystem)
                CMS.getSubsystem(IProfileSubsystem.ID);
            IProfile profile = ps.getProfile(profileId);
            ArgBlock argBlock = new ArgBlock();
            argBlock.set("cert_request_type", "pkcs10");
            argBlock.set("cert_request", pkcs10String);
            CertEnrollmentRequest certRequest =
                CertEnrollmentRequestFactory.create(argBlock, profile, locale);
            EnrollmentProcessor processor =
                new EnrollmentProcessor("createSubCA", locale);
            Map<String, Object> resultMap = processor.processEnrollment(
                certRequest, null, authorityID, null, authToken);
            IRequest requests[] = (IRequest[]) resultMap.get(CAProcessor.ARG_REQUESTS);
            IRequest request = requests[0];
            Integer result = request.getExtDataInInteger(IRequest.RESULT);
            if (result != null && !result.equals(IRequest.RES_SUCCESS))
                throw new EBaseException("createSubCA: certificate request submission resulted in error: " + result);
            RequestStatus requestStatus = request.getRequestStatus();
            if (requestStatus != RequestStatus.COMPLETE)
                throw new EBaseException("createSubCA: certificate request did not complete; status: " + requestStatus);

            // Add certificate to nssdb
            X509CertImpl cert = request.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);
            cryptoManager.importCertPackage(cert.getEncoded(), nickname);
        } catch (Exception e) {
            // something went wrong; delete just-added entry
            CMS.debug("Error creating lightweight CA certificate");
            CMS.debug(e);
            try {
                deleteAuthorityEntry(aid);
            } catch (ELdapException e2) {
                // we are about to throw ECAException, so just
                // log this error.
                CMS.debug("Error deleting new authority entry after failure during certificate generation: " + e2);
            }
            throw new ECAException("Error creating lightweight CA certificate: " + e);
        }

        return new CertificateAuthority(
            hostCA, subjectX500Name,
            aid, this.authorityID,
            nickname, Collections.singleton(thisClone),
            description, true);
    }

    /**
     * Add an LDAP entry for the host authority.
     *
     * This method also sets the authorityID and authorityDescription
     * fields.
     *
     * It is the caller's responsibility to add the returned
     * AuthorityID to the caMap.
     */
    private AuthorityID addHostAuthorityEntry() throws EBaseException {
        if (!isHostAuthority())
            throw new EBaseException("Can only invoke from host CA");

        // generate authority ID
        AuthorityID aid = new AuthorityID();
        String aidString = aid.toString();

        // build database entry
        String dn = "cn=" + aidString + "," + authorityBaseDN();
        String dnString = null;
        try {
            dnString = mName.toLdapDNString();
        } catch (IOException e) {
            throw new EBaseException("Failed to convert issuer DN to string: " + e);
        }

        String desc = "Host authority";
        LDAPAttribute[] attrs = {
            new LDAPAttribute("objectclass", "authority"),
            new LDAPAttribute("cn", aidString),
            new LDAPAttribute("authorityID", aidString),
            new LDAPAttribute("authorityKeyNickname", getNickname()),
            new LDAPAttribute("authorityEnabled", "TRUE"),
            new LDAPAttribute("authorityDN", dnString),
            new LDAPAttribute("description", desc)
        };
        LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);
        LDAPEntry ldapEntry = new LDAPEntry(dn, attrSet);

        addAuthorityEntry(aid, ldapEntry);

        this.authorityID = aid;
        this.authorityDescription = desc;
        return aid;
    }

    private void addAuthorityEntry(AuthorityID aid, LDAPEntry entry)
            throws ELdapException {
        LDAPControl[] responseControls;
        LDAPConnection conn = dbFactory.getConn();
        synchronized (hostCA) {
            try {
                conn.add(entry, getCommitConstraints());
                responseControls = conn.getResponseControls();
            } catch (LDAPException e) {
                throw new ELdapException("addAuthorityEntry: failed to add entry", e);
            } finally {
                dbFactory.returnConn(conn);
            }
            postCommit(aid, responseControls);
        }
    }

    /**
     * Modify _this_ authority with the given modification set.
     */
    private void modifyAuthorityEntry(LDAPModificationSet mods)
            throws ELdapException {
        String dn = "cn=" + authorityID.toString() + "," + authorityBaseDN();
        LDAPControl[] responseControls;
        LDAPConnection conn = dbFactory.getConn();
        synchronized (hostCA) {
            try {
                conn.modify(dn, mods, getCommitConstraints());
                responseControls = conn.getResponseControls();
            } catch (LDAPException e) {
                throw new ELdapException("modifyAuthorityEntry: failed to modify entry", e);
            } finally {
                dbFactory.returnConn(conn);
            }
            postCommit(authorityID, responseControls);
        }
    }

    private LDAPConstraints getCommitConstraints() {
        String[] attrs = {"entryUSN", "nsUniqueId"};
        LDAPConstraints cons = new LDAPConstraints();
        LDAPPostReadControl control = new LDAPPostReadControl(true, attrs);
        cons.setServerControls(control);
        return cons;
    }

    /**
     * Post-commit processing of authority to track its entryUSN and nsUniqueId
     */
    private void postCommit(AuthorityID aid, LDAPControl[] responseControls) {
        LDAPPostReadControl control = (LDAPPostReadControl)
            LDAPUtil.getControl(LDAPPostReadControl.class, responseControls);
        LDAPEntry entry = control.getEntry();

        LDAPAttribute attr = entry.getAttribute("entryUSN");
        if (attr != null) {
            Integer entryUSN = new Integer(attr.getStringValueArray()[0]);
            entryUSNs.put(aid, entryUSN);
            CMS.debug("postCommit: new entryUSN = " + entryUSN);
        }

        attr = entry.getAttribute("nsUniqueId");
        if (attr != null) {
            String nsUniqueId = attr.getStringValueArray()[0];
            nsUniqueIds.put(aid, nsUniqueId);
            CMS.debug("postCommit: nsUniqueId = " + nsUniqueId);
        }
    }

    /**
     * Update lightweight authority attributes.
     *
     * Pass null values to exclude an attribute from the update.
     *
     * If a passed value matches the current value, it is excluded
     * from the update.
     *
     * To remove optional string values, pass the empty string.
     */
    public void modifyAuthority(Boolean enabled, String desc)
            throws EBaseException {
        if (isHostAuthority() && enabled != null && !enabled)
            throw new CATypeException("Cannot disable the host CA");

        LDAPModificationSet mods = new LDAPModificationSet();

        boolean nextEnabled = authorityEnabled;
        if (enabled != null && enabled.booleanValue() != authorityEnabled) {
            mods.add(
                LDAPModification.REPLACE,
                new LDAPAttribute("authorityEnabled", enabled ? "TRUE" : "FALSE"));
            nextEnabled = enabled;
        }

        String nextDesc = authorityDescription;
        if (desc != null) {
            if (!desc.isEmpty() && authorityDescription != null
                    && !desc.equals(authorityDescription)) {
                mods.add(
                    LDAPModification.REPLACE,
                    new LDAPAttribute("description", desc));
                nextDesc = desc;
            } else if (desc.isEmpty() && authorityDescription != null) {
                mods.add(
                    LDAPModification.DELETE,
                    new LDAPAttribute("description", authorityDescription));
                nextDesc = null;
            } else if (!desc.isEmpty() && authorityDescription == null) {
                mods.add(
                    LDAPModification.ADD,
                    new LDAPAttribute("description", desc));
                nextDesc = desc;
            }
        }

        if (mods.size() > 0) {
            modifyAuthorityEntry(mods);

            // update was successful; update CA's state
            authorityEnabled = nextEnabled;
            authorityDescription = nextDesc;
        }
    }

    /**
     * Add this instance to the authorityKeyHosts
     */
    private void addInstanceToAuthorityKeyHosts() throws ELdapException {
        String thisClone = CMS.getEEHost() + ":" + CMS.getEESSLPort();
        if (authorityKeyHosts.contains(thisClone)) {
            // already there; nothing to do
            return;
        }
        LDAPModificationSet mods = new LDAPModificationSet();
        mods.add(
            LDAPModification.ADD,
            new LDAPAttribute("authorityKeyHost", thisClone));
        modifyAuthorityEntry(mods);
        authorityKeyHosts.add(thisClone);
    }

    public synchronized void deleteAuthority() throws EBaseException {
        if (isHostAuthority())
            throw new CATypeException("Cannot delete the host CA");

        if (authorityEnabled)
            throw new CAEnabledException("Must disable CA before deletion");

        boolean hasSubCAs = false;
        for (ICertificateAuthority ca : getCAs()) {
            AuthorityID parentAID = ca.getAuthorityParentID();
            if (parentAID != null && parentAID.equals(this.authorityID)) {
                hasSubCAs = true;
                break;
            }
        }
        if (hasSubCAs)
            throw new CANotLeafException("CA with sub-CAs cannot be deleted (delete sub-CAs first)");

        shutdown();

        deleteAuthorityEntry(authorityID);
        deleteAuthorityNSSDB();
    }

    /** Delete keys and certs of this authority from NSSDB.
     */
    private void deleteAuthorityNSSDB() throws ECAException {
        CryptoManager cryptoManager;
        try {
            cryptoManager = CryptoManager.getInstance();
        } catch (CryptoManager.NotInitializedException e) {
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
            CMS.debug("deleteAuthority: cert is not on token: " + e);
            // if the cert isn't there, never mind
        } catch (TokenException e) {
            CMS.debug("deleteAuthority: TokenExcepetion while deleting cert: " + e);
            throw new ECAException("TokenException while deleting cert: " + e);
        }
    }

    private void deleteAuthorityEntry(AuthorityID aid) throws ELdapException {
        String dn = "cn=" + aid.toString() + "," + authorityBaseDN();
        LDAPConnection conn = dbFactory.getConn();
        synchronized (hostCA) {
            try {
                conn.delete(dn);
            } catch (LDAPException e) {
                throw new ELdapException("Error deleting authority entry: " + dn, e);
            } finally {
                dbFactory.returnConn(conn);
            }

            String nsUniqueId = nsUniqueIds.get(aid);
            if (nsUniqueId != null)
                deletedNsUniqueIds.add(nsUniqueId);
            forgetAuthority(aid);
        }
    }

    private void checkInitialLoadDone() {
        if (initialNumAuthorities != null
                && numAuthoritiesLoaded >= initialNumAuthorities)
            initialLoadDone.countDown();
    }

    public void run() {
        int op = LDAPPersistSearchControl.ADD
            | LDAPPersistSearchControl.MODIFY
            | LDAPPersistSearchControl.DELETE
            | LDAPPersistSearchControl.MODDN;
        LDAPPersistSearchControl persistCtrl =
            new LDAPPersistSearchControl(op, false, true, true);

        CMS.debug("authorityMonitor: starting.");

        while (!stopped) {
            LDAPConnection conn = null;
            try {
                conn = dbFactory.getConn();
                LDAPSearchConstraints cons = conn.getSearchConstraints();
                cons.setServerControls(persistCtrl);
                cons.setBatchSize(1);
                cons.setServerTimeLimit(0 /* seconds */);
                String[] attrs = {"*", "entryUSN", "nsUniqueId", "numSubordinates"};
                LDAPSearchResults results = conn.search(
                    authorityBaseDN(), LDAPConnection.SCOPE_SUB,
                    "(objectclass=*)", attrs, false, cons);
                while (!stopped && results.hasMoreElements()) {
                    LDAPEntry entry = results.next();

                    /* This behaviour requires detailed explanation.
                     *
                     * We want to block startup until all the
                     * lightweight CAs existing at startup time are
                     * loaded.  To do this, we need to know how many
                     * authority entries there are.  And we must do
                     * this atomically - we cannot issue two LDAP
                     * searches in case things change.
                     *
                     * Therefore, we do a subtree search from the
                     * authority container.  When we find the
                     * container (objectClass=organizationalUnit),
                     * we set initialNumAuthorities to the value of
                     * its numSubordinates attribute.
                     *
                     * We increment numAuthoritiesLoaded for each
                     * authority entry.  When numAuthoritiesLoaded
                     * equals initialNumAuthorities, we unlock the
                     * initialLoadDone latch.
                     */
                    String[] objectClasses =
                        entry.getAttribute("objectClass").getStringValueArray();
                    if (Arrays.asList(objectClasses).contains("organizationalUnit")) {
                        initialNumAuthorities = new Integer(
                            entry.getAttribute("numSubordinates")
                                .getStringValueArray()[0]);
                        checkInitialLoadDone();
                        continue;
                    }

                    LDAPEntryChangeControl changeControl = (LDAPEntryChangeControl)
                        LDAPUtil.getControl(
                            LDAPEntryChangeControl.class, results.getResponseControls());
                    CMS.debug("authorityMonitor: Processed change controls.");
                    if (changeControl != null) {
                        int changeType = changeControl.getChangeType();
                        switch (changeType) {
                        case LDAPPersistSearchControl.ADD:
                            CMS.debug("authorityMonitor: ADD");
                            readAuthority(entry);
                            break;
                        case LDAPPersistSearchControl.DELETE:
                            CMS.debug("authorityMonitor: DELETE");
                            handleDELETE(entry);
                            break;
                        case LDAPPersistSearchControl.MODIFY:
                            CMS.debug("authorityMonitor: MODIFY");
                            // TODO how do we handle authorityID change?
                            readAuthority(entry);
                            break;
                        case LDAPPersistSearchControl.MODDN:
                            CMS.debug("authorityMonitor: MODDN");
                            handleMODDN(new DN(changeControl.getPreviousDN()), entry);
                            break;
                        default:
                            CMS.debug("authorityMonitor: unknown change type: " + changeType);
                            break;
                        }
                    } else {
                        CMS.debug("authorityMonitor: immediate result");
                        readAuthority(entry);
                        numAuthoritiesLoaded += 1;
                        checkInitialLoadDone();
                    }
                }
            } catch (ELdapException e) {
                CMS.debug("authorityMonitor: failed to get LDAPConnection. Retrying in 1 second.");
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            } catch (LDAPException e) {
                CMS.debug("authorityMonitor: Failed to execute LDAP search for lightweight CAs: " + e);
            } finally {
                try {
                    dbFactory.returnConn(conn);
                } catch (Exception e) {
                    CMS.debug("authorityMonitor: Error releasing the LDAPConnection" + e.toString());
                }
            }
        }
        CMS.debug("authorityMonitor: stopping.");
    }

    private synchronized void readAuthority(LDAPEntry entry) {
        String nsUniqueId =
            entry.getAttribute("nsUniqueId").getStringValueArray()[0];
        if (deletedNsUniqueIds.contains(nsUniqueId)) {
            CMS.debug("readAuthority: ignoring entry with nsUniqueId '"
                    + nsUniqueId + "' due to deletion");
            return;
        }

        LDAPAttribute aidAttr = entry.getAttribute("authorityID");
        LDAPAttribute nickAttr = entry.getAttribute("authorityKeyNickname");
        LDAPAttribute keyHostsAttr = entry.getAttribute("authorityKeyHost");
        LDAPAttribute dnAttr = entry.getAttribute("authorityDN");
        LDAPAttribute parentAIDAttr = entry.getAttribute("authorityParentID");
        LDAPAttribute parentDNAttr = entry.getAttribute("authorityParentDN");

        if (aidAttr == null || nickAttr == null || dnAttr == null) {
            CMS.debug("Malformed authority object; required attribute(s) missing: " + entry.getDN());
            return;
        }

        AuthorityID aid = new AuthorityID((String)
            aidAttr.getStringValues().nextElement());

        LDAPAttribute entryUSN = entry.getAttribute("entryUSN");
        if (entryUSN == null) {
            log(ILogger.LL_FAILURE, "Authority entry has no entryUSN.  " +
                "This is likely because the USN plugin is not enabled in the database");
            return;
        }

        Integer newEntryUSN = new Integer(entryUSN.getStringValueArray()[0]);
        CMS.debug("readAuthority: new entryUSN = " + newEntryUSN);
        Integer knownEntryUSN = entryUSNs.get(aid);
        if (knownEntryUSN != null) {
            CMS.debug("readAuthority: known entryUSN = " + knownEntryUSN);
            if (newEntryUSN <= knownEntryUSN) {
                CMS.debug("readAuthority: data is current");
                return;
            }
        }

        X500Name dn = null;
        try {
            dn = new X500Name((String) dnAttr.getStringValues().nextElement());
        } catch (IOException e) {
            CMS.debug("Malformed authority object; invalid authorityDN: " + entry.getDN());
        }

        String desc = null;
        LDAPAttribute descAttr = entry.getAttribute("description");
        if (descAttr != null)
            desc = (String) descAttr.getStringValues().nextElement();

        if (dn.equals(mName)) {
            foundHostAuthority = true;
            this.authorityID = aid;
            this.authorityDescription = desc;
            caMap.put(aid, this);
            return;
        }

        @SuppressWarnings("unused")
        X500Name parentDN = null;
        if (parentDNAttr != null) {
            try {
                parentDN = new X500Name((String) parentDNAttr.getStringValues().nextElement());
            } catch (IOException e) {
                CMS.debug("Malformed authority object; invalid authorityParentDN: " + entry.getDN());
                return;
            }
        }

        String keyNick = (String) nickAttr.getStringValues().nextElement();

        Collection<String> keyHosts;
        if (keyHostsAttr == null) {
            keyHosts = Collections.emptyList();
        } else {
            @SuppressWarnings("unchecked")
            Enumeration<String> keyHostsEnum = keyHostsAttr.getStringValues();
            keyHosts = Collections.list(keyHostsEnum);
        }

        AuthorityID parentAID = null;
        if (parentAIDAttr != null)
            parentAID = new AuthorityID((String)
                parentAIDAttr.getStringValues().nextElement());

        boolean enabled = true;
        LDAPAttribute enabledAttr = entry.getAttribute("authorityEnabled");
        if (enabledAttr != null) {
            String enabledString = (String)
                enabledAttr.getStringValues().nextElement();
            enabled = enabledString.equalsIgnoreCase("TRUE");
        }

        try {
            CertificateAuthority ca = new CertificateAuthority(
                hostCA, dn, aid, parentAID, keyNick, keyHosts, desc, enabled);
            caMap.put(aid, ca);
            entryUSNs.put(aid, newEntryUSN);
            nsUniqueIds.put(aid, nsUniqueId);
        } catch (EBaseException e) {
            CMS.debug("Error initialising lightweight CA: " + e);
        }
    }

    private synchronized void handleDELETE(LDAPEntry entry) {
        LDAPAttribute attr = entry.getAttribute("nsUniqueId");
        String nsUniqueId = null;
        if (attr != null)
            nsUniqueId = attr.getStringValueArray()[0];

        if (deletedNsUniqueIds.remove(nsUniqueId)) {
            CMS.debug("handleDELETE: delete was already effected");
            return;
        }

        AuthorityID aid = null;
        attr = entry.getAttribute("authorityID");
        if (attr != null) {
            aid = new AuthorityID(attr.getStringValueArray()[0]);
            CertificateAuthority ca = (CertificateAuthority) getCA(aid);
            if (ca == null)
                return;  // shouldn't happen

            try {
                ca.deleteAuthorityNSSDB();
            } catch (ECAException e) {
                // log and carry on
                CMS.debug(
                    "Caught exception attempting to delete NSSDB material "
                    + "for authority '" + aid + "': " + e);
            }
            forgetAuthority(aid);
        }
    }

    private void forgetAuthority(AuthorityID aid) {
        caMap.remove(aid);
        entryUSNs.remove(aid);
        nsUniqueIds.remove(aid);
    }

    private synchronized void handleMODDN(DN oldDN, LDAPEntry entry) {
        DN authorityBase = new DN(authorityBaseDN());

        boolean wasMonitored = oldDN.isDescendantOf(authorityBase);
        boolean isMonitored = (new DN(entry.getDN())).isDescendantOf(authorityBase);
        if (wasMonitored && !isMonitored) {
            LDAPAttribute attr = entry.getAttribute("authorityID");
            if (attr != null) {
                AuthorityID aid = new AuthorityID(attr.getStringValueArray()[0]);
                forgetAuthority(aid);
            }
        } else if (!wasMonitored && isMonitored) {
            readAuthority(entry);
        }
    }

    private class KeyRetrieverRunner implements Runnable {
        private AuthorityID aid;
        private String nickname;
        private Collection<String> hosts;

        public KeyRetrieverRunner(
                AuthorityID aid, String nickname, Collection<String> hosts) {
            this.aid = aid;
            this.nickname = nickname;
            this.hosts = hosts;
        }

        public void run() {
            try {
                long d = 10000;  // initial delay of 10 seconds
                while (!_run()) {
                    CMS.debug("Retrying in " + d / 1000 + " seconds");
                    try {
                        Thread.sleep(d);
                    } catch (InterruptedException e) {
                        break;
                    }
                    d += d / 2;  // back off
                }
            } finally {
                // remove self from tracker
                keyRetrieverThreads.remove(aid);
            }
        }

        /**
         * Main routine of key retrieval and key import.
         *
         * @return false if retrieval should be retried, or true if
         *         the process is "done".  Note that a result of true
         *         does not necessarily imply that the process fully
         *         completed.  See comments at sites of 'return true;'
         *         below.
         */
        private boolean _run() {
            String KR_CLASS_KEY = "features.authority.keyRetrieverClass";
            String KR_CONFIG_KEY = "features.authority.keyRetrieverConfig";

            String className = null;
            try {
                className = CMS.getConfigStore().getString(KR_CLASS_KEY);
            } catch (EBaseException e) {
                CMS.debug("Unable to read key retriever class from CS.cfg: " + e);
                return false;
            }

            IConfigStore krConfig = CMS.getConfigStore().getSubStore(KR_CONFIG_KEY);

            KeyRetriever kr = null;
            try {
                Class<? extends KeyRetriever> cls =
                    Class.forName(className).asSubclass(KeyRetriever.class);

                // If there is an accessible constructor that takes
                // an IConfigStore, invoke that; otherwise invoke
                // the nullary constructor.
                try {
                    kr = cls.getDeclaredConstructor(IConfigStore.class)
                        .newInstance(krConfig);
                } catch (NoSuchMethodException | SecurityException
                        | IllegalAccessException e) {
                    kr = cls.newInstance();
                }
            } catch (ClassNotFoundException e) {
                CMS.debug("Could not find class: " + className);
                CMS.debug(e);
                return false;
            } catch (ClassCastException e) {
                CMS.debug("Class is not an instance of KeyRetriever: " + className);
                CMS.debug(e);
                return false;
            } catch (InstantiationException | IllegalAccessException
                    | IllegalArgumentException | InvocationTargetException e) {
                CMS.debug("Could not instantiate class: " + className);
                CMS.debug(e);
                return false;
            }

            KeyRetriever.Result krr = null;
            try {
                krr = kr.retrieveKey(nickname, hosts);
            } catch (Throwable e) {
                CMS.debug("Caught exception during execution of KeyRetriever.retrieveKey");
                CMS.debug(e);
                return false;
            }

            if (krr == null) {
                CMS.debug("KeyRetriever did not return a result.");
                return false;
            }

            CMS.debug("Importing key and cert");
            byte[] certBytes = krr.getCertificate();
            byte[] paoData = krr.getPKIArchiveOptions();
            try {
                CryptoManager manager = CryptoManager.getInstance();
                CryptoToken token = manager.getInternalKeyStorageToken();

                X509Certificate cert = manager.importCACertPackage(certBytes);
                PublicKey pubkey = cert.getPublicKey();
                token.getCryptoStore().deleteCert(cert);

                PrivateKey unwrappingKey = hostCA.mSigningUnit.getPrivateKey();

                CryptoUtil.importPKIArchiveOptions(
                    token, unwrappingKey, pubkey, paoData);

                cert = manager.importUserCACertPackage(certBytes, nickname);
            } catch (Throwable e) {
                CMS.debug("Caught exception during cert/key import");
                CMS.debug(e);
                return false;
            }

            CertificateAuthority ca;
            boolean initSigUnitSucceeded = false;
            try {
                CMS.debug("Reinitialising SigningUnit");

                /* While we were retrieving the key and cert, the
                 * CertificateAuthority instance in the caMap might
                 * have been replaced, so look it up afresh.
                 */
                ca = (CertificateAuthority) getCA(aid);
                if (ca == null) {
                    /* We got the key, but the authority has been
                     * deleted.  Do not retry.
                     */
                    CMS.debug("Authority was deleted; returning.");
                    return true;
                }

                // re-init signing unit, but avoid triggering
                // key replication if initialisation fails again
                // for some reason
                //
                initSigUnitSucceeded = ca.initSigUnit(/* retrieveKeys */ false);
            } catch (Throwable e) {
                CMS.debug("Caught exception during SigningUnit re-init");
                CMS.debug(e);
                return false;
            }

            if (!initSigUnitSucceeded) {
                CMS.debug("Failed to re-init SigningUnit");
                return false;
            }

            CMS.debug("Adding self to authorityKeyHosts attribute");
            try {
                ca.addInstanceToAuthorityKeyHosts();
            } catch (Throwable e) {
                /* We retrieved key, imported it, and successfully
                 * re-inited the signing unit.  The only thing that
                 * failed was adding this host to the list of hosts
                 * that possess the key.  This is unlikely, and the
                 * key is available elsewhere, so no need to retry.
                 */
                CMS.debug("Failed to add self to authorityKeyHosts");
                CMS.debug(e);
                return true;
            }

            /* All good! */
            return true;
        }
    }

}
