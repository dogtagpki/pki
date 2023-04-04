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
package com.netscape.kra;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;
import java.util.Vector;

import org.dogtagpki.legacy.kra.KRAPolicy;
import org.dogtagpki.legacy.policy.IPolicyProcessor;
import org.dogtagpki.server.kra.KRAConfig;
import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.kra.KRAEngineConfig;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi;
import org.mozilla.jss.crypto.PQGParamGenException;
import org.mozilla.jss.crypto.PQGParams;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.listeners.EListenersException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.event.SecurityDataArchivalProcessedEvent;
import com.netscape.certsrv.logging.event.SecurityDataArchivalRequestEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryProcessedEvent;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestListener;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.security.Credential;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cms.request.RequestScheduler;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.cmscore.dbs.KeyStatusUpdateTask;
import com.netscape.cmscore.dbs.ReplicaIDRepository;
import com.netscape.cmscore.request.KeyRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestNotifier;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmscore.request.RequestSubsystem;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * A class represents an key recovery authority (KRA). A KRA
 * is responsible to maintain key pairs that have been
 * escrowed. It provides archive and recovery key pairs
 * functionalities.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class KeyRecoveryAuthority extends Subsystem implements IAuthority {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeyRecoveryAuthority.class);
    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    public static final String ID = "kra";

    public final static String OFFICIAL_NAME = "Data Recovery Manager";

    public final static String PROP_NAME = "name";
    public final static String PROP_HTTP = "http";
    public final static String PROP_POLICY = "policy";

    public final static String PROP_TOKEN = "token";
    public final static String PROP_SHARE = "share";
    public final static String PROP_PROTECTOR = "protector";
    public final static String PROP_LOGGING = "logging";
    public final static String PROP_QUEUE_REQUESTS = "queueRequests";
    public final static String PROP_STORAGE_KEY = "storageUnit";
    public final static String PROP_TRANSPORT_KEY = "transportUnit";
    public static final String PROP_NEW_NICKNAME = "newNickname";
    public static final String PROP_KEYDB_INC = "keydbInc";

    public final static String PROP_NOTIFY_SUBSTORE = "notification";
    public final static String PROP_REQ_IN_Q_SUBSTORE = "requestInQ";

    private static final String PARAM_CREDS = "creds";
    private static final String PARAM_LOCK = "lock";
    private static final String PARAM_PK12 = "pk12";
    private static final String PARAM_ERROR = "error";

    protected boolean mInitialized = false;
    protected KRAConfig mConfig;
    protected KRAPolicy mPolicy = null;
    protected X500Name mName = null;
    protected boolean mQueueRequests = false;
    protected String mId = null;

    protected TransportKeyUnit mTransportKeyUnit;
    protected StorageKeyUnit mStorageKeyUnit = null;
    protected Hashtable<String, Credential[]> mAutoRecovery = new Hashtable<>();
    protected boolean mAutoRecoveryOn = false;
    protected KeyRepository mKeyDB = null;
    protected ReplicaIDRepository mReplicaRepot = null;
    protected int mRecoveryIDCounter = 0;
    protected Hashtable<String, Hashtable<String, Object>> mRecoveryParams =
            new Hashtable<>();
    protected org.mozilla.jss.crypto.X509Certificate mJssCert = null;
    protected CryptoToken mKeygenToken = null;

    // holds the number of bits of entropy to collect for each keygen
    private int mEntropyBitsPerKeyPair = 0;

    // the number of milliseconds which it is acceptable to block while
    // getting entropy - anything longer will cause a warning.
    // 0 means this warning is disabled
    private int mEntropyBlockWarnMilliseconds = 0;

    // for the notification listener
    public RequestListener mReqInQListener = null;

    public KeyStatusUpdateTask keyStatusUpdateTask;

    private final static String SIGNED_AUDIT_AGENT_DELIMITER = ", ";
    /**
     * Constructs an escrow authority.
     * <P>
     */
    public KeyRecoveryAuthority() {
        super();
    }

    /**
     * Retrieves subsystem identifier.
     *
     * @return subsystem id
     */
    @Override
    public String getId() {
        return mId;
    }

    /**
     * Sets subsystem identifier.
     *
     * @param id subsystem id
     * @exception EBaseException failed to set id
     */
    @Override
    public void setId(String id) throws EBaseException {
        mId = id;
    }

    /**
     * Returns policy processor of the key recovery
     * authority.
     *
     * @return policy processor
     */
    public IPolicyProcessor getPolicyProcessor() {
        return mPolicy.getPolicyProcessor();
    }

    // initialize entropy collection parameters
    private void initEntropy(ConfigStore config) {
        mEntropyBitsPerKeyPair = 0;
        mEntropyBlockWarnMilliseconds = 50;
        // initialize entropy collection
        ConfigStore ecs = config.getSubStore("entropy", ConfigStore.class);
        if (ecs != null) {
            try {
                mEntropyBitsPerKeyPair = ecs.getInteger("bitsperkeypair", 0);
                mEntropyBlockWarnMilliseconds = ecs.getInteger("blockwarnms", 50);
            } catch (EBaseException eb) {
                // ok - we deal with missing parameters above
            }
        }
        logger.debug("KeyRecoveryAuthority Entropy bits = " + mEntropyBitsPerKeyPair);
        if (mEntropyBitsPerKeyPair == 0) {
            //logger.info(CMS.getLogMessage("CMSCORE_KRA_ENTROPY_COLLECTION_DISABLED"));
        } else {
            //logger.info(CMS.getLogMessage("CMSCORE_KRA_ENTROPY_COLLECTION_ENABLED"));
            logger.debug("KeyRecoveryAuthority about to add Entropy");
            addEntropy(false);
            logger.debug("KeyRecoveryAuthority back from add Entropy");
        }

    }

    /**
     * Adds entropy to the token used for supporting server-side keygen
     * Parameters are set in the config file
     *
     * @param logflag create log messages at info level to report entropy shortage
     */
    public void addEntropy(boolean logflag) {
        logger.debug("KeyRecoveryAuthority addEntropy()");
        if (mEntropyBitsPerKeyPair == 0) {
            logger.debug("KeyRecoveryAuthority returning - disabled()");
            return;
        }
        long start = System.currentTimeMillis();
        try {
            JssSubsystem jssSubsystem = engine.getJSSSubsystem();
            jssSubsystem.addEntropy(mEntropyBitsPerKeyPair);
        } catch (Exception e) {
            logger.warn("KeyRecoveryAuthority: " + e.getMessage(), e);
            if (logflag) {
                logger.warn(CMS.getLogMessage("CMSCORE_KRA_ENTROPY_ERROR",
                                e.getMessage()));
            }
        }
        long end = System.currentTimeMillis();
        long duration = end - start;

        if (mEntropyBlockWarnMilliseconds > 0 &&
                duration > mEntropyBlockWarnMilliseconds) {

            logger.debug("KeyRecoveryAuthority returning - warning - entropy took too long (ms=" +
                    duration + ")");
            if (logflag) {
                logger.warn(CMS.getLogMessage("CMSCORE_KRA_ENTROPY_BLOCKED_WARNING",
                                "" + (int) duration));
            }
        }
        logger.debug("KeyRecoveryAuthority returning ");
    }

    public void startKeyStatusUpdate() throws EBaseException {

        logger.info("KeyRecoveryAuthority: Key status update task:");

        KRAEngine engine = KRAEngine.getInstance();
        DBSubsystem dbSubsystem = engine.getDBSubsystem();

        int interval = mConfig.getInteger("keyStatusUpdateInterval", 10 * 60);
        logger.info("KeyRecoveryAuthority: - interval: " + interval);

        if (keyStatusUpdateTask != null) {
            keyStatusUpdateTask.stop();
        }

        if (interval == 0 || !dbSubsystem.getEnableSerialMgmt()) {
            logger.info("KeyRecoveryAuthority: Key status update task is disabled");
            return;
        }

        logger.info("KeyRecoveryAuthority: Starting key status update task");

        KeyRequestRepository requestRepository = engine.getKeyRequestRepository();
        keyStatusUpdateTask = new KeyStatusUpdateTask(mKeyDB, requestRepository, interval);
        keyStatusUpdateTask.start();
    }

    /**
     * Starts this subsystem. It loads and initializes all
     * necessary components. This subsystem is started by
     * KRASubsystem.
     *
     * @param config Subsystem configuration
     * @exception Exception Unable to initialize subsystem
     */
    @Override
    public void init(ConfigStore config) throws Exception {

        logger.debug("KeyRecoveryAuthority init() begins");

        if (mInitialized)
            return;

        KRAEngine kraEngine = (KRAEngine) engine;
        KRAEngineConfig engineConfig = kraEngine.getConfig();
        DBSubsystem dbSubsystem = engine.getDBSubsystem();

        mConfig = engineConfig.getKRAConfig();

        // initialize policy processor
        mPolicy = new KRAPolicy();
        mPolicy.init(this, mConfig.getSubStore(PROP_POLICY, ConfigStore.class));

        // create key repository
        int keydb_inc = mConfig.getInteger(PROP_KEYDB_INC, 5);

        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        SecureRandom secureRandom = jssSubsystem.getRandomNumberGenerator();

        mKeyDB = new KeyRepository(secureRandom, dbSubsystem);
        mKeyDB.setCMSEngine(engine);
        mKeyDB.init();

        // read transport key from internal database
        mTransportKeyUnit = new TransportKeyUnit();
        try {
            mTransportKeyUnit.init(mConfig.getSubStore(PROP_TRANSPORT_KEY, ConfigStore.class));
        } catch (Exception e) {
            logger.warn("KeyRecoveryAuthority: transport unit exception " + e.getMessage(), e);
            //XXX            throw e;
            return;
        }

        // retrieve the authority name from transport cert
        try {
            mJssCert = mTransportKeyUnit.getCertificate();
            X509CertImpl certImpl = new
                    X509CertImpl(mJssCert.getEncoded());

            mName = certImpl.getSubjectName();
        } catch (CertificateEncodingException e) {
            logger.error("KeyRecoveryAuthority: " + e.getMessage(), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_LOAD_FAILED",
                        "transport cert " + e.toString()));
        } catch (CertificateException e) {
            logger.error("KeyRecoveryAuthority: " + e.getMessage(), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_LOAD_FAILED",
                        "transport cert " + e.toString()));
        }

        // read transport key from storage key
        mStorageKeyUnit = new StorageKeyUnit();
        try {
            mStorageKeyUnit.init(
                    mConfig.getSubStore(PROP_STORAGE_KEY, ConfigStore.class),
                    mConfig.getBoolean("keySplitting", false));
        } catch (EBaseException e) {
            logger.error("KeyRecoveryAuthority: storage unit exception " + e.getMessage(), e);
            throw e;
        }

        // setup token for server-side key generation for user enrollments
        String serverKeygenTokenName = mConfig.getString("serverKeygenTokenName", null);
        if (serverKeygenTokenName == null) {
            logger.debug("serverKeygenTokenName set to nothing");
            if (mStorageKeyUnit.getToken() != null) {
                try {
                    String storageToken = mStorageKeyUnit.getToken().getName();
                    if (!CryptoUtil.isInternalToken(storageToken)) {
                        logger.debug("Auto set serverKeygenTokenName to " + storageToken);
                        serverKeygenTokenName = storageToken;
                    }
                } catch (Exception e) {
                }
            }
        }
        if (serverKeygenTokenName == null) {
            serverKeygenTokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
        }
        if (CryptoUtil.isInternalToken(serverKeygenTokenName))
            serverKeygenTokenName = CryptoUtil.INTERNAL_TOKEN_NAME;

        try {
            mKeygenToken = CryptoUtil.getKeyStorageToken(serverKeygenTokenName);
            logger.debug("KeyRecoveryAuthority: token: " + mKeygenToken.getName());
            logger.debug("KeyRecoveryAuthority: set up keygenToken");
        } catch (NoSuchTokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", serverKeygenTokenName));
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        }

        logger.debug("KeyRecoveryAuthority: about to init entropy");
        initEntropy(mConfig);
        logger.debug("KeyRecoveryAuthority: completed init of entropy");

        logger.info(mName.toString() + " is started");

        // setup the KRA request queue
        IService service = new KRAService(this);

        RequestNotifier requestNotifier = new KRANotify();
        requestNotifier.setCMSEngine(engine);
        engine.setRequestNotifier(requestNotifier);

        RequestNotifier pendingNotifier = new RequestNotifier();
        pendingNotifier.setCMSEngine(engine);
        engine.setPendingNotifier(pendingNotifier);

        RequestSubsystem reqSub = engine.getRequestSubsystem();
        int reqdb_inc = mConfig.getInteger("reqdbInc", 5);

        RequestRepository requestRepository = new KeyRequestRepository(secureRandom, dbSubsystem);
        requestRepository.setCMSEngine(engine);
        requestRepository.init();

        engine.setRequestRepository(requestRepository);

        RequestQueue requestQueue = new RequestQueue(
                dbSubsystem,
                requestRepository,
                mPolicy,
                service,
                requestNotifier,
                pendingNotifier);
        engine.setRequestQueue(requestQueue);

        startKeyStatusUpdate();

        // init request scheduler if configured
        String schedulerClass =
                mConfig.getString("requestSchedulerClass", null);

        if (schedulerClass != null) {
            try {
                RequestScheduler scheduler = (RequestScheduler) Class.forName(schedulerClass).getDeclaredConstructor().newInstance();

                requestQueue.setRequestScheduler(scheduler);
            } catch (Exception e) {
                // do nothing here
            }
        }
        initNotificationListeners();

        mReplicaRepot = new ReplicaIDRepository(dbSubsystem);
        mReplicaRepot.setCMSEngine(engine);
        mReplicaRepot.init();

        logger.debug("Replica Repot inited");

    }

    /**
     * Returns the token that generates user key pairs for supporting server-side keygen
     *
     * @return keygen token
     */
    public CryptoToken getKeygenToken() {
        return mKeygenToken;
    }

    /**
     * Returns the request listener that listens on
     * the request completion event.
     *
     * @return request listener
     */
    public RequestListener getRequestInQListener() {
        return mReqInQListener;
    }

    /**
     * Retrieves the transport certificate.
     */
    public org.mozilla.jss.crypto.X509Certificate getTransportCert() {
        return mJssCert;
    }

    /**
     * Clears up system during garbage collection.
     */
    @Override
    protected void finalize() {
        shutdown();
    }

    /**
     * Starts this service. When this method is called, all
     * service
     *
     * @exception EBaseException failed to startup this subsystem
     */
    @Override
    public void startup() throws EBaseException {
        logger.debug("KeyRecoveryAuthority startup() begins");

        KRAEngine engine = KRAEngine.getInstance();
        RequestQueue requestQueue = engine.getRequestQueue();

        if (requestQueue != null) {
            // setup administration operations if everything else is fine
            engine.recoverRequestQueue();
            logger.debug("KeyRecoveryAuthority startup() call request Q recover");

            // Note that we use our instance id for registration.
            // This helps us to support multiple instances
            // of a subsystem within server.

            // register remote admin interface
            mInitialized = true;
        } else {
            logger.warn("KeyRecoveryAuthority: mRequestQueue is null, could be in preop mode");
        }
    }

    /**
     * Shutdowns this subsystem.
     */
    @Override
    public void shutdown() {
        if (!mInitialized)
            return;

        if (mStorageKeyUnit != null) {
            mStorageKeyUnit.shutdown();
        }

        if (keyStatusUpdateTask != null) {
            keyStatusUpdateTask.stop();
        }

        if (mKeyDB != null) {
            mKeyDB.shutdown();
        }

        logger.info(mName + " is stopped");

        mInitialized = false;
    }

    /**
     * Retrieves the configuration store of this subsystem.
     * <P>
     *
     * @return configuration store
     */
    @Override
    public KRAConfig getConfigStore() {
        return mConfig;
    }

    /**
     * Enables the auto recovery state. Once KRA is in the auto
     * recovery state, no recovery agents need to be present for
     * providing credentials. This feature is for enabling
     * user-based recovery operation.
     *
     * @param cs list of agent credentials
     * @param on true if auto recovery state is on
     * @return current auto recovery state
     */
    public boolean setAutoRecoveryState(Credential cs[], boolean on) {
        if (on) {
            // check credential before enabling it
            try {
                getStorageKeyUnit().login(cs);
            } catch (Exception e) {
                return false;
            }
        }
        // maintain in-memory variable; don't store it in config
        mAutoRecoveryOn = on;
        return true;
    }

    /**
     * Retrieves the current auto recovery state.
     *
     * @return true if auto recovery state is on
     */
    public boolean getAutoRecoveryState() {
        // maintain in-memory variable; don't store it in config
        return mAutoRecoveryOn;
    }

    /**
     * Returns a list of users who are in auto
     * recovery mode.
     *
     * @return list of user IDs that are accepted in the
     *         auto recovery mode
     */
    public Enumeration<String> getAutoRecoveryIDs() {
        return mAutoRecovery.keys();
    }

    /**
     * Adds credentials to the given authorizated recovery operation.
     * In distributed recovery mode, recovery agent login to the
     * agent interface and submit its credential for a particular
     * recovery operation.
     *
     * @param id new identifier to the auto recovery mode
     * @param creds list of credentials
     */
    public void addAutoRecovery(String id, Credential creds[]) {
        mAutoRecovery.put(id, creds);
    }

    /**
     * Removes auto recovery mode from the given user id.
     *
     * @param id id of user to be removed from auto
     *            recovery mode
     */
    public void removeAutoRecovery(String id) {
        mAutoRecovery.remove(id);
    }

    /**
     * Returns the number of required agents. In M-out-of-N
     * recovery schema, only M agents are required even there
     * are N agents. This method returns M.
     *
     * @return number of required agents
     * @exception EBaseException failed to retrieve info
     */
    public int getNoOfRequiredAgents() throws EBaseException {
        if (mConfig.getBoolean("keySplitting", false)) {
            return mStorageKeyUnit.getNoOfRequiredAgents();
        }
        int ret = -1;
        ret = mConfig.getInteger("noOfRequiredRecoveryAgents", 1);
        if (ret <= 0) {
            throw new EBaseException("Invalid parameter noOfRequiredRecoveryAgents");
        }
        return ret;
    }

    public int getNoOfRequiredSecurityDataRecoveryAgents() throws EBaseException {
        int ret = -1;
        ret = mConfig.getInteger("noOfRequiredSecurityDataRecoveryAgents", 1);
        if (ret <= 0) {
            throw new EBaseException("Invalid parameter noOfRequiredSecurityDataRecoveryAgents");
        }
        return ret;
    }

    /**
     * Sets number of required agents for
     * recovery operation
     *
     * @param number number of agents
     * @exception EBaseException invalid setting
     */
    public void setNoOfRequiredAgents(int number) throws EBaseException {
        if (mConfig.getBoolean("keySplitting")) {
            mStorageKeyUnit.setNoOfRequiredAgents(number);
        } else {
            mConfig.putInteger("noOfRequiredRecoveryAgents", number);
        }
    }

    /**
     * Returns the current recovery identifier.
     *
     * @return recovery identifier
     */
    public String getRecoveryID() {
        return Integer.toString(mRecoveryIDCounter++);
    }

    /**
     * Creates recovery parameters for the given recovery operation.
     *
     * @param recoveryID recovery id
     * @return recovery parameters
     * @exception EBaseException failed to create
     */
    public Hashtable<String, Object> createRecoveryParams(String recoveryID)
            throws EBaseException {
        Hashtable<String, Object> h = new Hashtable<>();

        h.put(PARAM_CREDS, new Vector<Credential>());
        h.put(PARAM_LOCK, new Object());
        mRecoveryParams.put(recoveryID, h);
        return h;
    }

    /**
     * Destroys recovery parameters for the given recovery operation.
     *
     * @param recoveryID recovery id
     * @exception EBaseException failed to destroy
     */
    public void destroyRecoveryParams(String recoveryID)
            throws EBaseException {
        mRecoveryParams.remove(recoveryID);
    }

    /**
     * Retrieves recovery parameters for the given recovery operation.
     *
     * @param recoveryID recovery id
     * @return recovery parameters
     * @exception EBaseException failed to retrieve
     */
    public Hashtable<String, Object> getRecoveryParams(String recoveryID)
            throws EBaseException {
        return mRecoveryParams.get(recoveryID);
    }

    /**
     * Creates PKCS12 package in memory.
     *
     * @param recoveryID recovery id
     * @param pk12 package in bytes
     */
    public void createPk12(String recoveryID, byte[] pk12)
            throws EBaseException {
        Hashtable<String, Object> h = getRecoveryParams(recoveryID);

        h.put(PARAM_PK12, pk12);
    }

    /**
     * Retrieves PKCS12 package by recovery identifier.
     *
     * @param recoveryID recovery id
     * @return pkcs12 package in bytes
     */
    public byte[] getPk12(String recoveryID)
            throws EBaseException {
        return (byte[]) getRecoveryParams(recoveryID).get(PARAM_PK12);
    }

    /**
     * Creates error for a specific recovery operation.
     *
     * @param recoveryID recovery id
     * @param error error
     * @exception EBaseException failed to create error
     */
    public void createError(String recoveryID, String error)
            throws EBaseException {
        Hashtable<String, Object> h = getRecoveryParams(recoveryID);

        h.put(PARAM_ERROR, error);
    }

    /**
     * Retrieves error by recovery identifier.
     *
     * @param recoveryID recovery id
     * @return error message
     */
    public String getError(String recoveryID)
            throws EBaseException {
        return (String) getRecoveryParams(recoveryID).get(PARAM_ERROR);
    }

    /**
     * Retrieve the current approval agents
     */
    public Vector<Credential> getAppAgents(
            String recoveryID) throws EBaseException {
        Hashtable<String, Object> h = getRecoveryParams(recoveryID);
        @SuppressWarnings("unchecked")
        Vector<Credential> dc = (Vector<Credential>) h.get(PARAM_CREDS);

        return dc;
    }

    /**
     * Retrieves credentials in the distributed recovery operation.
     *
     * This puts KRA in a waiting mode, it never returns until all
     * the necessary passwords are collected.
     *
     * @param recoveryID recovery id
     * @return agent's credentials
     * @exception EBaseException failed to retrieve
     */
    public Credential[] getDistributedCredentials(
            String recoveryID)
            throws EBaseException {
        Hashtable<String, Object> h = getRecoveryParams(recoveryID);
        @SuppressWarnings("unchecked")
        Vector<Credential> dc = (Vector<Credential>) h.get(PARAM_CREDS);
        Object lock = h.get(PARAM_LOCK);

        synchronized (lock) {
            while (dc.size() < getNoOfRequiredAgents()) {
                logger.debug("KeyRecoveryAuthority: cfu in synchronized lock for getDistributedCredentials");
                try {
                    lock.wait();
                } catch (InterruptedException e) {
                }
            }
            Credential creds[] = new Credential[dc.size()];

            dc.copyInto(creds);
            return creds;
        }
    }

    /**
     * Verifies credential.
     */
    private void verifyCredential(Vector<Credential> creds, String uid,
            String pwd) throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();

        // see if we have the uid already
        if (!mConfig.getBoolean("keySplitting")) {
            // check if the uid is in the specified group
            UGSubsystem ug = engine.getUGSubsystem();
            if (!ug.isMemberOf(uid, mConfig.getString("recoveryAgentGroup"))) {
                // invalid group
                throw new EBaseException(CMS.getUserMessage("CMS_KRA_CREDENTIALS_NOT_EXIST"));
            }
        }

        for (int i = 0; i < creds.size(); i++) {
            Credential c = creds.elementAt(i);

            if (c.getIdentifier().equals(uid)) {
                // duplicated uid
                throw new EBaseException(CMS.getUserMessage("CMS_KRA_CREDENTIALS_EXIST"));
            }
        }
        if (mConfig.getBoolean("keySplitting")) {
            mStorageKeyUnit.checkPassword(uid, pwd);
        }
    }

    /**
     * Adds password in the distributed recovery operation.
     *
     * @param recoveryID recovery id
     * @param uid agent uid
     * @param pwd agent password
     * @exception EBaseException failed to add
     */
    public void addDistributedCredential(String recoveryID,
            String uid, String pwd) throws EBaseException {
        Hashtable<String, Object> h = getRecoveryParams(recoveryID);
        @SuppressWarnings("unchecked")
        Vector<Credential> dc = (Vector<Credential>) h.get(PARAM_CREDS);
        Object lock = h.get(PARAM_LOCK);

        synchronized (lock) {
            verifyCredential(dc, uid, pwd);
            // verify password
            dc.addElement(new Credential(uid, pwd));
            // modify status object
            lock.notify();
        }
    }

    /**
     * Archives key. This creates a key record in the key
     * repository.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST used whenever a user private key archive
     * request is made (this is when the DRM receives the request)
     * <li>signed.audit LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST_PROCESSED used whenever a user private key
     * archive request is processed (this is when the DRM processes the request)
     * </ul>
     *
     * @param rec key record to be archived
     * @return executed request
     * @exception EBaseException failed to archive key
     * @return the request
     *         <P>
     */
    public Request archiveKey(KeyRecord rec)
            throws EBaseException {
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID();
        String auditPublicKey = auditPublicKey(rec);

        KRAEngine engine = KRAEngine.getInstance();
        KeyRequestRepository requestRepository = engine.getKeyRequestRepository();
        Request r = null;

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            r = requestRepository.createRequest(KRAService.ENROLLMENT);

            audit(SecurityDataArchivalRequestEvent.createSuccessEvent(
                        auditSubjectID,
                        auditRequesterID,
                        r.getRequestId(),
                        null));

        } catch (EBaseException eAudit1) {
            audit(SecurityDataArchivalRequestEvent.createFailureEvent(
                        auditSubjectID,
                        auditRequesterID,
                        null /* requestId */,
                        null /*clientKeyId */,
                        eAudit1));
            throw eAudit1;
        }

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (r != null) {
                r.setExtData(EnrollmentService.ATTR_KEY_RECORD, rec.getSerialNumber());
                RequestQueue queue = engine.getRequestQueue();
                queue.processRequest(r);
            }

            audit(SecurityDataArchivalProcessedEvent.createSuccessEvent(
                    auditSubjectID,
                    auditRequesterID,
                    r.getRequestId(),
                    null,
                    new KeyId(rec.getSerialNumber()),
                    auditPublicKey));

        } catch (EBaseException eAudit1) {

            audit(SecurityDataArchivalProcessedEvent.createFailureEvent(
                    auditSubjectID,
                    auditRequesterID,
                    r.getRequestId(),
                    null,
                    new KeyId(rec.getSerialNumber()),
                    eAudit1.getMessage(),
                    auditPublicKey));

            throw eAudit1;
        }

        return r;
    }

    /**
     * Initiate asynchronous key recovery
     *
     * @param kid key identifier
     * @param cert certificate embedded in PKCS12
     * @param agent agent requesting recovery
     * @param realm authorization realm
     * @return requestId
     * @exception EBaseException failed to initiate async recovery
     */
    public String initAsyncKeyRecovery(BigInteger kid, X509CertImpl cert, String agent, String realm)
            throws EBaseException {

        String auditPublicKey = auditPublicKey(cert);
        RequestId auditRecoveryID = null;
        String auditSubjectID = auditSubjectID();

        KRAEngine engine = KRAEngine.getInstance();
        KeyRequestRepository requestRepository = engine.getKeyRequestRepository();
        Request r = null;

        try {
            r = requestRepository.createRequest(KRAService.RECOVERY);

            r.setExtData(RecoveryService.ATTR_SERIALNO, kid);
            r.setExtData(RecoveryService.ATTR_USER_CERT, cert);
            // first one in the "approvingAgents" list is the initiating agent
            r.setExtData(Request.ATTR_APPROVE_AGENTS, agent);
            r.setRequestStatus(RequestStatus.PENDING);
            r.setRealm(realm);
            RequestQueue queue = engine.getRequestQueue();
            requestRepository.updateRequest(r);
            auditRecoveryID = r.getRequestId();

            // store a message in the signed audit log file
            audit(new SecurityDataRecoveryEvent(
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditRecoveryID,
                        null,
                        auditPublicKey));
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            audit(new SecurityDataRecoveryEvent(
                    auditSubjectID,
                    ILogger.FAILURE,
                    auditRecoveryID,
                    null,
                    auditPublicKey));
            throw eAudit1;
        }

        //NO call to queue.processRequest(r) because it is only initiating
        return r.getRequestId().toString();
    }

    /**
     * is async recovery request status APPROVED -
     * i.e. all required # of recovery agents approved
     *
     * @param reqID request id
     * @return true if # of recovery required agents approved; false otherwise
     */
    public boolean isApprovedAsyncKeyRecovery(String reqID)
            throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        RequestRepository requestRepository = engine.getRequestRepository();

        Request r = requestRepository.readRequest(new RequestId(reqID));
        return r.getRequestStatus() == RequestStatus.APPROVED;
    }

    /**
     * get async recovery request initiating agent
     *
     * @param reqID request id
     * @return agentUID
     */
    public String getInitAgentAsyncKeyRecovery(String reqID)
            throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        RequestRepository requestRepository = engine.getRequestRepository();

        Request r = requestRepository.readRequest(new RequestId(reqID));

        String agents = r.getExtDataInString(Request.ATTR_APPROVE_AGENTS);
        if (agents == null) { // no approvingAgents existing, can't be async recovery
            logger.debug("getInitAgentAsyncKeyRecovery: no approvingAgents in request");
        } else {
            int i = agents.indexOf(",");
            if (i == -1) {
                return agents;
            }
            return agents.substring(0, i);
        }

        return null;
    }

    /**
     * Add async recovery agent to approving agent list of the recovery request
     * record.
     *
     * This method will check to see if the agent belongs to the recovery group
     * first before adding.
     *
     * @param reqID request id
     * @param agentID agent id
     * @exception EBaseException failed to initiate async recovery
     */
    public void addAgentAsyncKeyRecovery(String reqID, String agentID)
            throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();

        // check if the uid is in the specified group
        UGSubsystem ug = engine.getUGSubsystem();
        if (!ug.isMemberOf(agentID, mConfig.getString("recoveryAgentGroup"))) {
            // invalid group
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_CREDENTIALS_NOT_EXIST"));
        }

        RequestRepository requestRepository = engine.getRequestRepository();
        RequestQueue queue = engine.getRequestQueue();
        Request r = requestRepository.readRequest(new RequestId(reqID));

        String agents = r.getExtDataInString(Request.ATTR_APPROVE_AGENTS);
        if (agents != null) {
            int count = 0;
            StringTokenizer st = new StringTokenizer(agents, ",");
            for (; st.hasMoreTokens();) {
                String a = st.nextToken();
                // first one is the initiating agent
                if ((count != 0) && a.equals(agentID)) {
                    // duplicated uid
                    throw new EBaseException(CMS.getUserMessage("CMS_KRA_CREDENTIALS_EXIST"));
                }
                count++;
            }
            int agentsRequired =
                    (r.getRequestType().equals(Request.SECURITY_DATA_RECOVERY_REQUEST)) ?
                            getNoOfRequiredSecurityDataRecoveryAgents() :
                            getNoOfRequiredAgents();

            // note: if count==1 and required agents is 1, it's good to add
            // and it'd look like "agent1,agent1" - that's the only duplicate allowed
            if (count <= agentsRequired) { //all good, add it
                r.setExtData(Request.ATTR_APPROVE_AGENTS,
                        agents + "," + agentID);
                if (count == agentsRequired) {
                    r.setRequestStatus(RequestStatus.APPROVED);
                } else {
                    r.setRequestStatus(RequestStatus.PENDING);
                }
                requestRepository.updateRequest(r);
            }
        } else { // no approvingAgents existing, can't be async recovery
            logger.debug("addAgentAsyncKeyRecovery: no approvingAgents in request. Async recovery request not initiated?");
        }
    }

    /**
     * Recovers key for administrators. This method is
     * invoked by the agent operation of the key recovery servlet.
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST used whenever a user private key recovery request is
     * made (this is when the DRM receives the request)
     * <li>signed.audit LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST_PROCESSED used whenever a user private key recovery
     * request is processed (this is when the DRM processes the request)
     * </ul>
     *
     * @param kid key identifier
     * @param creds list of recovery agent credentials
     * @param password password of the PKCS12 package
     * @param cert certificate that will be put in PKCS12
     * @param delivery file, mail or something else
     * @param nickname string containing the nickname of the id cert for this
     *            subsystem
     * @exception EBaseException failed to recover key
     * @return a byte array containing the key
     */
    public byte[] doKeyRecovery(BigInteger kid,
            Credential creds[], String password,
            X509CertImpl cert,
            String delivery, String nickname,
            String agent)
            throws EBaseException {
        String auditSubjectID = auditSubjectID();
        RequestId auditRecoveryID = auditRecoveryID();
        String auditPublicKey = auditPublicKey(cert);
        String auditAgents = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        KRAEngine engine = KRAEngine.getInstance();
        KeyRequestRepository requestRepository = engine.getKeyRequestRepository();

        Request r = null;
        Hashtable<String, Object> params = null;

        logger.debug("KeyRecoveryAuthority: in synchronous doKeyRecovery()");
        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            r = requestRepository.createRequest(KRAService.RECOVERY);

            // set transient parameters
            params = createVolatileRequest(r.getRequestId());

            if (mConfig.getBoolean("keySplitting")) {
                params.put(RecoveryService.ATTR_AGENT_CREDENTIALS, creds);
            }
            params.put(RecoveryService.ATTR_TRANSPORT_PWD, password);

            r.setExtData(RecoveryService.ATTR_SERIALNO, kid);
            r.setExtData(RecoveryService.ATTR_USER_CERT, cert);
            if (nickname != null) {
                nickname = nickname.trim();
                if (!nickname.equals("")) {
                    r.setExtData(RecoveryService.ATTR_NICKNAME, nickname);
                }
            }
            // for both sync and async recovery
            r.setExtData(Request.ATTR_APPROVE_AGENTS, agent);

            // store a message in the signed audit log file
            audit(new SecurityDataRecoveryEvent(
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditRecoveryID,
                        new KeyId(kid),
                        auditPublicKey));
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            audit(new SecurityDataRecoveryEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRecoveryID,
                        new KeyId(kid),
                        auditPublicKey));

            throw eAudit1;
        }

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            RequestQueue queue = engine.getRequestQueue();
            queue.processRequest(r);

            if (r.getExtDataInString(Request.ERROR) == null) {
                byte pkcs12[] = (byte[]) params.get(
                        RecoveryService.ATTR_PKCS12);

                auditAgents = auditAgents(creds);

                audit(new SecurityDataRecoveryProcessedEvent(
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditRecoveryID,
                            new KeyId(kid),
                            null,
                            auditAgents));

                destroyVolatileRequest(r.getRequestId());

                return pkcs12;
            }
            audit(new SecurityDataRecoveryProcessedEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRecoveryID,
                        new KeyId(kid),
                        r.getExtDataInString(Request.ERROR),
                        auditAgents));

            throw new EBaseException(r.getExtDataInString(Request.ERROR));
        } catch (EBaseException eAudit1) {
            audit(new SecurityDataRecoveryProcessedEvent(
                    auditSubjectID,
                    ILogger.FAILURE,
                    auditRecoveryID,
                    new KeyId(kid),
                    eAudit1.getMessage(),
                    auditAgents));
            throw eAudit1;
        }
    }

    /**
     * Async Recovers key for administrators. This method is
     * invoked by the agent operation of the key recovery servlet.
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST
     * used whenever a user private key recovery request is
     * made (this is when the DRM receives the request)
     * <li>signed.audit LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST_PROCESSED
     * used whenever a user private key recovery
     * request is processed (this is when the DRM processes the request)
     * </ul>
     *
     * @param requestID request id
     * @param password password of the PKCS12 package
     *            subsystem
     * @exception EBaseException failed to recover key
     * @return a byte array containing the key
     */
    public byte[] doKeyRecovery(
            String reqID,
            String password)
            throws EBaseException {
        String auditSubjectID = auditSubjectID();
        RequestId auditRecoveryID = new RequestId(reqID);
        String auditAgents = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        KeyId keyID = null;

        KRAEngine engine = KRAEngine.getInstance();
        RequestRepository requestRepository = engine.getRequestRepository();
        RequestQueue queue = engine.getRequestQueue();

        Hashtable<String, Object> params = null;

        logger.debug("KeyRecoveryAuthority: in asynchronous doKeyRecovery()");
        Request r = requestRepository.readRequest(new RequestId(reqID));

        auditAgents = r.getExtDataInString(Request.ATTR_APPROVE_AGENTS);
        BigInteger serialNumber = r.getExtDataInBigInteger("serialNumber");
        keyID = serialNumber != null? new KeyId(serialNumber) : null;

        // set transient parameters
        params = createVolatileRequest(r.getRequestId());
        params.put(RecoveryService.ATTR_TRANSPORT_PWD, password);

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            logger.debug("KeyRecoveryAuthority: in asynchronous doKeyRecovery(), request state ="
                    + r.getRequestStatus().toString());
            // can only process requests in begin state
            r.setRequestStatus(RequestStatus.BEGIN);
            queue.processRequest(r);

            if (r.getExtDataInString(Request.ERROR) == null) {
                byte pkcs12[] = (byte[]) params.get(
                        RecoveryService.ATTR_PKCS12);

                audit(new SecurityDataRecoveryProcessedEvent(
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditRecoveryID,
                            keyID,
                            null,
                            auditAgents));

                destroyVolatileRequest(r.getRequestId());

                return pkcs12;
            }
            audit(new SecurityDataRecoveryProcessedEvent(
                    auditSubjectID,
                    ILogger.FAILURE,
                    auditRecoveryID,
                    keyID,
                    r.getExtDataInString(Request.ERROR),
                    auditAgents));

            throw new EBaseException(r.getExtDataInString(Request.ERROR));
        } catch (EBaseException eAudit1) {
            audit(new SecurityDataRecoveryProcessedEvent(
                    auditSubjectID,
                    ILogger.FAILURE,
                    auditRecoveryID,
                    keyID,
                    eAudit1.getMessage(),
                    auditAgents));
            throw eAudit1;
        }
    }

    /**
     * Constructs a recovery request and submits it
     * to the request subsystem for processing.
     *
     * @param kid key identifier
     * @param creds list of recovery agent credentials
     * @param password password of the PKCS12 package
     * @param cert certificate that will be put in PKCS12
     * @param delivery file, mail or something else
     * @return executed request
     * @exception EBaseException failed to recover key
     */
    public Request recoverKey(BigInteger kid,
            Credential creds[], String password,
            X509CertImpl cert,
            String delivery) throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KeyRequestRepository requestRepository = engine.getKeyRequestRepository();

        Request r = requestRepository.createRequest("recovery");
        r.setExtData(RecoveryService.ATTR_SERIALNO, kid);
        r.setExtData(RecoveryService.ATTR_TRANSPORT_PWD, password);
        r.setExtData(RecoveryService.ATTR_USER_CERT, cert);
        r.setExtData(RecoveryService.ATTR_DELIVERY, delivery);

        RequestQueue queue = engine.getRequestQueue();
        queue.processRequest(r);

        return r;
    }

    /**
     * Process synchronous archival and recovery requests
     *
     * (TODO(alee): should we do this in a separate thread?
     * @throws EBaseException
     */
    public void processSynchronousRequest(Request request) throws EBaseException {
        SecurityDataProcessor processor = new SecurityDataProcessor(this);
        switch(request.getRequestType()){
            case Request.SECURITY_DATA_ENROLLMENT_REQUEST:
                processor.archive(request);
                break;
            case Request.SECURITY_DATA_RECOVERY_REQUEST:
                processor.recover(request);
                break;
            default:
                throw new EBaseException("Unsupported synchronous request type: " + request.getRequestType());
        }
    }

    /**
     * Are ephemeral requests enabled for SECURITY_DATA recovery and archival
     *
     * @param realm authz realm
     */
    public boolean isEphemeral(String realm) {
        try {
            return mConfig.getBoolean("ephemeralRequests", false);
        } catch (EBaseException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Is the SECURITY_DATA retrieval synchronous?
     *
     * @param realm
     */
    public boolean isRetrievalSynchronous(String realm) {
        try {
            return getNoOfRequiredSecurityDataRecoveryAgents() == 1;
        } catch (EBaseException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Recovers key for end-entities.
     *
     * @param creds list of credentials
     * @param encryptionChain certificate chain
     * @param signingCert signing cert
     * @param transportCert certificate to protect in-transit key
     * @param ownerName owner name
     * @return executed request
     * @exception EBaseException failed to recover key
     */
    public Request recoverKey(Credential creds[], CertificateChain
            encryptionChain, X509CertImpl signingCert,
            X509CertImpl transportCert,
            X500Name ownerName) throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();

        KeyRequestRepository requestRepository = engine.getKeyRequestRepository();
        Request r = requestRepository.createRequest("recovery");

        ByteArrayOutputStream certChainOut = new ByteArrayOutputStream();
        try {
            encryptionChain.encode(certChainOut);
            r.setExtData(RecoveryService.ATTR_ENCRYPTION_CERTS,
                    certChainOut.toByteArray());
        } catch (IOException e) {
            logger.warn("Error encoding certificate chain", e);
        }

        r.setExtData(RecoveryService.ATTR_SIGNING_CERT, signingCert);
        r.setExtData(RecoveryService.ATTR_TRANSPORT_CERT, transportCert);

        DerOutputStream ownerNameOut = new DerOutputStream();
        try {
            ownerName.encode(ownerNameOut);
            r.setExtData(RecoveryService.ATTR_OWNER_NAME,
                    ownerNameOut.toByteArray());
        } catch (IOException e) {
            logger.warn("Error encoding X500Name for owner name", e);
        }

        RequestQueue queue = engine.getRequestQueue();
        queue.processRequest(r);

        return r;
    }

    /**
     * Retrieves the storage key unit. The storage key
     * is used to wrap the user key for long term
     * storage.
     *
     * @return storage key unit.
     */
    public IStorageKeyUnit getStorageKeyUnit() {
        return mStorageKeyUnit;
    }

    /**
     * Retrieves the transport key unit.
     *
     * @return transport key unit
     */
    public TransportKeyUnit getTransportKeyUnit() {
        return mTransportKeyUnit;
    }

    /**
     * Returns the name of this subsystem. This name is
     * extracted from the transport certificate.
     *
     * @return KRA name
     */
    public X500Name getX500Name() {
        return mName;
    }

    public String getNickName() {
        return getNickname();
    }

    /**
     * Returns the nickname of the transport certificate.
     *
     * @return transport certificate nickname.
     */
    public String getNickname() {
        try {
            return mTransportKeyUnit.getNickName();
        } catch (EBaseException e) {
            return null;
        }
    }

    /**
     * Sets the nickname of the transport certificate.
     *
     * @param str nickname
     */
    public void setNickname(String str) {
        try {
            mTransportKeyUnit.setNickName(str);
        } catch (EBaseException e) {
        }
    }

    /**
     * Returns the new nickname of the transport certifiate.
     *
     * @return new nickname
     */
    public String getNewNickName() throws EBaseException {
        return mConfig.getString(PROP_NEW_NICKNAME, "");
    }

    /**
     * Sets the new nickname of the transport certifiate.
     *
     * @param name new nickname
     */
    public void setNewNickName(String name) {
        mConfig.putString(PROP_NEW_NICKNAME, name);
    }

    public IPolicy getPolicy() {
        return mPolicy;
    }

    /**
     * Retrieves the key repository. The key repository
     * stores archived keys.
     */
    public KeyRepository getKeyRepository() {
        return mKeyDB;
    }

    /**
     * Retrieves replica ID repository.
     *
     * @return replica ID repository
     */
    public ReplicaIDRepository getReplicaRepository() {
        return mReplicaRepot;
    }

    /**
     * Retrieves the DN of this escrow authority.
     * <P>
     *
     * @return distinguished name
     */
    protected String getDN() {
        return getX500Name().toString();
    }

    /**
     * init notification related listeners -
     * right now only RequestInQueue listener is available for KRA
     */
    private void initNotificationListeners() {
        ConfigStore nc = null;

        try {
            nc = mConfig.getSubStore(PROP_NOTIFY_SUBSTORE, ConfigStore.class);
            if (nc != null && nc.size() > 0) {
                // Initialize Request In Queue notification listener
                String requestInQListenerClassName =
                        nc.getString("certificateIssuedListenerClassName",
                                "com.netscape.cms.listeners.RequestInQListener");

                try {
                    mReqInQListener = (RequestListener) Class.forName(requestInQListenerClassName).getDeclaredConstructor().newInstance();
                    mReqInQListener.setCMSEngine(engine);
                    mReqInQListener.init(this, nc);
                } catch (Exception e1) {
                    logger.warn(CMS.getLogMessage("CMSCORE_KRA_REGISTER_LISTENER", requestInQListenerClassName), e1);
                }
            } else {
                logger.warn("No KRA notification Module configuration found");
            }

        } catch (EPropertyNotFound e) {
            logger.warn(CMS.getLogMessage("CMSCORE_KRA_NOTIFY_ERROR", e.toString()), e);

        } catch (EListenersException e) {
            logger.warn(CMS.getLogMessage("CMSCORE_KRA_NOTIFY_ERROR", e.toString()), e);

        } catch (EBaseException e) {
            logger.warn(CMS.getLogMessage("CMSCORE_KRA_NOTIFY_ERROR", e.toString()), e);
        }
    }

    /**
     * temporary accepted ras.
     */
    /* code no longer used
    public X500Name[] getAcceptedRAs() {
        // temporary. use usr/grp for real thing.
        X500Name radn = null;
        String raname = null;

        try {
            raname = mConfig.getString("acceptedRA", null);
            if (raname != null) {
                radn = new X500Name(raname);
            }

        } catch (IOException e) {
            logger.warn(CMS.getLogMessage("CMSCORE_KRA_INVALID_RA_NAME", raname, e.toString()), e);

        } catch (EBaseException e) {
            // ignore - set to null.
            logger.warn(CMS.getLogMessage("CMSCORE_KRA_INVALID_RA_SETUP", e.toString()), e);
        }
        return new X500Name[] { radn };
    }
    */

    public Hashtable<String, Hashtable<String, Object>> mVolatileRequests =
            new Hashtable<>();

    /**
     * Creates a request object to store attributes that
     * will not be serialized. Currently, request queue
     * framework will try to serialize all the attribute into
     * persistent storage. Things like passwords are not
     * desirable to be stored.
     *
     * @param id request id
     * @return volatile requests
     */
    public Hashtable<String, Object> createVolatileRequest(RequestId id) {
        Hashtable<String, Object> params = new Hashtable<>();

        mVolatileRequests.put(id.toString(), params);
        return params;
    }

    /**
     * Retrieves the request object.
     *
     * @param id request id
     * @return volatile requests
     */
    public Hashtable<String, Object> getVolatileRequest(RequestId id) {
        return mVolatileRequests.get(id.toString());
    }

    /**
     * Destroys the request object.
     *
     * @param id request id
     */
    public void destroyVolatileRequest(RequestId id) {
        mVolatileRequests.remove(id.toString());
    }

    @Override
    public String getOfficialName() {
        return OFFICIAL_NAME;
    }

    protected void audit(LogEvent event) {
        signedAuditLogger.log(event);
    }

    /**
     * Signed Audit Log Subject ID
     *
     * This method is called to obtain the "SubjectID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message SubjectID
     */
    private String auditSubjectID() {

        String subjectID = null;

        // Initialize subjectID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            subjectID = (String)
                    auditContext.get(SessionContext.USER_ID);

            if (subjectID != null) {
                subjectID = subjectID.trim();
            } else {
                subjectID = ILogger.NONROLEUSER;
            }
        } else {
            subjectID = ILogger.UNIDENTIFIED;
        }

        return subjectID;
    }

    /**
     * Signed Audit Log Requester ID
     *
     * This method is called to obtain the "RequesterID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message RequesterID
     */
    private String auditRequesterID() {

        String requesterID = null;

        // Initialize requesterID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            requesterID = (String)
                    auditContext.get(SessionContext.REQUESTER_ID);

            if (requesterID != null) {
                requesterID = requesterID.trim();
            } else {
                requesterID = ILogger.UNIDENTIFIED;
            }
        } else {
            requesterID = ILogger.UNIDENTIFIED;
        }

        return requesterID;
    }

    /*
     * Returns the requestID for the recovery request for audit logs.
     */
    private RequestId auditRecoveryID() {
        SessionContext auditContext = SessionContext.getExistingContext();
        if (auditContext != null) {
            String recoveryID = (String) auditContext.get(SessionContext.RECOVERY_ID);
            if (recoveryID != null) {
                return new RequestId(recoveryID.trim());
            }
        }

        return null;
    }

    /**
     * Signed Audit Log Public Key
     *
     * This method is called to obtain the public key from the passed in
     * "X509Certificate" for a signed audit log message.
     * <P>
     *
     * @param cert an X509Certificate
     * @return key string containing the certificate's public key
     */
    private String auditPublicKey(X509Certificate cert) {

        if (cert == null) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        byte rawData[] = cert.getPublicKey().getEncoded();

        // convert "rawData" into "base64Data"
        if (rawData != null) {
            String base64Data = Utils.base64encode(rawData, true).trim();

            // concatenate lines
            return base64Data.replace("\r", "").replace("\n", "");
        }

        return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
    }

    /**
     * Signed Audit Log Public Key
     *
     * This method is called to obtain the public key from the passed in
     * "KeyRecord" for a signed audit log message.
     * <P>
     *
     * @param rec a Key Record
     * @return key string containing the certificate's public key
     */
    private String auditPublicKey(KeyRecord rec) {

        if (rec == null) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        byte rawData[] = null;

        try {
            rawData = rec.getPublicKeyData();
        } catch (EBaseException e) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        String key = null;

        // convert "rawData" into "base64Data"
        if (rawData != null) {
            String base64Data = null;

            base64Data = Utils.base64encode(rawData, true).trim();

            // concatenate lines
            key = base64Data.replace("\r", "").replace("\n", "");
        }

        if (key == null) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }
        key = key.trim();

        return key.isEmpty() ? ILogger.SIGNED_AUDIT_EMPTY_VALUE : key;
    }

    /**
     * Signed Audit Agents
     *
     * This method is called to extract agent uids from the passed in
     * "Credentials[]" and return a string of comma-separated agent uids.
     * <P>
     *
     * @param creds array of credentials
     * @return a comma-separated string of agent uids
     */
    private String auditAgents(Credential creds[]) {
        if (creds == null)
            return null;

        String agents = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        String uid = null;

        for (int i = 0; i < creds.length; i++) {
            uid = creds[i].getIdentifier();

            if (uid != null) {
                uid = uid.trim();
            }

            if (uid != null &&
                    !uid.equals("")) {

                if (i == 0) {
                    agents = uid;
                } else {
                    agents += SIGNED_AUDIT_AGENT_DELIMITER + uid;
                }
            }
        }

        return agents;
    }

    /**
     * Generate an asymmetric key pair.
     *
     * @param alg
     * @param keySize
     * @param keyCurve
     * @param pqg
     * @param usageList - RSA only for now
     * @return key pair
     * @throws EBaseException
     */
    public KeyPair generateKeyPair(String alg, int keySize, String keyCurve,
            PQGParams pqg, KeyPairGeneratorSpi.Usage[] usageList) throws EBaseException {
        return generateKeyPair(alg, keySize, keyCurve, pqg, usageList, false);
    }

    public KeyPair generateKeyPair(String alg, int keySize, String keyCurve,
            PQGParams pqg, KeyPairGeneratorSpi.Usage[] usageList, boolean temp) throws EBaseException {
        KeyPairAlgorithm kpAlg = null;

        if (alg.equals("RSA"))
            kpAlg = KeyPairAlgorithm.RSA;
        else if (alg.equals("EC"))
            kpAlg = KeyPairAlgorithm.EC;
        else
            kpAlg = KeyPairAlgorithm.DSA;

        try {
            KeyPair kp = generateKeyPair(kpAlg, keySize, keyCurve, pqg, usageList, temp);

            return kp;
        } catch (InvalidParameterException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEYSIZE_PARAMS",
                        "" + keySize));
        } catch (PQGParamGenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_PQG_GEN_FAILED"));
        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED",
                        kpAlg.toString()));
        } catch (TokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR_1", e.toString()));
        } catch (InvalidAlgorithmParameterException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED", "DSA"));
        }
    }

    public KeyPair generateKeyPair(
            KeyPairAlgorithm kpAlg, int keySize, String keyCurve, PQGParams pqg,
            KeyPairGeneratorSpi.Usage[] usageList )
            throws NoSuchAlgorithmException, TokenException, InvalidAlgorithmParameterException,
            InvalidParameterException, PQGParamGenException {
        return generateKeyPair(kpAlg, keySize, keyCurve, pqg, usageList, true);
    }
    public KeyPair generateKeyPair(
            KeyPairAlgorithm kpAlg, int keySize, String keyCurve, PQGParams pqg,
            KeyPairGeneratorSpi.Usage[] usageList, boolean temp)
            throws NoSuchAlgorithmException, TokenException, InvalidAlgorithmParameterException,
            InvalidParameterException, PQGParamGenException {

        KRAEngine engine = KRAEngine.getInstance();
        CryptoToken token = getKeygenToken();

        logger.debug("NetkeyKeygenService: key pair is to be generated on slot: " + token.getName());

        /*
           make it temporary so can work with HSM
           netHSM works with
              temporary == true
              sensitive == <do not specify>
              extractable == <do not specify>
           LunaSA2 works with
              temporary == true
              sensitive == true
              extractable == true
        */
        KeyPairGenerator kpGen = token.getKeyPairGenerator(kpAlg);
        KRAEngineConfig config = engine.getConfig();
        ConfigStore kgConfig = config.getSubStore("kra.keygen", ConfigStore.class);
        boolean tp = temp;
        boolean sp = false;
        boolean ep = false;
        if ((kgConfig != null) && (!kgConfig.equals(""))) {
            try {
                tp = kgConfig.getBoolean("temporaryPairs", false);
                sp = kgConfig.getBoolean("sensitivePairs", false);
                ep = kgConfig.getBoolean("extractablePairs", false);
                logger.debug("NetkeyKeygenService: found config store: kra.keygen");
                // by default, let nethsm work
                if (!tp && !sp && !ep) {
                    if (kpAlg == KeyPairAlgorithm.EC) {
                        // set to what works for nethsm
                        tp = true;
                        sp = false;
                        ep = true;
                    } else
                        tp = true;
                    }
            } catch (Exception e) {
                logger.warn("NetkeyKeygenService: kgConfig.getBoolean failed: " + e.getMessage(), e);
                // by default, let nethsm work
                tp = true;
            }
        } else {
            // by default, let nethsm work
            logger.debug("NetkeyKeygenService: cannot find config store: kra.keygen, assume temporaryPairs==true");
            if (kpAlg == KeyPairAlgorithm.EC) {
                // set to what works for nethsm
                tp = true;
                sp = false;
                ep = true;
            } else {
                tp = true;
            }
        }

        if (kpAlg == KeyPairAlgorithm.EC) {

            KeyPair pair = null;

            try {
                pair = CryptoUtil.generateECCKeyPair(
                        token,
                        keyCurve /* ECC_curve default */,
                        tp /* temporary */,
                        sp ? 1 : 0 /* sensitive */,
                        ep ? 1 : 0 /* extractable */,
                        null,
                        CryptoUtil.ECDH_USAGES_MASK);
                logger.debug("NetkeyKeygenService: after key pair generation" );
            } catch (Exception e) {
                logger.warn("NetkeyKeygenService: key pair generation with exception: " + e.getMessage(), e);
            }
            return pair;

        }
        //only specified to "true" will it be set
        if (tp) {
            logger.debug("NetkeyKeygenService: setting temporaryPairs to true");
            kpGen.temporaryPairs(true);
        }

        if (sp) {
            logger.debug("NetkeyKeygenService: setting sensitivePairs to true");
            kpGen.sensitivePairs(true);
        }

        if (ep) {
            logger.debug("NetkeyKeygenService: setting extractablePairs to true");
            kpGen.extractablePairs(true);
        }

        if (kpAlg == KeyPairAlgorithm.DSA) {
            if (pqg == null) {
                kpGen.initialize(keySize);
            } else {
                kpGen.initialize(pqg);
            }
        } else {
            kpGen.initialize(keySize);
        }

        if (usageList != null)
            kpGen.setKeyPairUsages(usageList, usageList);

        if (pqg == null) {
            KeyPair kp = null;
            synchronized (new Object()) {
                logger.debug("NetkeyKeygenService: key pair generation begins");
                kp = kpGen.genKeyPair();
                logger.debug("NetkeyKeygenService: key pair generation done");
                addEntropy(true);
            }
            return kp;
        }
        // DSA
        KeyPair kp = null;

        /* no DSA for now... netkey prototype
        do {
            // 602548 NSS bug - to overcome it, we use isBadDSAKeyPair
            kp = kpGen.genKeyPair();
        }
        while (isBadDSAKeyPair(kp));
        */
        return kp;
    }
}
