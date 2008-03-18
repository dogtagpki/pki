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


import java.lang.*;
import java.util.*;
import java.security.cert.X509Certificate;
import java.security.cert.*;
import java.math.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import netscape.security.x509.*;
import netscape.security.util.DerOutputStream;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.listeners.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.dbs.keydb.*;
import com.netscape.cmscore.dbs.*;
import com.netscape.certsrv.policy.*;
import com.netscape.certsrv.kra.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.security.*;
import com.netscape.cmscore.request.*;
import com.netscape.certsrv.apps.*;

import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;


/**
 * A class represents an key recovery authority (KRA). A KRA
 * is responsible to maintain key pairs that have been
 * escrowed. It provides archive and recovery key pairs
 * functionalities. 
 * <P>
 *
 * @author thomask
 * @version $Revision: 14563 $, $Date: 2007-05-01 10:35:23 -0700 (Tue, 01 May 2007) $
 */
public class KeyRecoveryAuthority implements IAuthority, IKeyService, IKeyRecoveryAuthority {

    public final static String OFFICIAL_NAME = "Data Recovery Manager";

    /**
     * Internal Constants
     */

    private static final String PR_INTERNAL_TOKEN_NAME = "internal";
    private static final String PARAM_CREDS = "creds";
    private static final String PARAM_LOCK = "lock";
    private static final String PARAM_PK12 = "pk12";
    private static final String PARAM_ERROR = "error";
    private static final String PARAM_AGENT = "agent";

    private final static String KEY_RESP_NAME = "keyRepository";

    private Hashtable mRequestProcessor = new Hashtable();

    protected boolean mInitialized = false;
    protected IConfigStore mConfig = null;
    protected ILogger mLogger = CMS.getLogger();
    protected KRAPolicy mPolicy = null;
    protected X500Name mName = null;
    protected boolean mQueueRequests = false;
    protected String mId = null;
    protected IRequestQueue mRequestQueue = null;
    protected TransportKeyUnit mTransportKeyUnit = null;
    protected StorageKeyUnit mStorageKeyUnit = null;
    protected Hashtable mAutoRecovery = new Hashtable();
    protected boolean mAutoRecoveryOn = false;
    protected KeyRepository mKeyDB = null;
    protected IRequestNotifier mNotify = null;
    protected IRequestNotifier mPNotify = null;
    protected ISubsystem mOwner = null;
    protected int mRecoveryIDCounter = 0;
    protected Hashtable mRecoveryParams = new Hashtable();
    protected org.mozilla.jss.crypto.X509Certificate mJssCert = null;
    protected CryptoToken mKeygenToken = null;

        // holds the number of bits of entropy to collect for each keygen
        private int mEntropyBitsPerKeyPair=0;

        // the number of milliseconds which it is acceptable to block while
        // getting entropy - anything longer will cause a warning.
        // 0 means this warning is disabled
        private int mEntropyBlockWarnMilliseconds = 0;



    // for the notification listener
    public IRequestListener mReqInQListener = null;

    private ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();
    private final static byte EOL[] = { Character.LINE_SEPARATOR };
    private final static String SIGNED_AUDIT_AGENT_DELIMITER = ", ";
    private final static String
        LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST =
        "LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST_4";
    private final static String
        LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_PROCESSED =
        "LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_PROCESSED_3";
    private final static String LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST =
        "LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST_4";
    private final static String LOGGING_SIGNED_AUDIT_KEY_RECOVERY_PROCESSED =
        "LOGGING_SIGNED_AUDIT_KEY_RECOVERY_PROCESSED_4";

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
    public String getId() {
        return mId;
    }

    /**
     * Sets subsystem identifier.
     *
     * @param id subsystem id
     * @exception EBaseException failed to set id
     */
    public void setId(String id) throws EBaseException {
        mId = id;
    }

    public IPolicyProcessor getPolicyProcessor() {
        return mPolicy.getPolicyProcessor();
    }

    // initialize entropy collection parameters
    private void initEntropy(IConfigStore config)
    {
        mEntropyBitsPerKeyPair = 0;
        mEntropyBlockWarnMilliseconds = 50;
        // initialize entropy collection
        IConfigStore ecs = config.getSubStore("entropy");
        if (ecs != null) {
            try {
                mEntropyBitsPerKeyPair = ecs.getInteger("bitsperkeypair",0);
                mEntropyBlockWarnMilliseconds = ecs.getInteger("blockwarnms",50);
            } catch (EBaseException eb) {
                // ok - we deal with missing parameters above
            }
        }
		CMS.debug("KeyRecoveryAuthority Entropy bits = "+mEntropyBitsPerKeyPair);
        if (mEntropyBitsPerKeyPair == 0) {
            //log(ILogger.LL_INFO,
                //CMS.getLogMessage("CMSCORE_KRA_ENTROPY_COLLECTION_DISABLED"));
        } else {
            //log(ILogger.LL_INFO,
                //CMS.getLogMessage("CMSCORE_KRA_ENTROPY_COLLECTION_ENABLED"));
			CMS.debug("KeyRecoveryAuthority about to add Entropy");
            addEntropy(false);
			CMS.debug("KeyRecoveryAuthority back from add Entropy");
        }

    }


    public void addEntropy(boolean logflag) {
		CMS.debug("KeyRecoveryAuthority addEntropy()");
        if (mEntropyBitsPerKeyPair == 0) {
			CMS.debug("KeyRecoveryAuthority returning - disabled()"); 
			return; 
		}
        long start = System.currentTimeMillis();
        try {
            com.netscape.cmscore.security.JssSubsystem.getInstance().
                addEntropy(mEntropyBitsPerKeyPair);
        } catch (Exception e) {
			CMS.debug("KeyRecoveryAuthority returning - error - see log file"); 
			CMS.debug("exception: "+e.getMessage());
			CMS.debug(e);
			if (logflag) {
            	log(ILogger.LL_INFO,
                	CMS.getLogMessage("CMSCORE_KRA_ENTROPY_ERROR",
                    	e.getMessage()));
			}
        }
        long end   = System.currentTimeMillis();
        long duration = end-start;

        if (mEntropyBlockWarnMilliseconds > 0  &&
            duration > mEntropyBlockWarnMilliseconds) {

			CMS.debug("KeyRecoveryAuthority returning - warning - entropy took too long (ms="+
				duration+")"); 
			if (logflag) {
            	log(ILogger.LL_INFO,
                	CMS.getLogMessage("CMSCORE_KRA_ENTROPY_BLOCKED_WARNING",
                    	""+(int)duration));
			}
        }
		CMS.debug("KeyRecoveryAuthority returning "); 
    }



    /** 
     * Starts this subsystem. It loads and initializes all 
     * necessary components. This subsystem is started by
     * KRASubsystem.
     * <P>
     * 
     * @param owner owner of this subsystem
     * @param config configuration store for this subsystem
     * @exception EBaseException failed to start subsystem
     */
    public void init(ISubsystem owner, IConfigStore config) 
        throws EBaseException {
	CMS.debug("KeyRecoveryAuthority init() begins");
        if (mInitialized)
            return;

        mConfig = config;
        mOwner = owner;

        // initialize policy processor
        mPolicy = new KRAPolicy();
        mPolicy.init(this, mConfig.getSubStore(PROP_POLICY));

        // create key repository
        int keydb_inc = mConfig.getInteger(PROP_KEYDB_INC, 5);

        mKeyDB = new KeyRepository(getDBSubsystem(),
                    keydb_inc,
                    "ou=" + KEY_RESP_NAME + ",ou=" + 
                    getId() + "," +
                    getDBSubsystem().getBaseDN());

        // read transport key from internal database
        mTransportKeyUnit = new TransportKeyUnit();
        try {
          mTransportKeyUnit.init(this, mConfig.getSubStore(
                PROP_TRANSPORT_KEY));
        } catch (EBaseException e) {
            CMS.debug("KeyRecoveryAuthority: transport unit exception " + e.toString());
//XXX            throw e;
	return;
        }

        // retrieve the authority name from transport cert
        try {
            mJssCert = mTransportKeyUnit.getCertificate();
            X509CertImpl certImpl = new 
                X509CertImpl(mJssCert.getEncoded());

            mName = (X500Name) certImpl.getSubjectDN();
        } catch (CertificateEncodingException e) {
            CMS.debug("KeyRecoveryAuthority: " + e.toString());
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_LOAD_FAILED",
                        "transport cert " + e.toString()));
        } catch (CertificateException e) {
            CMS.debug("KeyRecoveryAuthority: " + e.toString());
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_LOAD_FAILED",
                        "transport cert " + e.toString()));
        }

        // read transport key from storage key
        mStorageKeyUnit = new StorageKeyUnit();
        try {
           mStorageKeyUnit.init(this, 
             mConfig.getSubStore(PROP_STORAGE_KEY));
        } catch (EBaseException e) {
            CMS.debug("KeyRecoveryAuthority: storage unit exception " + e.toString());
            throw e;
        }

	// setup token for server-side key generation for user enrollments
	String serverKeygenTokenName = mConfig.getString("serverKeygenTokenName", null);
     if (serverKeygenTokenName == null) {
       CMS.debug("serverKeygenTokenName set to nothing");
       if (mStorageKeyUnit.getToken() != null) {
         try {
           String storageToken = mStorageKeyUnit.getToken().getName();
           if (!storageToken.equals("internal")) {
             CMS.debug("Auto set serverKeygenTokenName to " + storageToken);
             serverKeygenTokenName = storageToken;
           }
         } catch (Exception e) {
         }
       }
     }
     if (serverKeygenTokenName == null) {
         serverKeygenTokenName = "internal";
     } 
        if (serverKeygenTokenName.equalsIgnoreCase(PR_INTERNAL_TOKEN_NAME))
            serverKeygenTokenName = PR_INTERNAL_TOKEN_NAME;

        try {
            if (serverKeygenTokenName.equalsIgnoreCase(PR_INTERNAL_TOKEN_NAME)) {
		CMS.debug("KeyRecoveryAuthority: getting internal crypto token for serverkeygen");
                mKeygenToken = CryptoManager.getInstance().getInternalKeyStorageToken();
            } else {
		CMS.debug("KeyRecoveryAuthority: getting HSM token for serverkeygen");
                mKeygenToken = CryptoManager.getInstance().getTokenByName(serverKeygenTokenName);
            }
	    CMS.debug("KeyRecoveryAuthority: set up keygenToken");
        } catch (NoSuchTokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", serverKeygenTokenName));
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        }

	    CMS.debug("KeyRecoveryAuthority: about to init entropy");
		initEntropy(mConfig);
	    CMS.debug("KeyRecoveryAuthority: completed init of entropy");

        getLogger().log(ILogger.EV_SYSTEM, ILogger.S_KRA, 
            ILogger.LL_INFO, mName.toString() + " is started");

        // setup the KRA request queue
        IService service = new KRAService(this);

        mNotify = new KRANotify(this);
        mPNotify = new ARequestNotifier();
        IRequestSubsystem reqSub = RequestSubsystem.getInstance();
        int reqdb_inc = mConfig.getInteger("reqdbInc", 5);

        mRequestQueue = reqSub.getRequestQueue(getId(), reqdb_inc,
                    mPolicy, service, mNotify, mPNotify);

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
        initNotificationListeners();
    }

    public CryptoToken getKeygenToken() {
	return mKeygenToken;
    }

    public IRequestListener getRequestInQListener() {
        return mReqInQListener;
    }

    public org.mozilla.jss.crypto.X509Certificate getTransportCert() {
        return mJssCert;
    }

    /**
     * Clears up system during garbage collection.
     */
    public void finalize() {
        shutdown();
    }

    /**
     * Starts this service. When this method is called, all
     * service 
     *
     * @exception EBaseException failed to startup this subsystem
     */
    public void startup() throws EBaseException {
	CMS.debug("KeyRecoveryAuthority startup() begins");

	if (mRequestQueue != null) {
        // setup administration operations if everything else is fine
        mRequestQueue.recover();
	CMS.debug("KeyRecoveryAuthority startup() call request Q recover");

        // Note that we use our instance id for registration.
        // This helps us to support multiple instances
        // of a subsystem within server.

        // register remote admin interface
        mInitialized = true;
	} else {
	    CMS.debug("KeyRecoveryAuthority: mRequestQueue is null, could be in preop mode");
	}
    }

    /**
     * Shutdowns this subsystem.
     */
    public void shutdown() {
        if (!mInitialized)
            return;

        mTransportKeyUnit.shutdown();
        mStorageKeyUnit.shutdown();
        getLogger().log(ILogger.EV_SYSTEM, ILogger.S_KRA, 
            ILogger.LL_INFO, mName.toString() + " is stopped");
        mInitialized = false;
    }

    /**
     * Retrieves the configuration store of this subsystem.
     * <P>
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Changes the auto recovery state.
     *
     * @param cs list of recovery agent credentials
     * @param on turn of auto recovery or not
     * @return operation success or not
     */
    public boolean setAutoRecoveryState(Credential cs[], boolean on) {
        if (on == true) {
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
     * @return enable or not
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
     * auto recovery mode
     */
    public Enumeration getAutoRecoveryIDs() {
        return mAutoRecovery.keys();
    }

    /**
     * Adds auto recovery mode to the given user id.
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
     * recovery mode
     */
    public void removeAutoRecovery(String id) {
        mAutoRecovery.remove(id);
    }

    /**
     * Retrieves logger from escrow authority.
     *
     * @return logger
     */
    public ILogger getLogger() {
        return CMS.getLogger();
    }

    /**
     * Retrieves number of required agents for 
     * recovery operation.
     *
     * @return number of required agents
     * @exception EBaseException failed to retrieve info
     */
    public int getNoOfRequiredAgents() throws EBaseException {
        if (mConfig.getBoolean("keySplitting")) {
		    return mStorageKeyUnit.getNoOfRequiredAgents(); 
        } else {
            int ret = -1;
        	ret = mConfig.getInteger("noOfRequiredRecoveryAgents", 1);
            if (ret <= 0) {
              throw new EBaseException("Invalid parameter noOfRequiredecoveryAgents");
            }
            return ret;
        }
    }

    /**
     * Distributed recovery.
     */
    public String getRecoveryID() {
        return Integer.toString(mRecoveryIDCounter++);
    }

    public Hashtable createRecoveryParams(String recoveryID) 
        throws EBaseException {
        Hashtable h = new Hashtable();

        h.put(PARAM_CREDS, new Vector());
        h.put(PARAM_LOCK, new Object());
        mRecoveryParams.put(recoveryID, h);
        return h;
    }

    public void destroyRecoveryParams(String recoveryID) 
        throws EBaseException {
        mRecoveryParams.remove(recoveryID);
    }

    public Hashtable getRecoveryParams(String recoveryID) 
        throws EBaseException {
        return (Hashtable) mRecoveryParams.get(recoveryID);
    }

    public void createPk12(String recoveryID, byte[] pk12)
        throws EBaseException {
        Hashtable h = getRecoveryParams(recoveryID);

        h.put(PARAM_PK12, pk12);
    }

    public byte[] getPk12(String recoveryID)
        throws EBaseException {
        return (byte[]) getRecoveryParams(recoveryID).get(PARAM_PK12);
    }

    public void createError(String recoveryID, String error)
        throws EBaseException {
        Hashtable h = getRecoveryParams(recoveryID);

        h.put(PARAM_ERROR, error);
    }

    public String getError(String recoveryID)
        throws EBaseException {
        return (String) getRecoveryParams(recoveryID).get(PARAM_ERROR);
    }

    /**
     * Retrieve the current approval agents
     */
    public Vector getAppAgents(
        String recoveryID) throws EBaseException {
        Hashtable h = getRecoveryParams(recoveryID);
        Vector dc = (Vector) h.get(PARAM_CREDS);

        return dc;
    }

    /**
     * Retrieves a list credentials. This puts KRA in a waiting
     * mode, it never returns until all the necessary passwords
     * are collected.
     */
    public Credential[] getDistributedCredentials(
        String recoveryID) 
        throws EBaseException {
        Hashtable h = getRecoveryParams(recoveryID);
        Vector dc = (Vector) h.get(PARAM_CREDS);
        Object lock = (Object) h.get(PARAM_LOCK);

        synchronized (lock) {
            while (dc.size() < getNoOfRequiredAgents()) { 
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
    private void verifyCredential(Vector creds, String uid, 
        String pwd) throws EBaseException {
            // see if we have the uid already

        if (!mConfig.getBoolean("keySplitting")) {
              // check if the uid is in the specified group
            IUGSubsystem ug = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);
            if (!ug.isMemberOf(uid, mConfig.getString("recoveryAgentGroup"))) {
              // invalid group
              throw new EBaseException(CMS.getUserMessage("CMS_KRA_CREDENTIALS_NOT_EXIST"));
            }
        }

        for (int i = 0; i < creds.size(); i++) {
            Credential c = (Credential) creds.elementAt(i);

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
     * Adds password.
     */
    public void addDistributedCredential(String recoveryID, 
        String uid, String pwd) throws EBaseException {
        Hashtable h = getRecoveryParams(recoveryID);
        Vector dc = (Vector) h.get(PARAM_CREDS);
        Object lock = (Object) h.get(PARAM_LOCK);

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
     * <li>signed.audit LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST used
     * whenever a user private key archive request is made (this is when the
     * DRM receives the request)
     * <li>signed.audit LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_PROCESSED used
     * whenever a user private key archive request is processed (this is when
     * the DRM processes the request)
     * </ul>
     * @param rec key record to be archived
     * @return executed request
     * @exception EBaseException failed to archive key
     * @return the request
     * <P>
     */
    public IRequest archiveKey(KeyRecord rec) 
        throws EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID();
        String auditPublicKey = auditPublicKey(rec);
        String auditArchiveID = ILogger.UNIDENTIFIED;

        IRequestQueue queue = null;
        IRequest r = null;
        String id = null;

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            queue = getRequestQueue();

            r = queue.newRequest(KRAService.ENROLLMENT);

            if (r != null) {
                // overwrite "auditArchiveID" if and only if "id" != null
                id = r.getRequestId().toString();
                if (id != null) {
                    auditArchiveID = id.trim();
                }
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditRequesterID,
                        auditArchiveID);

            audit(auditMessage);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequesterID,
                        auditArchiveID);

            audit(auditMessage);

            throw eAudit1;
        }

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (r != null) {
                r.setExtData(EnrollmentService.ATTR_KEY_RECORD, rec.getSerialNumber());
                queue.processRequest(r);
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_PROCESSED,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditPublicKey);

            audit(auditMessage);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_PROCESSED,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditPublicKey);

            audit(auditMessage);

            throw eAudit1;
        }

        return r;
    }

    /**
     * Recovers key for administrators. This method is
     * invoked by the agent operation of the key recovery servlet.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST used whenever
     * a user private key recovery request is made (this is when the DRM
     * receives the request)
     * <li>signed.audit LOGGING_SIGNED_AUDIT_KEY_RECOVERY_PROCESSED used whenever
     * a user private key recovery request is processed (this is when the DRM
     * processes the request)
     * </ul>
     * @param kid key identifier
     * @param creds list of recovery agent credentials
     * @param password password of the PKCS12 package
     * @param cert certficate that will be put in PKCS12
     * @param delivery file, mail or something else
     * @param nickname string containing the nickname of the id cert for this
     * subsystem
     * @exception EBaseException failed to recover key
     * @return a byte array containing the key
     */
    public byte[] doKeyRecovery(BigInteger kid,
        Credential creds[], String password, 
        X509CertImpl cert,
        String delivery, String nickname) 
        throws EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRecoveryID = auditRecoveryID();
        String auditPublicKey = auditPublicKey(cert);
        String auditAgents = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        IRequestQueue queue = null;
        IRequest r = null;
        Hashtable params = null;


        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            queue = getRequestQueue();
            r = queue.newRequest(KRAService.RECOVERY);

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

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditRecoveryID,
                        auditPublicKey);

            audit(auditMessage);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRecoveryID,
                        auditPublicKey);

            audit(auditMessage);

            throw eAudit1;
        }

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            queue.processRequest(r);

            if (r.getExtDataInString(IRequest.ERROR) == null) {
                byte pkcs12[] = (byte[]) params.get(
                        RecoveryService.ATTR_PKCS12);

                auditAgents = auditAgents(creds);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_KEY_RECOVERY_PROCESSED,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditRecoveryID,
                            auditAgents);

                audit(auditMessage);

                destroyVolatileRequest(r.getRequestId());

                return pkcs12;
            } else {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_KEY_RECOVERY_PROCESSED,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRecoveryID,
                            auditAgents);

                audit(auditMessage);

                throw new EBaseException(r.getExtDataInString(IRequest.ERROR));
            }
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_KEY_RECOVERY_PROCESSED,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRecoveryID,
                        auditAgents);

            audit(auditMessage);

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
     * @param cert certficate that will be put in PKCS12
     * @param delivery file, mail or something else
     * @return executed request
     * @exception EBaseException failed to recover key
     */
    public IRequest recoverKey(BigInteger kid,
        Credential creds[], String password, 
        X509CertImpl cert,
        String delivery) throws EBaseException {
        IRequestQueue queue = getRequestQueue();
        IRequest r = queue.newRequest("recovery");

        r.setExtData(RecoveryService.ATTR_SERIALNO, kid);
        r.setExtData(RecoveryService.ATTR_TRANSPORT_PWD, password);
        r.setExtData(RecoveryService.ATTR_USER_CERT, cert);
        r.setExtData(RecoveryService.ATTR_DELIVERY, delivery);
        queue.processRequest(r);
        return r;
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
    public IRequest recoverKey(Credential creds[], CertificateChain
        encryptionChain, X509CertImpl signingCert,
        X509CertImpl transportCert,
        X500Name ownerName) throws EBaseException {
        IRequestQueue queue = getRequestQueue();
        IRequest r = queue.newRequest("recovery");

        ByteArrayOutputStream certChainOut = new ByteArrayOutputStream();
        try {
            encryptionChain.encode(certChainOut);
            r.setExtData(RecoveryService.ATTR_ENCRYPTION_CERTS,
                    certChainOut.toByteArray());
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                "Error encoding certificate chain");
        }

        r.setExtData(RecoveryService.ATTR_SIGNING_CERT, signingCert);
        r.setExtData(RecoveryService.ATTR_TRANSPORT_CERT, transportCert);

        DerOutputStream ownerNameOut = new DerOutputStream();
        try {
            ownerName.encode(ownerNameOut);
            r.setExtData(RecoveryService.ATTR_OWNER_NAME,
                    ownerNameOut.toByteArray());
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                "Error encoding X500Name for owner name");
        }

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
    public ITransportKeyUnit getTransportKeyUnit() {
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
     * Returns the nickname for the id cert of this 
     * subsystem.
     *
     * @return nickname of the transport certificate
     */
    public String getNickname() {
        try {
            return mTransportKeyUnit.getNickName();
        } catch (EBaseException e) {
            return null;
        }
    }

    public void setNickname(String str) {
        try {
            mTransportKeyUnit.setNickName(str);
        } catch (EBaseException e) {
        }
    }
       
    public String getNewNickName() throws EBaseException {
        return mConfig.getString(PROP_NEW_NICKNAME, "");
    }
 
    public void setNewNickName(String name) {
        mConfig.putString(PROP_NEW_NICKNAME, name);
    }

    public IPolicy getPolicy() {
        return mPolicy;
    }

    /**
     * Retrieves KRA request repository.
     * <P>
     *
     * @return request repository
     */
    public IRequestQueue getRequestQueue() {
        return mRequestQueue;
    }

    /**
     * Retrieves the key repository. The key repository 
     * stores archived keys.
     * <P>
     */
    public IKeyRepository getKeyRepository() {
        return mKeyDB;
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
     * Retrieves database connection.
     */
    public IDBSubsystem getDBSubsystem() {
        return DBSubsystem.getInstance();
    }

    /**
     * Logs an event.
     *
     * @param level log level
     * @param msg message to log
     */
    public void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_KRA, 
            level, msg);
    }

    /**
     * Registers a request listener.
     *
     * @param l request listener
     */
    public void registerRequestListener(IRequestListener l) {
        // it's initialized.
        if (mNotify != null) 
            mNotify.registerListener(l);
    }

    public void registerPendingListener(IRequestListener l) {
        mPNotify.registerListener(l);
    }

    /**
     * init notification related listeners -
     * right now only RequestInQueue listener is available for KRA
     */
    private void initNotificationListeners() {
        IConfigStore nc = null;

        try {
            nc = mConfig.getSubStore(PROP_NOTIFY_SUBSTORE);
            if (nc != null && nc.size() > 0) {
                // Initialize Request In Queue notification listener
                IConfigStore rq = nc.getSubStore(PROP_REQ_IN_Q_SUBSTORE);
                IAuthority cSub = (IAuthority) this;

                String requestInQListenerClassName = nc.getString("certificateIssuedListenerClassName", "com.netscape.cms.listeners.RequestInQListener");

                try {
                    mReqInQListener = (IRequestListener) Class.forName(requestInQListenerClassName).newInstance();
                    mReqInQListener.init(this, nc);
                } catch (Exception e1) {
                    log(ILogger.LL_FAILURE, 
                        CMS.getLogMessage("CMSCORE_KRA_REGISTER_LISTENER", requestInQListenerClassName));
                }
            } else {
                log(ILogger.LL_INFO, 
                    "No KRA notification Module configuration found");
            }
        } catch (EPropertyNotFound e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSCORE_KRA_NOTIFY_ERROR", e.toString()));
        } catch (EListenersException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSCORE_KRA_NOTIFY_ERROR", e.toString()));
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSCORE_KRA_NOTIFY_ERROR", e.toString()));
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
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_KRA, 
                ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSCORE_KRA_INVALID_RA_NAME", raname, e.toString()));
        } catch (EBaseException e) {
            // ignore - set to null.
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_KRA, 
                ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSCORE_KRA_INVALID_RA_SETUP", e.toString()));
        }
        return new X500Name[] { radn };
    }
	*/

    public Hashtable mVolatileRequests = new Hashtable();

    /**
     * Creates a request object to store attributes that
     * will not be serialized. Currently, request queue
     * framework will try to serialize all the attribute into
     * persistent storage. Things like passwords are not
     * desirable to be stored.
     */
    public Hashtable createVolatileRequest(RequestId id) {
        Hashtable params = new Hashtable();

        mVolatileRequests.put(id.toString(), params);
        return params;
    }

    public Hashtable getVolatileRequest(RequestId id) {
        return (Hashtable) mVolatileRequests.get(id.toString());
    }

    public void destroyVolatileRequest(RequestId id) {
        mVolatileRequests.remove(id.toString());
    }

    public String getOfficialName() {
        return OFFICIAL_NAME;
    }

    /**
     * Signed Audit Log
     *
     * This method is called to store messages to the signed audit log.
     * <P>
     *
     * @param msg signed audit log message
     */
    private void audit(String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (mSignedAuditLogger == null) {
            return;
        }

        mSignedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
            null,
            ILogger.S_SIGNED_AUDIT,
            ILogger.LL_SECURITY,
            msg);
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
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

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
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

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

    /**
     * Signed Audit Log Recovery ID
     *
     * This method is called to obtain the "RecoveryID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message RecoveryID
     */
    private String auditRecoveryID() {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String recoveryID = null;

        // Initialize recoveryID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            recoveryID = (String)
                    auditContext.get(SessionContext.RECOVERY_ID);

            if (recoveryID != null) {
                recoveryID = recoveryID.trim();
            } else {
                recoveryID = ILogger.UNIDENTIFIED;
            }
        } else {
            recoveryID = ILogger.UNIDENTIFIED;
        }

        return recoveryID;
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
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        if (cert == null) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        byte rawData[] = cert.getPublicKey().getEncoded();
        String key = null;

        // convert "rawData" into "base64Data"
        if (rawData != null) {
            String base64Data = null;

            base64Data = CMS.BtoA(rawData).trim();

            // extract all line separators from the "base64Data"
            for (int i = 0; i < base64Data.length(); i++) {
                if (base64Data.substring(i, i).getBytes() != EOL) {
                    key += base64Data.substring(i, i);
                }
            }
        }

        if (key != null) {
            key = key.trim();

            if (key.equals("")) {
                return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
            } else {
                return key;
            }
        } else {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }
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
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

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

            base64Data = CMS.BtoA(rawData).trim();

            // extract all line separators from the "base64Data"
            for (int i = 0; i < base64Data.length(); i++) {
                if (base64Data.substring(i, i).getBytes() != EOL) {
                    key += base64Data.substring(i, i);
                }
            }
        }

        if (key != null) {
            key = key.trim();

            if (key.equals("")) {
                return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
            } else {
                return key;
            }
        } else {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }
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

        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

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
}

