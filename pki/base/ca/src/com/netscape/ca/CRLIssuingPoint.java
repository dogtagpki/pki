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


import java.util.*;
import java.math.*;
import java.io.*;
import java.security.cert.CRLException;
import java.security.NoSuchAlgorithmException;
import netscape.security.x509.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.security.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.cmscore.dbs.*;
import com.netscape.certsrv.dbs.crldb.ICRLRepository;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.publish.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.ca.ICMSCRLExtension;
import com.netscape.cmscore.request.CertRequestConstants;
import com.netscape.cmscore.ldap.*;
import com.netscape.cmscore.util.Debug;


/**
 * This class encapsulates CRL issuing mechanism. CertificateAuthority 
 * contains a map of CRLIssuingPoint indexed by string ids. Each issuing 
 * point contains information about CRL issuing and publishing parameters 
 * as well as state information which includes last issued CRL, next CRL 
 * serial number, time of the next update etc. 
 * If autoUpdateInterval is set to non-zero value then worker thread 
 * is created that will perform CRL update at scheduled intervals. Update 
 * can also be triggered by invoking updateCRL method directly. Another 
 * parameter minUpdateInterval can be used to prevent CRL
 * from being updated too often
 * <P>
 *
 * @author awnuk
 * @author lhsiao
 * @author galperin
 * @version $Revision: 14562 $, $Date: 2007-05-01 10:31:12 -0700 (Tue, 01 May 2007) $
 */

public class CRLIssuingPoint implements ICRLIssuingPoint, Runnable {

    public static final long SECOND = 1000L;
    public static final long MINUTE = (SECOND * 60L);

    private static final int CRL_PAGE_SIZE = 10000;

    /* configuration file property names */

    public IPublisherProcessor mPublisherProcessor = null;

    private ILogger mLogger = CMS.getLogger();

    private IConfigStore mConfigStore;

    private ICRLPublisher mCRLPublisher = null;
    private int mCountMod = 0;
    private int mCount = 0;
    private int mPageSize = CRL_PAGE_SIZE;

    private CMSCRLExtensions mCMSCRLExtensions = null;

    /**
     * Internal unique id of this CRL issuing point.
     */
    protected String mId = null;

    /**
     * Reference to the CertificateAuthority instance which owns this 
     * issuing point.
     */
    protected ICertificateAuthority mCA = null;

    /**
     * Reference to the CRL repository maintained in CA.
     */
    protected ICRLRepository mCRLRepository = null;

    /**
     * Reference to the cert repository maintained in CA.
     */
    private ICertificateRepository mCertRepository = null;

    /**
     * Enable CRL issuing point.
     */
    private boolean mEnable = true;

    /**
     * Description of the issuing point
     */
    private String mDescription = null;

    /**
     * CRL cache
     */
    private Hashtable mCRLCerts = new Hashtable();
    private Hashtable mRevokedCerts = new Hashtable();
    private Hashtable mUnrevokedCerts = new Hashtable();
    private Hashtable mExpiredCerts = new Hashtable();
    private boolean mIncludeExpiredCerts = false;
    private boolean mIncludeExpiredCertsOneExtraTime = false;
    private boolean mCACertsOnly = false;

    private boolean mProfileCertsOnly = false;
    private Vector  mProfileList = null;

    /**
     * Enable CRL cache.
     */
    private boolean mEnableCRLCache = true;
    private boolean mCRLCacheIsCleared = true;
    private boolean mEnableCacheRecovery = false;
    private String  mFirstUnsaved = null;

    /**
     * Last CRL cache update
     */
    private long mLastCacheUpdate = 0;

    /**
     * Time interval in milliseconds between consequential CRL cache 
     * updates performed automatically.
     */
    private long mCacheUpdateInterval;

    /**
     * Enable CRL updates.
     */
    private boolean mEnableCRLUpdates = true;

    /**
     * CRL update schema.
     */
    private int mUpdateSchema = 1;
    private int mSchemaCounter = 0;

    /**
     * Enable CRL daily updates at listed times.
     */
    private boolean mEnableDailyUpdates = false;
    private Vector mDailyUpdates = null; 

    /**
     * Enable CRL auto update with interval
     */
    private boolean mEnableUpdateFreq = false;

    /**
     * Time interval in milliseconds between consequential CRL Enable CRL daily update at updates 
     * performed automatically.
     */
    private long mAutoUpdateInterval;

    /**
     * Minimum time interval in milliseconds between consequential 
     * CRL updates (manual or automatic).
     */
    private long mMinUpdateInterval;

    /**
     * Update CRL even if auto interval > 0
     */
    private boolean mAlwaysUpdate = false;

    /**
     * next update grace period
     */
    private long mNextUpdateGracePeriod; 

    /**
     * Boolean flag controlling whether CRLv2 extensions are to be 
     * used in CRL.
     */
    private boolean mAllowExtensions = false;

    /**
     * DN of the directory entry where CRLs from this issuing point 
     * are published.
     */
    private String mPublishDN = null;

    /**
     * signing algorithm
     */
    private String mSigningAlgorithm = null;
    private String mLastSigningAlgorithm = null;

    /**
     * Cached value of the CRL extensions to be placed in CRL
     */
    //protected CRLExtensions mCrlExtensions;

    /**
     * CRL number
     */
    private BigInteger mCRLNumber;
    private BigInteger mNextCRLNumber;
    private BigInteger mLastCRLNumber;

    /**
     * Delta CRL number
     */
    private BigInteger mDeltaCRLNumber;
    private BigInteger mNextDeltaCRLNumber;

    /**
     * Last CRL update date
     */
    private Date mLastUpdate;
    private Date mLastFullUpdate;

    /**
     * Next scheduled CRL update date
     */
    private Date mNextUpdate;
    private Date mNextDeltaUpdate;
    private boolean mExtendedNextUpdate;

    /**
     * Worker thread doing auto-update
     */
    private Thread mUpdateThread = null;

    /**
     * for going one more round when auto-interval is set to 0 (turned off) 
     */
    private boolean mDoLastAutoUpdate = false;

    /**
     * whether issuing point has been initialized.
     */
    private int mInitialized = CRL_IP_NOT_INITIALIZED;

    /**
     * number of entries in the CRL
     */
    private long mCRLSize = -1;
    private long mDeltaCRLSize = -1;

    /**
     * update status, publishing status Strings to store in requests to 
     * display result.
     */
    private String mCrlUpdateStatus;
    private String mCrlUpdateError;
    private String mCrlPublishStatus;
    private String mCrlPublishError;

    /** 
     * begin, end serial number range of revoked certs if any.
     */
    protected BigInteger mBeginSerial = null;
    protected BigInteger mEndSerial = null;

    private int mUpdatingCRL = CRL_UPDATE_DONE;

    private boolean mDoManualUpdate = false;
    private String  mSignatureAlgorithmForManualUpdate = null;

    private boolean mPublishOnStart = false;
    private long[] mSplits = new long[10];

    /**
     * Constructs a CRL issuing point from instantiating from class name.
     * CRL Issuing point must be followed by method call init(CA, id, config);
     */
    public CRLIssuingPoint() {
    }

    public boolean isCRLIssuingPointEnabled() {
        return mEnable;
    }

    public void enableCRLIssuingPoint(boolean enable) {
        if ((!enable) && (mEnable ^ enable)) {
            clearCRLCache();
            updateCRLCacheRepository();
        }
        mEnable = enable;
        setAutoUpdates();
    }

    public boolean isCRLGenerationEnabled() {
        return mEnableCRLUpdates;
    }

    public String getCrlUpdateStatusStr() {
        return mCrlUpdateStatus;
    }

    public String getCrlUpdateErrorStr() {
        return mCrlUpdateError;
    }

    public String getCrlPublishStatusStr() {
        return mCrlPublishStatus;
    }

    public String getCrlPublishErrorStr() {
        return mCrlPublishError;
    }

    public ICMSCRLExtensions getCRLExtensions() {
        return mCMSCRLExtensions;
    }

    public int isCRLIssuingPointInitialized() {
        return mInitialized;
    }

    public boolean isManualUpdateSet() {
        return mDoManualUpdate;
    }

    public boolean areExpiredCertsIncluded() {
        return mIncludeExpiredCerts;
    }

    public boolean isCACertsOnly() {
        return mCACertsOnly;
    }

    public boolean isProfileCertsOnly() {
        return (mProfileCertsOnly && mProfileList != null && mProfileList.size() > 0);
    }

    public boolean checkCurrentProfile(String id) {
        boolean b = false;

        if (mProfileCertsOnly && mProfileList != null && mProfileList.size() > 0) {
            for (int k = 0; k < mProfileList.size(); k++) {
                String profileId = (String) mProfileList.elementAt(k);
                if (id != null && profileId != null && profileId.equalsIgnoreCase(id)) {
                    b = true;
                    break;
                }
            }
        }
            
        return b;
    }


    /**
     * Initializes a CRL issuing point config.
     * <P>
     *
     * @param ca reference to CertificateAuthority instance which 
     * owns this issuing point.
     * @param id string id of this CRL issuing point.
     * @param config configuration of this CRL issuing point.
     * @exception EBaseException if initialization failed
     * @exception IOException
     */
    public void init(ISubsystem ca, String id, IConfigStore config) 
        throws EBaseException {
        mCA = (ICertificateAuthority) ca;
        mId = id;

        if (mId.equals(ICertificateAuthority.PROP_MASTER_CRL)) {
            mCrlUpdateStatus = IRequest.CRL_UPDATE_STATUS;
            mCrlUpdateError = IRequest.CRL_UPDATE_ERROR;
            mCrlPublishStatus = IRequest.CRL_PUBLISH_STATUS;
            mCrlPublishError = IRequest.CRL_PUBLISH_ERROR;
        } else {
            mCrlUpdateStatus = IRequest.CRL_UPDATE_STATUS + "_" + mId;
            mCrlUpdateError = IRequest.CRL_UPDATE_ERROR + "_" + mId;
            mCrlPublishStatus = IRequest.CRL_PUBLISH_STATUS + "_" + mId;
            mCrlPublishError = IRequest.CRL_PUBLISH_ERROR + "_" + mId;
        }

        mConfigStore = config;

        IConfigStore crlSubStore = mCA.getConfigStore().getSubStore(mCA.PROP_CRL_SUBSTORE);
        mPageSize = crlSubStore.getInteger(mCA.PROP_CRL_PAGE_SIZE, CRL_PAGE_SIZE);
        CMS.debug("CRL Page Size: "+ mPageSize);

        mCountMod = config.getInteger("countMod",0);
        mCRLRepository = mCA.getCRLRepository();
        mCertRepository = mCA.getCertificateRepository();
        ((CertificateRepository) mCertRepository).addCRLIssuingPoint(mId, this);
        mPublisherProcessor = mCA.getPublisherProcessor();

        //mCRLPublisher = mCA.getCRLPublisher();
        ((CAService) mCA.getCAService()).addCRLIssuingPoint(mId, this);

        // read in config parameters.
        initConfig(config);

        // create request listener.
        String lname = RevocationRequestListener.class.getName();
        String crlListName = lname + "_" + mId;

        if (mCA.getRequestListener(crlListName) == null) {
            mCA.registerRequestListener(
                crlListName, new RevocationRequestListener());
        }

        for (int i = 0; i < mSplits.length; i++) {
            mSplits[i] = 0;
        }

        // this will start a thread if necessary for automatic updates.
        setAutoUpdates();
    }


    private int checkTime(String time) {
        String digits = "0123456789";

        int len = time.length();
        if (len < 3 || len > 5) return -1;

        int s = time.indexOf(':');
        if (s < 0 || s > 2 || (len - s) != 3) return -1;

        int h = 0;
        for (int i = 0; i < s; i++) {
            h *= 10;
            int k = digits.indexOf(time.charAt(i));
            if (k < 0) return -1;
            h += k;
        }
        if (h > 23)  return -1;

        int m = 0;
        for (int i = s+1; i < len; i++) {
            m *= 10;
            int k = digits.indexOf(time.charAt(i));
            if (k < 0) return -1;
            m += k;
        }
        if (m > 59)  return -1;

        return ((h * 60) + m);
    }

    private Vector getTimeList(String list) {
        if (list == null) return null;
        if (list.length() > 0 && list.charAt(list.length()-1) == ',') return null;

        Vector listedTimes = new Vector();

        StringTokenizer elements = new StringTokenizer(list, ",", true);
        int t0 = -1;
        int n = 0;
        while (elements.hasMoreTokens()) {
            String element = elements.nextToken().trim();
            if (element == null || element.length() == 0) return null;
            if (element.equals(",") && n % 2 == 0) return null;
            if (n % 2 == 0) {
                int t = checkTime(element);
                if (t < 0) {
                    return null;
                } else {
                    if (t > t0) {
                        listedTimes.addElement(Integer.valueOf(t));
                        t0 = t;
                    } else {
                        return null;
                    }
                }
            }
            n++;
        }
        if (n % 2 == 0) return null;

        return listedTimes;
    }

    private String checkProfile(String id, Enumeration e) {
        if (e != null) {
            while (e.hasMoreElements()) {
                String profileId = (String) e.nextElement();
                if (profileId != null && profileId.equalsIgnoreCase(id))
                    return id;
            }
        }
        return null;
    }

    private Vector getProfileList(String list) {
        Enumeration e = null;
        IConfigStore pc = CMS.getConfigStore().getSubStore("profile");
        if (pc != null) e = pc.getSubStoreNames();
        if (list == null) return null;
        if (list.length() > 0 && list.charAt(list.length()-1) == ',') return null;

        Vector listedProfiles = new Vector();

        StringTokenizer elements = new StringTokenizer(list, ",", true);
        int t0 = -1;
        int n = 0;
        while (elements.hasMoreTokens()) {
            String element = elements.nextToken().trim();
            if (element == null || element.length() == 0) return null;
            if (element.equals(",") && n % 2 == 0) return null;
            if (n % 2 == 0) {
                String id = checkProfile(element, e);
                if (id != null) {
                    listedProfiles.addElement(id);
                }
            }
            n++;
        }
        if (n % 2 == 0) return null;

        return listedProfiles;
    }


    /**
     * get CRL config store info
     */
    protected void initConfig(IConfigStore config)
        throws EBaseException {

        mEnable = config.getBoolean(Constants.PR_ENABLE, true);
        mDescription = config.getString(Constants.PR_DESCRIPTION);

        // Get CRL cache config.
        mEnableCRLCache = config.getBoolean(Constants.PR_ENABLE_CACHE, true);
        mCacheUpdateInterval = MINUTE * config.getInteger(Constants.PR_CACHE_FREQ, 0);
        mEnableCacheRecovery = config.getBoolean(Constants.PR_CACHE_RECOVERY, false);

        // check if CRL generation is enabled
        mEnableCRLUpdates = config.getBoolean(Constants.PR_ENABLE_CRL, true);

        // get update schema
        mUpdateSchema = config.getInteger(Constants.PR_UPDATE_SCHEMA, 1);
        mSchemaCounter = 0;

        // Get always update even if updated perdically.
        mAlwaysUpdate = config.getBoolean(Constants.PR_UPDATE_ALWAYS, false);

        // Get list of daily updates.
        mEnableDailyUpdates = config.getBoolean(Constants.PR_ENABLE_DAILY, false);
        String daily = config.getString(Constants.PR_DAILY_UPDATES, null);
        mDailyUpdates = getTimeList(daily);
        if (mDailyUpdates == null || mDailyUpdates.isEmpty()) {
            mEnableDailyUpdates = false;
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_INVALID_TIME_LIST"));
        }

        // Get auto update interval in minutes.
        mEnableUpdateFreq = config.getBoolean(Constants.PR_ENABLE_FREQ, true);
        mAutoUpdateInterval = MINUTE * config.getInteger(Constants.PR_UPDATE_FREQ, 0);
        mMinUpdateInterval = MINUTE * config.getInteger(PROP_MIN_UPDATE_INTERVAL, 0);
        if (mEnableUpdateFreq && mAutoUpdateInterval > 0 &&
            mAutoUpdateInterval < mMinUpdateInterval)
            mAutoUpdateInterval = mMinUpdateInterval;

        // get next update grace period 
        mNextUpdateGracePeriod = MINUTE * config.getInteger(Constants.PR_GRACE_PERIOD, 0);

        // Get V2 or V1 CRL 
        mAllowExtensions = config.getBoolean(Constants.PR_EXTENSIONS, false);

        mIncludeExpiredCerts = config.getBoolean(Constants.PR_INCLUDE_EXPIREDCERTS, false);
        mIncludeExpiredCertsOneExtraTime = config.getBoolean(Constants.PR_INCLUDE_EXPIREDCERTS_ONEEXTRATIME, false);
        mCACertsOnly = config.getBoolean(Constants.PR_CA_CERTS_ONLY, false);
        mProfileCertsOnly = config.getBoolean(Constants.PR_PROFILE_CERTS_ONLY, false);
        if (mProfileCertsOnly) {
            String profiles = config.getString(Constants.PR_PROFILE_LIST, null);
            mProfileList = getProfileList(profiles);
        }

        // Get default signing algorithm.
        // check if algorithm is supported.
        mSigningAlgorithm = mCA.getCRLSigningUnit().getDefaultAlgorithm();
        String algorithm = config.getString(Constants.PR_SIGNING_ALGORITHM, null);

        if (algorithm != null) {
            // make sure this algorithm is acceptable to CA. 
            mCA.getCRLSigningUnit().checkSigningAlgorithmFromName(algorithm);
            mSigningAlgorithm = algorithm;
        }

        mPublishOnStart = config.getBoolean(PROP_PUBLISH_ON_START, false);
        // if publish dn is null then certificate will be published to 
        // CA's entry in the directory.
        mPublishDN = config.getString(PROP_PUBLISH_DN, null);

        mCMSCRLExtensions = new CMSCRLExtensions(this, config);

        mExtendedNextUpdate = (mUpdateSchema > 1 && isDeltaCRLEnabled())?
                                config.getBoolean(Constants.PR_EXTENDED_NEXT_UPDATE, true):
                                false;

        // Get serial number ranges if any.
        mBeginSerial = config.getBigInteger(PROP_BEGIN_SERIAL, null);
        if (mBeginSerial != null && mBeginSerial.compareTo(BigInteger.ZERO) < 0) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY_1", 
                        PROP_BEGIN_SERIAL, "BigInteger", "positive number"));
        }
        mEndSerial = config.getBigInteger(PROP_END_SERIAL, null);
        if (mEndSerial != null && mEndSerial.compareTo(BigInteger.ZERO) < 0) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY_1", 
                        PROP_END_SERIAL, "BigInteger", "positive number"));
        }
    }

    /**
     * Reads CRL issuing point, if missing, it creates one.
     * Initializes CRL cache and republishes CRL if requested
     * Called from auto update thread (run()).
     * Do not call it from init(), because it will block CMS on start.
     */
    private void initCRL() {
        ICRLIssuingPointRecord crlRecord = null;

        mLastCacheUpdate = System.currentTimeMillis() + mCacheUpdateInterval;

        try {
            crlRecord = mCRLRepository.readCRLIssuingPointRecord(mId);
        } catch (EDBNotAvailException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_INST_CRL", e.toString()));
            mInitialized = CRL_IP_INITIALIZATION_FAILED;
            return;
        } catch (EBaseException e) {
            // CRL was never set.
            // fall to the following.. 
        }

        if (crlRecord != null) {
            mCRLNumber = crlRecord.getCRLNumber();
            if (crlRecord.getCRLSize() != null) {
                mCRLSize = crlRecord.getCRLSize().longValue();
            }
            mNextCRLNumber = mCRLNumber.add(BigInteger.ONE);

            if (crlRecord.getDeltaCRLSize() != null) {
                mDeltaCRLSize = crlRecord.getDeltaCRLSize().longValue();
            }

            mDeltaCRLNumber = crlRecord.getDeltaCRLNumber();
            if (mDeltaCRLNumber == null) {
                mDeltaCRLNumber = mCRLNumber; // better recovery later
            } else {
                if (mDeltaCRLNumber.compareTo(mCRLNumber) < 0) {
                    mDeltaCRLNumber = mCRLNumber;
                    clearCRLCache();
                    mDeltaCRLSize = -1L;
                }
            }
            mNextDeltaCRLNumber = mDeltaCRLNumber.add(BigInteger.ONE);

            if (mNextDeltaCRLNumber.compareTo(mNextCRLNumber) > 0) {
                mNextCRLNumber = mNextDeltaCRLNumber;
            }

            mLastCRLNumber = BigInteger.ZERO;

            mLastUpdate = crlRecord.getThisUpdate();
            if (mLastUpdate == null) {
                mLastUpdate = new Date(0L);
            }
            mLastFullUpdate = null;

            mNextUpdate = crlRecord.getNextUpdate();
            if (isDeltaCRLEnabled()) {
                mNextDeltaUpdate = (mNextUpdate != null)? new Date(mNextUpdate.getTime()): null;
            }

            mFirstUnsaved = crlRecord.getFirstUnsaved();
            if (Debug.on()) {
                Debug.trace("initCRL  CRLNumber="+mCRLNumber.toString()+"  CRLSize="+mCRLSize+
                            "  FirstUnsaved="+mFirstUnsaved);
            }
            if (mFirstUnsaved == null ||
                (mFirstUnsaved != null && mFirstUnsaved.equals(ICRLIssuingPointRecord.NEW_CACHE))) {
                clearCRLCache();
                updateCRLCacheRepository();
            } else {
                byte[] crl = crlRecord.getCRL();

                if (crl != null) {
                    X509CRLImpl x509crl = null;

                    if (mEnableCRLCache || mPublishOnStart) {
                        try {
                            x509crl = new X509CRLImpl(crl);
                        } catch (Exception e) {
                            clearCRLCache();
                            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_DECODE_CRL", e.toString()));
                        } catch (OutOfMemoryError e) {
                            clearCRLCache();
                            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_DECODE_CRL", e.toString()));
                            mInitialized = CRL_IP_INITIALIZATION_FAILED;
                            return;
                        }
                    }
                    if (x509crl != null) {
                        mLastFullUpdate = x509crl.getThisUpdate();
                        if (mEnableCRLCache) {
                            if (mCRLCacheIsCleared && mUpdatingCRL == CRL_UPDATE_DONE) {
                                mRevokedCerts = crlRecord.getRevokedCerts();
                                if (mRevokedCerts == null) {
                                    mRevokedCerts = new Hashtable();
                                }
                                mUnrevokedCerts = crlRecord.getUnrevokedCerts();
                                if (mUnrevokedCerts == null) {
                                    mUnrevokedCerts = new Hashtable();
                                }
                                mExpiredCerts = crlRecord.getExpiredCerts();
                                if (mExpiredCerts == null) {
                                    mExpiredCerts = new Hashtable();
                                }
                                if (isDeltaCRLEnabled()) {
                                    mNextUpdate = x509crl.getNextUpdate();
                                }
                                mCRLCerts = x509crl.getListOfRevokedCertificates();
                            }
                            if (mFirstUnsaved != null && !mFirstUnsaved.equals(ICRLIssuingPointRecord.CLEAN_CACHE)) {
                                recoverCRLCache();
                            } else {
                                mCRLCacheIsCleared = false;
                            }
                            mInitialized = CRL_IP_INITIALIZED;
                        }
                        if (mPublishOnStart) {
                            try {
                                publishCRL(x509crl);
                                x509crl = null;
                            } catch (EBaseException e) {
                                x509crl = null;
                                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_CRL", mCRLNumber.toString(), e.toString()));
                            } catch (OutOfMemoryError e) {
                                x509crl = null;
                                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_CRL", mCRLNumber.toString(), e.toString()));
                            }
                        }
                    }
                }
            }
        }

        if (crlRecord == null) {
            // no crl was ever created, or crl in db is corrupted. 
            // create new one.
            try {
                crlRecord = new CRLIssuingPointRecord(mId, BigInteger.ZERO, Long.valueOf(-1),
                                               null, null, BigInteger.ZERO, Long.valueOf(-1),
                                          mRevokedCerts, mUnrevokedCerts, mExpiredCerts);
                mCRLRepository.addCRLIssuingPointRecord(crlRecord);
                mCRLNumber = BigInteger.ZERO;     //BIG_ZERO;
                mNextCRLNumber = BigInteger.ONE;  //BIG_ONE;
                mLastCRLNumber = mCRLNumber;
                mDeltaCRLNumber = mCRLNumber;
                mNextDeltaCRLNumber = mNextCRLNumber;
                mLastUpdate = new Date(0L);
                if (crlRecord != null) {
                    // This will trigger updateCRLNow, which will also publish CRL.
                    if ((mDoManualUpdate == false) &&
                        (mEnableCRLCache || mAlwaysUpdate ||
                         (mEnableUpdateFreq && mAutoUpdateInterval > 0))) {
                        mInitialized = CRL_IP_INITIALIZED;
                        setManualUpdate(null);
                    }
                }
            } catch (EBaseException ex) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_CREATE_CRL", ex.toString()));
                mInitialized = CRL_IP_INITIALIZATION_FAILED;
                return;
            }
        }
        mInitialized = CRL_IP_INITIALIZED;
    }

    private Object configMonitor = new Object();

    public boolean updateConfig(NameValuePairs params) {
        synchronized (configMonitor) {
            boolean noRestart = true;
            boolean modifiedSchedule = false;

            for (int i = 0; i < params.size(); i++) {
                NameValuePair p = params.elementAt(i);
                String name = p.getName();
                String value = p.getValue();
                
                // -- Update Schema --
                if (name.equals(Constants.PR_ENABLE_CRL)) {
                    if (value.equals(Constants.FALSE) && mEnableCRLUpdates) {
                        mEnableCRLUpdates = false;
                        modifiedSchedule = true;
                    } else if (value.equals(Constants.TRUE) && (!mEnableCRLUpdates)) {
                        mEnableCRLUpdates = true;
                        modifiedSchedule = true;
                    }
                }

                if (name.equals(Constants.PR_UPDATE_SCHEMA)) {
                    try {
                        if (value != null && value.length() > 0) {
                            int schema = Integer.parseInt(value.trim());
                            if (mUpdateSchema != schema) {
                                mUpdateSchema = schema;
                                mSchemaCounter = 0;
                                modifiedSchedule = true;
                            }
                        }
                    } catch (NumberFormatException e) {
                        noRestart = false;
                    }
                }

                if (name.equals(Constants.PR_EXTENDED_NEXT_UPDATE)) {
                    if (value.equals(Constants.FALSE) && mExtendedNextUpdate) {
                        mExtendedNextUpdate = false;
                    } else if (value.equals(Constants.TRUE) && (!mExtendedNextUpdate)) {
                        mExtendedNextUpdate = true;
                    }
                }

                // -- Update Frequency --
                if (name.equals(Constants.PR_UPDATE_ALWAYS)) {
                    if (value.equals(Constants.FALSE) && mAlwaysUpdate) {
                        mAlwaysUpdate = false;
                    } else if (value.equals(Constants.TRUE) && (!mAlwaysUpdate)) {
                        mAlwaysUpdate = true;
                    }
                }

                if (name.equals(Constants.PR_ENABLE_DAILY)) {
                    if (value.equals(Constants.FALSE) && mEnableDailyUpdates) {
                        mEnableDailyUpdates = false;
                        modifiedSchedule = true;
                    } else if (value.equals(Constants.TRUE) && (!mEnableDailyUpdates)) {
                        mEnableDailyUpdates = true;
                        modifiedSchedule = true;
                    }
                }

                if (name.equals(Constants.PR_DAILY_UPDATES)) {
                    Vector dailyUpdates = getTimeList(value);
                    if (((dailyUpdates != null) ^ (mDailyUpdates != null)) ||
                        (dailyUpdates != null && mDailyUpdates != null &&
                        (!mDailyUpdates.equals(dailyUpdates)))) {
                        if (dailyUpdates != null) {
                            mDailyUpdates = (Vector) dailyUpdates.clone();
                        } else {
                            mDailyUpdates = null;
                        }
                        modifiedSchedule = true;
                    }
                    if (mDailyUpdates == null || mDailyUpdates.isEmpty()) {
                        mEnableDailyUpdates = false;
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_INVALID_TIME_LIST"));
                    }
                }

                if (name.equals(Constants.PR_ENABLE_FREQ)) {
                    if (value.equals(Constants.FALSE) && mEnableUpdateFreq) {
                        mEnableUpdateFreq = false;
                        modifiedSchedule = true;
                    } else if (value.equals(Constants.TRUE) && (!mEnableUpdateFreq)) {
                        mEnableUpdateFreq = true;
                        modifiedSchedule = true;
                    }
                }

                if (name.equals(Constants.PR_UPDATE_FREQ)) {
                    try {
                        if (value != null && value.length() > 0) {
                            long t = MINUTE * Long.parseLong(value.trim());
                            if (mAutoUpdateInterval != t) {
                                mAutoUpdateInterval = t;
                                modifiedSchedule = true;
                            }
                        } else {
                            if (mAutoUpdateInterval != 0) {
                                mAutoUpdateInterval = 0;
                                modifiedSchedule = true;
                            }
                        }
                    } catch (NumberFormatException e) {
                        noRestart = false;
                    }
                }

                if (name.equals(Constants.PR_GRACE_PERIOD)) {
                    try {
                        if (value != null && value.length() > 0) {
                            mNextUpdateGracePeriod = MINUTE * Long.parseLong(value.trim());
                        }
                    } catch (NumberFormatException e) {
                        noRestart = false;
                    }
                }

                // -- CRL Cache --
                if (name.equals(Constants.PR_ENABLE_CACHE)) {
                    if (value.equals(Constants.FALSE) && mEnableCRLCache) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mEnableCRLCache = false;
                        modifiedSchedule = true;
                    } else if (value.equals(Constants.TRUE) && (!mEnableCRLCache)) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mEnableCRLCache = true;
                        modifiedSchedule = true;
                    }
                }

                if (name.equals(Constants.PR_CACHE_FREQ)) {
                    try {
                        if (value != null && value.length() > 0) {
                            long t = MINUTE * Long.parseLong(value.trim());
                            if (mCacheUpdateInterval != t) {
                                mCacheUpdateInterval = t;
                                modifiedSchedule = true;
                            }
                        }
                    } catch (NumberFormatException e) {
                        noRestart = false;
                    }
                }

                if (name.equals(Constants.PR_CACHE_RECOVERY)) {
                    if (value.equals(Constants.FALSE) && mEnableCacheRecovery) {
                        mEnableCacheRecovery = false;
                    } else if (value.equals(Constants.TRUE) && (!mEnableCacheRecovery)) {
                        mEnableCacheRecovery = true;
                    }
                }

                // -- CRL Format --
                if (name.equals(Constants.PR_SIGNING_ALGORITHM)) {
                    if (value != null) value = value.trim();
                    if (!mSigningAlgorithm.equals(value)) {
                        mSigningAlgorithm = value;
                    }
                }

                if (name.equals(Constants.PR_EXTENSIONS)) {
                    if (value.equals(Constants.FALSE) && mAllowExtensions) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mAllowExtensions = false;
                    } else if (value.equals(Constants.TRUE) && (!mAllowExtensions)) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mAllowExtensions = true;
                    }
                }

                if (name.equals(Constants.PR_INCLUDE_EXPIREDCERTS)) {
                    if (value.equals(Constants.FALSE) && mIncludeExpiredCerts) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mIncludeExpiredCerts = false;
                    } else if (value.equals(Constants.TRUE) && (!mIncludeExpiredCerts)) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mIncludeExpiredCerts = true;
                    }
                }

                if (name.equals(Constants.PR_INCLUDE_EXPIREDCERTS_ONEEXTRATIME)) {
                    if (value.equals(Constants.FALSE) && mIncludeExpiredCertsOneExtraTime) {
                        mIncludeExpiredCertsOneExtraTime = false;
                    } else if (value.equals(Constants.TRUE) && (!mIncludeExpiredCertsOneExtraTime)) {
                        mIncludeExpiredCertsOneExtraTime = true;
                    }
                }

                if (name.equals(Constants.PR_CA_CERTS_ONLY)) {
                    if (value.equals(Constants.FALSE) && mCACertsOnly) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mCACertsOnly = false;
                    } else if (value.equals(Constants.TRUE) && (!mCACertsOnly)) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mCACertsOnly = true;
                    }
                }

                if (name.equals(Constants.PR_PROFILE_CERTS_ONLY)) {
                    if (value.equals(Constants.FALSE) && mProfileCertsOnly) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mProfileCertsOnly = false;
                    } else if (value.equals(Constants.TRUE) && (!mProfileCertsOnly)) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mProfileCertsOnly = true;
                    }
                }

                if (name.equals(Constants.PR_PROFILE_LIST)) {
                    Vector profileList = getProfileList(value);
                    if (((profileList != null) ^ (mProfileList != null)) ||
                        (profileList != null && mProfileList != null &&
                        (!mProfileList.equals(profileList)))) {
                        if (profileList != null) {
                            mProfileList = (Vector) profileList.clone();
                        } else {
                            mProfileList = null;
                        }
                        clearCRLCache();
                        updateCRLCacheRepository();
                    }
                    if (mProfileList == null || mProfileList.isEmpty()) {
                        mProfileCertsOnly = false;
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_INVALID_PROFILE_LIST"));
                    }
                }
            }

            if (modifiedSchedule) setAutoUpdates();

            return noRestart;
        }
    }

    /**
     * This method is called during shutdown.
     * <P>
     */
    public synchronized void shutdown() {
        // this should stop a thread if necessary
        if (mEnableCRLCache && mCacheUpdateInterval > 0) {
            updateCRLCacheRepository();
        }
        mEnable = false;

        setAutoUpdates();
        if (mUpdateThread != null)
            mUpdateThread.destroy();
    }

    /**
     * Returns internal id of this CRL issuing point.
     * <P>
     *
     * @return internal id of this CRL issuing point
     */
    public String getId() {
        return mId;
    }

    /**
     * Returns internal description of this CRL issuing point.
     * <P>
     *
     * @return internal description of this CRL issuing point
     */
    public String getDescription() {
        return mDescription;
    }

    /**
     * Sets internal description of this CRL issuing point.
     *
     * @param description description for this CRL issuing point.
     */
    public void setDescription(String description) {
        mDescription = description;
    }

    /**
     * Returns DN of the directory entry where CRLs.from this issuing point
     * are published.
     * <P>
     *
     * @return DN of the directory entry where CRLs are published.
     */
    public String getPublishDN() {
        return mPublishDN;
    }

    /**
     * Returns signing algorithm.
     * <P>
     *
     * @return SigningAlgorithm.
     */
    public String getSigningAlgorithm() {
        return mSigningAlgorithm;
    }

    public String getLastSigningAlgorithm() {
        return mLastSigningAlgorithm;
    }

    /**
     * Returns current CRL generation schema for this CRL issuing point.
     * <P>
     *
     * @return current CRL generation schema for this CRL issuing point
     */
    public int getCRLSchema() {
        return mUpdateSchema;
    }

    /**
     * Returns current CRL number of this CRL issuing point.
     * <P>
     *
     * @return current CRL number of this CRL issuing point
     */
    public BigInteger getCRLNumber() {
        return mCRLNumber;
    }

    /**
     * Returns current delta CRL number of this CRL issuing point.
     * <P>
     *
     * @return current delta CRL number of this CRL issuing point
     */
    public BigInteger getDeltaCRLNumber() {
        return (isDeltaCRLEnabled() && mDeltaCRLSize > -1)? mDeltaCRLNumber: BigInteger.ZERO;
    }

    /**
     * Returns next CRL number of this CRL issuing point.
     * <P>
     *
     * @return next CRL number of this CRL issuing point
     */
    public BigInteger getNextCRLNumber() {
        return mNextDeltaCRLNumber;
    }

    /**
     * Returns number of entries in the CRL
     * <P>
     *
     * @return number of entries in the CRL
     */
    public long getCRLSize() {
        return (mCRLCerts.size() > 0 && mCRLSize == 0)? mCRLCerts.size(): mCRLSize;
    }

    /**
     * Returns number of entries in delta CRL
     * <P>
     *
     * @return number of entries in delta CRL
     */
    public long getDeltaCRLSize() {
        return mDeltaCRLSize;
    }

    /**
     * Returns last update time
     * <P>
     *
     * @return last CRL update time
     */
    public Date getLastUpdate() {
        return mLastUpdate;
    }

    /**
     * Returns next update time
     * <P>
     *
     * @return next CRL update time
     */
    public Date getNextUpdate() {
        return mNextUpdate;
    }

    /**
     * Returns next update time
     * <P>
     *
     * @return next CRL update time
     */
    public Date getNextDeltaUpdate() {
        return mNextDeltaUpdate;
    }

    /**
     * Returns all the revoked certificates from the CRL cache.
     * <P>
     *
     * @return set of all the revoked certificates or null if there are none.
     */
    public Set getRevokedCertificates(int start, int end) {
        if (mCRLCacheIsCleared || mCRLCerts == null || mCRLCerts.isEmpty()) {
            return null;
        } else {
            ArraySet certSet = new ArraySet();
            Collection badCerts = mCRLCerts.values();
            Object[] objs = badCerts.toArray();
            for (int i = start; i < end && i < objs.length; i++)
                certSet.add(objs[i]);
            return certSet;
        }
    }

    /**
     * Returns certificate authority.
     * <P>
     *
     * @return certificate authority
     */
    public ISubsystem getCertificateAuthority() {
        return mCA;
    }

    /**
     * Sets CRL auto updates
     */

    private synchronized void setAutoUpdates() {
        if ((mEnable && mUpdateThread == null) &&
            ((mEnableCRLCache && mCacheUpdateInterval > 0) ||
             (mEnableCRLUpdates &&
              ((mEnableDailyUpdates && mDailyUpdates != null &&
                mDailyUpdates.size() > 0) ||
               (mEnableUpdateFreq && mAutoUpdateInterval > 0) ||
               (mInitialized == CRL_IP_NOT_INITIALIZED) ||
                mDoLastAutoUpdate || mDoManualUpdate)))) {
            mUpdateThread = new Thread(this, "CRLIssuingPoint-" + mId);
            log(ILogger.LL_INFO, CMS.getLogMessage("CMSCORE_CA_ISSUING_START_CRL", mId));
            mUpdateThread.setDaemon(true);
            mUpdateThread.start();
        }

        if ((mInitialized == CRL_IP_INITIALIZED) && (((mNextUpdate != null) ^
            ((mEnableDailyUpdates && mDailyUpdates != null && mDailyUpdates.size() > 0) ||
             (mEnableUpdateFreq && mAutoUpdateInterval > 0))) ||
             (!mEnableCRLUpdates && mNextUpdate != null))) {
             mDoLastAutoUpdate = true;
        }

        if (mEnableUpdateFreq && mAutoUpdateInterval > 0 &&
            mAutoUpdateInterval < mMinUpdateInterval) {
            mAutoUpdateInterval = mMinUpdateInterval;
        }

        notifyAll();
    }

    /**
     * Sets CRL manual-update 
     * Starts or stops worker thread as necessary.
     */
    public synchronized void setManualUpdate(String signatureAlgorithm) {
        if (!mDoManualUpdate) {
            mDoManualUpdate = true;
            mSignatureAlgorithmForManualUpdate = signatureAlgorithm;
            if (mEnableUpdateFreq && mAutoUpdateInterval > 0 && mUpdateThread != null) {
                notifyAll();
            } else {
                setAutoUpdates();
            }
        }
    }

    /**
     * @return auto update interval in milliseconds.
     */
    public long getAutoUpdateInterval() {
        return (mEnableUpdateFreq)? mAutoUpdateInterval: 0;
    }

    /**
     * @return always update the CRL 
     */
    public boolean getAlwaysUpdate() { 
        return mAlwaysUpdate;
    }

    /**
     * @return next update grace period in minutes.
     */

    public long getNextUpdateGracePeriod() {
        return mNextUpdateGracePeriod;
    }


    private long findNextUpdate(boolean fromLastUpdate, boolean delta) {
        long now = System.currentTimeMillis();
        TimeZone tz = TimeZone.getDefault();
        int offset = tz.getOffset(now);
        long oneDay = 1440L * MINUTE;
        long nowToday = (now + (long)offset) % oneDay;
        long startOfToday = now - nowToday;

        long lastUpdate = (mLastUpdate != null && fromLastUpdate)? mLastUpdate.getTime(): now;
        long last = (lastUpdate + (long)offset) % oneDay;
        long lastDay = lastUpdate - last;

        boolean isDeltaEnabled = isDeltaCRLEnabled();
        long next = 0L;
        long nextUpdate = 0L;

        if ((delta || fromLastUpdate) && isDeltaEnabled &&
            mUpdateSchema > 1 && mNextDeltaUpdate != null) {
            nextUpdate = mNextDeltaUpdate.getTime();
        } else if (mNextUpdate != null) {
            nextUpdate = mNextUpdate.getTime();
        }

        if (mEnableDailyUpdates &&
            mDailyUpdates != null && mDailyUpdates.size() > 0) {
            long firstTime = MINUTE * ((Integer)mDailyUpdates.elementAt(0)).longValue();
            int n = 0;
            if (mDailyUpdates.size() == 1 &&
                mEnableUpdateFreq && mAutoUpdateInterval > 0) {
                long t = firstTime;
                long interval = mAutoUpdateInterval;
                if (mExtendedNextUpdate && (!fromLastUpdate) && (!delta) &&
                    isDeltaEnabled && mUpdateSchema > 1) {
                    interval *= mUpdateSchema;
                }
                while  (t < oneDay) {
                    if (t - mMinUpdateInterval > last) break;
                    t += interval;
                    n++;
                }
                n = n % mUpdateSchema;

                if (t <= oneDay) {
                    next = lastDay + t;
                    if (t == firstTime && fromLastUpdate) {
                        mSchemaCounter = 0;
                    } else if (n != mSchemaCounter && fromLastUpdate) {
                        if (mSchemaCounter != 0 && (mSchemaCounter < n || n == 0)) {
                            mSchemaCounter = n;
                        }
                    }
                } else {
                    next = lastDay + oneDay + firstTime;
                    if (fromLastUpdate) {
                        mSchemaCounter = 0;
                    }
                }
            } else {
                int k = 1;
                if ((!fromLastUpdate) && (!delta) &&
                    isDeltaEnabled && mUpdateSchema > 1) {
                    k = mUpdateSchema;
                }
                int i;
                for (i = 0; i < mDailyUpdates.size(); i += k) {
                    long t = MINUTE * ((Integer)mDailyUpdates.elementAt(i)).longValue();
                    if (t - mMinUpdateInterval > last) break;
                    n++;
                }
                n = n % mUpdateSchema;

                if (i < mDailyUpdates.size()) {
                    next = lastDay + (MINUTE * ((Integer)mDailyUpdates.elementAt(i)).longValue());
                    if (i == 0 && fromLastUpdate) {
                        mSchemaCounter = 0;
                    } else if (n != mSchemaCounter && fromLastUpdate) {
                        if (mSchemaCounter != 0 && (mSchemaCounter < n || n == 0)) {
                            mSchemaCounter = n;
                        }
                    }
                } else {
                    // done with today
                    next = lastDay + oneDay + firstTime;
                    if (fromLastUpdate) {
                        mSchemaCounter = 0;
                    }
                }
            }
        } else if (mEnableUpdateFreq && mAutoUpdateInterval > 0) {
            if (!delta &&  isDeltaEnabled && mUpdateSchema > 1) {
                next = lastUpdate + (mUpdateSchema * mAutoUpdateInterval);
            } else {
                next = lastUpdate + mAutoUpdateInterval;
            }
        }

        if (fromLastUpdate && nextUpdate > 0 && nextUpdate < next) {
            next = nextUpdate;
        }

        return (fromLastUpdate)? next-now: next;
    }


    /**
     * Implements Runnable interface. Defines auto-update 
     * logic used by worker thread.
     * <P>
     */
    public void run() {
        while (mEnable && ((mEnableCRLCache && mCacheUpdateInterval > 0) ||
                           (mInitialized == CRL_IP_NOT_INITIALIZED) ||
                            mDoLastAutoUpdate || (mEnableCRLUpdates &&
                            ((mEnableDailyUpdates && mDailyUpdates != null &&
                              mDailyUpdates.size() > 0) ||
                             (mEnableUpdateFreq && mAutoUpdateInterval > 0) ||
                              mDoManualUpdate)))) {

            synchronized (this) {
                long delay = 0;
                long delay2 = 0;
                boolean doCacheUpdate = false;
                boolean scheduledUpdates = mEnableCRLUpdates &&
                    ((mEnableDailyUpdates && mDailyUpdates != null &&
                      mDailyUpdates.size() > 0) ||
                    (mEnableUpdateFreq && mAutoUpdateInterval > 0));

                if (mInitialized == CRL_IP_NOT_INITIALIZED)
                    initCRL();
                if (mInitialized == CRL_IP_INITIALIZED && (!mEnable)) break;

                if ((mEnableCRLUpdates && mDoManualUpdate) || mDoLastAutoUpdate) {
                    delay = 0;
                } else if (scheduledUpdates) {
                    delay = findNextUpdate(true, false);
                }

                if (mEnableCRLCache && mCacheUpdateInterval > 0) {
                    delay2 = mLastCacheUpdate + mCacheUpdateInterval -
                             System.currentTimeMillis();
                    if (delay2 < delay ||
                        (!(scheduledUpdates || mDoLastAutoUpdate ||
                           (mEnableCRLUpdates && mDoManualUpdate)))) {
                        delay = delay2;
                        if (delay <= 0) {
                            doCacheUpdate = true;
                            mLastCacheUpdate = System.currentTimeMillis();
                        }
                    }
                }

                if (delay > 0) {
                    try { 
                        wait(delay);
                    } catch (InterruptedException e) {
                    }
                } else {
                    try {
                        if (doCacheUpdate) {
                            updateCRLCacheRepository();
                        } else if (mAutoUpdateInterval > 0 || mDoLastAutoUpdate || mDoManualUpdate) {
                            updateCRL();
                        }
                    } catch (Exception e) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_CRL",
                            (doCacheUpdate)?"update CRL cache":"update CRL", e.toString()));
                        if (Debug.on()) {
                            Debug.trace((doCacheUpdate)?"update CRL cache":"update CRL" + " error " + e);
                            Debug.printStackTrace(e);
                        }
                    }
                    // put this here to prevent continuous loop if internal 
                    // db is down.
                    if (mDoLastAutoUpdate)
                        mDoLastAutoUpdate = false;
                    if (mDoManualUpdate) {
                        mDoManualUpdate = false;
                        mSignatureAlgorithmForManualUpdate = null;
                    }
                }
            }
        }
        mUpdateThread = null;
    }


    /**
     * Updates CRL and publishes it.  
     * If time elapsed since last CRL update is less than 
     * minUpdateInterval silently returns.
     * Otherwise determines nextUpdate by adding autoUpdateInterval or 
     * minUpdateInterval to the current time. If neither of the 
     * intervals are defined nextUpdate will be null.
     * Then using specified configuration parameters it formulates new 
     * CRL, signs it, updates CRLIssuingPointRecord in the database 
     * and publishes CRL in the directory.
     * <P>
     */
    private void updateCRL() throws EBaseException {
        /*
        if (mEnableUpdateFreq && mAutoUpdateInterval > 0 && 
            (System.currentTimeMillis() - mLastUpdate.getTime() < 
                mMinUpdateInterval)) {
            // log or alternatively throw an Exception
            return;
        }
        */
        if (mDoManualUpdate && mSignatureAlgorithmForManualUpdate != null) {
            updateCRLNow(mSignatureAlgorithmForManualUpdate);
        } else {
            updateCRLNow();
        }
    }

    /**
     * This method may be overrided by CRLWithExpiredCerts.java
     */
    public String getFilter() {
        // PLEASE DONT CHANGE THE FILTER. It is indexed.
        // Changing it will degrade performance. See
        // also com.netscape.certsetup.LDAPUtil.java
        String filter = "";

        if (mIncludeExpiredCerts)
            filter += "(|";
        filter += "(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED + ")";
        if (mIncludeExpiredCerts)
            filter += "(" + CertRecord.ATTR_CERT_STATUS + "=" + CertRecord.STATUS_REVOKED_EXPIRED + "))";

        if (mCACertsOnly) {
            filter += "(x509cert.BasicConstraints.isCA=on)";
        }

        if (mProfileCertsOnly && mProfileList != null && mProfileList.size() > 0) {
            if (mProfileList.size() > 1) {
                filter += "(|";
            }
            for (int k = 0; k < mProfileList.size(); k++) {
                String id = (String) mProfileList.elementAt(k);
                filter += "(" + CertRecord.ATTR_META_INFO + "=profileId:" + id + ")";
            }
            if (mProfileList.size() > 1) {
                filter += ")";
            }
        }

        // check if any ranges specified.
        if (mBeginSerial != null) {
            filter += "(" + CertRecord.ATTR_ID + ">=" + mBeginSerial.toString() + ")";
        }
        if (mEndSerial != null) {
            filter += "(" + CertRecord.ATTR_ID + "<=" + mEndSerial.toString() + ")";
        }

        // get all revoked non-expired certs.
        if (mEndSerial != null || mBeginSerial != null || mCACertsOnly ||
            (mProfileCertsOnly && mProfileList != null && mProfileList.size() > 0)) {
            filter = "(&" + filter + ")";
        }

        return filter;
    }

    /**
     * Gets a enumeration of revoked certs to put into CRL.
     * This does not include expired certs.
     * <i>Override this method to make a CRL other than the 
     * full/complete CRL.</i>
     * @return Enumeration of CertRecords to put into CRL. 
     * @exception EBaseException if an error occured in the database.
     */
    public void processRevokedCerts(IElementProcessor p)
        throws EBaseException {
        CertRecProcessor cp = (CertRecProcessor) p;
        String filter = getFilter();

        // NOTE: dangerous cast. 
        // correct way would be to modify interface and add
        // accessor but we don't want to touch the interface
        CertificateRepository cr = (CertificateRepository)mCertRepository;

        CMS.debug("About to start processRevokedCerts");
        synchronized (cr.mCertStatusUpdateThread) {
            CMS.debug("Starting processRevokedCerts (entered lock)");
            ICertRecordList list = mCertRepository.findCertRecordsInList(filter,
                    new String[] {ICertRecord.ATTR_ID, ICertRecord.ATTR_REVO_INFO, "objectclass" },
                    "serialno",
                    mPageSize);

            int totalSize = list.getSize();

            list.processCertRecords(0, totalSize - 1, cp);
            CMS.debug("processRevokedCerts done");
        }
    }

    /**
     * clears CRL cache
     */
    public void clearCRLCache() {
        mCRLCacheIsCleared = true;
        mCRLCerts.clear();
        mRevokedCerts.clear();
        mUnrevokedCerts.clear();
        mExpiredCerts.clear();
        mSchemaCounter = 0;
    }

    /**
     * clears Delta-CRL cache
     */
    public void clearDeltaCRLCache() {
        mRevokedCerts.clear();
        mUnrevokedCerts.clear();
        mExpiredCerts.clear();
        mSchemaCounter = 0;
    }

    /**
     * recovers CRL cache
     */
    private void recoverCRLCache() {
        if (mEnableCacheRecovery) {
            String filter = "(requeststate=complete)";
            if (Debug.on()) {
                Debug.trace("recoverCRLCache  mFirstUnsaved="+mFirstUnsaved+"  filter="+filter);
            }
            IRequestQueue mQueue = mCA.getRequestQueue();

            IRequestVirtualList list = mQueue.getPagedRequestsByFilter(
                        new RequestId(mFirstUnsaved), filter, 500, "requestId");
            if (Debug.on()) {
                Debug.trace("recoverCRLCache  size="+list.getSize()+"  index="+list.getCurrentIndex());
            }

            int s = list.getSize() - list.getCurrentIndex();
            for (int i = 0; i < s; i++) {
                IRequest request = null;
                try {
                    request = list.getElementAt(i);
                } catch (Exception e) {
                    // handled below
                }
                if (request == null) {
                    continue;
                }
                if (Debug.on()) {
                    Debug.trace("recoverCRLCache  request="+request.getRequestId().toString()+
                                "  type="+request.getRequestType());
                }
                if (IRequest.REVOCATION_REQUEST.equals(request.getRequestType())) {
                    RevokedCertImpl revokedCert[] =
                        request.getExtDataInRevokedCertArray(IRequest.CERT_INFO);
                    for (int j = 0; j < revokedCert.length; j++) {
                        if (Debug.on()) {
                            Debug.trace("recoverCRLCache R j="+j+"  length="+revokedCert.length+
                                        "  SerialNumber=0x"+revokedCert[j].getSerialNumber().toString(16));
                        }
                        updateRevokedCert(REVOKED_CERT, revokedCert[j].getSerialNumber(), revokedCert[j]);
                    }
                } else if (IRequest.UNREVOCATION_REQUEST.equals(request.getRequestType())) {
                    BigInteger serialNo[] = request.getExtDataInBigIntegerArray(IRequest.OLD_SERIALS);
                    for (int j = 0; j < serialNo.length; j++) {
                        if (Debug.on()) {
                            Debug.trace("recoverCRLCache U j="+j+"  length="+serialNo.length+
                                        "  SerialNumber=0x"+serialNo[j].toString(16));
                        }
                        updateRevokedCert(UNREVOKED_CERT, serialNo[j], null);
                    }
                }
            }

            try {
                mCRLRepository.updateRevokedCerts(mId, mRevokedCerts, mUnrevokedCerts);
                mFirstUnsaved = ICRLIssuingPointRecord.CLEAN_CACHE;
                mCRLCacheIsCleared = false;
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_CRL_CACHE", e.toString()));
            }
        } else {
            clearCRLCache();
            updateCRLCacheRepository();
        }
    }

    public int getNumberOfRecentlyRevokedCerts() {
        return mRevokedCerts.size();
    }

    public int getNumberOfRecentlyUnrevokedCerts() {
        return mUnrevokedCerts.size();
    }

    public int getNumberOfRecentlyExpiredCerts() {
        return mExpiredCerts.size();
    }

    /**
     * get required crl entry extensions
     */
    public CRLExtensions getRequiredEntryExtensions(CRLExtensions exts) {
        CRLExtensions entryExt = null;

        if (mAllowExtensions && exts != null && exts.size() > 0) {
            entryExt = new CRLExtensions();
            Vector extNames = mCMSCRLExtensions.getCRLEntryExtensionNames();

            for (int i = 0; i < extNames.size(); i++) {
                String extName = (String) extNames.elementAt(i);

                if (mCMSCRLExtensions.isCRLExtensionEnabled(extName)) {
                    int k;

                    for (k = 0; k < exts.size(); k++) {
                        Extension ext = (Extension) exts.elementAt(k);
                        String name = mCMSCRLExtensions.getCRLExtensionName(
                                ext.getExtensionId().toString());

                        if (extName.equals(name)) {
                            if (!(ext instanceof CRLReasonExtension) ||
                                (((CRLReasonExtension) ext).getReason().toInt() >
                                    RevocationReason.UNSPECIFIED.toInt())) {
                                mCMSCRLExtensions.addToCRLExtensions(entryExt, extName, ext);
                            }
                            break;
                        }
                    }
                    if (k == exts.size()) {
                        mCMSCRLExtensions.addToCRLExtensions(entryExt, extName, null);
                    }
                }
            }
        }

        return entryExt;
    }

    private static final int REVOKED_CERT = 1;
    private static final int UNREVOKED_CERT = 2;
    private Object cacheMonitor = new Object();

    /**
     * update CRL cache with new revoked-unrevoked certificate info
     */
    private void updateRevokedCert(int certType,
                                   BigInteger serialNumber,
                                   RevokedCertImpl revokedCert) {
        updateRevokedCert(certType, serialNumber, revokedCert, null);
    }

    private void updateRevokedCert(int certType,
                                   BigInteger serialNumber,
                                   RevokedCertImpl revokedCert,
                                   String requestId) {
        synchronized (cacheMonitor) {
            if (requestId != null && mFirstUnsaved != null &&
                mFirstUnsaved.equals(ICRLIssuingPointRecord.CLEAN_CACHE)) {
                mFirstUnsaved = requestId;
                try {
                    mCRLRepository.updateFirstUnsaved(mId, mFirstUnsaved);
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_CRL_CACHE", e.toString()));
                }
            }
            if (certType == REVOKED_CERT) {
                if (mUnrevokedCerts.containsKey(serialNumber)) {
                    mUnrevokedCerts.remove(serialNumber);
                    if (mCRLCerts.containsKey(serialNumber)) {
                        Date revocationDate = revokedCert.getRevocationDate();
                        CRLExtensions entryExt = getRequiredEntryExtensions(revokedCert.getExtensions());
                        RevokedCertImpl newRevokedCert =
                            new RevokedCertImpl(serialNumber, revocationDate, entryExt);

                        mCRLCerts.put(serialNumber, (RevokedCertificate) newRevokedCert);
                    }
                } else {
                    Date revocationDate = revokedCert.getRevocationDate();
                    CRLExtensions entryExt = getRequiredEntryExtensions(revokedCert.getExtensions());
                    RevokedCertImpl newRevokedCert =
                        new RevokedCertImpl(serialNumber, revocationDate, entryExt);

                    mRevokedCerts.put(serialNumber, (RevokedCertificate) newRevokedCert);
                }
            } else if (certType == UNREVOKED_CERT) {
                if (mRevokedCerts.containsKey(serialNumber)) {
                    mRevokedCerts.remove(serialNumber);
                } else {
                    CRLExtensions entryExt = new CRLExtensions();

                    try {
                        entryExt.set(CRLReasonExtension.REMOVE_FROM_CRL.getName(),
                            CRLReasonExtension.REMOVE_FROM_CRL);
                    } catch (IOException e) {
                    }
                    RevokedCertImpl newRevokedCert = new RevokedCertImpl(serialNumber,
                            CMS.getCurrentDate(), entryExt);

                    mUnrevokedCerts.put(serialNumber, (RevokedCertificate) newRevokedCert);
                }
            }
        }
    }

    /**
     * registers revoked certificates
     */
    public void addRevokedCert(BigInteger serialNumber, RevokedCertImpl revokedCert) {
        addRevokedCert(serialNumber, revokedCert, null);
    }

    public void addRevokedCert(BigInteger serialNumber, RevokedCertImpl revokedCert,
                               String requestId) {
        if (mEnable && mEnableCRLCache) {
            updateRevokedCert(REVOKED_CERT, serialNumber, revokedCert, requestId);

            if (mCacheUpdateInterval == 0) {
                try {
                    mCRLRepository.updateRevokedCerts(mId, mRevokedCerts, mUnrevokedCerts);
                    mFirstUnsaved = ICRLIssuingPointRecord.CLEAN_CACHE;
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_REVOKED_CERT", mId, e.toString()));
                }
            }
        }
    }

    /**
     * registers unrevoked certificates
     */
    public void addUnrevokedCert(BigInteger serialNumber) {
        addUnrevokedCert(serialNumber, null);
    }

    public void addUnrevokedCert(BigInteger serialNumber, String requestId) {
        if (mEnable && mEnableCRLCache) {
            updateRevokedCert(UNREVOKED_CERT, serialNumber, null, requestId);

            if (mCacheUpdateInterval == 0) {
                try {
                    mCRLRepository.updateRevokedCerts(mId, mRevokedCerts, mUnrevokedCerts);
                    mFirstUnsaved = ICRLIssuingPointRecord.CLEAN_CACHE;
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_UNREVOKED_CERT", mId, e.toString()));
                }
            }
        }
    }

    /**
     * registers expired certificates
     */
    public void addExpiredCert(BigInteger serialNumber) {
        if (mEnable && mEnableCRLCache && (!mIncludeExpiredCerts)) {
            if (!(mExpiredCerts.containsKey(serialNumber))) {
                CRLExtensions entryExt = new CRLExtensions();

                try {
                    entryExt.set(CRLReasonExtension.REMOVE_FROM_CRL.getName(),
                        CRLReasonExtension.REMOVE_FROM_CRL);
                } catch (IOException e) {
                }
                RevokedCertImpl newRevokedCert = new RevokedCertImpl(serialNumber,
                        CMS.getCurrentDate(), entryExt);

                mExpiredCerts.put(serialNumber, (RevokedCertificate) newRevokedCert);
            }

            if (mCacheUpdateInterval == 0) {
                try {
                    mCRLRepository.updateExpiredCerts(mId, mExpiredCerts);
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_EXPIRED_CERT", mId, e.toString()));
                }
            }
        }
    }

    private Object repositoryMonitor = new Object();

    public void updateCRLCacheRepository() {
        synchronized (repositoryMonitor) {
            try {
                mCRLRepository.updateCRLCache(mId, Long.valueOf(mCRLSize),
                    mRevokedCerts, mUnrevokedCerts, mExpiredCerts);
                mFirstUnsaved = ICRLIssuingPointRecord.CLEAN_CACHE;
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_CRL_CACHE", e.toString()));
            }
        }
    }

    public boolean isDeltaCRLEnabled() {
        return (mAllowExtensions && mEnableCRLCache &&
                mCMSCRLExtensions.isCRLExtensionEnabled(DeltaCRLIndicatorExtension.NAME) &&
                mCMSCRLExtensions.isCRLExtensionEnabled(CRLNumberExtension.NAME) &&
                mCMSCRLExtensions.isCRLExtensionEnabled(CRLReasonExtension.NAME));
    }

    public boolean isThisCurrentDeltaCRL(X509CRLImpl deltaCRL) {
        boolean result = false;

        if (isDeltaCRLEnabled() && mDeltaCRLSize > -1) {
            if (deltaCRL != null) {
                CRLExtensions crlExtensions = deltaCRL.getExtensions();

                if (crlExtensions != null) {
                    for (int k = 0; k < crlExtensions.size(); k++) {
                        Extension ext = (Extension) crlExtensions.elementAt(k);

                        if (DeltaCRLIndicatorExtension.OID.equals(ext.getExtensionId().toString())) {
                            DeltaCRLIndicatorExtension dExt = (DeltaCRLIndicatorExtension) ext;
                            BigInteger crlNumber = null;

                            try {
                                crlNumber = (BigInteger) dExt.get(DeltaCRLIndicatorExtension.NUMBER);
                            } catch (IOException e) {
                            }
                            if (crlNumber != null && (crlNumber.equals(mLastCRLNumber) ||
                                                      mLastCRLNumber.equals(BigInteger.ZERO))) {
                                result = true;
                            }
                        }
                    }
                }
            }
        }
        return (result);
    }

    public boolean isCRLCacheEnabled() {
        return mEnableCRLCache;
    }

    public boolean isCRLCacheEmpty() {
        return ((mCRLCerts != null)? mCRLCerts.isEmpty(): true);
    }

    public Date getRevocationDateFromCache(BigInteger serialNumber,
        boolean checkDeltaCache,
        boolean includeExpiredCerts) {
        Date revocationDate = null;

        if (mCRLCerts.containsKey(serialNumber)) {
            revocationDate = ((RevokedCertificate) mCRLCerts.get(serialNumber)).getRevocationDate();
        }

        if (checkDeltaCache && isDeltaCRLEnabled()) {
            if (mUnrevokedCerts.containsKey(serialNumber)) {
                revocationDate = null;
            }
            if (mRevokedCerts.containsKey(serialNumber)) {
                revocationDate = ((RevokedCertificate) mRevokedCerts.get(serialNumber)).getRevocationDate();
            }
            if (!includeExpiredCerts && mExpiredCerts.containsKey(serialNumber)) {
                revocationDate = null;
            }
        }

        return revocationDate;
    }

    public Vector getSplitTimes() {
        Vector splits = new Vector();

        for (int i = 0; i < mSplits.length; i++) {
            splits.addElement(Long.valueOf(mSplits[i]));
        }
        return splits;
    }

    public int isCRLUpdateInProgress() {
        return mUpdatingCRL;
    }

    /**
     * updates CRL and publishes it now
     */
    public void updateCRLNow()
        throws EBaseException {

        updateCRLNow(null);
    }

    public synchronized void updateCRLNow(String signingAlgorithm)
        throws EBaseException {

        if ((!mEnable) || (!mEnableCRLUpdates && !mDoLastAutoUpdate)) return;
        CMS.debug("Updating CRL");
        mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER, AuditFormat.LEVEL,
                    CMS.getLogMessage("CMSCORE_CA_CA_CRL_UPDATE_STARTED"),
                    new Object[] {
                        getId(),
                        getNextCRLNumber(),
                        Boolean.toString(isDeltaCRLEnabled()),
                        Boolean.toString(isCRLCacheEnabled()),
                        Boolean.toString(mEnableCacheRecovery),
                        Boolean.toString(mCRLCacheIsCleared),
                        ""+mCRLCerts.size()+","+mRevokedCerts.size()+","+mUnrevokedCerts.size()+","+mExpiredCerts.size()+""
                    }
                   );
        mUpdatingCRL = CRL_UPDATE_STARTED;
        if (signingAlgorithm == null || signingAlgorithm.length() == 0)
            signingAlgorithm = mSigningAlgorithm;
        mLastSigningAlgorithm = signingAlgorithm;
        Date thisUpdate = CMS.getCurrentDate();
        Date nextUpdate = null;
        Date nextDeltaUpdate = null;

        if (mEnableCRLUpdates && ((mEnableDailyUpdates &&
            mDailyUpdates != null && mDailyUpdates.size() > 0) ||
            (mEnableUpdateFreq && mAutoUpdateInterval > 0))) {

            if ((!isDeltaCRLEnabled()) || mSchemaCounter == 0) {
                nextUpdate = new Date(findNextUpdate(false, false));
                mNextUpdate = new Date(nextUpdate.getTime());
            }
            if (isDeltaCRLEnabled()) {
                if (mUpdateSchema > 1) {
                    nextDeltaUpdate = new Date(findNextUpdate(false, true));
                    if (mExtendedNextUpdate && mSchemaCounter > 0 &&
                        mNextUpdate != null && mNextUpdate.equals(nextDeltaUpdate)) {
                        mSchemaCounter = mUpdateSchema - 1;
                    }
                } else {
                    nextDeltaUpdate = new Date(nextUpdate.getTime());
                }
            }
        }

        for (int i = 0; i < mSplits.length; i++) {
            mSplits[i] = 0;
        }

        mLastUpdate = thisUpdate;
        // mNextUpdate = nextUpdate;
        mNextDeltaUpdate = (nextDeltaUpdate != null)? new Date(nextDeltaUpdate.getTime()): null;
        if (nextUpdate != null) {
            nextUpdate.setTime((nextUpdate.getTime())+mNextUpdateGracePeriod);
        }
        if (nextDeltaUpdate != null) {
            nextDeltaUpdate.setTime((nextDeltaUpdate.getTime())+mNextUpdateGracePeriod);
        }

        mSplits[0] -= System.currentTimeMillis();
        Hashtable clonedRevokedCerts = (Hashtable) mRevokedCerts.clone();
        Hashtable clonedUnrevokedCerts = (Hashtable) mUnrevokedCerts.clone();
        Hashtable clonedExpiredCerts = (Hashtable) mExpiredCerts.clone();

        mSplits[0] += System.currentTimeMillis();

        // starting from the beginning

        if ((!mEnableCRLCache) ||
            ((mCRLCacheIsCleared && mCRLCerts.isEmpty() && clonedRevokedCerts.isEmpty() &&
              clonedUnrevokedCerts.isEmpty() && clonedExpiredCerts.isEmpty()) ||
                (mCRLCerts.isEmpty() && (!clonedUnrevokedCerts.isEmpty())) ||
                (mCRLCerts.size() < clonedUnrevokedCerts.size()) ||
                (mCRLCerts.isEmpty() && (mCRLSize > 0)) ||
                (mCRLCerts.size() > 0 && mCRLSize == 0))) {

            mSplits[5] -= System.currentTimeMillis();
            mDeltaCRLSize = -1;
            clearCRLCache();
            clonedRevokedCerts.clear();
            clonedUnrevokedCerts.clear();
            clonedExpiredCerts.clear();
            mSchemaCounter = 0;

            IStatsSubsystem statsSub = (IStatsSubsystem)CMS.getSubsystem("stats");
            if (statsSub != null) {
              statsSub.startTiming("generation");
            }

            CertRecProcessor cp = new CertRecProcessor(mCRLCerts, this, mLogger);
            processRevokedCerts(cp);

            if (statsSub != null) {
              statsSub.endTiming("generation");
            }

            mCRLCacheIsCleared = false;
            mSplits[5] += System.currentTimeMillis();
        } else {
            if (isDeltaCRLEnabled()) {
                mSplits[1] -= System.currentTimeMillis();
                Hashtable deltaCRLCerts = (Hashtable) clonedRevokedCerts.clone();

                deltaCRLCerts.putAll(clonedUnrevokedCerts);
                if (mIncludeExpiredCertsOneExtraTime) {
                    if (!clonedExpiredCerts.isEmpty()) {
                        for (Enumeration e = clonedExpiredCerts.keys(); e.hasMoreElements();) {
                            BigInteger serialNumber = (BigInteger) e.nextElement();
                            if ((mLastFullUpdate != null &&
                                 mLastFullUpdate.after(((RevokedCertificate)(mExpiredCerts.get(serialNumber))).getRevocationDate())) ||
                                 mLastFullUpdate == null) {
                                deltaCRLCerts.put(serialNumber, clonedExpiredCerts.get(serialNumber));
                            }
                        }
                    }
                } else {
                    deltaCRLCerts.putAll(clonedExpiredCerts);
                }

                mLastCRLNumber = mCRLNumber;

                CRLExtensions ext = new CRLExtensions();
                Vector extNames = mCMSCRLExtensions.getCRLExtensionNames();

                for (int i = 0; i < extNames.size(); i++) {
                    String extName = (String) extNames.elementAt(i);

                    if (mCMSCRLExtensions.isCRLExtensionEnabled(extName) &&
                        (!extName.equals(FreshestCRLExtension.NAME))) {
                        mCMSCRLExtensions.addToCRLExtensions(ext, extName, null);
                    }
                }
                mSplits[1] += System.currentTimeMillis();

                X509CRLImpl newX509DeltaCRL = null;

                try {
                    mSplits[2] -= System.currentTimeMillis();
                    byte[] newDeltaCRL;

                    // #56123 - dont generate CRL if no revoked certificates
        	    if (mConfigStore.getBoolean("noCRLIfNoRevokedCert", false)) {
                        if (deltaCRLCerts.size() == 0) {
                            CMS.debug("CRLIssuingPoint: No Revoked Certificates Found And noCRLIfNoRevokedCert is set to true - No Delta CRL Generated");
                            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", "No Revoked Certificates"));
                        }
                    }
                    X509CRLImpl crl = new X509CRLImpl(mCA.getCRLX500Name(),
                            AlgorithmId.get(signingAlgorithm),
                            thisUpdate, nextDeltaUpdate, deltaCRLCerts, ext);

                    newX509DeltaCRL = mCA.sign(crl, signingAlgorithm);
                    newDeltaCRL = newX509DeltaCRL.getEncoded();
                    mSplits[2] += System.currentTimeMillis();

                    mSplits[3] -= System.currentTimeMillis();
                    mCRLRepository.updateDeltaCRL(mId, mNextDeltaCRLNumber,
                              Long.valueOf(deltaCRLCerts.size()), mNextDeltaUpdate, newDeltaCRL);
                    mSplits[3] += System.currentTimeMillis();

                    mDeltaCRLSize = deltaCRLCerts.size();


                    long totalTime = 0;
                    String splitTimes = "  (";
                    for (int i = 1; i < mSplits.length && i < 5; i++) {
                        totalTime += mSplits[i];
                        if (i > 1) splitTimes += ",";
                        splitTimes += Long.toString(mSplits[i]);
                    }
                    splitTimes += ")";
                    mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                                AuditFormat.LEVEL,
                                CMS.getLogMessage("CMSCORE_CA_CA_DELTA_CRL_UPDATED"),
                                new Object[] {
                                    getId(),
                                    getNextCRLNumber(),
                                    getCRLNumber(),
                                    getLastUpdate(),
                                    getNextDeltaUpdate(),
                                    Long.toString(mDeltaCRLSize), 
                                    Long.toString(totalTime)+splitTimes
                                }
                               );
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_OR_STORE_DELTA", e.toString()));
                    mDeltaCRLSize = -1;
                } catch (NoSuchAlgorithmException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_DELTA", e.toString()));
                    mDeltaCRLSize = -1;
                } catch (CRLException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_DELTA", e.toString()));
                    mDeltaCRLSize = -1;
                } catch (X509ExtensionException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_DELTA", e.toString()));
                    mDeltaCRLSize = -1;
                } catch (OutOfMemoryError e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_DELTA", e.toString()));
                    mDeltaCRLSize = -1;
                }

                try {
                    mSplits[4] -= System.currentTimeMillis();
                    publishCRL(newX509DeltaCRL, true);
                    mSplits[4] += System.currentTimeMillis();
                } catch (EBaseException e) {
                    newX509DeltaCRL = null;
                    if (Debug.on()) 
                        Debug.printStackTrace(e);
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_DELTA", mCRLNumber.toString(), e.toString()));
                } catch (OutOfMemoryError e) {
                    newX509DeltaCRL = null;
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_DELTA", mCRLNumber.toString(), e.toString()));
                }
            } else {
                mDeltaCRLSize = -1;
            }

            mSplits[5] -= System.currentTimeMillis();

            if (mSchemaCounter == 0) {
                if (((!mCRLCerts.isEmpty()) && ((!clonedRevokedCerts.isEmpty()) ||
                    (!clonedUnrevokedCerts.isEmpty()) || (!clonedExpiredCerts.isEmpty()))) ||
                    (mCRLCerts.isEmpty() && (mCRLSize == 0) && (!clonedRevokedCerts.isEmpty()))) {

                    if (!clonedUnrevokedCerts.isEmpty()) {
                        for (Enumeration e = clonedUnrevokedCerts.keys(); e.hasMoreElements();) {
                            BigInteger serialNumber = (BigInteger) e.nextElement();

                            if (mCRLCerts.containsKey(serialNumber)) {
                                mCRLCerts.remove(serialNumber);
                            }
                            mUnrevokedCerts.remove(serialNumber);
                        }
                    }

                    if (!clonedRevokedCerts.isEmpty()) {
                        for (Enumeration e = clonedRevokedCerts.keys(); e.hasMoreElements();) {
                            BigInteger serialNumber = (BigInteger) e.nextElement();

                            mCRLCerts.put(serialNumber, mRevokedCerts.get(serialNumber));
                            mRevokedCerts.remove(serialNumber);
                        }
                    }

                    if (!clonedExpiredCerts.isEmpty()) {
                        for (Enumeration e = clonedExpiredCerts.keys(); e.hasMoreElements();) {
                            BigInteger serialNumber = (BigInteger) e.nextElement();

                            if ((!mIncludeExpiredCertsOneExtraTime) ||
                                 (mLastFullUpdate != null &&
                                  mLastFullUpdate.after(((RevokedCertificate)(mExpiredCerts.get(serialNumber))).getRevocationDate())) ||
                                 mLastFullUpdate == null) {
                                if (mCRLCerts.containsKey(serialNumber)) {
                                    mCRLCerts.remove(serialNumber);
                                }
                                mExpiredCerts.remove(serialNumber);
                            }
                        }
                    }
                }
                mLastFullUpdate = mLastUpdate;
            }
            mSplits[5] += System.currentTimeMillis();
        }

        clonedRevokedCerts.clear();
        clonedUnrevokedCerts.clear();
        clonedExpiredCerts.clear();
        clonedRevokedCerts = null;
        clonedUnrevokedCerts = null;
        clonedExpiredCerts = null;

        if ((!isDeltaCRLEnabled()) || mSchemaCounter == 0) {
            mSplits[6] -= System.currentTimeMillis();
            if (mNextDeltaCRLNumber.compareTo(mNextCRLNumber) > 0) {
                mNextCRLNumber = mNextDeltaCRLNumber;
            }

            CRLExtensions ext = null;

            if (mAllowExtensions) {
                ext = new CRLExtensions();
                Vector extNames = mCMSCRLExtensions.getCRLExtensionNames();

                for (int i = 0; i < extNames.size(); i++) {
                    String extName = (String) extNames.elementAt(i);

                    if (mCMSCRLExtensions.isCRLExtensionEnabled(extName) &&
                        (!extName.equals(DeltaCRLIndicatorExtension.NAME))) {
                        mCMSCRLExtensions.addToCRLExtensions(ext, extName, null);
                    }
                }
            }
            mSplits[6] += System.currentTimeMillis();
            // for audit log

            X509CRLImpl newX509CRL;

            try {
                byte[] newCRL;

                CMS.debug("Making CRL wth algorithm " +
                    signingAlgorithm + " " + AlgorithmId.get(signingAlgorithm));

                mSplits[7] -= System.currentTimeMillis();

                // #56123 - dont generate CRL if no revoked certificates
      	    	if (mConfigStore.getBoolean("noCRLIfNoRevokedCert", false)) {
                        if (mCRLCerts.size() == 0) {
                            CMS.debug("CRLIssuingPoint: No Revoked Certificates Found And noCRLIfNoRevokedCert is set to true - No CRL Generated");
                            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", "No Revoked Certificates"));
                        }
                }
                CMS.debug("before new X509CRLImpl");
                X509CRLImpl crl = new X509CRLImpl(mCA.getCRLX500Name(),
                        AlgorithmId.get(signingAlgorithm),
                        thisUpdate, nextUpdate, mCRLCerts, ext);

                CMS.debug("before sign");
                newX509CRL = mCA.sign(crl, signingAlgorithm);

                CMS.debug("before getEncoded()");
                newCRL = newX509CRL.getEncoded();
                CMS.debug("after getEncoded()");
                mSplits[7] += System.currentTimeMillis();

                mSplits[8] -= System.currentTimeMillis();

                Date nextUpdateDate = mNextUpdate;
                if (isDeltaCRLEnabled() && mUpdateSchema > 1 && mNextDeltaUpdate != null) {
                    nextUpdateDate = mNextDeltaUpdate;
                }
                mCRLRepository.updateCRLIssuingPointRecord(
                    mId, newCRL, thisUpdate, nextUpdateDate,
                    mNextCRLNumber, Long.valueOf(mCRLCerts.size()),
                    mRevokedCerts, mUnrevokedCerts, mExpiredCerts);
                mFirstUnsaved = ICRLIssuingPointRecord.CLEAN_CACHE;
                mSplits[8] += System.currentTimeMillis();

                mCRLSize = mCRLCerts.size();
                mCRLNumber = mNextCRLNumber;
                mDeltaCRLNumber = mCRLNumber;
                mNextCRLNumber = mCRLNumber.add(BigInteger.ONE);
                mNextDeltaCRLNumber = mNextCRLNumber;


                CMS.debug("Logging CRL Update to transaction log");
                long totalTime = 0;                   
                long crlTime = 0;                   
                long deltaTime = 0;                   
                String splitTimes = "  (";
                for (int i = 0; i < mSplits.length; i++) {
                    totalTime += mSplits[i];
                    if (i > 0 && i < 5) {
                        deltaTime += mSplits[i];
                    } else {
                        crlTime += mSplits[i];
                    }
                    if (i > 0) splitTimes += ",";
                    splitTimes += Long.toString(mSplits[i]);
                }
                splitTimes += "," + Long.toString(deltaTime) + "," + Long.toString(crlTime) + "," + Long.toString(totalTime) + ")";
                mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                            AuditFormat.LEVEL,
                            CMS.getLogMessage("CMSCORE_CA_CA_CRL_UPDATED"),
                            new Object[] { 
                                getId(),
                                getCRLNumber(),
                                getLastUpdate(),
                                getNextUpdate(),
                                Long.toString(mCRLSize),
                                Long.toString(totalTime),
                                Long.toString(crlTime),
                                Long.toString(deltaTime)+splitTimes
                            }
                           );
                CMS.debug("Finished Logging CRL Update to transaction log");

            } catch (EBaseException e) {
                newX509CRL = null;
                mUpdatingCRL = CRL_UPDATE_DONE;
                if (Debug.on()) 
                    Debug.printStackTrace(e);
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_OR_STORE_CRL", e.toString()));
                throw new ECAException(CMS.getUserMessage("CMS_CA_FAILED_CONSTRUCTING_CRL", e.toString()));
            } catch (NoSuchAlgorithmException e) {
                newX509CRL = null;
                mUpdatingCRL = CRL_UPDATE_DONE;
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_CRL", e.toString()));
                throw new ECAException(CMS.getUserMessage("CMS_CA_FAILED_CONSTRUCTING_CRL", e.toString()));
            } catch (CRLException e) {
                newX509CRL = null;
                mUpdatingCRL = CRL_UPDATE_DONE;
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_CRL", e.toString()));
                throw new ECAException(CMS.getUserMessage("CMS_CA_FAILED_CONSTRUCTING_CRL", e.toString()));
            } catch (X509ExtensionException e) {
                newX509CRL = null;
                mUpdatingCRL = CRL_UPDATE_DONE;
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_CRL", e.toString()));
                throw new ECAException(CMS.getUserMessage("CMS_CA_FAILED_CONSTRUCTING_CRL", e.toString()));
            } catch (OutOfMemoryError e) {
                newX509CRL = null;
                mUpdatingCRL = CRL_UPDATE_DONE;
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_CRL", e.toString()));
                throw new ECAException(CMS.getUserMessage("CMS_CA_FAILED_CONSTRUCTING_CRL", e.toString()));
            }

            try {
                mSplits[9] -= System.currentTimeMillis();
                mUpdatingCRL = CRL_PUBLISHING_STARTED;
                publishCRL(newX509CRL);
                newX509CRL = null;
                mSplits[9] += System.currentTimeMillis();
            } catch (EBaseException e) {
                newX509CRL = null;
                mUpdatingCRL = CRL_UPDATE_DONE;
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_CRL", mCRLNumber.toString(), e.toString()));
            } catch (OutOfMemoryError e) {
                newX509CRL = null;
                mUpdatingCRL = CRL_UPDATE_DONE;
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_CRL", mCRLNumber.toString(), e.toString()));
            }
        }

        if (isDeltaCRLEnabled() && mDeltaCRLSize > -1 && mSchemaCounter > 0) {
            mDeltaCRLNumber = mNextDeltaCRLNumber;
            mNextDeltaCRLNumber = mDeltaCRLNumber.add(BigInteger.ONE);
        }
        
        mSchemaCounter++;
        if (mSchemaCounter >= mUpdateSchema) mSchemaCounter = 0;

        mUpdatingCRL = CRL_UPDATE_DONE;
        notifyAll();
    }

    /**
     * publish CRL. called from updateCRLNow() and init().
     */

    public void publishCRL() 
        throws EBaseException {
        publishCRL(null);
    }

    protected void publishCRL(X509CRLImpl x509crl) 
        throws EBaseException {
        publishCRL(x509crl, false);
    }

    protected void publishCRL(X509CRLImpl x509crl, boolean isDeltaCRL) 
        throws EBaseException {
        SessionContext sc = SessionContext.getContext();

        IStatsSubsystem statsSub = (IStatsSubsystem)CMS.getSubsystem("stats");
        if (statsSub != null) {
          statsSub.startTiming("crl_publishing");
        }

        if (mCountMod == 0) {
          sc.put(SC_CRL_COUNT, Integer.toString(mCount));
        } else {
          sc.put(SC_CRL_COUNT, Integer.toString(mCount%mCountMod));
        }
        mCount++;
        sc.put(SC_ISSUING_POINT_ID, mId);
        if (isDeltaCRL) {
            sc.put(SC_IS_DELTA_CRL, "true");
        } else {
            sc.put(SC_IS_DELTA_CRL, "false");
        }

        ICRLIssuingPointRecord crlRecord = null;

        CMS.debug("Publish CRL");
        try {
            if (x509crl == null) {
                crlRecord = mCRLRepository.readCRLIssuingPointRecord(mId);
                if (crlRecord != null) {
                    byte[] crl = (isDeltaCRL) ? crlRecord.getDeltaCRL() : crlRecord.getCRL();

                    if (crl != null) {
                        x509crl = new X509CRLImpl(crl);
                    }
                }
            }
            if (x509crl != null &&
                mPublisherProcessor != null && mPublisherProcessor.enabled()) {
                if (mPublishDN != null) {
                    mPublisherProcessor.publishCRL(mPublishDN, x509crl);
                    CMS.debug("CRL published to " + mPublishDN);
                } else {
                    mPublisherProcessor.publishCRL(x509crl,getId());
                    CMS.debug("CRL published.");
                }
            }
        } catch (Exception e) {
            CMS.debug("Could not publish CRL. Error " + e);
            CMS.debug("Could not publish CRL. ID " + mId);
            throw new EErrorPublishCRL(
                    CMS.getUserMessage("CMS_CA_ERROR_PUBLISH_CRL", mId, e.toString()));
        } finally {
          if (statsSub != null) {
            statsSub.endTiming("crl_publishing");
          }
        }
    }

    protected void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_CA, level, 
            "CRLIssuingPoint " + mId + " - " + msg);
    }

    void setConfigParam(String name, String value) {
        mConfigStore.putString(name, value);
    }

    class RevocationRequestListener implements IRequestListener {

        public void init(ISubsystem sys, IConfigStore config)
            throws EBaseException {
        }

        public void set(String name, String val) {
        }

        public void accept(IRequest r) {
            String requestType = r.getRequestType();

            if (requestType.equals(IRequest.REVOCATION_REQUEST) ||
                requestType.equals(IRequest.UNREVOCATION_REQUEST) ||
                requestType.equals(IRequest.CLA_CERT4CRL_REQUEST) ||
                requestType.equals(IRequest.CLA_UNCERT4CRL_REQUEST)) {
                CMS.debug("Revocation listener called.");
                // check if serial number is in begin/end range if set.
                if (mBeginSerial != null || mEndSerial != null) {
                    CMS.debug(
                        "Checking if serial number is between " +
                        mBeginSerial + " and " + mEndSerial);
                    BigInteger[] serialNos = 
                        r.getExtDataInBigIntegerArray(IRequest.OLD_SERIALS);

                    if (serialNos == null || serialNos.length == 0) {
                        X509CertImpl oldCerts[] = 
                            r.getExtDataInCertArray(IRequest.OLD_CERTS);

                        if (oldCerts == null || oldCerts.length == 0) 
                            return;
                        serialNos = new BigInteger[oldCerts.length];
                        for (int i = 0; i < oldCerts.length; i++) {
                            serialNos[i] = oldCerts[i].getSerialNumber();
                        }
                    }
					
                    boolean inRange = false;

                    for (int i = 0; i < serialNos.length; i++) {
                        if ((mBeginSerial == null || 
                                serialNos[i].compareTo(mBeginSerial) >= 0) &&
                            (mEndSerial == null || 
                                serialNos[i].compareTo(mEndSerial) <= 0)) {
                            inRange = true;
                        }
                    }
                    if (!inRange) {
                        return;
                    }
                }

                if (mAlwaysUpdate) {
                    try {
                        updateCRLNow();
                        r.setExtData(mCrlUpdateStatus, IRequest.RES_SUCCESS);
                        if (mPublisherProcessor != null) {
                            r.setExtData(mCrlPublishStatus, IRequest.RES_SUCCESS);
                        }
                    } catch (EErrorPublishCRL e) {
                        // error already logged in updateCRLNow();
                        r.setExtData(mCrlUpdateStatus, IRequest.RES_SUCCESS);
                        if (mPublisherProcessor != null) {
                            r.setExtData(mCrlPublishStatus, IRequest.RES_ERROR);
                            r.setExtData(mCrlPublishError, e);
                        }
                    } catch (EBaseException e) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_UPDATE_CRL", e.toString()));
                        r.setExtData(mCrlUpdateStatus, IRequest.RES_ERROR);
                        r.setExtData(mCrlUpdateError, e);
                    } catch (Exception e) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CA_ISSUING_UPDATE_CRL", e.toString()));
                        if (Debug.on())
                            Debug.printStackTrace(e);
                        r.setExtData(mCrlUpdateStatus, IRequest.RES_ERROR);
                        r.setExtData(mCrlUpdateError,
                            new EBaseException(
                                CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString())));
                    }
                }
            }
        }
    }
}


class CertRecProcessor implements IElementProcessor {
    private Hashtable mCRLCerts = null;
    private boolean mAllowExtensions;
    private ILogger mLogger;
    private CRLIssuingPoint mIP = null;

    public CertRecProcessor(Hashtable crlCerts, CRLIssuingPoint ip, ILogger logger) {
        mCRLCerts = crlCerts;
        mLogger = logger;
        mIP = ip;
    }

    public void process(Object o) throws EBaseException {
        try {
            CertRecord certRecord = (CertRecord) o;

            CRLExtensions entryExt = null;
            BigInteger serialNumber = certRecord.getSerialNumber();
            Date revocationDate = certRecord.getRevocationDate();
            IRevocationInfo revInfo = certRecord.getRevocationInfo();

            if (revInfo != null) {
                entryExt = mIP.getRequiredEntryExtensions(revInfo.getCRLEntryExtensions());
            }
            RevokedCertificate newRevokedCert =
                new RevokedCertImpl(serialNumber, revocationDate, entryExt);

            mCRLCerts.put(serialNumber, (RevokedCertificate) newRevokedCert);
            if (serialNumber != null) {
                CMS.debug("Putting certificate serial: 0x"+serialNumber.toString(16)+" into CRL hashtable");
            }
        } catch (EBaseException e) {
            CMS.debug(
                "CA failed constructing CRL entry: " +
                (mCRLCerts.size() + 1) + " " + e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_FAILED_CONSTRUCTING_CRL", e.toString()));
        }
    }
}

