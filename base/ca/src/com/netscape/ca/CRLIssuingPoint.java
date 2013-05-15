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

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.Vector;

import netscape.security.util.BitArray;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLNumberExtension;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.DeltaCRLIndicatorExtension;
import netscape.security.x509.Extension;
import netscape.security.x509.FreshestCRLExtension;
import netscape.security.x509.IssuingDistributionPoint;
import netscape.security.x509.IssuingDistributionPointExtension;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.RevokedCertificate;
import netscape.security.x509.X509CRLImpl;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509ExtensionException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.ca.EErrorPublishCRL;
import com.netscape.certsrv.ca.ICMSCRLExtensions;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.dbs.EDBNotAvailException;
import com.netscape.certsrv.dbs.IElementProcessor;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertRecordList;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.dbs.certdb.IRevocationInfo;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.dbs.crldb.ICRLRepository;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.ILdapRule;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.IRequestVirtualList;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
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
 * @version $Revision$, $Date$
 */

public class CRLIssuingPoint implements ICRLIssuingPoint, Runnable {

    /* Foreign config param for IssuingDistributionPointExtension. */
    public static final String PROP_CACERTS = "onlyContainsCACerts";

    public static final long SECOND = 1000L;
    public static final long MINUTE = (SECOND * 60L);

    private static final int CRL_PAGE_SIZE = 10000;

    /* configuration file property names */

    public IPublisherProcessor mPublisherProcessor = null;

    private ILogger mLogger = CMS.getLogger();

    private IConfigStore mConfigStore;

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
    private Hashtable<BigInteger, RevokedCertificate> mCRLCerts = new Hashtable<BigInteger, RevokedCertificate>();
    private Hashtable<BigInteger, RevokedCertificate> mRevokedCerts = new Hashtable<BigInteger, RevokedCertificate>();
    private Hashtable<BigInteger, RevokedCertificate> mUnrevokedCerts = new Hashtable<BigInteger, RevokedCertificate>();
    private Hashtable<BigInteger, RevokedCertificate> mExpiredCerts = new Hashtable<BigInteger, RevokedCertificate>();
    private boolean mIncludeExpiredCerts = false;
    private boolean mIncludeExpiredCertsOneExtraTime = false;
    private boolean mCACertsOnly = false;

    private boolean mProfileCertsOnly = false;
    private Vector<String> mProfileList = null;

    /**
     * Enable CRL cache.
     */
    private boolean mEnableCRLCache = true;
    private boolean mCRLCacheIsCleared = true;
    private boolean mEnableCacheRecovery = false;
    private String mFirstUnsaved = null;
    private boolean mEnableCacheTesting = false;

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
    private Vector<Vector<Integer>> mDailyUpdates = null;
    private int mCurrentDay = 0;
    private int mLastDay = 0;
    private int mTimeListSize = 0;
    private boolean mExtendedTimeList = false;

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
      * next update as this update extension
      */
    private long mNextAsThisUpdateExtension; 

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
    private String mSignatureAlgorithmForManualUpdate = null;

    private boolean mPublishOnStart = false;
    private long[] mSplits = new long[10];

    private boolean mSaveMemory = false;

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
                String profileId = mProfileList.elementAt(k);
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
     *            owns this issuing point.
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

        IConfigStore crlSubStore = mCA.getConfigStore().getSubStore(ICertificateAuthority.PROP_CRL_SUBSTORE);
        mPageSize = crlSubStore.getInteger(ICertificateAuthority.PROP_CRL_PAGE_SIZE, CRL_PAGE_SIZE);
        CMS.debug("CRL Page Size: " + mPageSize);

        mCountMod = config.getInteger("countMod", 0);
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
        if (len < 3 || len > 5)
            return -1;

        int s = time.indexOf(':');
        if (s < 0 || s > 2 || (len - s) != 3)
            return -1;

        int h = 0;
        for (int i = 0; i < s; i++) {
            h *= 10;
            int k = digits.indexOf(time.charAt(i));
            if (k < 0)
                return -1;
            h += k;
        }
        if (h > 23)
            return -1;

        int m = 0;
        for (int i = s + 1; i < len; i++) {
            m *= 10;
            int k = digits.indexOf(time.charAt(i));
            if (k < 0)
                return -1;
            m += k;
        }
        if (m > 59)
            return -1;

        return ((h * 60) + m);
    }

    private boolean areTimeListsIdentical(Vector<Vector<Integer>> list1, Vector<Vector<Integer>> list2) {
        boolean identical = true;
        if (list1 == null || list2 == null)
            identical = false;
        if (identical && list1.size() != list2.size())
            identical = false;
        for (int i = 0; identical && i < list1.size(); i++) {
            Vector<Integer> times1 = list1.elementAt(i);
            Vector<Integer> times2 = list2.elementAt(i);
            if (times1.size() != times2.size())
                identical = false;
            for (int j = 0; identical && j < times1.size(); j++) {
                if ((((times1.elementAt(j))).intValue()) != (((times2.elementAt(j))).intValue())) {
                    identical = false;
                }
            }
        }
        CMS.debug("areTimeListsIdentical:  identical: " + identical);
        return identical;
    }

    private int getTimeListSize(Vector<Vector<Integer>> listedDays) {
        int listSize = 0;
        for (int i = 0; listedDays != null && i < listedDays.size(); i++) {
            Vector<Integer> listedTimes = listedDays.elementAt(i);
            listSize += ((listedTimes != null) ? listedTimes.size() : 0);
        }
        CMS.debug("getTimeListSize:  ListSize=" + listSize);
        return listSize;
    }

    private boolean isTimeListExtended(String list) {
        boolean extendedTimeList = true;
        if (list == null || list.indexOf('*') == -1)
            extendedTimeList = false;
        return extendedTimeList;
    }

    private Vector<Vector<Integer>> getTimeList(String list) {
        boolean timeListPresent = false;
        if (list == null || list.length() == 0)
            return null;
        if (list.charAt(0) == ',' || list.charAt(list.length() - 1) == ',')
            return null;

        Vector<Vector<Integer>> listedDays = new Vector<Vector<Integer>>();

        StringTokenizer days = new StringTokenizer(list, ";", true);
        Vector<Integer> listedTimes = null;
        while (days.hasMoreTokens()) {
            String dayList = days.nextToken().trim();
            if (dayList == null)
                continue;

            if (dayList.equals(";")) {
                if (timeListPresent) {
                    timeListPresent = false;
                } else {
                    listedTimes = new Vector<Integer>();
                    listedDays.addElement(listedTimes);
                }
                continue;
            } else {
                listedTimes = new Vector<Integer>();
                listedDays.addElement(listedTimes);
                timeListPresent = true;
            }
            int t0 = -1;
            StringTokenizer times = new StringTokenizer(dayList, ",");
            while (times.hasMoreTokens()) {
                String time = times.nextToken();
                int k = 1;
                if (time.charAt(0) == '*') {
                    time = time.substring(1);
                    k = -1;
                }
                int t = checkTime(time);
                if (t < 0) {
                    return null;
                } else {
                    if (t > t0) {
                        listedTimes.addElement(Integer.valueOf(k * t));
                        t0 = t;
                    } else {
                        return null;
                    }
                }
            }
        }
        if (!timeListPresent) {
            listedTimes = new Vector<Integer>();
            listedDays.addElement(listedTimes);
        }

        return listedDays;
    }

    private String checkProfile(String id, Enumeration<String> e) {
        if (e != null) {
            while (e.hasMoreElements()) {
                String profileId = e.nextElement();
                if (profileId != null && profileId.equalsIgnoreCase(id))
                    return id;
            }
        }
        return null;
    }

    private Vector<String> getProfileList(String list) {
        Enumeration<String> e = null;
        IConfigStore pc = CMS.getConfigStore().getSubStore("profile");
        if (pc != null)
            e = pc.getSubStoreNames();
        if (list == null)
            return null;
        if (list.length() > 0 && list.charAt(list.length() - 1) == ',')
            return null;

        Vector<String> listedProfiles = new Vector<String>();

        StringTokenizer elements = new StringTokenizer(list, ",", true);
        int n = 0;
        while (elements.hasMoreTokens()) {
            String element = elements.nextToken().trim();
            if (element == null || element.length() == 0)
                return null;
            if (element.equals(",") && n % 2 == 0)
                return null;
            if (n % 2 == 0) {
                String id = checkProfile(element, e);
                if (id != null) {
                    listedProfiles.addElement(id);
                }
            }
            n++;
        }
        if (n % 2 == 0)
            return null;

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
        mEnableCacheTesting = config.getBoolean(Constants.PR_CACHE_TESTING, false);

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
        mExtendedTimeList = isTimeListExtended(daily);
        mTimeListSize = getTimeListSize(mDailyUpdates);
        if (mDailyUpdates == null || mDailyUpdates.isEmpty() || mTimeListSize == 0) {
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

        // get next update as this update extension 
        mNextAsThisUpdateExtension = MINUTE * config.getInteger(Constants.PR_NEXT_AS_THIS_EXTENSION, 0);

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

        mSaveMemory = config.getBoolean("saveMemory", false);

        mCMSCRLExtensions = new CMSCRLExtensions(this, config);

        mExtendedNextUpdate =
                ((mUpdateSchema > 1 || (mEnableDailyUpdates && mExtendedTimeList)) && isDeltaCRLEnabled()) ?
                                config.getBoolean(Constants.PR_EXTENDED_NEXT_UPDATE, true) :
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
     * @throws EBaseException
     */
    private void initCRL() throws EBaseException {
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
                mNextDeltaUpdate = (mNextUpdate != null) ? new Date(mNextUpdate.getTime()) : null;
            }

            mFirstUnsaved = crlRecord.getFirstUnsaved();
            if (Debug.on()) {
                Debug.trace("initCRL  CRLNumber=" + mCRLNumber.toString() + "  CRLSize=" + mCRLSize +
                            "  FirstUnsaved=" + mFirstUnsaved);
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
                                    mRevokedCerts = new Hashtable<BigInteger, RevokedCertificate>();
                                }
                                mUnrevokedCerts = crlRecord.getUnrevokedCerts();
                                if (mUnrevokedCerts == null) {
                                    mUnrevokedCerts = new Hashtable<BigInteger, RevokedCertificate>();
                                }
                                mExpiredCerts = crlRecord.getExpiredCerts();
                                if (mExpiredCerts == null) {
                                    mExpiredCerts = new Hashtable<BigInteger, RevokedCertificate>();
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
                                log(ILogger.LL_FAILURE,
                                        CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_CRL", mCRLNumber.toString(),
                                                e.toString()));
                            } catch (OutOfMemoryError e) {
                                x509crl = null;
                                log(ILogger.LL_FAILURE,
                                        CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_CRL", mCRLNumber.toString(),
                                                e.toString()));
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
                mCRLNumber = BigInteger.ZERO; //BIG_ZERO;
                mNextCRLNumber = BigInteger.ONE; //BIG_ONE;
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

            for (Map.Entry<String, String> entry : params.entrySet()) {
                String name = entry.getKey();
                String value = entry.getValue();

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
                    boolean extendedTimeList = isTimeListExtended(value);
                    Vector<Vector<Integer>> dailyUpdates = getTimeList(value);
                    if (mExtendedTimeList != extendedTimeList) {
                        mExtendedTimeList = extendedTimeList;
                        modifiedSchedule = true;
                    }
                    if (!areTimeListsIdentical(mDailyUpdates, dailyUpdates)) {
                        mCurrentDay = 0;
                        mLastDay = 0;
                        mDailyUpdates = dailyUpdates;
                        mTimeListSize = getTimeListSize(mDailyUpdates);
                        modifiedSchedule = true;
                    }
                    if (mDailyUpdates == null || mDailyUpdates.isEmpty() || mTimeListSize == 0) {
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

                if (name.equals(Constants.PR_NEXT_AS_THIS_EXTENSION)) {
                    try {
                        if (value != null && value.length() > 0) {
                            mNextAsThisUpdateExtension = MINUTE * Long.parseLong(value.trim());
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

                if (name.equals(Constants.PR_CACHE_TESTING)) {
                    if (value.equals(Constants.FALSE) && mEnableCacheTesting) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mEnableCacheTesting = false;
                        setManualUpdate(null);
                    } else if (value.equals(Constants.TRUE) && (!mEnableCacheTesting)) {
                        mEnableCacheTesting = true;
                    }
                }

                // -- CRL Format --
                if (name.equals(Constants.PR_SIGNING_ALGORITHM)) {
                    if (value != null)
                        value = value.trim();
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
                    Extension distExt = getCRLExtension(IssuingDistributionPointExtension.NAME);
                    IssuingDistributionPointExtension iExt = (IssuingDistributionPointExtension) distExt;
                    IssuingDistributionPoint issuingDistributionPoint = null;
                    if (iExt != null)
                        issuingDistributionPoint = iExt.getIssuingDistributionPoint();
                    if (value.equals(Constants.FALSE) && mCACertsOnly) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mCACertsOnly = false;
                    } else if (value.equals(Constants.TRUE) && (!mCACertsOnly)) {
                        clearCRLCache();
                        updateCRLCacheRepository();
                        mCACertsOnly = true;
                    }
                    //attempt to sync the IssuingDistributionPoint Extension value of
                    //onlyContainsCACerts
                    if (issuingDistributionPoint != null && params.size() > 1) {
                        boolean onlyContainsCACerts = issuingDistributionPoint.getOnlyContainsCACerts();
                        if (onlyContainsCACerts != mCACertsOnly) {
                            IConfigStore config = mCA.getConfigStore();
                            IConfigStore crlsSubStore =
                                    config.getSubStore(ICertificateAuthority.PROP_CRL_SUBSTORE);
                            IConfigStore crlSubStore = crlsSubStore.getSubStore(mId);
                            IConfigStore crlExtsSubStore =
                                    crlSubStore.getSubStore(ICertificateAuthority.PROP_CRLEXT_SUBSTORE);
                            crlExtsSubStore =
                                    crlExtsSubStore
                                            .getSubStore(IssuingDistributionPointExtension.NAME);

                            if (crlExtsSubStore != null) {
                                String val = "";
                                if (mCACertsOnly == true) {
                                    val = Constants.TRUE;
                                } else {
                                    val = Constants.FALSE;
                                }
                                crlExtsSubStore.putString(PROP_CACERTS, val);
                                try {
                                    crlExtsSubStore.commit(true);
                                } catch (Exception e) {
                                }
                            }
                        }
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
                    Vector<String> profileList = getProfileList(value);
                    if (((profileList != null) ^ (mProfileList != null)) ||
                            (profileList != null && mProfileList != null &&
                            (!mProfileList.equals(profileList)))) {
                        if (profileList != null) {
                            @SuppressWarnings("unchecked")
                            Vector<String> newProfileList = (Vector<String>) profileList.clone();
                            mProfileList = newProfileList;
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

            if (modifiedSchedule)
                setAutoUpdates();

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
        /*
        if (mUpdateThread != null) {
            try {
                mUpdateThread.interrupt();
            }
            catch (Exception e) {
            }
        }
        */
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

    public synchronized String getLastSigningAlgorithm() {
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
        return (isDeltaCRLEnabled() && mDeltaCRLSize > -1) ? mDeltaCRLNumber : BigInteger.ZERO;
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
        return (mCRLCerts.size() > 0 && mCRLSize == 0) ? mCRLCerts.size() : mCRLSize;
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
    public Set<RevokedCertificate> getRevokedCertificates(int start, int end) {
        if (mCRLCacheIsCleared || mCRLCerts == null || mCRLCerts.isEmpty()) {
            return null;
        } else {
            Set<RevokedCertificate> certSet = new LinkedHashSet<RevokedCertificate>(mCRLCerts.values());
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
                        mTimeListSize > 0) ||
                        (mEnableUpdateFreq && mAutoUpdateInterval > 0) ||
                        (mInitialized == CRL_IP_NOT_INITIALIZED) ||
                        mDoLastAutoUpdate || mDoManualUpdate)))) {
            mUpdateThread = new Thread(this, "CRLIssuingPoint-" + mId);
            log(ILogger.LL_INFO, CMS.getLogMessage("CMSCORE_CA_ISSUING_START_CRL", mId));
            mUpdateThread.setDaemon(true);
            mUpdateThread.start();
        }

        if ((mInitialized == CRL_IP_INITIALIZED) && (((mNextUpdate != null) ^
                ((mEnableDailyUpdates && mDailyUpdates != null && mTimeListSize > 0) ||
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
        return (mEnableUpdateFreq) ? mAutoUpdateInterval : 0;
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

    /**
     * Finds next update time expressed as delay or time of the next update.
     *
     * @param fromLastUpdate if true, function returns delay to the next update time
     *            otherwise returns the next update time.
     * @param delta if true, function returns the next update time for delta CRL,
     *            otherwise returns the next update time for CRL.
     * @return delay to the next update time or the next update time itself
     */
    private long findNextUpdate(boolean fromLastUpdate, boolean delta) {
        long now = System.currentTimeMillis();
        TimeZone tz = TimeZone.getDefault();
        int offset = tz.getOffset(now);
        long oneDay = 1440L * MINUTE;
        long nowToday = (now + offset) % oneDay;
        long startOfToday = now - nowToday;

        long lastUpdated = (mLastUpdate != null) ? mLastUpdate.getTime() : now;
        long lastUpdateDay = lastUpdated - ((lastUpdated + offset) % oneDay);

        long lastUpdate = (mLastUpdate != null && fromLastUpdate) ? mLastUpdate.getTime() : now;
        long last = (lastUpdate + offset) % oneDay;
        long lastDay = lastUpdate - last;

        boolean isDeltaEnabled = isDeltaCRLEnabled();
        long next = 0L;
        long nextUpdate = 0L;

        CMS.debug("findNextUpdate:  fromLastUpdate: " + fromLastUpdate + "  delta: " + delta);

        int numberOfDays = (int) ((startOfToday - lastUpdateDay) / oneDay);
        if (numberOfDays > 0 && mDailyUpdates.size() > 1 &&
                ((mCurrentDay == mLastDay) ||
                (mCurrentDay != ((mLastDay + numberOfDays) % mDailyUpdates.size())))) {
            mCurrentDay = (mLastDay + numberOfDays) % mDailyUpdates.size();
        }

        if ((delta || fromLastUpdate) && isDeltaEnabled &&
                (mUpdateSchema > 1 || (mEnableDailyUpdates && mExtendedTimeList)) &&
                mNextDeltaUpdate != null) {
            nextUpdate = mNextDeltaUpdate.getTime();
        } else if (mNextUpdate != null) {
            nextUpdate = mNextUpdate.getTime();
        }

        if (mEnableDailyUpdates &&
                mDailyUpdates != null && mDailyUpdates.size() > 0) {
            int n = 0;
            if (mDailyUpdates.size() == 1 && mDailyUpdates.elementAt(0).size() == 1 &&
                    mEnableUpdateFreq && mAutoUpdateInterval > 0) {
                // Interval updates with starting time
                long firstTime = MINUTE * mDailyUpdates.elementAt(0).elementAt(0).longValue();
                long t = firstTime;
                long interval = mAutoUpdateInterval;
                if (mExtendedNextUpdate && (!fromLastUpdate) && (!delta) &&
                        isDeltaEnabled && mUpdateSchema > 1) {
                    interval *= mUpdateSchema;
                }
                while (t < oneDay) {
                    if (t - mMinUpdateInterval > last)
                        break;
                    t += interval;
                    n++;
                }

                if (t <= oneDay) {
                    next = lastDay + t;
                    if (fromLastUpdate) {
                        n = n % mUpdateSchema;
                        if (t == firstTime) {
                            mSchemaCounter = 0;
                        } else if (n != mSchemaCounter) {
                            if (mSchemaCounter != 0 && (mSchemaCounter < n || n == 0)) {
                                mSchemaCounter = n;
                            }
                        }
                    }
                } else {
                    next = lastDay + oneDay + firstTime;
                    if (fromLastUpdate) {
                        mSchemaCounter = 0;
                    }
                }
            } else {
                // Daily updates following the list
                if (last > nowToday) {
                    last = nowToday - 100; // 100ms - precision
                }
                int i, m;
                for (i = 0, m = 0; i < mCurrentDay; i++) {
                    m += mDailyUpdates.elementAt(i).size();
                }
                // search the current day
                for (i = 0; i < mDailyUpdates.elementAt(mCurrentDay).size(); i++) {
                    long t = MINUTE * mDailyUpdates.elementAt(mCurrentDay).elementAt(i).longValue();
                    if (mEnableDailyUpdates && mExtendedTimeList) {
                        if (mExtendedNextUpdate && (!fromLastUpdate) && (!delta) && isDeltaEnabled) {
                            if (t < 0) {
                                t *= -1;
                            } else {
                                t = 0;
                            }
                        } else {
                            if (t < 0) {
                                t *= -1;
                            }
                        }
                    }
                    if (t - mMinUpdateInterval > last) {
                        if (mExtendedNextUpdate
                                && (!fromLastUpdate) && (!(mEnableDailyUpdates && mExtendedTimeList)) && (!delta) &&
                                isDeltaEnabled && mUpdateSchema > 1) {
                            i += mUpdateSchema - ((i + m) % mUpdateSchema);
                        }
                        break;
                    }
                    n++;
                }

                if (i < mDailyUpdates.elementAt(mCurrentDay).size()) {
                    // found inside the current day
                    next = (MINUTE * mDailyUpdates.elementAt(mCurrentDay).elementAt(i).longValue());
                    if (mEnableDailyUpdates && mExtendedTimeList && next < 0) {
                        next *= -1;
                        if (fromLastUpdate) {
                            mSchemaCounter = 0;
                        }
                    }
                    next += ((lastDay < lastUpdateDay) ? lastDay : lastUpdateDay) + (oneDay * (mCurrentDay - mLastDay));

                    if (fromLastUpdate && (!(mEnableDailyUpdates && mExtendedTimeList))) {
                        n = n % mUpdateSchema;
                        if (i == 0 && mCurrentDay == 0) {
                            mSchemaCounter = 0;
                        } else if (n != mSchemaCounter) {
                            if (mSchemaCounter != 0 && ((n == 0 && mCurrentDay == 0) || mSchemaCounter < n)) {
                                mSchemaCounter = n;
                            }
                        }
                    }
                } else {
                    // done with today
                    int j = i - mDailyUpdates.elementAt(mCurrentDay).size();
                    int nDays = 1;
                    long t = 0;
                    if (mDailyUpdates.size() > 1) {
                        while (nDays <= mDailyUpdates.size()) {
                            int nextDay = (mCurrentDay + nDays) % mDailyUpdates.size();
                            if (j < mDailyUpdates.elementAt(nextDay).size()) {
                                if (nextDay == 0 && (!(mEnableDailyUpdates && mExtendedTimeList)))
                                    j = 0;
                                t = MINUTE * mDailyUpdates.elementAt(nextDay).elementAt(j).longValue();
                                if (mEnableDailyUpdates && mExtendedTimeList) {
                                    if (mExtendedNextUpdate && (!fromLastUpdate) && (!delta) && isDeltaEnabled) {
                                        if (t < 0) {
                                            t *= -1;
                                        } else {
                                            j++;
                                            continue;
                                        }
                                    } else {
                                        if (t < 0) {
                                            t *= -1;
                                            if (fromLastUpdate) {
                                                mSchemaCounter = 0;
                                            }
                                        }
                                    }
                                }
                                break;
                            } else {
                                j -= mDailyUpdates.elementAt(nextDay).size();
                            }
                            nDays++;
                        }
                    }
                    next = ((lastDay < lastUpdateDay) ? lastDay : lastUpdateDay) + (oneDay * nDays) + t;

                    if (fromLastUpdate && mDailyUpdates.size() < 2) {
                        mSchemaCounter = 0;
                    }
                }
            }
        } else if (mEnableUpdateFreq && mAutoUpdateInterval > 0) {
            // Interval updates without starting time
            if (mExtendedNextUpdate && (!fromLastUpdate) && (!delta) && isDeltaEnabled && mUpdateSchema > 1) {
                next = lastUpdate + (mUpdateSchema * mAutoUpdateInterval);
            } else {
                next = lastUpdate + mAutoUpdateInterval;
            }
        }

        if (fromLastUpdate && nextUpdate > 0 && (nextUpdate < next || nextUpdate >= now)) {
            next = nextUpdate;
        }

        CMS.debug("findNextUpdate:  "
                + ((new Date(next)).toString()) + ((fromLastUpdate) ? "  delay: " + (next - now) : ""));

        return (fromLastUpdate) ? next - now : next;
    }

    /**
     * Implements Runnable interface. Defines auto-update
     * logic used by worker thread.
     * <P>
     */
    public void run() {
        try {
            while (mEnable && ((mEnableCRLCache && mCacheUpdateInterval > 0) ||
                    (mInitialized == CRL_IP_NOT_INITIALIZED) ||
                    mDoLastAutoUpdate || (mEnableCRLUpdates &&
                    ((mEnableDailyUpdates && mDailyUpdates != null &&
                            mTimeListSize > 0) ||
                            (mEnableUpdateFreq && mAutoUpdateInterval > 0) ||
                    mDoManualUpdate)))) {

                synchronized (this) {
                    long delay = 0;
                    long delay2 = 0;
                    boolean doCacheUpdate = false;
                    boolean scheduledUpdates = mEnableCRLUpdates &&
                            ((mEnableDailyUpdates && mDailyUpdates != null &&
                            mTimeListSize > 0) ||
                            (mEnableUpdateFreq && mAutoUpdateInterval > 0));

                    if (mInitialized == CRL_IP_NOT_INITIALIZED)
                        initCRL();

                    if (mInitialized == CRL_IP_INITIALIZED && (!mEnable))
                        break;

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
                                    (doCacheUpdate) ? "update CRL cache" : "update CRL", e.toString()));
                            if (Debug.on()) {
                                Debug.trace((doCacheUpdate) ? "update CRL cache" : "update CRL" + " error " + e);
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
        } catch (EBaseException e1) {
            e1.printStackTrace();
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
            StringBuffer tempBuffer = new StringBuffer();
            for (int k = 0; k < mProfileList.size(); k++) {
                String id = mProfileList.elementAt(k);
                tempBuffer.append("(" + CertRecord.ATTR_META_INFO + "=profileId:" + id + ")");
            }
            filter += tempBuffer.toString();
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
     *
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
        CertificateRepository cr = (CertificateRepository) mCertRepository;

        synchronized (cr.certStatusUpdateTask) {
            CMS.debug("Starting processRevokedCerts (entered lock)");
            ICertRecordList list = mCertRepository.findCertRecordsInList(
                    filter,
                    new String[] {
                            ICertRecord.ATTR_ID, ICertRecord.ATTR_REVO_INFO, "objectclass"
                    },
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
     * @throws EBaseException
     */
    private void recoverCRLCache() throws EBaseException {
        if (mEnableCacheRecovery) {
            // 553815 - original filter was not aligned with any VLV index
            // String filter = "(&(requeststate=complete)"+
            //                 "(|(requestType=" + IRequest.REVOCATION_REQUEST + ")"+
            //                 "(requestType=" + IRequest.UNREVOCATION_REQUEST + ")))";
            String filter = "(requeststate=complete)";
            if (Debug.on()) {
                Debug.trace("recoverCRLCache  mFirstUnsaved=" + mFirstUnsaved + "  filter=" + filter);
            }
            IRequestQueue mQueue = mCA.getRequestQueue();

            IRequestVirtualList list = mQueue.getPagedRequestsByFilter(
                        new RequestId(mFirstUnsaved), filter, 500, "requestId");
            if (Debug.on()) {
                Debug.trace("recoverCRLCache  size=" + list.getSize() + "  index=" + list.getCurrentIndex());
            }

            CertRecProcessor cp = new CertRecProcessor(mCRLCerts, this, mAllowExtensions);
            boolean includeCert = true;

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
                    Debug.trace("recoverCRLCache  request=" + request.getRequestId().toString() +
                                "  type=" + request.getRequestType());
                }
                if (IRequest.REVOCATION_REQUEST.equals(request.getRequestType())) {
                    RevokedCertImpl revokedCert[] =
                            request.getExtDataInRevokedCertArray(IRequest.CERT_INFO);
                    if (revokedCert != null) {
                        for (int j = 0; j < revokedCert.length; j++) {
                            if (Debug.on()) {
                                Debug.trace("recoverCRLCache R j=" + j + "  length=" + revokedCert.length +
                                        "  SerialNumber=0x" + revokedCert[j].getSerialNumber().toString(16));
                            }
                            if (cp != null)
                                includeCert = cp.checkRevokedCertExtensions(revokedCert[j].getExtensions());
                            if (includeCert) {
                                updateRevokedCert(REVOKED_CERT, revokedCert[j].getSerialNumber(), revokedCert[j]);
                            }
                        }
                    } else {
                        if (Debug.on()) {
                            Debug.trace("Revocation Request : Revoked Certificates is a Null or has Invalid Values");
                        }
                        log(ILogger.LL_FAILURE, "Revoked Certificates is a Null or has Invalid Values");
                        throw new EBaseException("Revocation Request : Revoked Certificates is a Null or has Invalid Values");
                    }
                } else if (IRequest.UNREVOCATION_REQUEST.equals(request.getRequestType())) {
                    BigInteger serialNo[] = request.getExtDataInBigIntegerArray(IRequest.OLD_SERIALS);
                    if (serialNo != null) {
                        for (int j = 0; j < serialNo.length; j++) {
                            if (Debug.on()) {
                                Debug.trace("recoverCRLCache U j=" + j + "  length=" + serialNo.length +
                                        "  SerialNumber=0x" + serialNo[j].toString(16));
                            }
                            updateRevokedCert(UNREVOKED_CERT, serialNo[j], null);
                        }
                    } else {
                        if (Debug.on()) {
                            Debug.trace("Unrevocation Request : Serial Numbers is a Null or has Invalid Values");
                        }
                        log(ILogger.LL_FAILURE, "Unrevocation Request : Serial Numbers is a Null or has Invalid Values");
                        throw new EBaseException("Unrevocation Request : Serial Numbers is a Null or has Invalid Values");
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

    private Extension getCRLExtension(String extName) {
        if (mAllowExtensions == false) {
            return null;
        }
        if (mCMSCRLExtensions.isCRLExtensionEnabled(extName) == false) {
            return null;
        }

        CMSCRLExtensions exts = (CMSCRLExtensions) this.getCRLExtensions();
        CRLExtensions ext = new CRLExtensions();

        Vector<String> extNames = exts.getCRLExtensionNames();
        for (int i = 0; i < extNames.size(); i++) {
            String curName = extNames.elementAt(i);
            if (curName.equals(extName)) {
                exts.addToCRLExtensions(ext, extName, null);
            }
        }
        Extension theExt = null;
        try {
            theExt = ext.get(extName);
        } catch (Exception e) {
        }

        CMS.debug("CRLIssuingPoint.getCRLExtension extension: " + theExt);
        return theExt;
    }

    /**
     * get required crl entry extensions
     */
    public CRLExtensions getRequiredEntryExtensions(CRLExtensions exts) {
        CRLExtensions entryExt = null;

        if (mAllowExtensions && exts != null && exts.size() > 0) {
            entryExt = new CRLExtensions();
            Vector<String> extNames = mCMSCRLExtensions.getCRLEntryExtensionNames();

            for (int i = 0; i < extNames.size(); i++) {
                String extName = extNames.elementAt(i);

                if (mCMSCRLExtensions.isCRLExtensionEnabled(extName)) {
                    int k;

                    for (k = 0; k < exts.size(); k++) {
                        Extension ext = exts.elementAt(k);
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

                        mCRLCerts.put(serialNumber, newRevokedCert);
                    }
                } else {
                    Date revocationDate = revokedCert.getRevocationDate();
                    CRLExtensions entryExt = getRequiredEntryExtensions(revokedCert.getExtensions());
                    RevokedCertImpl newRevokedCert =
                            new RevokedCertImpl(serialNumber, revocationDate, entryExt);

                    mRevokedCerts.put(serialNumber, newRevokedCert);
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

                    mUnrevokedCerts.put(serialNumber, newRevokedCert);
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

        CertRecProcessor cp = new CertRecProcessor(mCRLCerts, this, mAllowExtensions);
        boolean includeCert = true;
        if (cp != null)
            includeCert = cp.checkRevokedCertExtensions(revokedCert.getExtensions());

        if (mEnable && mEnableCRLCache && includeCert == true) {
            updateRevokedCert(REVOKED_CERT, serialNumber, revokedCert, requestId);

            if (mCacheUpdateInterval == 0) {
                try {
                    mCRLRepository.updateRevokedCerts(mId, mRevokedCerts, mUnrevokedCerts);
                    mFirstUnsaved = ICRLIssuingPointRecord.CLEAN_CACHE;
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_REVOKED_CERT", mId, e.toString()));
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
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_UNREVOKED_CERT", mId, e.toString()));
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

                mExpiredCerts.put(serialNumber, newRevokedCert);
            }

            if (mCacheUpdateInterval == 0) {
                try {
                    mCRLRepository.updateExpiredCerts(mId, mExpiredCerts);
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_EXPIRED_CERT", mId, e.toString()));
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
                        Extension ext = crlExtensions.elementAt(k);

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
        return ((mCRLCerts != null) ? mCRLCerts.isEmpty() : true);
    }

    public boolean isCRLCacheTestingEnabled() {
        return mEnableCacheTesting;
    }

    public Date getRevocationDateFromCache(BigInteger serialNumber,
            boolean checkDeltaCache,
            boolean includeExpiredCerts) {
        Date revocationDate = null;

        if (mCRLCerts.containsKey(serialNumber)) {
            revocationDate = mCRLCerts.get(serialNumber).getRevocationDate();
        }

        if (checkDeltaCache && isDeltaCRLEnabled()) {
            if (mUnrevokedCerts.containsKey(serialNumber)) {
                revocationDate = null;
            }
            if (mRevokedCerts.containsKey(serialNumber)) {
                revocationDate = mRevokedCerts.get(serialNumber).getRevocationDate();
            }
            if (!includeExpiredCerts && mExpiredCerts.containsKey(serialNumber)) {
                revocationDate = null;
            }
        }

        return revocationDate;
    }

    public synchronized Vector<Long> getSplitTimes() {
        Vector<Long> splits = new Vector<Long>();

        for (int i = 0; i < mSplits.length; i++) {
            splits.addElement(Long.valueOf(mSplits[i]));
        }
        return splits;
    }

    public synchronized int isCRLUpdateInProgress() {
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

        if ((!mEnable) || (!mEnableCRLUpdates && !mDoLastAutoUpdate))
            return;
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
                                    mCRLCerts.size() + "," + mRevokedCerts.size() + "," + mUnrevokedCerts.size()
                                    + "," + mExpiredCerts.size() + ""
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
                mDailyUpdates != null && mTimeListSize > 0) ||
                (mEnableUpdateFreq && mAutoUpdateInterval > 0))) {

            if ((!isDeltaCRLEnabled()) || mSchemaCounter == 0 || mUpdateSchema == 1) {
                nextUpdate = new Date(findNextUpdate(false, false));
                mNextUpdate = new Date(nextUpdate.getTime());
            }
            if (isDeltaCRLEnabled()) {
                if (mUpdateSchema > 1 || (mEnableDailyUpdates && mExtendedTimeList && mTimeListSize > 1)) {
                    nextDeltaUpdate = new Date(findNextUpdate(false, true));
                    if (mExtendedNextUpdate && mSchemaCounter > 0 &&
                            mNextUpdate != null && mNextUpdate.equals(nextDeltaUpdate)) {
                        if (mEnableDailyUpdates && mExtendedTimeList && mTimeListSize > 1) {
                            mSchemaCounter = mTimeListSize - 1;
                        } else {
                            mSchemaCounter = mUpdateSchema - 1;
                        }
                    }
                } else {
                    nextDeltaUpdate = new Date(nextUpdate.getTime());
                    if (mUpdateSchema == 1) {
                        mSchemaCounter = 0;
                    }
                }
            }
        }

        for (int i = 0; i < mSplits.length; i++) {
            mSplits[i] = 0;
        }

        mLastUpdate = thisUpdate;
        // mNextUpdate = nextUpdate;
        mNextDeltaUpdate = (nextDeltaUpdate != null) ? new Date(nextDeltaUpdate.getTime()) : null;
        if (mNextAsThisUpdateExtension > 0) {
            Date nextUpdateAsThisUpdateExtension = new Date(thisUpdate.getTime()+mNextAsThisUpdateExtension);
            if (nextUpdate != null && nextUpdate.before(nextUpdateAsThisUpdateExtension)) {
                nextUpdate = nextUpdateAsThisUpdateExtension;
            }
            if (nextDeltaUpdate != null && nextDeltaUpdate.before(nextUpdateAsThisUpdateExtension)) {
                nextDeltaUpdate = nextUpdateAsThisUpdateExtension;
            }
        }
        if (nextUpdate != null) {
            nextUpdate.setTime((nextUpdate.getTime()) + mNextUpdateGracePeriod);
        }
        if (nextDeltaUpdate != null) {
            nextDeltaUpdate.setTime((nextDeltaUpdate.getTime()) + mNextUpdateGracePeriod);
        }

        mSplits[0] -= System.currentTimeMillis();
        @SuppressWarnings("unchecked")
        Hashtable<BigInteger, RevokedCertificate> clonedRevokedCerts =
                (Hashtable<BigInteger, RevokedCertificate>) mRevokedCerts.clone();
        @SuppressWarnings("unchecked")
        Hashtable<BigInteger, RevokedCertificate> clonedUnrevokedCerts =
                (Hashtable<BigInteger, RevokedCertificate>) mUnrevokedCerts.clone();
        @SuppressWarnings("unchecked")
        Hashtable<BigInteger, RevokedCertificate> clonedExpiredCerts =
                (Hashtable<BigInteger, RevokedCertificate>) mExpiredCerts.clone();

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

            IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
            if (statsSub != null) {
                statsSub.startTiming("generation");
            }
            CertRecProcessor cp = new CertRecProcessor(mCRLCerts, this, mAllowExtensions);
            processRevokedCerts(cp);

            if (statsSub != null) {
                statsSub.endTiming("generation");
            }

            mCRLCacheIsCleared = false;
            mSplits[5] += System.currentTimeMillis();
        } else {
            if (isDeltaCRLEnabled()) {
                mSplits[1] -= System.currentTimeMillis();
                @SuppressWarnings("unchecked")
                Hashtable<BigInteger, RevokedCertificate> deltaCRLCerts =
                        (Hashtable<BigInteger, RevokedCertificate>) clonedRevokedCerts.clone();

                deltaCRLCerts.putAll(clonedUnrevokedCerts);
                if (mIncludeExpiredCertsOneExtraTime) {
                    if (!clonedExpiredCerts.isEmpty()) {
                        for (Enumeration<BigInteger> e = clonedExpiredCerts.keys(); e.hasMoreElements();) {
                            BigInteger serialNumber = e.nextElement();
                            if ((mLastFullUpdate != null &&
                                    mLastFullUpdate.after((mExpiredCerts.get(serialNumber)).getRevocationDate())) ||
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
                Vector<String> extNames = mCMSCRLExtensions.getCRLExtensionNames();

                for (int i = 0; i < extNames.size(); i++) {
                    String extName = extNames.elementAt(i);

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
                            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                                    "No Revoked Certificates"));
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
                    StringBuffer splitTimes = new StringBuffer("  (");
                    for (int i = 1; i < mSplits.length && i < 5; i++) {
                        totalTime += mSplits[i];
                        if (i > 1)
                            splitTimes.append(",");
                        splitTimes.append(String.valueOf(mSplits[i]));
                    }
                    splitTimes.append(")");
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
                                    Long.toString(totalTime) + splitTimes.toString()
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
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_DELTA", mCRLNumber.toString(), e.toString()));
                } catch (OutOfMemoryError e) {
                    newX509DeltaCRL = null;
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_DELTA", mCRLNumber.toString(), e.toString()));
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
                        for (Enumeration<BigInteger> e = clonedUnrevokedCerts.keys(); e.hasMoreElements();) {
                            BigInteger serialNumber = e.nextElement();

                            if (mCRLCerts.containsKey(serialNumber)) {
                                mCRLCerts.remove(serialNumber);
                            }
                            mUnrevokedCerts.remove(serialNumber);
                        }
                    }

                    if (!clonedRevokedCerts.isEmpty()) {
                        for (Enumeration<BigInteger> e = clonedRevokedCerts.keys(); e.hasMoreElements();) {
                            BigInteger serialNumber = e.nextElement();

                            mCRLCerts.put(serialNumber, mRevokedCerts.get(serialNumber));
                            mRevokedCerts.remove(serialNumber);
                        }
                    }

                    if (!clonedExpiredCerts.isEmpty()) {
                        for (Enumeration<BigInteger> e = clonedExpiredCerts.keys(); e.hasMoreElements();) {
                            BigInteger serialNumber = e.nextElement();

                            if ((!mIncludeExpiredCertsOneExtraTime) ||
                                    (mLastFullUpdate != null &&
                                    mLastFullUpdate.after((mExpiredCerts.get(serialNumber)).getRevocationDate())) ||
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
                Vector<String> extNames = mCMSCRLExtensions.getCRLExtensionNames();

                for (int i = 0; i < extNames.size(); i++) {
                    String extName = extNames.elementAt(i);

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

                CMS.debug("Making CRL with algorithm " +
                        signingAlgorithm + " " + AlgorithmId.get(signingAlgorithm));

                mSplits[7] -= System.currentTimeMillis();

                // #56123 - dont generate CRL if no revoked certificates
                if (mConfigStore.getBoolean("noCRLIfNoRevokedCert", false)) {
                    if (mCRLCerts.size() == 0) {
                        CMS.debug("CRLIssuingPoint: No Revoked Certificates Found And noCRLIfNoRevokedCert is set to true - No CRL Generated");
                        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR",
                                "No Revoked Certificates"));
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
                if (isDeltaCRLEnabled() && (mUpdateSchema > 1 ||
                        (mEnableDailyUpdates && mExtendedTimeList)) && mNextDeltaUpdate != null) {
                    nextUpdateDate = mNextDeltaUpdate;
                }
                if (mSaveMemory) {
                    mCRLRepository.updateCRLIssuingPointRecord(
                            mId, newCRL, thisUpdate, nextUpdateDate,
                            mNextCRLNumber, Long.valueOf(mCRLCerts.size()));
                    updateCRLCacheRepository();
                } else {
                    mCRLRepository.updateCRLIssuingPointRecord(
                            mId, newCRL, thisUpdate, nextUpdateDate,
                            mNextCRLNumber, Long.valueOf(mCRLCerts.size()),
                            mRevokedCerts, mUnrevokedCerts, mExpiredCerts);
                    mFirstUnsaved = ICRLIssuingPointRecord.CLEAN_CACHE;
                }

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
                StringBuilder splitTimes = new StringBuilder("  (");
                for (int i = 0; i < mSplits.length; i++) {
                    totalTime += mSplits[i];
                    if (i > 0 && i < 5) {
                        deltaTime += mSplits[i];
                    } else {
                        crlTime += mSplits[i];
                    }
                    if (i > 0)
                        splitTimes.append(",");
                    splitTimes.append(mSplits[i]);
                }
                splitTimes.append(String.format(",%d,%d,%d)",deltaTime,crlTime,totalTime));
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
                                    Long.toString(deltaTime) + splitTimes
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
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_CRL", mCRLNumber.toString(), e.toString()));
            } catch (OutOfMemoryError e) {
                newX509CRL = null;
                mUpdatingCRL = CRL_UPDATE_DONE;
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_CRL", mCRLNumber.toString(), e.toString()));
            }
        }

        if (isDeltaCRLEnabled() && mDeltaCRLSize > -1 && mSchemaCounter > 0) {
            mDeltaCRLNumber = mNextDeltaCRLNumber;
            mNextDeltaCRLNumber = mDeltaCRLNumber.add(BigInteger.ONE);
        }

        if ((!(mEnableDailyUpdates && mExtendedTimeList)) || mSchemaCounter == 0)
            mSchemaCounter++;
        if ((mEnableDailyUpdates && mExtendedTimeList && mSchemaCounter >= mTimeListSize) ||
                (mUpdateSchema > 1 && mSchemaCounter >= mUpdateSchema))
            mSchemaCounter = 0;
        mLastDay = mCurrentDay;

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

    /*
     *  The Session Context is a Hashtable, but without type information.
     *  Suppress the warnings generated by adding to the session context
     *
     */
    protected void publishCRL(X509CRLImpl x509crl, boolean isDeltaCRL)
            throws EBaseException {
        SessionContext sc = SessionContext.getContext();

        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        if (statsSub != null) {
            statsSub.startTiming("crl_publishing");
        }

        if (mCountMod == 0) {
            sc.put(SC_CRL_COUNT, Integer.toString(mCount));
        } else {
            sc.put(SC_CRL_COUNT, Integer.toString(mCount % mCountMod));
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
                Enumeration<ILdapRule> rules = mPublisherProcessor.getRules(IPublisherProcessor.PROP_LOCAL_CRL);
                if (rules == null || !rules.hasMoreElements()) {
                    CMS.debug("CRL publishing is not enabled.");
                } else {
                    if (mPublishDN != null) {
                        mPublisherProcessor.publishCRL(mPublishDN, x509crl);
                        CMS.debug("CRL published to " + mPublishDN);
                    } else {
                        mPublisherProcessor.publishCRL(x509crl, getId());
                        CMS.debug("CRL published.");
                    }
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

    protected synchronized void log(int level, String msg) {
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
    private Hashtable<BigInteger, RevokedCertificate> mCRLCerts = null;
    private boolean mAllowExtensions = false;
    private CRLIssuingPoint mIP = null;

    private boolean mIssuingDistPointAttempted = false;
    private boolean mIssuingDistPointEnabled = false;
    private BitArray mOnlySomeReasons = null;

    public CertRecProcessor(Hashtable<BigInteger, RevokedCertificate> crlCerts, CRLIssuingPoint ip,
            boolean allowExtensions) {
        mCRLCerts = crlCerts;
        mIP = ip;
        mAllowExtensions = allowExtensions;
        mIssuingDistPointAttempted = false;
        mIssuingDistPointEnabled = false;
        mOnlySomeReasons = null;
    }

    private boolean initCRLIssuingDistPointExtension() {
        boolean result = false;
        CMSCRLExtensions exts = null;

        if (mIssuingDistPointAttempted == true) {
            if ((mIssuingDistPointEnabled == true) && (mOnlySomeReasons != null)) {
                return true;
            } else {
                return false;
            }
        }

        mIssuingDistPointAttempted = true;
        exts = (CMSCRLExtensions) mIP.getCRLExtensions();
        if (exts == null) {
            return result;
        }
        boolean isIssuingDistPointExtEnabled = false;
        isIssuingDistPointExtEnabled =
                exts.isCRLExtensionEnabled(IssuingDistributionPointExtension.NAME);
        if (isIssuingDistPointExtEnabled == false) {
            mIssuingDistPointEnabled = false;
            return false;
        }

        mIssuingDistPointEnabled = true;

        //Get info out of the IssuingDistPointExtension
        CRLExtensions ext = new CRLExtensions();
        Vector<String> extNames = exts.getCRLExtensionNames();
        for (int i = 0; i < extNames.size(); i++) {
            String extName = extNames.elementAt(i);
            if (extName.equals(IssuingDistributionPointExtension.NAME)) {
                exts.addToCRLExtensions(ext, extName, null);
            }
        }
        Extension issuingDistExt = null;
        try {
            issuingDistExt = ext.get(IssuingDistributionPointExtension.NAME);
        } catch (Exception e) {
        }

        IssuingDistributionPointExtension iExt = null;
        if (issuingDistExt != null)
            iExt = (IssuingDistributionPointExtension) issuingDistExt;
        IssuingDistributionPoint issuingDistributionPoint = null;
        if (iExt != null)
            issuingDistributionPoint = iExt.getIssuingDistributionPoint();

        BitArray onlySomeReasons = null;

        if (issuingDistributionPoint != null)
            onlySomeReasons = issuingDistributionPoint.getOnlySomeReasons();

        boolean applyReasonMatch = false;

        if (onlySomeReasons != null) {
            applyReasonMatch = !onlySomeReasons.toString().equals("0000000");
            CMS.debug("applyReasonMatch " + applyReasonMatch);
            if (applyReasonMatch == true) {
                mOnlySomeReasons = onlySomeReasons;
                result = true;
            }
        }
        return result;
    }

    private boolean checkOnlySomeReasonsExtension(CRLExtensions entryExts) {
        boolean includeCert = true;
        //This is exactly how the Pretty Print code obtains the reason code
        //through the extensions
        if (entryExts == null) {
            return includeCert;
        }

        Extension crlReasonExt = null;
        try {
            crlReasonExt = entryExts.get(CRLReasonExtension.NAME);
        } catch (Exception e) {
            return includeCert;
        }

        RevocationReason reason = null;
        int reasonIndex = 0;
        if (crlReasonExt != null) {
            try {
                CRLReasonExtension theReason = (CRLReasonExtension) crlReasonExt;
                reason = (RevocationReason) theReason.get("value");
                reasonIndex = reason.toInt();
                CMS.debug("revoked reason " + reason);
            } catch (Exception e) {
                return includeCert;
            }
        } else {
            return includeCert;
        }
        boolean reasonMatch = false;
        if (mOnlySomeReasons != null) {
            reasonMatch = mOnlySomeReasons.get(reasonIndex);
            if (reasonMatch != true) {
                includeCert = false;
            } else {
                CMS.debug("onlySomeReasons match! reason: " + reason);
            }
        }

        return includeCert;
    }

    public boolean checkRevokedCertExtensions(CRLExtensions crlExtensions) {
        //For now just check the onlySomeReason CRL IssuingDistributionPoint extension

        boolean includeCert = true;
        if ((crlExtensions == null) || (mAllowExtensions == false)) {
            return includeCert;
        }
        boolean inited = initCRLIssuingDistPointExtension();

        //If the CRLIssuingDistPointExtension is not available or
        // if onlySomeReasons does not apply, bail.
        if (inited == false) {
            return includeCert;
        }

        //Check the onlySomeReasonsExtension
        includeCert = checkOnlySomeReasonsExtension(crlExtensions);

        return includeCert;
    }

    public void process(Object o) throws EBaseException {
        try {
            CertRecord certRecord = (CertRecord) o;

            CRLExtensions entryExt = null, crlExts = null;
            BigInteger serialNumber = certRecord.getSerialNumber();
            Date revocationDate = certRecord.getRevocationDate();
            IRevocationInfo revInfo = certRecord.getRevocationInfo();

            if (revInfo != null) {
                crlExts = revInfo.getCRLEntryExtensions();
                entryExt = mIP.getRequiredEntryExtensions(crlExts);
            }
            RevokedCertificate newRevokedCert =
                    new RevokedCertImpl(serialNumber, revocationDate, entryExt);

            boolean includeCert = checkRevokedCertExtensions(crlExts);

            if (includeCert == true) {
                mCRLCerts.put(serialNumber, newRevokedCert);
                CMS.debug("Putting certificate serial: 0x" + serialNumber.toString(16) + " into CRL hashtable");
            }
        } catch (EBaseException e) {
            CMS.debug(
                    "CA failed constructing CRL entry: " +
                            (mCRLCerts.size() + 1) + " " + e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_FAILED_CONSTRUCTING_CRL", e.toString()));
        }
    }
}
