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
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.Vector;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.ICMSCRLExtensions;
import org.dogtagpki.server.ca.ICRLIssuingPoint;
import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLNumberExtension;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.DeltaCRLIndicatorExtension;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.FreshestCRLExtension;
import org.mozilla.jss.netscape.security.x509.IssuingDistributionPoint;
import org.mozilla.jss.netscape.security.x509.IssuingDistributionPointExtension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.RevokedCertificate;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.ca.EErrorPublishCRL;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.dbs.EDBNotAvailException;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.IElementProcessor;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.DeltaCRLGenerationEvent;
import com.netscape.certsrv.logging.event.DeltaCRLPublishingEvent;
import com.netscape.certsrv.logging.event.FullCRLGenerationEvent;
import com.netscape.certsrv.logging.event.FullCRLPublishingEvent;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestVirtualList;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.CRLRepository;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertRecordList;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.ldap.CAPublisherProcessor;
import com.netscape.cmscore.ldap.LdapRule;
import com.netscape.cmscore.request.CertRequestRepository;

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

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CRLIssuingPoint.class);

    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    /* Foreign config param for IssuingDistributionPointExtension. */
    public static final String PROP_CACERTS = "onlyContainsCACerts";

    public static final long SECOND = 1000L;
    public static final long MINUTE = (SECOND * 60L);

    private static final int CRL_PAGE_SIZE = 10000;

    private static final String PROP_CRL_STARTING_NUMBER = "startingCrlNumber";

    /* configuration file property names */

    public CAPublisherProcessor mPublisherProcessor;

    private CRLIssuingPointConfig mConfigStore;

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
    protected CRLRepository mCRLRepository;

    /**
     * Reference to the cert repository maintained in CA.
     */
    private CertificateRepository mCertRepository;

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
    boolean mAlwaysUpdate = false;

    /**
     * next update grace period
     */
    private long mNextUpdateGracePeriod;

    /**
     * time to wait at the next loop if exception happens during CRL generation
     */
    private long mUnexpectedExceptionWaitTime;

    /**
     * Max number allowed to loop if exception happens during CRL generation.
     * When mUnexpectedExceptionLoopMax is reached, a slow down procedure
     * will be executed
     */
    private int mUnexpectedExceptionLoopMax;

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
    private CRLIssuingPointStatus mInitialized =
        CRLIssuingPointStatus.NotInitialized;

    /**
     * number of entries in the CRL
     */
    private long mCRLSize = -1;
    private long mDeltaCRLSize = -1;

    /**
     * update status, publishing status Strings to store in requests to
     * display result.
     */
    String mCrlUpdateStatus;
    String mCrlUpdateError;
    String mCrlPublishStatus;
    String mCrlPublishError;

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
     * One time config flag that we have an updated schedule and we want it
     * followed immediately after startup.
     */

    private boolean mAutoUpdateIntervalEffectiveAtStart = false;


     /* Optional future value for thisUpdate field of generated CRL
      * Feature for now only available by command line "sslget" examples:
      *
      * # with future update date:

       sslget -n "PKI Administrator for localhost.localdomain"
             -e "crlIssuingPoint=MasterCRL&signatureAlgorithm&waitForUpdate=true&clearCRLCache=true&customFutureThisUpdateDateValue=2020:9:22:13:0:0"
             -v -d . -p ""  -r /ca/agent/ca/updateCRL localhost.localdomain:8443


       # Cancel any outstanding future thisUpdate value already established, if necessary to recover
       sslget -n "PKI Administrator for localhost.localdomain"
             -e "crlIssuingPoint=MasterCRL&signatureAlgorithm&waitForUpdate=true&clearCRLCache=true&cancelCurCustomFutureThisUpdateValue=true"
             -v -d . -p ""  -r /ca/agent/ca/updateCRL localhost.localdomain:8443


     */
    private Date mCustomFutureThisUpdateValue = null;

    private boolean mForbidCustomFutureThisUpdateValue = true;

    private boolean mCancelCurFutureThisUpdateValue=false;

    /**
     * Constructs a CRL issuing point from instantiating from class name.
     * CRL Issuing point must be followed by method call init(CA, id, config);
     */
    public CRLIssuingPoint() {
    }

    @Override
    public boolean isCRLIssuingPointEnabled() {
        return mEnable;
    }

    @Override
    public void enableCRLIssuingPoint(boolean enable) {
        if (!enable && mEnable) {
            clearCRLCache();
            updateCRLCacheRepository();
        } else if (enable && !mEnable) {
            // Mark the CRLIP as NotInitialized so that the CRL
            // entry will be read afresh when it is reinitialised.
            // This ensures monotonicity of the CRL number, if some
            // other clone was issuing CRLs in the meantime.
            //
            // See also:
            //   https://github.com/dogtagpki/pki/issues/3202
            //   https://pagure.io/freeipa/issue/7815
            //
            mInitialized = CRLIssuingPointStatus.NotInitialized;
        }
        mEnable = enable;
        setAutoUpdates();
    }

    @Override
    public boolean isCRLGenerationEnabled() {
        return mEnableCRLUpdates;
    }

    @Override
    public String getCrlUpdateStatusStr() {
        return mCrlUpdateStatus;
    }

    @Override
    public String getCrlUpdateErrorStr() {
        return mCrlUpdateError;
    }

    @Override
    public String getCrlPublishStatusStr() {
        return mCrlPublishStatus;
    }

    @Override
    public String getCrlPublishErrorStr() {
        return mCrlPublishError;
    }

    @Override
    public ICMSCRLExtensions getCRLExtensions() {
        return mCMSCRLExtensions;
    }

    @Override
    public void setCustomFutureThisUpdateValue(Date futureThisUpdate) {
        mCustomFutureThisUpdateValue = futureThisUpdate;
    }

    @Override
    public void setCancelCurFutureThisUpdateValue(boolean b) {
        mCancelCurFutureThisUpdateValue = b;

    }

    @Override
    public boolean isCRLIssuingPointInitialized() {
        return mInitialized == CRLIssuingPointStatus.Initialized;
    }

    @Override
    public boolean isManualUpdateSet() {
        return mDoManualUpdate;
    }

    @Override
    public boolean areExpiredCertsIncluded() {
        return mIncludeExpiredCerts;
    }

    @Override
    public boolean isCACertsOnly() {
        return mCACertsOnly;
    }

    @Override
    public boolean isProfileCertsOnly() {
        return (mProfileCertsOnly && mProfileList != null && mProfileList.size() > 0);
    }

    @Override
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
    @Override
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

        mConfigStore = (CRLIssuingPointConfig) config;

        IConfigStore crlSubStore = mCA.getConfigStore().getSubStore(ICertificateAuthority.PROP_CRL_SUBSTORE);
        mPageSize = crlSubStore.getInteger(ICertificateAuthority.PROP_CRL_PAGE_SIZE, CRL_PAGE_SIZE);
        logger.debug("CRL Page Size: " + mPageSize);

        mCountMod = mConfigStore.getCountMod();

        CAEngine engine = CAEngine.getInstance();
        mCRLRepository = engine.getCRLRepository();
        mCertRepository = engine.getCertificateRepository();
        mPublisherProcessor = engine.getPublisherProcessor();

        //mCRLPublisher = mCA.getCRLPublisher();

        // read in config parameters.
        initConfig(mConfigStore);

        // create request listener.
        String lname = RevocationRequestListener.class.getName();
        String crlListName = lname + "_" + mId;

        if (mCA.getRequestListener(crlListName) == null) {
            mCA.registerRequestListener(
                    crlListName, new RevocationRequestListener(this));
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
        logger.debug("areTimeListsIdentical:  identical: " + identical);
        return identical;
    }

    private int getTimeListSize(Vector<Vector<Integer>> listedDays) {
        int listSize = 0;
        for (int i = 0; listedDays != null && i < listedDays.size(); i++) {
            Vector<Integer> listedTimes = listedDays.elementAt(i);
            listSize += ((listedTimes != null) ? listedTimes.size() : 0);
        }
        logger.debug("getTimeListSize:  ListSize=" + listSize);
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
        CAEngine engine = CAEngine.getInstance();
        IConfigStore pc = engine.getConfig().getSubStore("profile");
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
    protected void initConfig(CRLIssuingPointConfig config) throws EBaseException {

        mEnable = config.getEnable();
        mDescription = config.getDescription();

        // Get CRL cache config.
        mEnableCRLCache = config.getEnableCRLCache();
        mCacheUpdateInterval = MINUTE * config.getCacheUpdateInterval();
        mEnableCacheRecovery = config.getEnableCacheRecovery();
        mEnableCacheTesting = config.getEnableCacheTesting();

        // check if CRL generation is enabled
        mEnableCRLUpdates = config.getEnableCRLUpdates();

        // get update schema
        mUpdateSchema = config.getUpdateSchema();
        mSchemaCounter = 0;

        // Get always update even if updated perdically.
        mAlwaysUpdate = config.getAlwaysUpdate();

        // Get list of daily updates.
        mEnableDailyUpdates = config.getEnableDailyUpdates();
        String daily = config.getDailyUpdates();
        mDailyUpdates = getTimeList(daily);
        mExtendedTimeList = isTimeListExtended(daily);
        mTimeListSize = getTimeListSize(mDailyUpdates);
        if (mDailyUpdates == null || mDailyUpdates.isEmpty() || mTimeListSize == 0) {
            mEnableDailyUpdates = false;
            logger.warn(CMS.getLogMessage("CMSCORE_CA_INVALID_TIME_LIST"));
        }

        // Get auto update interval in minutes.
        mEnableUpdateFreq = config.getEnableUpdateInterval();
        mAutoUpdateInterval = MINUTE * config.getAutoUpdateInterval();
        mMinUpdateInterval = MINUTE * config.getMinUpdateInterval();
        if (mEnableUpdateFreq && mAutoUpdateInterval > 0 &&
                mAutoUpdateInterval < mMinUpdateInterval)
            mAutoUpdateInterval = mMinUpdateInterval;

        // get next update grace period
        mNextUpdateGracePeriod = MINUTE * config.getNextUpdateGracePeriod();
        // get unexpected exception wait time; default to 30 minutes
        mUnexpectedExceptionWaitTime = MINUTE * config.getUnexpectedExceptionWaitTime();
        logger.debug("CRLIssuingPoint:initConfig: mUnexpectedExceptionWaitTime set to " + mUnexpectedExceptionWaitTime);
        // get unexpected exception loop max; default to 10 times
        mUnexpectedExceptionLoopMax = config.getUnexpectedExceptionLoopMax();
        logger.debug("CRLIssuingPoint:initConfig: mUnexpectedExceptionLoopMax set to " + mUnexpectedExceptionLoopMax);

        // get next update as this update extension
        mNextAsThisUpdateExtension = MINUTE * config.getNextAsThisUpdateExtension();

        // Get V2 or V1 CRL
        mAllowExtensions = config.getAllowExtensions();

        mIncludeExpiredCerts = config.getIncludeExpiredCerts();
        mIncludeExpiredCertsOneExtraTime = config.getIncludeExpiredCertsOneExtraTime();
        mCACertsOnly = config.getCACertsOnly();
        mProfileCertsOnly = config.getProfileCertsOnly();
        if (mProfileCertsOnly) {
            String profiles = config.getProfileList();
            mProfileList = getProfileList(profiles);
        }

        // Get default signing algorithm.
        // check if algorithm is supported.
        mSigningAlgorithm = mCA.getCRLSigningUnit().getDefaultAlgorithm();
        String algorithm = config.getSigningAlgorithm();

        if (algorithm != null) {
            // make sure this algorithm is acceptable to CA.
            mCA.getCRLSigningUnit().checkSigningAlgorithmFromName(algorithm);
            mSigningAlgorithm = algorithm;
        }

        mPublishOnStart = config.getPublishOnStart();
        // if publish dn is null then certificate will be published to
        // CA's entry in the directory.
        mPublishDN = config.getPublishDN();

        mSaveMemory = config.getSaveMemory();

        mCMSCRLExtensions = new CMSCRLExtensions(this, config);

        mExtendedNextUpdate =
                ((mUpdateSchema > 1 || (mEnableDailyUpdates && mExtendedTimeList)) && isDeltaCRLEnabled()) ?
                                config.getExtendedNextUpdate() :
                                false;

        // Get serial number ranges if any.
        mBeginSerial = config.getCRLBeginSerialNo();
        if (mBeginSerial != null && mBeginSerial.compareTo(BigInteger.ZERO) < 0) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY_1",
                            PROP_BEGIN_SERIAL, "BigInteger", "positive number"));
        }
        mEndSerial = config.getCRLEndSerialNo();
        if (mEndSerial != null && mEndSerial.compareTo(BigInteger.ZERO) < 0) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY_1",
                            PROP_END_SERIAL, "BigInteger", "positive number"));
        }

        mAutoUpdateIntervalEffectiveAtStart = config.getAutoUpdateIntervalEffectiveAtStart();
        logger.debug("CRLIssuingPoint.initConfig : mAutoUpdateIntervalEffectiveAtStart: " +  mAutoUpdateIntervalEffectiveAtStart);
	mForbidCustomFutureThisUpdateValue = config.getBoolean("forbidCustomFutureThisUpdateValue",true);
        logger.debug("CRLIssuingPoint.initConfig: mForbidCustomFutureThisUpdateValue " + mForbidCustomFutureThisUpdateValue);
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
            logger.info("CRLIssuingPoint: reading CRL issuing point: " + mId);
            crlRecord = mCRLRepository.readCRLIssuingPointRecord(mId);

        } catch (EDBNotAvailException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_ISSUING_INST_CRL", e.toString()), e);
            mInitialized = CRLIssuingPointStatus.InitializationFailed;
            return;

        } catch (EDBRecordNotFoundException e) {
            logger.warn("CRLIssuingPoint: CRL issuing point not found: " + mId);
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

            logger.debug("CRLIssuingPoint.initCRL: mNextUpdate: " + mNextUpdate);

            if (isDeltaCRLEnabled()) {
                mNextDeltaUpdate = (mNextUpdate != null) ? new Date(mNextUpdate.getTime()) : null;
            }

            mFirstUnsaved = crlRecord.getFirstUnsaved();
            logger.debug("initCRL  CRLNumber=" + mCRLNumber.toString() + "  CRLSize=" + mCRLSize +
                            "  FirstUnsaved=" + mFirstUnsaved);
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
                            logger.warn(CMS.getLogMessage("CMSCORE_CA_ISSUING_DECODE_CRL", e.toString()), e);

                        } catch (OutOfMemoryError e) {
                            clearCRLCache();
                            logger.error(CMS.getLogMessage("CMSCORE_CA_ISSUING_DECODE_CRL", e.toString()), e);
                            mInitialized = CRLIssuingPointStatus.InitializationFailed;
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
                            mInitialized = CRLIssuingPointStatus.Initialized;
                        }
                        if (mPublishOnStart) {
                            try {
                                publishCRL(x509crl);
                                x509crl = null;

                            } catch (EBaseException e) {
                                x509crl = null;
                                logger.warn(CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_CRL", mCRLNumber.toString(),
                                                e.toString()), e);

                            } catch (OutOfMemoryError e) {
                                x509crl = null;
                                logger.warn(CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_CRL", mCRLNumber.toString(),
                                                e.toString()), e);
                            }
                        }
                    }
                }
            }
        }

        if (crlRecord == null) {
            // no crl was ever created, or crl in db is corrupted.
            logger.info("CRLIssuingPoint: creating new CRL issuing point: " + mId);

            IConfigStore ipStore = mCA.getConfigStore().getSubStore(ICertificateAuthority.PROP_CRL_SUBSTORE).getSubStore(mId);

            try {
                BigInteger startingCrlNumberBig = ipStore.getBigInteger(PROP_CRL_STARTING_NUMBER, BigInteger.ZERO);
                logger.debug("CRLIssuingPoint: startingCrlNumber: " + startingCrlNumberBig);

                // Check for bogus negative value

                if(startingCrlNumberBig.compareTo(BigInteger.ZERO) < 0) {
                    //Make it the default of ZERO
                    startingCrlNumberBig = BigInteger.ZERO;
                }

                crlRecord = new CRLIssuingPointRecord(mId, startingCrlNumberBig, Long.valueOf(-1),
                                               null, null, BigInteger.ZERO, Long.valueOf(-1),
                                          mRevokedCerts, mUnrevokedCerts, mExpiredCerts);
                mCRLRepository.addCRLIssuingPointRecord(crlRecord);
                mCRLNumber = startingCrlNumberBig;

                // The default case calls for ZERO being the starting point where
                // it is then incremented by one to ONE
                // If we specificy an explicit starting point,
                // We want that exact number to be the next CRL Number.
                if(mCRLNumber.compareTo(BigInteger.ZERO) == 0) {
                    mNextCRLNumber = BigInteger.ONE;
                } else {
                    mNextCRLNumber = mCRLNumber;
                }

                mLastCRLNumber = mCRLNumber;
                mDeltaCRLNumber = mCRLNumber;
                mNextDeltaCRLNumber = mNextCRLNumber;
                mLastUpdate = new Date(0L);

                if (crlRecord != null) {
                    // This will trigger updateCRLNow, which will also publish CRL.
                    if ((mDoManualUpdate == false) &&
                            (mEnableCRLCache || mAlwaysUpdate ||
                            (mEnableUpdateFreq && mAutoUpdateInterval > 0))) {
                        mInitialized = CRLIssuingPointStatus.Initialized;
                        setManualUpdate(null);
                    }
                }

            } catch (EBaseException ex) {
                logger.error(CMS.getLogMessage("CMSCORE_CA_ISSUING_CREATE_CRL", ex.toString()), ex);
                mInitialized = CRLIssuingPointStatus.InitializationFailed;
                return;
            }
        }

        mInitialized = CRLIssuingPointStatus.Initialized;
    }

    private Object configMonitor = new Object();

    @Override
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
                        logger.warn(CMS.getLogMessage("CMSCORE_CA_INVALID_TIME_LIST"));
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
                        logger.warn(CMS.getLogMessage("CMSCORE_CA_INVALID_PROFILE_LIST"));
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
    @Override
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
    @Override
    public String getId() {
        return mId;
    }

    /**
     * Returns internal description of this CRL issuing point.
     * <P>
     *
     * @return internal description of this CRL issuing point
     */
    @Override
    public String getDescription() {
        return mDescription;
    }

    /**
     * Sets internal description of this CRL issuing point.
     *
     * @param description description for this CRL issuing point.
     */
    @Override
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
    @Override
    public String getPublishDN() {
        return mPublishDN;
    }

    /**
     * Returns signing algorithm.
     * <P>
     *
     * @return SigningAlgorithm.
     */
    @Override
    public String getSigningAlgorithm() {
        return mSigningAlgorithm;
    }

    @Override
    public synchronized String getLastSigningAlgorithm() {
        return mLastSigningAlgorithm;
    }

    /**
     * Returns current CRL generation schema for this CRL issuing point.
     * <P>
     *
     * @return current CRL generation schema for this CRL issuing point
     */
    @Override
    public int getCRLSchema() {
        return mUpdateSchema;
    }

    /**
     * Returns current CRL number of this CRL issuing point.
     * <P>
     *
     * @return current CRL number of this CRL issuing point
     */
    @Override
    public BigInteger getCRLNumber() {
        return mCRLNumber;
    }

    /**
     * Returns current delta CRL number of this CRL issuing point.
     * <P>
     *
     * @return current delta CRL number of this CRL issuing point
     */
    @Override
    public BigInteger getDeltaCRLNumber() {
        return (isDeltaCRLEnabled() && mDeltaCRLSize > -1) ? mDeltaCRLNumber : BigInteger.ZERO;
    }

    /**
     * Returns next CRL number of this CRL issuing point.
     * <P>
     *
     * @return next CRL number of this CRL issuing point
     */
    @Override
    public BigInteger getNextCRLNumber() {
        return mNextDeltaCRLNumber;
    }

    /**
     * Returns number of entries in the CRL
     * <P>
     *
     * @return number of entries in the CRL
     */
    @Override
    public long getCRLSize() {
        return (mCRLCerts.size() > 0 && mCRLSize == 0) ? mCRLCerts.size() : mCRLSize;
    }

    /**
     * Returns number of entries in delta CRL
     * <P>
     *
     * @return number of entries in delta CRL
     */
    @Override
    public long getDeltaCRLSize() {
        return mDeltaCRLSize;
    }

    /**
     * Returns last update time
     * <P>
     *
     * @return last CRL update time
     */
    @Override
    public Date getLastUpdate() {
        return mLastUpdate;
    }

    /**
     * Returns next update time
     * <P>
     *
     * @return next CRL update time
     */
    @Override
    public Date getNextUpdate() {
        return mNextUpdate;
    }

    /**
     * Returns next update time
     * <P>
     *
     * @return next CRL update time
     */
    @Override
    public Date getNextDeltaUpdate() {
        return mNextDeltaUpdate;
    }

    /**
     * Returns all the revoked certificates from the CRL cache.
     * <P>
     *
     * @return set of all the revoked certificates or null if there are none.
     */
    @Override
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
    @Override
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
                        (mInitialized == CRLIssuingPointStatus.NotInitialized) ||
                        mDoLastAutoUpdate || mDoManualUpdate)))) {

            logger.info(CMS.getLogMessage("CMSCORE_CA_ISSUING_START_CRL", mId));

            mUpdateThread = new Thread(this, "CRLIssuingPoint-" + mId);
            mUpdateThread.setDaemon(true);
            mUpdateThread.start();
        }

        if (isCRLIssuingPointInitialized() && (((mNextUpdate != null) ^
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
    @Override
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
    @Override
    public long getAutoUpdateInterval() {
        return (mEnableUpdateFreq) ? mAutoUpdateInterval : 0;
    }

    /**
     * @return always update the CRL
     */
    @Override
    public boolean getAlwaysUpdate() {
        return mAlwaysUpdate;
    }

    /**
     * @return next update grace period in minutes.
     */

    @Override
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

        //If we have already created a future thisUpdate value, make "now" this time in the future.
        long futureNow = 0;
        if(mCustomFutureThisUpdateValue!= null) {
            futureNow = mCustomFutureThisUpdateValue.getTime();
            if(futureNow > now) {
                now = futureNow;
            }
        }
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

        logger.debug("CRLIssuingPoint.findNextUpdate: mLastUpdate: " + mLastUpdate);
        logger.debug("CRLIssuingPoint.findNextUpdate: mNextUpdate: " + mNextUpdate);
        logger.debug("CRLIssuingPoint.findNextUpdate: mAutoUpdateInterval: " + mAutoUpdateInterval / 60000);
        logger.debug("CRLIssuingPOint.findNextUpdate: lastUpdate: " + new Date(lastUpdate));

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
                    if (mDailyUpdates.size() >= 1) {
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

        logger.debug("CRLIssuingPoint.findNextUpdate: nextUpdate : " + new Date(nextUpdate) + " next: " + new Date(next));

        if (fromLastUpdate && nextUpdate > 0 && (nextUpdate < next || nextUpdate >= now)) {
            // We have the one time schedule updated flag set in CS.cfg, which means
            // we want the schedule adhered to now instead of waiting for the next update for it
            // to take effect.
            // Here the variable "next" has the newly calculated nextUpdate value
            // Here the variable "nextUpdate" contains the nextUpdate value from the previous schedule
            if (mAutoUpdateIntervalEffectiveAtStart) {
                // Check and see if the new schedule has taken us into the past:
                if(next <= now ) {
                    mNextUpdate = new Date(now);
                    logger.debug("CRLIssuingPoint.findNextUpdate: schedule updated to the past. Making mNextUpdate now: " +  mNextUpdate);
                    next = now;
                }  else {
                    //alter the value of the nextUpdate to be the time calculated from the new schedule
                    mNextUpdate = new Date(next);
                }

                logger.debug("CRLIssuingPoint.findNextUpdate: taking updated schedule value: " + mNextUpdate);
                // Now clear it since we only want this once upon startup.
                mAutoUpdateIntervalEffectiveAtStart = false;
            } else {
                logger.debug("CRLIssuingPoint.findNextUpdate: taking current schedule's nextUpdate value: " + new Date(nextUpdate));
                //Normal behavior where the previous or current shedule's nextUpdate time is observed.
                next = nextUpdate;
            }
        }

        logger.debug("findNextUpdate:  "
                + ((new Date(next)).toString()) + ((fromLastUpdate) ? "  delay: " + (next - now) : ""));

        return (fromLastUpdate) ? next - now : next;
    }

    public void handleUnexpectedFailure(int loopCounter, long timeOfUnexpectedFailure) {

        logger.info("CRLIssuingPoint: Handling unexpected failure");
        logger.info("CRLIssuingPoint: - loop counter: " + loopCounter);

        if (loopCounter <= mUnexpectedExceptionLoopMax) {
            logger.info("CRLIssuingPoint: Max loop not reached, no wait time");
            return;
        }

        logger.info("CRLIssuingPoint: Max loop reached, slowdown procedure ensues");

        long now = System.currentTimeMillis();
        logger.info("CRLIssuingPoint: - now: " + now);
        logger.info("CRLIssuingPoint: - time of unexpected failure: " + timeOfUnexpectedFailure);

        long timeLapse = now - timeOfUnexpectedFailure;
        logger.info("CRLIssuingPoint: - time lapse: " + timeLapse);

        long waitTime = mUnexpectedExceptionWaitTime - timeLapse;
        logger.info("CRLIssuingPoint: Wait time after last failure:" + waitTime);

        if (waitTime <= 0) {
            logger.info("CRLIssuingPoint: No wait after failure");
            return;
        }

        logger.info("CRLIssuingPoint: Waiting for " + waitTime + " ms");

        try {
            wait(waitTime);

        } catch (InterruptedException e) {
            logger.error("CRLIssuingPoint: " + e.getMessage(), e);
        }

        // timeOfUnexpectedFailure will be reset again if it still fails
    }

    /**
     * Implements Runnable interface. Defines auto-update
     * logic used by worker thread.
     * <P>
     */
    @Override
    public void run() {
        /*
         * mechnism to slow down the infinite loop when depending
         * components are not available: e.g. Directory server, HSM
         */
        boolean unexpectedFailure = false;
        long timeOfUnexpectedFailure = 0;
        int loopCounter = 0;

        try {
            while (mEnable && ((mEnableCRLCache && mCacheUpdateInterval > 0) ||
                    (mInitialized == CRLIssuingPointStatus.NotInitialized) ||
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

                    if (mInitialized == CRLIssuingPointStatus.NotInitialized) {
                        initCRL();
                    }

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
                        /*
                         * handle last failure so we don't get into
                         * non-delayed loop
                         */
                        if (unexpectedFailure == true) {
                            // it gets mUnexpectedExceptionLoopMax tries
                            loopCounter++;
                            handleUnexpectedFailure(loopCounter, timeOfUnexpectedFailure);
                        }

                        logger.debug("CRLIssuingPoint:run(): before CRL generation");
                        try {
                            if (doCacheUpdate) {
                                updateCRLCacheRepository();
                            } else if (mAutoUpdateInterval > 0 || mDoLastAutoUpdate || mDoManualUpdate) {
                                updateCRL();
                            }
                            // reset if no exception
                            if (unexpectedFailure == true) {
                                logger.debug("CRLIssuingPoint:run(): reset unexpectedFailure values if no Exception.");
                                unexpectedFailure = false;
                                timeOfUnexpectedFailure = 0;
                                loopCounter = 0;
                            }
                        } catch (Exception e) {
                            logger.debug("CRLIssuingPoint:run(): unexpectedFailure occurred:" + e);
                            unexpectedFailure = true;
                            timeOfUnexpectedFailure = System.currentTimeMillis();
                            logger.warn(CMS.getLogMessage("CMSCORE_CA_ISSUING_CRL",
                                    (doCacheUpdate) ? "update CRL cache" : "update CRL", e.toString()));
                            logger.warn((doCacheUpdate) ? "update CRL cache" : "update CRL" + " error " + e, e);
                        }
                        // put this here to prevent continuous loop if internal
                        // db is down.
                        if (mDoLastAutoUpdate)
                            logger.debug("CRLIssuingPoint:run(): mDoLastAutoUpdate set to false");
                            mDoLastAutoUpdate = false;
                        if (mDoManualUpdate) {
                            logger.debug("CRLIssuingPoint:run(): mDoManualUpdate set to false");
                            mDoManualUpdate = false;
                            mSignatureAlgorithmForManualUpdate = null;
                        }
                    }

                }
            }
        } catch (EBaseException e1) {
            e1.printStackTrace();
        }
        logger.debug("CRLIssuingPoint:run(): out of the while loop");
        mUpdateThread = null;
    }

    /**
     * Updates CRL and publishes it.
     */
    private void updateCRL() throws EBaseException {
        if (mDoManualUpdate && mSignatureAlgorithmForManualUpdate != null) {
            updateCRLNow(mSignatureAlgorithmForManualUpdate);
        } else {
            updateCRLNow();
        }
    }

    /**
     * This method may be overrided by CRLWithExpiredCerts.java
     */
    @Override
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

        String issuerFilter =
            "(" + CertRecord.ATTR_X509CERT_ISSUER
            + "=" + mCA.getX500Name().toString() + ")";
        // host authority may be absent issuer attribute
        if (mCA.isHostAuthority()) {
            issuerFilter =
                "(|"
                + "(!(" + CertRecord.ATTR_X509CERT_ISSUER + "=*))"
                + issuerFilter
                + ")";
        }
        filter += issuerFilter;

        // get all revoked non-expired certs.
        filter = "(&" + filter + ")";

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
    @Override
    public void processRevokedCerts(IElementProcessor p)
            throws EBaseException {
        CertRecordProcessor cp = (CertRecordProcessor) p;
        String filter = getFilter();

        CAEngine engine = CAEngine.getInstance();
        synchronized (engine.certStatusUpdateTask) {

            logger.debug("Starting processRevokedCerts (entered lock)");
            // this code and CertStatusUpdateTask.updateCertStatus() are mutually exclusive

            CertRecordList list = mCertRepository.findCertRecordsInList(
                    filter,
                    new String[] {
                            CertRecord.ATTR_ID, CertRecord.ATTR_REVO_INFO, "objectclass"
                    },
                    "serialno",
                    mPageSize);

            int totalSize = list.getSize();

            list.processCertRecords(0, totalSize - 1, cp);
            logger.debug("processRevokedCerts done");
        }
    }

    /**
     * clears CRL cache
     */
    @Override
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
    @Override
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
            logger.debug("recoverCRLCache  mFirstUnsaved=" + mFirstUnsaved + "  filter=" + filter);

            CAEngine engine = CAEngine.getInstance();
            CertRequestRepository requestRepository = engine.getCertRequestRepository();

            IRequestVirtualList list = requestRepository.getPagedRequestsByFilter(
                        new RequestId(mFirstUnsaved),
                        false,
                        filter,
                        500,
                        "requestId");

            logger.debug("recoverCRLCache  size=" + list.getSize() + "  index=" + list.getCurrentIndex());

            CertRecordProcessor cp = new CertRecordProcessor(mCRLCerts, this, mAllowExtensions);
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
                logger.debug("recoverCRLCache  request=" + request.getRequestId().toString() +
                                "  type=" + request.getRequestType());
                if (IRequest.REVOCATION_REQUEST.equals(request.getRequestType())) {
                    RevokedCertImpl revokedCert[] =
                            request.getExtDataInRevokedCertArray(IRequest.CERT_INFO);
                    if (revokedCert != null) {
                        for (int j = 0; j < revokedCert.length; j++) {
                            logger.debug("recoverCRLCache R j=" + j + "  length=" + revokedCert.length +
                                        "  SerialNumber=0x" + revokedCert[j].getSerialNumber().toString(16));
                            if (cp != null)
                                includeCert = cp.checkRevokedCertExtensions(revokedCert[j].getExtensions());
                            if (includeCert) {
                                updateRevokedCert(REVOKED_CERT, revokedCert[j].getSerialNumber(), revokedCert[j]);
                            }
                        }
                    } else {
                        logger.error("Revocation Request: Revoked Certificates is a Null or has Invalid Values");
                        throw new EBaseException("Revocation Request: Revoked Certificates is a Null or has Invalid Values");
                    }
                } else if (IRequest.UNREVOCATION_REQUEST.equals(request.getRequestType())) {
                    BigInteger serialNo[] = request.getExtDataInBigIntegerArray(IRequest.OLD_SERIALS);
                    if (serialNo != null) {
                        for (int j = 0; j < serialNo.length; j++) {
                            logger.debug("recoverCRLCache U j=" + j + "  length=" + serialNo.length +
                                        "  SerialNumber=0x" + serialNo[j].toString(16));
                            updateRevokedCert(UNREVOKED_CERT, serialNo[j], null);
                        }
                    } else {
                        logger.error("Unrevocation Request: Serial Numbers is a Null or has Invalid Values");
                        throw new EBaseException("Unrevocation Request: Serial Numbers is a Null or has Invalid Values");
                    }
                }
            }

            try {
                mCRLRepository.updateRevokedCerts(mId, mRevokedCerts, mUnrevokedCerts);
                mFirstUnsaved = ICRLIssuingPointRecord.CLEAN_CACHE;
                mCRLCacheIsCleared = false;
            } catch (EBaseException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_CRL_CACHE", e.toString()), e);
            }
        } else {
            clearCRLCache();
            updateCRLCacheRepository();
        }
    }

    @Override
    public int getNumberOfRecentlyRevokedCerts() {
        return mRevokedCerts.size();
    }

    @Override
    public int getNumberOfRecentlyUnrevokedCerts() {
        return mUnrevokedCerts.size();
    }

    @Override
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

        logger.debug("CRLIssuingPoint.getCRLExtension extension: " + theExt);
        return theExt;
    }

    /**
     * get required crl entry extensions
     */
    @Override
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
                    logger.warn(CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_CRL_CACHE", e.toString()), e);
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
                            new Date(), entryExt);

                    mUnrevokedCerts.put(serialNumber, newRevokedCert);
                }
            }
        }
    }

    /**
     * registers revoked certificates
     */
    @Override
    public void addRevokedCert(BigInteger serialNumber, RevokedCertImpl revokedCert) {
        addRevokedCert(serialNumber, revokedCert, null);
    }

    @Override
    public void addRevokedCert(BigInteger serialNumber, RevokedCertImpl revokedCert,
                               String requestId) {

        CertRecordProcessor cp = new CertRecordProcessor(mCRLCerts, this, mAllowExtensions);
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
                    logger.warn(CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_REVOKED_CERT", mId, e.toString()), e);
                }
            }
        }
    }

    /**
     * registers unrevoked certificates
     */
    @Override
    public void addUnrevokedCert(BigInteger serialNumber) {
        addUnrevokedCert(serialNumber, null);
    }

    @Override
    public void addUnrevokedCert(BigInteger serialNumber, String requestId) {
        if (mEnable && mEnableCRLCache) {
            updateRevokedCert(UNREVOKED_CERT, serialNumber, null, requestId);

            if (mCacheUpdateInterval == 0) {
                try {
                    mCRLRepository.updateRevokedCerts(mId, mRevokedCerts, mUnrevokedCerts);
                    mFirstUnsaved = ICRLIssuingPointRecord.CLEAN_CACHE;
                } catch (EBaseException e) {
                    logger.warn(CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_UNREVOKED_CERT", mId, e.toString()), e);
                }
            }
        }
    }

    /**
     * registers expired certificates
     */
    @Override
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
                        new Date(), entryExt);

                mExpiredCerts.put(serialNumber, newRevokedCert);
            }

            if (mCacheUpdateInterval == 0) {
                try {
                    mCRLRepository.updateExpiredCerts(mId, mExpiredCerts);
                } catch (EBaseException e) {
                    logger.warn(CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_EXPIRED_CERT", mId, e.toString()), e);
                }
            }
        }
    }

    private Object repositoryMonitor = new Object();

    @Override
    public void updateCRLCacheRepository() {
        synchronized (repositoryMonitor) {
            try {
                mCRLRepository.updateCRLCache(mId, Long.valueOf(mCRLSize),
                        mRevokedCerts, mUnrevokedCerts, mExpiredCerts);
                mFirstUnsaved = ICRLIssuingPointRecord.CLEAN_CACHE;
            } catch (EBaseException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_CA_ISSUING_STORE_CRL_CACHE", e.toString()), e);
            }
        }
    }

    @Override
    public boolean isDeltaCRLEnabled() {
        return (mAllowExtensions && mEnableCRLCache &&
                mCMSCRLExtensions.isCRLExtensionEnabled(DeltaCRLIndicatorExtension.NAME) &&
                mCMSCRLExtensions.isCRLExtensionEnabled(CRLNumberExtension.NAME) &&
                mCMSCRLExtensions.isCRLExtensionEnabled(CRLReasonExtension.NAME));
    }

    @Override
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

    @Override
    public boolean isCRLCacheEnabled() {
        return mEnableCRLCache;
    }

    @Override
    public boolean isCRLCacheEmpty() {
        return ((mCRLCerts != null) ? mCRLCerts.isEmpty() : true);
    }

    @Override
    public boolean isCRLCacheTestingEnabled() {
        return mEnableCacheTesting;
    }

    @Override
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

    @Override
    public synchronized Vector<Long> getSplitTimes() {
        Vector<Long> splits = new Vector<Long>();

        for (int i = 0; i < mSplits.length; i++) {
            splits.addElement(Long.valueOf(mSplits[i]));
        }
        return splits;
    }

    @Override
    public synchronized int isCRLUpdateInProgress() {
        return mUpdatingCRL;
    }

    /**
     * updates CRL and publishes it now
     */
    @Override
    public void updateCRLNow()
            throws EBaseException {

        updateCRLNow(null);
    }

    @Override
    public synchronized void updateCRLNow(String signingAlgorithm)
            throws EBaseException {

        logger.info("CRLIssuingPoint: Updating " + mId);

        logger.debug("CRLIssuingPoint: - enable: " + mEnable);
        logger.debug("CRLIssuingPoint: - enable CRL updates: " + mEnableCRLUpdates);
        logger.debug("CRLIssuingPoint: - do last auto update: " + mDoLastAutoUpdate);

        CAEngine engine = CAEngine.getInstance();
        if ((!mEnable) || (!mEnableCRLUpdates && !mDoLastAutoUpdate))
            return;

        logger.debug("CRLIssuingPoint: - next CRL number: " + mNextDeltaCRLNumber);
        logger.debug("CRLIssuingPoint: - delta CRL enabled: " + isDeltaCRLEnabled());
        logger.debug("CRLIssuingPoint: - CRL cache enabled: " + mEnableCRLCache);
        logger.debug("CRLIssuingPoint: - cache recovery enabled: " + mCRLCacheIsCleared);
        logger.debug("CRLIssuingPoint: - cache size: " + mCRLCerts.size());
        logger.debug("CRLIssuingPoint: - revoked certs: " + mRevokedCerts.size());
        logger.debug("CRLIssuingPoint: - unrevoked certs: " + mUnrevokedCerts.size());
        logger.debug("CRLIssuingPoint: - expired certs: " + mExpiredCerts.size());

        mUpdatingCRL = CRL_UPDATE_STARTED;
        if (signingAlgorithm == null || signingAlgorithm.length() == 0)
            signingAlgorithm = mSigningAlgorithm;
        mLastSigningAlgorithm = signingAlgorithm;
        Date thisUpdate = null;
        Date nowDate = new Date();

	if(mForbidCustomFutureThisUpdateValue == true && mCustomFutureThisUpdateValue != null) {
            logger.debug("CRLIssuingPoint:updateCRLNow : Policy forbids use of the futerUpdate values feature.");
            mUpdatingCRL = CRL_UPDATE_DONE;
            mCustomFutureThisUpdateValue = null;
            throw new EBaseException("Can not update the CRL Now with future this update value, policy forbids it.");
        }

        if (mCustomFutureThisUpdateValue != null && mCustomFutureThisUpdateValue.after(nowDate)) {
            logger.debug("CRLIssuingPoint:updateCRLNow : Future thisUpdate value requested: " + mCustomFutureThisUpdateValue.toString());
            thisUpdate = mCustomFutureThisUpdateValue;
        } else {
            logger.debug("CRLIssuingPoint:updateCRLNow : mCancelCurFutureThisUpdateValue: " + mCancelCurFutureThisUpdateValue);
            //Check to see if the crl already has a future thisUpdate value. Thus we can't proceed
            if(nowDate.before(getLastUpdate()) && !mCancelCurFutureThisUpdateValue) {
                //Here we have a case where the optional custom future thisUpdate feature
                //has been employed. If this is the case, abort.

                //If the cancel custom future thisUpdate option is set,  proceed and allow a normal update now.
                //operation to take place.

                logger.debug("CRLIssuingPoint:updateCRLNow : Future thisUpdate has been set, exit this attempt to update the CRL.");
                mUpdatingCRL = CRL_UPDATE_DONE;
                mCancelCurFutureThisUpdateValue = false;
                throw new EBaseException("Can not update the CR Now : thisUpdate Field of CRL set to future date.");
            }
            thisUpdate = nowDate;
        }
        mCancelCurFutureThisUpdateValue = false;

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

        //Clear this value since it is no longer needed
        mCustomFutureThisUpdateValue = null;
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

            IStatsSubsystem statsSub = (IStatsSubsystem) engine.getSubsystem(IStatsSubsystem.ID);
            if (statsSub != null) {
                statsSub.startTiming("generation");
            }
            CertRecordProcessor cp = new CertRecordProcessor(mCRLCerts, this, mAllowExtensions);
            processRevokedCerts(cp);

            if (statsSub != null) {
                statsSub.endTiming("generation");
            }

            mCRLCacheIsCleared = false;
            mSplits[5] += System.currentTimeMillis();
        } else {
            if (isDeltaCRLEnabled()) {

                generateDeltaCRL(
                        clonedRevokedCerts,
                        clonedUnrevokedCerts,
                        clonedExpiredCerts,
                        signingAlgorithm,
                        thisUpdate,
                        nextDeltaUpdate);

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

            generateFullCRL(signingAlgorithm, thisUpdate, nextUpdate);
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

    CRLExtensions generateCRLExtensions(String excludedExtension) {

        CRLExtensions ext = new CRLExtensions();
        Vector<String> extNames = mCMSCRLExtensions.getCRLExtensionNames();

        for (int i = 0; i < extNames.size(); i++) {
            String extName = extNames.elementAt(i);

            if (extName.equals(excludedExtension)) continue;
            if (!mCMSCRLExtensions.isCRLExtensionEnabled(extName)) continue;

            mCMSCRLExtensions.addToCRLExtensions(ext, extName, null);
        }

        return ext;
    }

    void generateDeltaCRL(
            Hashtable<BigInteger, RevokedCertificate> clonedRevokedCerts,
            Hashtable<BigInteger, RevokedCertificate> clonedUnrevokedCerts,
            Hashtable<BigInteger, RevokedCertificate> clonedExpiredCerts,
            String signingAlgorithm,
            Date thisUpdate,
            Date nextDeltaUpdate) {

        mSplits[1] -= System.currentTimeMillis();

        @SuppressWarnings("unchecked")
        Hashtable<BigInteger, RevokedCertificate> deltaCRLCerts =
                (Hashtable<BigInteger, RevokedCertificate>) clonedRevokedCerts.clone();

        deltaCRLCerts.putAll(clonedUnrevokedCerts);

        if (mIncludeExpiredCertsOneExtraTime) {

            for (Enumeration<BigInteger> e = clonedExpiredCerts.keys(); e.hasMoreElements();) {
                BigInteger serialNumber = e.nextElement();
                if (mLastFullUpdate == null ||
                    mLastFullUpdate.after(mExpiredCerts.get(serialNumber).getRevocationDate())) {
                    deltaCRLCerts.put(serialNumber, clonedExpiredCerts.get(serialNumber));
                }
            }

        } else {
            deltaCRLCerts.putAll(clonedExpiredCerts);
        }

        mLastCRLNumber = mCRLNumber;

        CRLExtensions ext = generateCRLExtensions(FreshestCRLExtension.NAME);

        mSplits[1] += System.currentTimeMillis();

        X509CRLImpl newX509DeltaCRL = null;

        try {
            mSplits[2] -= System.currentTimeMillis();

            // #56123 - dont generate CRL if no revoked certificates
            if (mConfigStore.getNoCRLIfNoRevokedCert()) {
                if (deltaCRLCerts.size() == 0) {
                    logger.debug("CRLIssuingPoint: No Revoked Certificates Found And noCRLIfNoRevokedCert is set to true - No Delta CRL Generated");
                    mDeltaCRLSize = -1;
                    signedAuditLogger.log(DeltaCRLGenerationEvent.createSuccessEvent(
                            getAuditSubjectID(),
                            "No Revoked Certificates"));
                    return;
                }
            }

            X509CRLImpl crl = new X509CRLImpl(mCA.getCRLX500Name(),
                    AlgorithmId.get(signingAlgorithm),
                    thisUpdate, nextDeltaUpdate, deltaCRLCerts, ext);

            newX509DeltaCRL = mCA.sign(crl, signingAlgorithm);

            byte[] newDeltaCRL = newX509DeltaCRL.getEncoded();

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

            logger.debug("CRLIssuingPoint: - delta CRL number: " + mNextDeltaCRLNumber);
            logger.debug("CRLIssuingPoint: - against CRL number: " + mCRLNumber);
            logger.debug("CRLIssuingPoint: - last update: " + mLastUpdate);
            logger.debug("CRLIssuingPoint: - next update: " + mNextDeltaUpdate);
            logger.debug("CRLIssuingPoint: - delta CRL size: " + mDeltaCRLSize);
            logger.debug("CRLIssuingPoint: - total time: " + totalTime + splitTimes);

            signedAuditLogger.log(DeltaCRLGenerationEvent.createSuccessEvent(
                    getAuditSubjectID(),
                    mCRLNumber));

        } catch (EBaseException e) {
            String message = CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_OR_STORE_DELTA", e.toString());
            logger.error(message, e);
            mDeltaCRLSize = -1;
            signedAuditLogger.log(DeltaCRLGenerationEvent.createFailureEvent(
                    getAuditSubjectID(),
                    e.getMessage()));
            return;

        } catch (Throwable e) {
            String message = CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_DELTA", e.toString());
            logger.error(message, e);
            mDeltaCRLSize = -1;
            signedAuditLogger.log(DeltaCRLGenerationEvent.createFailureEvent(
                    getAuditSubjectID(),
                    e.getMessage()));
            return;
        }

        try {
            mSplits[4] -= System.currentTimeMillis();
            publishCRL(newX509DeltaCRL, true);
            mSplits[4] += System.currentTimeMillis();

            signedAuditLogger.log(new DeltaCRLPublishingEvent(getAuditSubjectID(), mCRLNumber));

        } catch (Throwable e) {
            String message = CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_DELTA", mCRLNumber.toString(), e.toString());
            logger.error(message, e);
            signedAuditLogger.log(new DeltaCRLPublishingEvent(getAuditSubjectID(), mCRLNumber, e.getMessage()));
        }
    }

    void generateFullCRL(
            String signingAlgorithm,
            Date thisUpdate,
            Date nextUpdate) throws EBaseException {

        logger.debug("generateFullCRL: thisUpdate: " + thisUpdate + " nextUpdate: " + nextUpdate);

        mSplits[6] -= System.currentTimeMillis();
        if (mNextDeltaCRLNumber.compareTo(mNextCRLNumber) > 0) {
            mNextCRLNumber = mNextDeltaCRLNumber;
        }

        CRLExtensions ext;
        if (mAllowExtensions) {
            ext = generateCRLExtensions(DeltaCRLIndicatorExtension.NAME);
        } else {
            ext = null;
        }
        mSplits[6] += System.currentTimeMillis();

        X509CRLImpl newX509CRL = null;

        try {
            logger.debug("Making CRL with algorithm " +
                    signingAlgorithm + " " + AlgorithmId.get(signingAlgorithm));

            mSplits[7] -= System.currentTimeMillis();

            // #56123 - dont generate CRL if no revoked certificates
            if (mConfigStore.getNoCRLIfNoRevokedCert()) {
                if (mCRLCerts.size() == 0) {
                    logger.debug("CRLIssuingPoint: No Revoked Certificates Found And noCRLIfNoRevokedCert is set to true - No CRL Generated");
                    signedAuditLogger.log(FullCRLGenerationEvent.createSuccessEvent(
                            getAuditSubjectID(),
                            "No Revoked Certificates"));
                    return;
                }
            }

            logger.debug("CRLIssuingPoint: creating CRL object");
            X509CRLImpl crl = new X509CRLImpl(mCA.getCRLX500Name(),
                    AlgorithmId.get(signingAlgorithm),
                    thisUpdate, nextUpdate, mCRLCerts, ext);

            logger.debug("CRLIssuingPoint: signing CRL");
            newX509CRL = mCA.sign(crl, signingAlgorithm);

            logger.debug("CRLIssuingPoint: encoding CRL");
            byte[] newCRL = newX509CRL.getEncoded();

            mSplits[7] += System.currentTimeMillis();

            mSplits[8] -= System.currentTimeMillis();

            Date nextUpdateDate = mNextUpdate;
            if (isDeltaCRLEnabled()
                    && (mUpdateSchema > 1 || mEnableDailyUpdates && mExtendedTimeList)
                    && mNextDeltaUpdate != null) {
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

            logger.debug("CRLIssuingPoint: Logging CRL Update to transaction log");
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

            logger.debug("CRLIssuingPoint: - CRL number: " + mCRLNumber);
            logger.debug("CRLIssuingPoint: - last update: " + mLastUpdate);
            logger.debug("CRLIssuingPoint: - next update: " + mNextUpdate);
            logger.debug("CRLIssuingPoint: - CRL size: " + mCRLSize);
            logger.debug("CRLIssuingPoint: - total time: " + totalTime);
            logger.debug("CRLIssuingPoint: - CRL time: " + crlTime);
            logger.debug("CRLIssuingPoint: - delta CRL time: " + deltaTime + splitTimes);

            logger.debug("CRLIssuingPoint: Finished Logging CRL Update to transaction log");

            signedAuditLogger.log(FullCRLGenerationEvent.createSuccessEvent(
                    getAuditSubjectID(),
                    mCRLNumber));

        } catch (EBaseException e) {
            mUpdatingCRL = CRL_UPDATE_DONE;
            String message = CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_OR_STORE_CRL", e.toString());
            logger.error(message, e);
            signedAuditLogger.log(FullCRLGenerationEvent.createFailureEvent(
                    getAuditSubjectID(),
                    e.getMessage()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_FAILED_CONSTRUCTING_CRL", e.toString()), e);

        } catch (Throwable e) {
            mUpdatingCRL = CRL_UPDATE_DONE;
            String message = CMS.getLogMessage("CMSCORE_CA_ISSUING_SIGN_CRL", e.toString());
            logger.error(message, e);
            signedAuditLogger.log(FullCRLGenerationEvent.createFailureEvent(
                    getAuditSubjectID(),
                    e.getMessage()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_FAILED_CONSTRUCTING_CRL", e.toString()), e);
        }

        try {
            mSplits[9] -= System.currentTimeMillis();
            mUpdatingCRL = CRL_PUBLISHING_STARTED;
            publishCRL(newX509CRL);
            mSplits[9] += System.currentTimeMillis();

            signedAuditLogger.log(new FullCRLPublishingEvent(getAuditSubjectID(), mCRLNumber));

        } catch (Throwable e) {
            mUpdatingCRL = CRL_UPDATE_DONE;
            String message = CMS.getLogMessage("CMSCORE_CA_ISSUING_PUBLISH_CRL", mCRLNumber.toString(), e.toString());
            logger.error(message, e);
            signedAuditLogger.log(new FullCRLPublishingEvent(getAuditSubjectID(), mCRLNumber, e.getMessage()));
            throw new ECAException(message, e);
        }
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

        CAEngine engine = CAEngine.getInstance();
        IStatsSubsystem statsSub = (IStatsSubsystem) engine.getSubsystem(IStatsSubsystem.ID);
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

        logger.debug("Publish CRL");
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
                    mPublisherProcessor != null && mPublisherProcessor.isCRLPublishingEnabled()) {
                Enumeration<LdapRule> rules = mPublisherProcessor.getRules(CAPublisherProcessor.PROP_LOCAL_CRL);
                if (rules == null || !rules.hasMoreElements()) {
                    logger.debug("CRL publishing is not enabled.");
                } else {
                    if (mPublishDN != null) {
                        mPublisherProcessor.publishCRL(mPublishDN, x509crl);
                        logger.debug("CRL published to " + mPublishDN);
                    } else {
                        mPublisherProcessor.publishCRL(x509crl, getId());
                        logger.debug("CRL published.");
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Could not publish CRL: " + e, e);
            logger.error("Could not publish CRL. ID " + mId);
            throw new EErrorPublishCRL(
                    CMS.getUserMessage("CMS_CA_ERROR_PUBLISH_CRL", mId, e.toString()));
        } finally {
            if (statsSub != null) {
                statsSub.endTiming("crl_publishing");
            }
        }
    }

    void setConfigParam(String name, String value) {
        mConfigStore.putString(name, value);
    }

    String getAuditSubjectID() {

        SessionContext context = SessionContext.getExistingContext();

        if (context == null) {
            return ILogger.UNIDENTIFIED;
        }

        String subjectID = (String)context.get(SessionContext.USER_ID);

        if (subjectID == null) {
            if (Thread.currentThread() == mUpdateThread) {
                return ILogger.SYSTEM_UID;

            } else {
                return ILogger.NONROLEUSER;
            }
        }

        return subjectID.trim();
    }
}
