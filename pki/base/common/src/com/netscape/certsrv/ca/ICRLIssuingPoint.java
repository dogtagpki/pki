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
package com.netscape.certsrv.ca;


import java.util.*;
import java.math.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import netscape.security.x509.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.request.IRequest;


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
 *
 * @version $Revision$, $Date$
 */

public interface ICRLIssuingPoint {

    public static final String PROP_PUBLISH_DN = "publishDN";
    public static final String PROP_PUBLISH_ON_START = "publishOnStart";
    public static final String PROP_MIN_UPDATE_INTERVAL = "minUpdateInterval";
    public static final String PROP_BEGIN_SERIAL = "crlBeginSerialNo";
    public static final String PROP_END_SERIAL = "crlEndSerialNo";

    public static final String SC_ISSUING_POINT_ID = "issuingPointId";
    public static final String SC_IS_DELTA_CRL = "isDeltaCRL";
    public static final String SC_CRL_COUNT = "crlCount";

    /**
     * for manual updates - requested by agent
     */
    public static final int CRL_UPDATE_DONE = 0;
    public static final int CRL_UPDATE_STARTED = 1;
    public static final int CRL_PUBLISHING_STARTED = 2;

    public static final int CRL_IP_NOT_INITIALIZED = 0;
    public static final int CRL_IP_INITIALIZED = 1;
    public static final int CRL_IP_INITIALIZATION_FAILED = -1;

    /**
     * Returns true if CRL issuing point is enabled.
     *
     * @return true if CRL issuing point is enabled
     */
    public boolean isCRLIssuingPointEnabled();

    /**
     * Returns true if CRL generation is enabled.
     *
     * @return true if CRL generation is enabled
     */
    public boolean isCRLGenerationEnabled();

    /**
     * Enables or disables CRL issuing point according to parameter.
     *
     * @param enable if true enables CRL issuing point
     */
    public void enableCRLIssuingPoint(boolean enable);

    /**
     * Returns CRL update status.
     *
     * @return CRL update status
     */
    public String getCrlUpdateStatusStr();

    /**
     * Returns CRL update error.
     *
     * @return CRL update error
     */
    public String getCrlUpdateErrorStr();

    /**
     * Returns CRL publishing status.
     *
     * @return CRL publishing status
     */
    public String getCrlPublishStatusStr();

    /**
     * Returns CRL publishing error.
     *
     * @return CRL publishing error
     */
    public String getCrlPublishErrorStr();

    /**
     * Returns CRL issuing point initialization status.
     *
     * @return status of CRL issuing point initialization
     */
    public int isCRLIssuingPointInitialized();

    /**
     * Checks if manual update is set.
     *
     * @return true if manual update is set
     */
    public boolean isManualUpdateSet();

    /**
     * Checks if expired certificates are included in CRL.
     *
     * @return true if expired certificates are included in CRL
     */
    public boolean areExpiredCertsIncluded();

    /**
     * Checks if CRL includes CA certificates only.
     *
     * @return true if CRL includes CA certificates only
     */
    public boolean isCACertsOnly();

    /**
     * Checks if CRL includes profile certificates only.
     *
     * @return true if CRL includes profile certificates only
     */
    public boolean isProfileCertsOnly();

    /**
     * Checks if CRL issuing point includes this profile.
     *
     * @return true if CRL issuing point includes this profile
     */
    public boolean checkCurrentProfile(String id);

    /**
     * Initializes CRL issuing point.
     *
     * @param ca certificate authority that holds CRL issuing point 
     * @param id CRL issuing point id
     * @param config configuration sub-store for CRL issuing point
     * @exception EBaseException thrown if initialization failed
     */
    public void init(ISubsystem ca, String id, IConfigStore config) 
        throws EBaseException;

    /**
     * This method is called during shutdown.
     * It updates CRL cache and stops thread controlling CRL updates.
     */
    public void shutdown();

    /**
     * Returns internal id of this CRL issuing point.
     *
     * @return internal id of this CRL issuing point
     */
    public String getId();

    /**
     * Returns internal description of this CRL issuing point.
     *
     * @return internal description of this CRL issuing point
     */
    public String getDescription();

    /**
     * Sets internal description of this CRL issuing point.
     *
     * @param description description for this CRL issuing point.
     */
    public void setDescription(String description);

    /**
     * Returns DN of the directory entry where CRLs from this issuing point
     * are published.
     *
     * @return DN of the directory entry where CRLs are published.
     */
    public String getPublishDN();

    /**
     * Returns signing algorithm.
     *
     * @return signing algorithm
     */
    public String getSigningAlgorithm();

    /**
     * Returns signing algorithm used in last signing operation..
     *
     * @return last signing algorithm
     */
    public String getLastSigningAlgorithm();

    /**
     * Returns current CRL generation schema for this CRL issuing point.
     * <P>
     *
     * @return current CRL generation schema for this CRL issuing point
     */
    public int getCRLSchema();

    /**
     * Returns current CRL number of this CRL issuing point.
     *
     * @return current CRL number of this CRL issuing point
     */
    public BigInteger getCRLNumber();

    /**
     * Returns current delta CRL number of this CRL issuing point.
     * <P>
     *
     * @return current delta CRL number of this CRL issuing point
     */
    public BigInteger getDeltaCRLNumber();

    /**
     * Returns next CRL number of this CRL issuing point.
     *
     * @return next CRL number of this CRL issuing point
     */
    public BigInteger getNextCRLNumber();

    /**
     * Returns number of entries in the current CRL.
     *
     * @return number of entries in the current CRL
     */
    public long getCRLSize();

    /**
     * Returns number of entries in delta CRL
     *
     * @return number of entries in delta CRL
     */
    public long getDeltaCRLSize();

    /**
     * Returns time of the last update.
     *
     * @return last CRL update time
     */
    public Date getLastUpdate();

    /**
     * Returns time of the next update.
     *
     * @return next CRL update time
     */
    public Date getNextUpdate();

    /**
     * Returns time of the next delta CRL update.
     *
     * @return next delta CRL update time
     */
    public Date getNextDeltaUpdate();

    /**
     * Returns all the revoked certificates from the CRL cache.
     *
     * @param start first requested CRL entry
     * @param end next after last requested CRL entry
     * @return set of all the revoked certificates or null if there are none.
     */
    public Set getRevokedCertificates(int start, int end);

    /**
     * Returns certificate authority.
     *
     * @return certificate authority
     */
    public ISubsystem getCertificateAuthority();

    /**
     * Schedules immediate CRL manual-update
     * and sets signature algorithm to be used for signing.
     *
     * @param signatureAlgorithm signature algorithm to be used for signing
     */
    public  void setManualUpdate(String signatureAlgorithm);

    /**
     * Returns auto update interval in milliseconds.
     *
     * @return auto update interval in milliseconds
     */
    public long getAutoUpdateInterval();

    /**
     * Returns true if CRL is updated for every change
     * of revocation status of any certificate.
     *
     * @return true if CRL update is always triggered by revocation operation
     */
    public boolean getAlwaysUpdate();

    /**
     * Returns next update grace period in minutes.
     *
     * @return next update grace period in minutes
     */
    public long getNextUpdateGracePeriod();

    /**
     * Returns filter used to build CRL based on information stored
     * in local directory.
     *
     * @return filter used to search local directory
     */
    public String getFilter();

    /**
     * Builds a list of revoked certificates to put them into CRL.
     * Calls certificate record processor to get necessary data
     * from certificate records.
     * This also regenerates CRL cache.
     *
     * @param cp certificate record processor
     * @exception EBaseException if an error occurred in the database.
     */
    public void processRevokedCerts(IElementProcessor cp)
        throws EBaseException;

    /**
     * Returns date of revoked certificate or null
     * if certificated is not listed as revoked.
     *
     * @param serialNumber serial number of certificate to be checked
     * @param checkDeltaCache true if delta CRL cache suppose to be
     *        included in checking process
     * @param includeExpiredCerts true if delta CRL cache with expired
     *        certificates suppose to be included in checking process
     * @return date of revoked certificate or null
     */
    public Date getRevocationDateFromCache(BigInteger serialNumber,
                                           boolean checkDeltaCache,
                                           boolean includeExpiredCerts);
    /**
     * Returns split times from CRL generation.
     *
     * @return split times from CRL generation in milliseconds
     */
    public Vector getSplitTimes();

    /**
     * Generates CRL now based on cache or local directory if cache
     * is not available. It also publishes CRL if it is required.
     *
     * @param signingAlgorithm signing algorithm to be used for CRL signing
     * @exception EBaseException if an error occurred during
     *            CRL generation or publishing
     */
    public  void updateCRLNow(String signingAlgorithm)
        throws EBaseException;

    /**
     * Clears CRL cache
     */
    public void clearCRLCache();

    /**
     * Clears delta-CRL cache
     */
    public void clearDeltaCRLCache();

    /**
     * Returns number of recently revoked certificates.
     *
     * @return number of recently revoked certificates
     */
    public int getNumberOfRecentlyRevokedCerts();

    /**
     * Returns number of recently unrevoked certificates.
     *
     * @return number of recently unrevoked certificates
     */
    public int getNumberOfRecentlyUnrevokedCerts();

    /**
     * Returns number of recently expired and revoked certificates.
     *
     * @return number of recently expired and revoked certificates
     */
    public int getNumberOfRecentlyExpiredCerts();

    /**
     * Converts list of extensions supplied by revocation request
     * to list of extensions required to be placed in CRL.
     *
     * @param exts list of extensions supplied by revocation request
     * @return list of extensions required to be placed in CRL
     */
    public CRLExtensions getRequiredEntryExtensions(CRLExtensions exts);

    /**
     * Adds revoked certificate to delta-CRL cache.
     *
     * @param serialNumber serial number of revoked certificate
     * @param revokedCert revocation information supplied by revocation request
     */
    public void addRevokedCert(BigInteger serialNumber, RevokedCertImpl revokedCert);

    /**
     * Adds revoked certificate to delta-CRL cache.
     *
     * @param serialNumber serial number of revoked certificate
     * @param revokedCert revocation information supplied by revocation request
     * @param requestId revocation request id
     */
    public void addRevokedCert(BigInteger serialNumber, RevokedCertImpl revokedCert,
                               String requestId);

    /**
     * Adds unrevoked certificate to delta-CRL cache.
     *
     * @param serialNumber serial number of unrevoked certificate
     */
    public void addUnrevokedCert(BigInteger serialNumber);

    /**
     * Adds unrevoked certificate to delta-CRL cache.
     *
     * @param serialNumber serial number of unrevoked certificate
     * @param requestId unrevocation request id
     */
    public void addUnrevokedCert(BigInteger serialNumber, String requestId);

    /**
     * Adds expired and revoked certificate to delta-CRL cache.
     *
     * @param serialNumber serial number of expired and revoked certificate
     */
    public void addExpiredCert(BigInteger serialNumber);

    /**
     * Updates CRL cache into local directory.
     */
    public void updateCRLCacheRepository();

    /**
     * Updates issuing point configuration according to supplied data
     * in name value pairs.
     *
     * @param params name value pairs defining new issuing point configuration
     * @return true if configuration is updated successfully
     */
    public boolean updateConfig(NameValuePairs params);

    /**
     * Returns true if delta-CRL is enabled.
     *
     * @return true if delta-CRL is enabled
     */
    public boolean isDeltaCRLEnabled();

    /**
     * Returns true if CRL cache is enabled.
     *
     * @return true if CRL cache is enabled
     */
    public boolean isCRLCacheEnabled();

    /**
     * Returns true if CRL cache is empty.
     *
     * @return true if CRL cache is empty
     */
    public boolean isCRLCacheEmpty();

    /**
     * Returns true if CRL cache testing is enabled.
     *
     * @return true if CRL cache testing is enabled
     */
    public boolean isCRLCacheTestingEnabled();

    /**
     * Returns true if supplied delta-CRL is matching current delta-CRL.
     *
     * @param deltaCRL delta-CRL to verify against current delta-CRL
     * @return true if supplied delta-CRL is matching current delta-CRL
     */
    public boolean isThisCurrentDeltaCRL(X509CRLImpl deltaCRL);

    /**
     * Returns status of CRL generation.
     *
     * @return one of the following according to CRL generation status:
     *         CRL_UPDATE_DONE, CRL_UPDATE_STARTED, and CRL_PUBLISHING_STARTED
     */
    public int isCRLUpdateInProgress();

    /**
     * Generates CRL now based on cache or local directory if cache
     * is not available. It also publishes CRL if it is required.
     * CRL is signed by default signing algorithm. 
     *
     * @exception EBaseException if an error occurred during
     *            CRL generation or publishing
     */
    public  void updateCRLNow() throws EBaseException;

    /**
     * Returns list of CRL extensions.
     *
     * @return list of CRL extensions
     */
    public ICMSCRLExtensions getCRLExtensions();
}

