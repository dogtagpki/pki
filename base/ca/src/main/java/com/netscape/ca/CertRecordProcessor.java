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

import java.math.BigInteger;
import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;

import org.mozilla.jss.netscape.security.util.BitArray;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.IssuingDistributionPoint;
import org.mozilla.jss.netscape.security.x509.IssuingDistributionPointExtension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.RevokedCertificate;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.ElementProcessor;
import com.netscape.cmscore.dbs.RevocationInfo;

public class CertRecordProcessor extends ElementProcessor {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertRecordProcessor.class);

    private Hashtable<BigInteger, RevokedCertificate> crlCerts;
    private boolean allowExtensions;
    private CRLIssuingPoint issuingPoint;

    private boolean issuingDistPointAttempted;
    private boolean issuingDistPointEnabled;
    private BitArray onlySomeReasons;

    public CertRecordProcessor(
            Hashtable<BigInteger, RevokedCertificate> crlCerts,
            CRLIssuingPoint ip,
            boolean allowExtensions) {

        this.crlCerts = crlCerts;
        this.issuingPoint = ip;
        this.allowExtensions = allowExtensions;
    }

    private boolean initCRLIssuingDistPointExtension() {

        boolean result = false;
        CMSCRLExtensions exts = null;

        if (issuingDistPointAttempted ) {
            return issuingDistPointEnabled == true && onlySomeReasons != null;
        }

        issuingDistPointAttempted = true;
        exts = issuingPoint.getCRLExtensions();

        if (exts == null) {
            return result;
        }

        boolean isIssuingDistPointExtEnabled = false;
        isIssuingDistPointExtEnabled = exts.isCRLExtensionEnabled(IssuingDistributionPointExtension.NAME);

        if (isIssuingDistPointExtEnabled == false) {
            issuingDistPointEnabled = false;
            return false;
        }

        issuingDistPointEnabled = true;

        // Get info out of the IssuingDistPointExtension
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

        if (issuingDistExt != null) {
            iExt = (IssuingDistributionPointExtension) issuingDistExt;
        }

        IssuingDistributionPoint issuingDistributionPoint = null;

        if (iExt != null) {
            issuingDistributionPoint = iExt.getIssuingDistributionPoint();
        }

        BitArray onlySomeReasons = null;

        if (issuingDistributionPoint != null) {
            onlySomeReasons = issuingDistributionPoint.getOnlySomeReasons();
        }

        boolean applyReasonMatch = false;

        if (onlySomeReasons != null) {
            applyReasonMatch = !onlySomeReasons.toString().equals("0000000");
            logger.debug("applyReasonMatch " + applyReasonMatch);
            if (applyReasonMatch == true) {
                this.onlySomeReasons = onlySomeReasons;
                result = true;
            }
        }

        return result;
    }

    private boolean checkOnlySomeReasonsExtension(CRLExtensions entryExts) {

        // This is exactly how the Pretty Print code obtains the reason code
        // through the extensions
        boolean includeCert = true;

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
                reasonIndex = reason.getCode();
                logger.debug("revoked reason " + reason);
            } catch (Exception e) {
                return includeCert;
            }
        } else {
            return includeCert;
        }

        boolean reasonMatch = false;
        if (onlySomeReasons != null) {
            reasonMatch = onlySomeReasons.get(reasonIndex);
            if (reasonMatch != true) {
                includeCert = false;
            } else {
                logger.debug("onlySomeReasons match! reason: " + reason);
            }
        }

        return includeCert;
    }

    public boolean checkRevokedCertExtensions(CRLExtensions crlExtensions) {

        // For now just check the onlySomeReason CRL IssuingDistributionPoint extension
        boolean includeCert = true;

        if ((crlExtensions == null) || (allowExtensions == false)) {
            return includeCert;
        }

        boolean inited = initCRLIssuingDistPointExtension();

        // If the CRLIssuingDistPointExtension is not available or
        // if onlySomeReasons does not apply, bail.
        if (inited == false) {
            return includeCert;
        }

        // Check the onlySomeReasonsExtension
        includeCert = checkOnlySomeReasonsExtension(crlExtensions);

        return includeCert;
    }

    @Override
    public void process(Object o) throws EBaseException {
        try {
            CertRecord certRecord = (CertRecord) o;

            BigInteger serialNumber = certRecord.getSerialNumber();
            CertId certID = new CertId(serialNumber);

            Date revocationDate = certRecord.getRevocationDate();
            RevocationInfo revInfo = certRecord.getRevocationInfo();

            CRLExtensions entryExt = null;
            CRLExtensions crlExts = null;

            if (revInfo != null) {
                crlExts = revInfo.getCRLEntryExtensions();
                entryExt = issuingPoint.getRequiredEntryExtensions(crlExts);
            }

            RevokedCertificate newRevokedCert = new RevokedCertImpl(serialNumber, revocationDate, entryExt);

            boolean includeCert = checkRevokedCertExtensions(crlExts);

            if (includeCert == true) {
                logger.info("CertRecordProcessor: Adding cert " + certID.toHexString() + " into CRL");
                crlCerts.put(serialNumber, newRevokedCert);
            }

        } catch (EBaseException e) {
            logger.error("CA failed constructing CRL entry: " + (crlCerts.size() + 1) + " " + e, e);
            throw new ECAException(CMS.getUserMessage("CMS_CA_FAILED_CONSTRUCTING_CRL", e.toString()));
        }
    }
}
