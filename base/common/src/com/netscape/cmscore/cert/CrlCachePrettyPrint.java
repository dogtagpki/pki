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
package com.netscape.cmscore.cert;

import java.text.DateFormat;
import java.util.Iterator;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.TimeZone;

import netscape.security.x509.CRLExtensions;
import netscape.security.x509.Extension;
import netscape.security.x509.RevokedCertificate;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.ICRLPrettyPrint;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;

/**
 * This class will display the certificate content in predefined
 * format.
 *
 * @author Andrew Wnuk
 * @version $Revision$, $Date$
 */
public class CrlCachePrettyPrint implements ICRLPrettyPrint {

    /*==========================================================
     * constants
     *==========================================================*/
    private final static String CUSTOM_LOCALE = "Custom";

    /*==========================================================
     * variables
     *==========================================================*/
    private ICRLIssuingPoint mIP = null;
    private PrettyPrintFormat pp = null;

    /*==========================================================
     * constructors
     *==========================================================*/

    public CrlCachePrettyPrint(ICRLIssuingPoint ip) {
        mIP = ip;
        pp = new PrettyPrintFormat(":");
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    /**
     * This method return string representation of the certificate
     * revocation list in predefined format using specified client
     * local. I18N Support.
     *
     * @param clientLocale Locale to be used for localization
     * @return string representation of the certificate
     */
    public String toString(Locale clientLocale) {
        return toString(clientLocale, 0, 0, 0);
    }

    public String toString(Locale clientLocale, long crlSize, long pageStart, long pageSize) {

        //get I18N resources
        ResourceBundle resource = ResourceBundle.getBundle(
                PrettyPrintResources.class.getName());
        DateFormat dateFormater = DateFormat.getDateTimeInstance(
                DateFormat.FULL, DateFormat.FULL, clientLocale);
        //get timezone and timezone ID
        String tz = " ";
        String tzid = " ";

        StringBuffer sb = new StringBuffer();

        try {
            sb.append(pp.indent(4) + resource.getString(
                      PrettyPrintResources.TOKEN_CRL) + "\n");
            sb.append(pp.indent(8) + resource.getString(
                      PrettyPrintResources.TOKEN_DATA) + "\n");

            String signingAlgorithm = mIP.getLastSigningAlgorithm();
            if (signingAlgorithm != null) {
                sb.append(pp.indent(12) + resource.getString(
                          PrettyPrintResources.TOKEN_SIGALG) +
                          signingAlgorithm + "\n");
            }
            sb.append(pp.indent(12) + resource.getString(
                      PrettyPrintResources.TOKEN_ISSUER) +
                      ((ICertificateAuthority) (mIP.getCertificateAuthority()))
                              .getCRLX500Name().toString() + "\n");
            // Format thisUpdate
            String thisUpdate = dateFormater.format(mIP.getLastUpdate());

            // get timezone and timezone ID
            if (TimeZone.getDefault() != null) {
                tz = TimeZone.getDefault().getDisplayName(
                            TimeZone.getDefault().inDaylightTime(mIP.getLastUpdate()),
                            TimeZone.SHORT,
                            clientLocale);
                tzid = TimeZone.getDefault().getID();
            }
            // Specify ThisUpdate
            if (tz.equals(tzid) || tzid.equals(CUSTOM_LOCALE)) {
                // Do NOT append timezone ID
                sb.append(pp.indent(12)
                        + resource.getString(
                                PrettyPrintResources.TOKEN_THIS_UPDATE)
                        + thisUpdate
                        + "\n");
            } else {
                // Append timezone ID
                sb.append(pp.indent(12)
                        + resource.getString(
                                PrettyPrintResources.TOKEN_THIS_UPDATE)
                        + thisUpdate
                        + " " + tzid + "\n");
            }
            // Check for presence of NextUpdate
            if (mIP.getNextUpdate() != null) {
                // Format nextUpdate
                String nextUpdate = dateFormater.format(mIP.getNextUpdate());

                // re-get timezone (just in case it is different . . .)
                if (TimeZone.getDefault() != null) {
                    tz = TimeZone.getDefault().getDisplayName(
                                TimeZone.getDefault().inDaylightTime(mIP.getNextUpdate()),
                                TimeZone.SHORT,
                                clientLocale);
                }
                // Specify NextUpdate
                if (tz.equals(tzid) || tzid.equals(CUSTOM_LOCALE)) {
                    // Do NOT append timezone ID
                    sb.append(pp.indent(12)
                            + resource.getString(
                                    PrettyPrintResources.TOKEN_NEXT_UPDATE)
                            + nextUpdate
                            + "\n");
                } else {
                    // Append timezone ID
                    sb.append(pp.indent(12)
                            + resource.getString(
                                    PrettyPrintResources.TOKEN_NEXT_UPDATE)
                            + nextUpdate
                            + " " + tzid + "\n");
                }
            }

            if (crlSize > 0 && pageStart == 0 && pageSize == 0) {
                sb.append(pp.indent(12) + resource.getString(
                        PrettyPrintResources.TOKEN_REVOKED_CERTIFICATES) + crlSize + "\n");
            } else if ((crlSize == 0 && pageStart == 0 && pageSize == 0) ||
                    (crlSize > 0 && pageStart > 0 && pageSize > 0)) {
                sb.append(pp.indent(12) + resource.getString(
                        PrettyPrintResources.TOKEN_REVOKED_CERTIFICATES));
                long upperLimit = crlSize;
                if (crlSize > 0 && pageStart > 0 && pageSize > 0) {
                    upperLimit = (pageStart + pageSize - 1 > crlSize) ? crlSize : pageStart + pageSize - 1;
                    sb.append("" + pageStart + "-" + upperLimit + " of " + crlSize);
                } else {
                    pageStart = 1;
                    sb.append("" + crlSize);
                }
                sb.append("\n");

                Set<RevokedCertificate> revokedCerts =
                        mIP.getRevokedCertificates((int) (pageStart - 1), (int) upperLimit);

                if (revokedCerts != null) {
                    Iterator<RevokedCertificate> i = revokedCerts.iterator();
                    long l = 1;

                    while ((i.hasNext()) && ((crlSize == 0) || (upperLimit - pageStart + 1 >= l))) {
                        RevokedCertificate revokedCert = i.next();

                        if ((crlSize == 0) || (upperLimit - pageStart + 1 >= l)) {
                            sb.append(pp.indent(16) + resource.getString(
                                    PrettyPrintResources.TOKEN_SERIAL) + "0x" +
                                    revokedCert.getSerialNumber().toString(16).toUpperCase() + "\n");
                            String revocationDate =
                                    dateFormater.format(revokedCert.getRevocationDate());

                            // re-get timezone
                            // (just in case it is different . . .)
                            if (TimeZone.getDefault() != null) {
                                tz = TimeZone.getDefault().getDisplayName(
                                            TimeZone.getDefault().inDaylightTime(
                                                    revokedCert.getRevocationDate()),
                                            TimeZone.SHORT,
                                            clientLocale);
                            }
                            // Specify revocationDate
                            if (tz.equals(tzid) ||
                                    tzid.equals(CUSTOM_LOCALE)) {
                                // Do NOT append timezone ID
                                sb.append(pp.indent(16)
                                        + resource.getString(
                                                PrettyPrintResources.TOKEN_REVOCATION_DATE)
                                        + revocationDate
                                        + "\n");
                            } else {
                                // Append timezone ID
                                sb.append(pp.indent(16)
                                        + resource.getString(
                                                PrettyPrintResources.TOKEN_REVOCATION_DATE)
                                        + revocationDate
                                        + " " + tzid + "\n");
                            }
                            if (revokedCert.hasExtensions()) {
                                sb.append(pp.indent(16) + resource.getString(
                                        PrettyPrintResources.TOKEN_EXTENSIONS) + "\n");
                                CRLExtensions crlExtensions = revokedCert.getExtensions();

                                if (crlExtensions != null) {
                                    for (int k = 0; k < crlExtensions.size(); k++) {
                                        Extension ext = crlExtensions.elementAt(k);
                                        ExtPrettyPrint extpp = new ExtPrettyPrint(ext, 20);

                                        sb.append(extpp.toString());
                                    }
                                }
                            }
                        }
                        l++;
                    }
                } else if (mIP.isCRLCacheEnabled() && mIP.isCRLCacheEmpty()) {
                    sb.append("\n" + pp.indent(16) + resource.getString(
                              PrettyPrintResources.TOKEN_CACHE_IS_EMPTY) + "\n\n");
                } else {
                    sb.append("\n" + pp.indent(16) + resource.getString(
                              PrettyPrintResources.TOKEN_CACHE_NOT_AVAILABLE) + "\n\n");
                }
            }

        } catch (Exception e) {
            sb.append("\n\n" + pp.indent(4) + resource.getString(
                    PrettyPrintResources.TOKEN_DECODING_ERROR) + "\n\n");
            CMS.debug("Exception=" + e.toString());
            CMS.debugStackTrace();
        }

        return sb.toString();
    }
}
