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
package netscape.security.util;

import java.text.DateFormat;
import java.util.Iterator;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.TimeZone;

import netscape.security.x509.CRLExtensions;
import netscape.security.x509.Extension;
import netscape.security.x509.RevokedCertificate;
import netscape.security.x509.X509CRLImpl;

/**
 * This class will display the certificate content in predefined
 * format.
 *
 * @author Andrew Wnuk
 * @version $Revision$, $Date$
 */
public class CrlPrettyPrint {

    /*==========================================================
     * constants
     *==========================================================*/
    private final static String CUSTOM_LOCALE = "Custom";

    /*==========================================================
     * variables
     *==========================================================*/
    private X509CRLImpl mCRL = null;
    private PrettyPrintFormat pp = null;

    /*==========================================================
     * constructors
     *==========================================================*/

    public CrlPrettyPrint(X509CRLImpl crl) {
        mCRL = crl;
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
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_VERSION) + " v");
            sb.append((mCRL.getVersion() + 1) + "\n");
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_SIGALG) + mCRL.getSigAlgName() +
                    " - " + mCRL.getSigAlgOID() + "\n");
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_ISSUER) +
                    mCRL.getIssuerDN().toString() + "\n");
            // Format thisUpdate
            String thisUpdate = dateFormater.format(mCRL.getThisUpdate());

            // get timezone and timezone ID
            if (TimeZone.getDefault() != null) {
                tz = TimeZone.getDefault().getDisplayName(
                            TimeZone.getDefault().inDaylightTime(
                                    mCRL.getThisUpdate()),
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
            if (mCRL.getNextUpdate() != null) {
                // Format nextUpdate
                String nextUpdate = dateFormater.format(mCRL.getNextUpdate());

                // re-get timezone (just in case it is different . . .)
                if (TimeZone.getDefault() != null) {
                    tz = TimeZone.getDefault().getDisplayName(
                                TimeZone.getDefault().inDaylightTime(
                                        mCRL.getNextUpdate()),
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
                if (crlSize > 0 && pageStart > 0 && pageSize > 0) {
                    long upperLimit = (pageStart + pageSize - 1 > crlSize) ? crlSize : pageStart + pageSize - 1;

                    sb.append("" + pageStart + "-" + upperLimit + " of " + crlSize);
                }
                sb.append("\n");

                Set<RevokedCertificate> revokedCerts = mCRL.getRevokedCertificates();

                if (revokedCerts != null) {
                    Iterator<RevokedCertificate> i = revokedCerts.iterator();
                    long l = 1;

                    while ((i.hasNext()) && ((crlSize == 0) || (pageStart + pageSize > l))) {
                        RevokedCertificate revokedCert = i.next();

                        if ((crlSize == 0) || ((pageStart <= l) && (pageStart + pageSize > l))) {
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
                }
            }

            CRLExtensions crlExtensions = mCRL.getExtensions();

            if (crlExtensions != null) {
                sb.append(pp.indent(8) + resource.getString(
                        PrettyPrintResources.TOKEN_EXTENSIONS) + "\n");
                for (int k = 0; k < crlExtensions.size(); k++) {
                    Extension ext = crlExtensions.elementAt(k);
                    ExtPrettyPrint extpp = new ExtPrettyPrint(ext, 12);

                    sb.append(extpp.toString());
                }
            }

            //take care of signature
            sb.append(pp.indent(8) + resource.getString(
                    PrettyPrintResources.TOKEN_SIGNATURE) + "\n");
            //XXX I18N Algorithm Name ?
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_ALGORITHM) +
                    mCRL.getSigAlgName() + " - " + mCRL.getSigAlgOID() + "\n");
            sb.append(pp.indent(12) + resource.getString(
                    PrettyPrintResources.TOKEN_SIGNATURE) + "\n");
            sb.append(pp.toHexString(mCRL.getSignature(), 16, 16));

        } catch (Exception e) {
            sb.append("\n\n" + pp.indent(4) + resource.getString(
                    PrettyPrintResources.TOKEN_DECODING_ERROR) + "\n\n");
            e.printStackTrace();
        }

        return sb.toString();
    }
}
