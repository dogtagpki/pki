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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.profile.def;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Locale;

import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.DNSName;
import netscape.security.x509.GeneralName;
import netscape.security.x509.GeneralNameInterface;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.SubjectAlternativeNameExtension;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This plugin will examine the most specific CN in the Subject DN,
 * and if it looks like a DNS name, will add it to the SAN extension.
 *
 * It will create the SAN extension if necessary.
 *
 * If there is already a SAN dnsName value that matches
 * (case-insensitively) the CN, it will not add the name.
 *
 * If there is no CN in the subject DN, does nothing.
 *
 * If the most specific CN does not look like a DNS name, does
 * nothing.
 *
 * This profile component should be configured to execute after
 * other profile components that set or modify the Subject DN or the
 * SAN extension.
 */
public class CommonNameToSANDefault extends EnrollExtDefault {

    private static final String LOG_PREFIX = "CommonNameToSANDefault: ";

    public void populate(IRequest _req, X509CertInfo info)
            throws EProfileException {
        // examine the Subject DN
        CertificateSubjectName subjectName;
        try {
            subjectName = (CertificateSubjectName) info.get(X509CertInfo.SUBJECT);
        } catch (CertificateException | IOException e) {
            CMS.debug(LOG_PREFIX + "failed to read Subject DN: " + e);
            return;
        }
        X500Name sdn;
        try {
            sdn = (X500Name) subjectName.get(CertificateSubjectName.DN_NAME);
        } catch (IOException e) {
            CMS.debug(LOG_PREFIX + "failed to retrieve SDN X500Name: " + e);
            return;
        }
        List<String> cns;
        try {
            cns = sdn.getAttributesForOid(X500Name.commonName_oid);
        } catch (IOException e) {
            // Couldn't read the CN for some reason.
            // Not a likely scenario so just log and return.
            CMS.debug(LOG_PREFIX + "failed to decode CN: " + e);
            return;
        }
        if (cns.size() < 1) {
            CMS.debug(LOG_PREFIX + "No CN in Subject DN; done");
            return;  // no Common Name; can't do anything
        }

        String cn = cns.get(cns.size() - 1); // "most specific" CN is at end

        CMS.debug(LOG_PREFIX + "Examining CN: " + cn);

        if (!isValidDNSName(cn)) {
            CMS.debug(LOG_PREFIX + "CN is not a DNS name; done");
            return;  // CN does not look like a DNS name
        }

        SubjectAlternativeNameExtension san = (SubjectAlternativeNameExtension)
            getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString(), info);

        if (san != null) {
            // check for existing name matching CN
            GeneralNames gns = san.getGeneralNames();
            for (GeneralNameInterface gn : gns) {
                if (gn instanceof GeneralName)
                    gn = ((GeneralName) gn).unwrap();
                if (gn instanceof DNSName) {
                    String dnsName = ((DNSName) gn).getValue();
                    if (cn.equalsIgnoreCase(dnsName)) {
                        CMS.debug(LOG_PREFIX
                            + "CN already has corresponding SAN dNSName; done");
                        return;  // CN is already in SAN
                    }
                }
            }
            gns.add(new DNSName(cn));  // add CN to SAN

            // reset extension value (encoded value may have been cached)
            san.setGeneralNames(gns);
            CMS.debug(LOG_PREFIX + "added CN to SAN; done");
        } else {
            GeneralNames gns = new GeneralNames();
            gns.add(new DNSName(cn));
            try {
                san = new SubjectAlternativeNameExtension(gns);
                addExtension(
                    PKIXExtensions.SubjectAlternativeName_Id.toString(), san, info);
            } catch (IOException e) {
                CMS.debug(LOG_PREFIX + "failed to construct SAN ext: " + e);
                return;
            }
            CMS.debug(LOG_PREFIX + "added SAN extension containing CN; done");
        }
    }

    public String getText(Locale locale) {
        return "This default add the Subject DN Common Name to the Subject "
            + "Alternative Name extension, if it looks like a DNS name.";
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    public String getValue(String name, Locale locale, X509CertInfo info) {
        return null;
    }

    public void setValue(
            String name, Locale locale, X509CertInfo info, String value) {
    }

    /** Validate DNS name syntax per Section 3.5 of RFC 1034
     * and Section 2.1 of RFC 1123, and the additional rules
     * of RFC 5280 Section 4.2.1.6.
     *
     * Further to those rules, we also ignore CNs that are valid
     * DNS names but which only have a single part (e.g. TLDs or
     * host short names).
     */
    public static boolean isValidDNSName(String s) {
        if (s == null)
            return false;

        if (s.length() < 1 || s.length() > 255)
            return false;

        String[] parts = s.split("\\.");

        if (parts.length < 2)
            return false;

        for (int i = 0; i < parts.length; i++) {
            char[] cs = parts[i].toCharArray();

            if (cs.length < 1 || cs.length > 63)
                return false;

            if (!isLetter(cs[0]))
                return false;

            if (!isLetDig(cs[cs.length - 1]))
                return false;

            for (int j = 0; j < cs.length; j++) {
                if (!isLetDigHyp(cs[j]))
                    return false;
            }
        }

        return true;
    }

    public static boolean isLetter(char c) {
        return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z';
    }

    public static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    public static boolean isLetDig(char c) {
        return isLetter(c) || isDigit(c);
    }

    public static boolean isLetDigHyp(char c) {
        return isLetDig(c) || c == '-';
    }

}
