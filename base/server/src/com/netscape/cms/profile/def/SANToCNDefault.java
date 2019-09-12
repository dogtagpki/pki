//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.profile.def;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Locale;

import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.DNSName;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.GeneralNameInterface;
import org.mozilla.jss.netscape.security.x509.GeneralNames;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This plug-in replaces the subject DN with CN=<DNS name>
 * using the first DNS name in the SAN extension.
 *
 * @author Endi S. Dewata
 */
public class SANToCNDefault extends EnrollExtDefault {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SANToCNDefault.class);

    public void populate(IRequest request, X509CertInfo info) throws EProfileException {

        X500Name subjectDN = info.getSubjectObj().getX500Name();
        logger.info("SANtoCNDefault: Subject DN: " + subjectDN);

        String cn;
        try {
            cn = subjectDN.getCommonName();

        } catch (NullPointerException e) {
            // X500Name.getCommonName() throws NPE if subject DN is blank
            // TODO: fix X500Name.getCommonName() to return null
            cn = null;

        } catch (IOException e) {
            String message = "SANtoCNDefault: Unable to get CN from subject DN: " + e.getMessage();
            logger.error(message);
            throw new EProfileException(message, e);
        }

        if (cn != null) {
            // subject DN already contains a DNS name in CN attribute
            return;
        }

        logger.info("SANtoCNDefault: Checking SAN extension");

        SubjectAlternativeNameExtension san = (SubjectAlternativeNameExtension)
            getExtension(PKIXExtensions.SubjectAlternativeName_Id.toString(), info);

        if (san == null) {
            String message = "SANtoCNDefault: Unable to find SAN extension";
            logger.error(message);
            throw new EProfileException(message);
        }

        logger.info("SANtoCNDefault: Getting the first DNS name from SAN");
        String dnsName = null;

        GeneralNames generalNames = san.getGeneralNames();
        for (GeneralNameInterface generalName : generalNames) {

            if (generalName instanceof GeneralName) {
                generalName = ((GeneralName) generalName).unwrap();
            }

            if (generalName instanceof DNSName) {
                dnsName = ((DNSName) generalName).getValue();
                break;
            }
        }

        if (dnsName == null) {
            String message = "SANtoCNDefault: Unable to find DNS name in SAN extension";
            logger.error(message);
            throw new EProfileException(message);
        }

        logger.info("SANtoCNDefault: DNS name: " + dnsName);

        try {
            X500Name newSubjectDN = new X500Name("CN=" + dnsName);
            logger.info("SANtoCNDefault: New subject DN: " + newSubjectDN);

            CertificateSubjectName subjectName = new CertificateSubjectName(newSubjectDN);
            info.set(X509CertInfo.SUBJECT, subjectName);

        } catch (CertificateException | IOException e) {
            String message = "SANtoCNDefault: Unable to set Subject DN: " + e.getMessage();
            logger.error(message);
            throw new EProfileException(message, e);
        }
    }

    public String getText(Locale locale) {
        return "This default constructs a Subject DN from the first DNS name in "
            + "Subject Alternative Name extension.";
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    public String getValue(String name, Locale locale, X509CertInfo info) {
        return null;
    }

    public void setValue(String name, Locale locale, X509CertInfo info, String value) {
    }
}
