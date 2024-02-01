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
package com.netscape.cms.crl;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CMSCRLExtension;
import org.mozilla.jss.netscape.security.x509.AuthorityKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.GeneralNames;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SerialNumber;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.ca.CRLIssuingPoint;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;

/**
 * This represents an authority key identifier extension.
 *
 * @version $Revision$, $Date$
 */
public class CMSAuthorityKeyIdentifierExtension
        extends CMSCRLExtension
        implements IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMSAuthorityKeyIdentifierExtension.class);

    public CMSAuthorityKeyIdentifierExtension() {
    }

    @Override
    public Extension setCRLExtensionCriticality(Extension ext,
            boolean critical) {
        AuthorityKeyIdentifierExtension authKeyIdExt = null;
        KeyIdentifier keyId = null;
        GeneralNames names = null;
        SerialNumber sn = null;

        try {
            keyId = (KeyIdentifier) ((AuthorityKeyIdentifierExtension) ext).get(
                        AuthorityKeyIdentifierExtension.KEY_ID);
            names = (GeneralNames) ((AuthorityKeyIdentifierExtension) ext).get(
                        AuthorityKeyIdentifierExtension.AUTH_NAME);
            sn = (SerialNumber) ((AuthorityKeyIdentifierExtension) ext).get(
                        AuthorityKeyIdentifierExtension.SERIAL_NUMBER);
            authKeyIdExt = new AuthorityKeyIdentifierExtension(critical, keyId, names, sn);
        } catch (IOException e) {
            logger.warn(CMS.getLogMessage("CRL_CREATE_AKI_EXT", e.toString()), e);
        }
        return authKeyIdExt;
    }

    @Override
    public Extension getCRLExtension(ConfigStore config, Object ip, boolean critical) {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        AuthorityKeyIdentifierExtension authKeyIdExt = null;
        CRLIssuingPoint crlIssuingPoint = (CRLIssuingPoint) ip;

        try {
            KeyIdentifier keyId = null;

            try {
                X509CertInfo info = (X509CertInfo) ca.getCACert().get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

                if (info != null) {
                    CertificateExtensions caCertExtensions = (CertificateExtensions)
                            info.get(X509CertInfo.EXTENSIONS);

                    if (caCertExtensions != null) {
                        for (int i = 0; i < caCertExtensions.size(); i++) {
                            Extension caCertExt = caCertExtensions.elementAt(i);

                            if (caCertExt instanceof SubjectKeyIdentifierExtension id) {
                                keyId = (KeyIdentifier) id.get(SubjectKeyIdentifierExtension.KEY_ID);
                            }
                        }
                    }
                }

            } catch (CertificateParsingException e) {
                logger.warn(CMS.getLogMessage("CRL_CERT_PARSING_ERROR", e.toString()), e);

            } catch (CertificateException e) {
                logger.warn(CMS.getLogMessage("CRL_CERT_CERT_EXCEPTION", e.toString()), e);
            }

            if (keyId != null) {
                authKeyIdExt = new AuthorityKeyIdentifierExtension(critical, keyId, null, null);
            } else {
                GeneralNames gNames = new GeneralNames();

                gNames.addElement(ca.getX500Name());

                authKeyIdExt = new AuthorityKeyIdentifierExtension(
                        critical,
                        null,
                        gNames,
                        new SerialNumber(ca.getCACert().getSerialNumber()));
            }

        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("CRL_CREATE_AKI_EXT", e.toString()), e);
        }

        return authKeyIdExt;
    }

    @Override
    public String getCRLExtOID() {
        return PKIXExtensions.AuthorityKey_Id.toString();
    }

    @Override
    public void getConfigParams(ConfigStore config, NameValuePairs nvp) {
    }

    @Override
    public String[] getExtendedPluginInfo() {
        String[] params = {
                //"type;choice(CRLExtension,CRLEntryExtension);CRL Extension Type. "+
                //"This field is not editable.",
                "enable;boolean;Check to enable Authority Key Identifier CRL extension.",
                "critical;boolean;Set criticality for Authority Key Identifier CRL extension.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ca-edit-crlextension-authoritykeyidentifier",
                IExtendedPluginInfo.HELP_TEXT +
                        ";The authority key identifier extension provides a means " +
                        "of identifying the public key corresponding to the private " +
                        "key used to sign a CRL."
            };

        return params;
    }
}
