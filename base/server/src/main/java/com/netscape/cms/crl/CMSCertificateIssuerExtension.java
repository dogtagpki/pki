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
import java.util.Locale;

import org.dogtagpki.server.ca.ICMSCRLExtension;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerExtension;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.GeneralNames;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.URIName;
import org.mozilla.jss.netscape.security.x509.X500Name;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.cmscore.apps.CMS;

/**
 * This represents a certificate issuer extension.
 *
 * @version $Revision$, $Date$
 */
public class CMSCertificateIssuerExtension
        implements ICMSCRLExtension, IExtendedPluginInfo {

    public final static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMSCertificateIssuerExtension.class);

    public CMSCertificateIssuerExtension() {
    }

    @Override
    public Extension setCRLExtensionCriticality(Extension ext,
            boolean critical) {
        CertificateIssuerExtension certIssuerExt = null;
        GeneralNames names = null;

        try {
            names = (GeneralNames) ((CertificateIssuerExtension) ext).get(
                        CertificateIssuerExtension.CERTIFICATE_ISSUER);
            certIssuerExt = new CertificateIssuerExtension(Boolean.valueOf(critical),
                        names);
        } catch (IOException e) {
            logger.warn(CMS.getLogMessage("CRL_CREATE_CERT_ISSUER_EXT", e.toString()), e);
        }

        return certIssuerExt;
    }

    @Override
    public Extension getCRLExtension(IConfigStore config,
            Object ip,
            boolean critical) {
        CertificateIssuerExtension certIssuerExt = null;
        int numNames = 0;

        try {
            numNames = config.getInteger("numNames", 0);
        } catch (EBaseException e) {
            logger.warn(CMS.getLogMessage("CRL_CREATE_INVALID_NUM_NAMES", e.toString()), e);
        }

        if (numNames > 0) {
            GeneralNames names = new GeneralNames();

            for (int i = 0; i < numNames; i++) {
                String nameType = null;

                try {
                    nameType = config.getString("nameType" + i);

                } catch (EPropertyNotFound e) {
                    logger.warn(CMS.getLogMessage("CRL_CREATE_UNDEFINED_TYPE", Integer.toString(i), e.toString()), e);

                } catch (EBaseException e) {
                    logger.warn(CMS.getLogMessage("CRL_CREATE_INVALID_TYPE", Integer.toString(i), e.toString()), e);
                }

                if (nameType != null) {
                    String name = null;

                    try {
                        name = config.getString("name" + i);

                    } catch (EPropertyNotFound e) {
                        logger.warn(CMS.getLogMessage("CRL_CREATE_UNDEFINED_TYPE", Integer.toString(i), e.toString()), e);

                    } catch (EBaseException e) {
                        logger.warn(CMS.getLogMessage("CRL_CREATE_INVALID_TYPE", Integer.toString(i), e.toString()), e);
                    }

                    if (name != null && name.length() > 0) {
                        if (nameType.equalsIgnoreCase("DirectoryName")) {
                            try {
                                X500Name dirName = new X500Name(name);

                                names.addElement(dirName);
                            } catch (IOException e) {
                                logger.warn(CMS.getLogMessage("CRL_CREATE_INVALID_500NAME", e.toString()), e);
                            }

                        } else if (nameType.equalsIgnoreCase("URI")) {
                            URIName uriName = new URIName(name);

                            names.addElement(uriName);
                        } else {
                            logger.warn(CMS.getLogMessage("CRL_CREATE_INVALID_NAME_TYPE", nameType));
                        }
                    }
                }
            }

            if (names.size() > 0) {
                try {
                    certIssuerExt = new CertificateIssuerExtension(
                                Boolean.valueOf(critical), names);
                } catch (IOException e) {
                    logger.warn(CMS.getLogMessage("CRL_CREATE_CERT_ISSUER_EXT", e.toString()), e);
                }
            }
        }

        return certIssuerExt;
    }

    @Override
    public String getCRLExtOID() {
        return PKIXExtensions.CertificateIssuer_Id.toString();
    }

    @Override
    public void getConfigParams(IConfigStore config, NameValuePairs nvp) {
        int numNames = 0;

        try {
            numNames = config.getInteger("numNames", 0);
        } catch (EBaseException e) {
            logger.warn(CMS.getLogMessage("CRL_CREATE_INVALID_NUM_NAMES", e.toString()), e);
        }

        nvp.put("numNames", String.valueOf(numNames));

        for (int i = 0; i < numNames; i++) {
            String nameType = null;

            try {
                nameType = config.getString("nameType" + i);

            } catch (EPropertyNotFound e) {
                logger.warn(CMS.getLogMessage("CRL_CREATE_UNDEFINED_TYPE", Integer.toString(i), e.toString()), e);

            } catch (EBaseException e) {
                logger.warn(CMS.getLogMessage("CRL_CREATE_INVALID_TYPE", Integer.toString(i), e.toString()), e);
            }

            if (nameType != null && nameType.length() > 0) {
                nvp.put("nameType" + i, nameType);
            } else {
                nvp.put("nameType" + i, "");
            }

            String name = null;

            try {
                name = config.getString("name" + i);

            } catch (EPropertyNotFound e) {
                logger.warn(CMS.getLogMessage("CRL_CREATE_UNDEFINED_TYPE", Integer.toString(i), e.toString()), e);

            } catch (EBaseException e) {
                logger.warn(CMS.getLogMessage("CRL_CREATE_INVALID_TYPE", Integer.toString(i), e.toString()), e);
            }

            if (name != null && name.length() > 0) {
                nvp.put("name" + i, name);
            } else {
                nvp.put("name" + i, "");
            }
        }

        if (numNames < 3) {
            for (int i = numNames; i < 3; i++) {
                nvp.put("nameType" + i, "");
                nvp.put("name" + i, "");
            }
        }
    }

    @Override
    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                //"type;choice(CRLExtension,CRLEntryExtension);CRL Entry Extension type."+
                //" This field is not editable.",
                "enable;boolean;Check to enable Certificate Issuer CRL entry extension.",
                "critical;boolean;Set criticality for Certificate Issuer CRL entry extension.",
                "numNames;number;Set number of certificate issuer names for the CRL entry.",
                "nameType0;choice(DirectoryName,URI);Select Certificate Issuer name type.",
                "name0;string;Enter Certificate Issuer name corresponding to the selected name type.",
                "nameType1;choice(DirectoryName,URI);Select Certificate Issuer name type.",
                "name1;string;Enter Certificate Issuer name corresponding to the selected name type.",
                "nameType2;choice(DirectoryName,URI);Select Certificate Issuer name type.",
                "name2;string;Enter Certificate Issuer name corresponding to the selected name type.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ca-edit-crlextension-certificateissuer",
                IExtendedPluginInfo.HELP_TEXT +
                        ";This CRL entry extension identifies the certificate issuer" +
                        " associated with an entry in an indirect CRL."
            };

        return params;
    }
}
