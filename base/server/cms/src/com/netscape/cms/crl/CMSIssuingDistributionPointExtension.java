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
import java.util.StringTokenizer;

import netscape.security.util.BitArray;
import netscape.security.x509.Extension;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.GeneralNamesException;
import netscape.security.x509.IssuingDistributionPoint;
import netscape.security.x509.IssuingDistributionPointExtension;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.RDN;
import netscape.security.x509.URIName;
import netscape.security.x509.X500Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ca.ICMSCRLExtension;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.logging.ILogger;

/**
 * This represents a issuing distribution point extension.
 *
 * @version $Revision$, $Date$
 */
public class CMSIssuingDistributionPointExtension
        implements ICMSCRLExtension, IExtendedPluginInfo {
    public static final String PROP_POINTTYPE = "pointType";
    public static final String PROP_POINTNAME = "pointName";
    public static final String PROP_DIRNAME = "DirectoryName";
    public static final String PROP_URINAME = "URI";
    public static final String PROP_RDNNAME = "RelativeToIssuer";
    public static final String PROP_CACERTS = "onlyContainsCACerts";
    public static final String PROP_USERCERTS = "onlyContainsUserCerts";
    public static final String PROP_INDIRECT = "indirectCRL";
    public static final String PROP_REASONS = "onlySomeReasons";

    private static final String[] reasonFlags = { "unused",
            "keyCompromise",
            "cACompromise",
            "affiliationChanged",
            "superseded",
            "cessationOfOperation",
            "certificateHold",
            "privilegeWithdrawn" };

    private ILogger mLogger = CMS.getLogger();

    public CMSIssuingDistributionPointExtension() {
    }

    public Extension setCRLExtensionCriticality(Extension ext,
            boolean critical) {
        IssuingDistributionPointExtension issuingDPointExt =
                (IssuingDistributionPointExtension) ext;

        issuingDPointExt.setCritical(critical);

        return issuingDPointExt;
    }

    public Extension getCRLExtension(IConfigStore config,
            Object ip,
            boolean critical) {

        CMS.debug("in CMSIssuingDistributionPointExtension::getCRLExtension.");
        IssuingDistributionPointExtension issuingDPointExt = null;
        IssuingDistributionPoint issuingDPoint = new IssuingDistributionPoint();

        GeneralNames names = new GeneralNames();
        RDN rdnName = null;

        String pointType = null;

        try {
            pointType = config.getString(PROP_POINTTYPE);
        } catch (EPropertyNotFound e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_UNDEFINED", e.toString()));
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_INVALID", e.toString()));
        }

        if (pointType != null) {
            String pointName = null;

            try {
                pointName = config.getString(PROP_POINTNAME);
            } catch (EPropertyNotFound e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_UNDEFINED", e.toString()));
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_INVALID", e.toString()));
            }

            if (pointName != null && pointName.length() > 0) {
                if (pointType.equalsIgnoreCase(PROP_RDNNAME)) {
                    try {
                        rdnName = new RDN(pointName);
                    } catch (IOException e) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_RDN", e.toString()));
                    }
                } else if (pointType.equalsIgnoreCase(PROP_DIRNAME)) {
                    try {
                        X500Name dirName = new X500Name(pointName);

                        names.addElement(dirName);
                    } catch (IOException e) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_INVALID_500NAME", e.toString()));
                    }
                } else if (pointType.equalsIgnoreCase(PROP_URINAME)) {
                    URIName uriName = new URIName(pointName);

                    names.addElement(uriName);
                } else {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_INVALID_POTINT_TYPE", pointType));
                }
            }
        }

        if (rdnName != null) {
            issuingDPoint.setRelativeName(rdnName);
        } else if (names.size() > 0) {
            try {
                issuingDPoint.setFullName(names);
            } catch (IOException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CANNOT_SET_NAME", e.toString()));
            } catch (GeneralNamesException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CANNOT_SET_NAME", e.toString()));
            }
        }

        String reasons = null;

        try {
            reasons = config.getString(PROP_REASONS, null);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_INVALID_PROPERTY", PROP_REASONS, e.toString()));
        }
        if (reasons != null && reasons.length() > 0) {

            boolean[] bits = { false, false, false, false, false, false, false };
            int k = 0;
            StringTokenizer st = new StringTokenizer(reasons, ",");

            while (st.hasMoreTokens()) {
                String bitName = st.nextToken();

                for (int i = 1; i < reasonFlags.length; i++) {
                    if (bitName.equalsIgnoreCase(reasonFlags[i])) {
                        bits[i] = true;
                        k++;
                        break;
                    }
                }
            }
            if (k > 0) {
                BitArray ba = new BitArray(bits);

                issuingDPoint.setOnlySomeReasons(ba);
            }

        }

        try {
            boolean caCertsOnly = config.getBoolean(PROP_CACERTS, false);

            if (caCertsOnly)
                issuingDPoint.setOnlyContainsCACerts(caCertsOnly);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_INVALID_PROPERTY", "caCertsOnly", e.toString()));
        }
        try {
            boolean userCertsOnly = config.getBoolean(PROP_USERCERTS, false);

            if (userCertsOnly)
                issuingDPoint.setOnlyContainsUserCerts(userCertsOnly);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_INVALID_PROPERTY", "userCertsOnly", e.toString()));
        }
        try {
            boolean indirectCRL = config.getBoolean(PROP_INDIRECT, false);

            if (indirectCRL)
                issuingDPoint.setIndirectCRL(indirectCRL);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_INVALID_PROPERTY", "indirectCRL", e.toString()));
        }

        issuingDPointExt = new IssuingDistributionPointExtension(issuingDPoint);
        issuingDPointExt.setCritical(critical);

        return issuingDPointExt;
    }

    public String getCRLExtOID() {
        return PKIXExtensions.IssuingDistributionPoint_Id.toString();
    }

    public void getConfigParams(IConfigStore config, NameValuePairs nvp) {
        String pointType = null;

        try {
            pointType = config.getString(PROP_POINTTYPE);
        } catch (EPropertyNotFound e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_UNDEFINED", e.toString()));
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_INVALID", e.toString()));
        }
        if (pointType != null && pointType.length() > 0) {
            nvp.put("pointType", pointType);
        } else {
            nvp.put("pointType", "");
        }

        String pointName = null;

        try {
            pointName = config.getString(PROP_POINTNAME);
        } catch (EPropertyNotFound e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_UNDEFINED", e.toString()));
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_INVALID", e.toString()));
        }
        if (pointName != null && pointName.length() > 0) {
            nvp.put("pointName", pointName);
        } else {
            nvp.put("pointName", "");
        }

        String reasons = null;

        try {
            reasons = config.getString(PROP_REASONS, null);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_INVALID_PROPERTY", PROP_REASONS, e.toString()));
        }
        if (reasons != null && reasons.length() > 0) {
            nvp.put(PROP_REASONS, reasons);
        } else {
            nvp.put(PROP_REASONS, "");
        }

        try {
            boolean caCertsOnly = config.getBoolean(PROP_CACERTS, false);

            nvp.put(PROP_CACERTS, String.valueOf(caCertsOnly));
        } catch (EBaseException e) {
            nvp.put(PROP_CACERTS, "false");
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_INVALID_PROPERTY", "caCertsOnly", e.toString()));
        }
        // Disable these for now unitl we support them fully
        /*
                try {
                    boolean userCertsOnly = config.getBoolean(PROP_USERCERTS, false);

                    nvp.add(PROP_USERCERTS, String.valueOf(userCertsOnly));
                } catch (EBaseException e) {
                    nvp.add(PROP_USERCERTS, "false");
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_INVALID_PROPERTY", "userCertsOnly", e.toString()));
                }

                try {
                    boolean indirectCRL = config.getBoolean(PROP_INDIRECT, false);

                    nvp.add(PROP_INDIRECT, String.valueOf(indirectCRL));
                } catch (EBaseException e) {
                    nvp.add(PROP_INDIRECT, "false");
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_INVALID_PROPERTY", "indirectCRL", e.toString()));
                }
        */
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        StringBuffer sb_reasons = new StringBuffer();
        sb_reasons.append(reasonFlags[1]);

        for (int i = 2; i < reasonFlags.length; i++) {
            sb_reasons.append(", ");
            sb_reasons.append(reasonFlags[i]);
        }
        String[] params = {
                //"type;choice(CRLExtension,CRLEntryExtension);"+
                //"CRL Extension type. This field is not editable.",
                "enable;boolean;Check to enable Issuing Distribution Point CRL extension.",
                "critical;boolean;Set criticality for Issuing Distribution Point CRL extension.",
                PROP_POINTTYPE + ";choice(" + PROP_DIRNAME + "," + PROP_URINAME + "," +
                        PROP_RDNNAME + ");Select Issuing Distribution Point name type.",
                PROP_POINTNAME + ";string;Enter Issuing Distribution Point name " +
                        "corresponding to the selected point type.",
                PROP_REASONS + ";string;Select any combination of the following reasons: " +
                        sb_reasons.toString(),
                PROP_CACERTS + ";boolean;Check if CRL contains CA certificates only",
                //   Remove these from the UI until they can be supported fully.
                //   PROP_USERCERTS + ";boolean;Check if CRL contains user certificates only",
                //   PROP_INDIRECT + ";boolean;Check if CRL is built indirectly.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ca-edit-crlextension-issuingdistributionpoint",
                IExtendedPluginInfo.HELP_TEXT +
                        ";The issuing distribution point is a critical CRL extension " +
                        "that identifies the CRL distribution point for a particular CRL."
            };

        return params;
    }

    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_CA, level,
                "CMSIssuingDistributionPointExtension - " + msg);
    }
}
