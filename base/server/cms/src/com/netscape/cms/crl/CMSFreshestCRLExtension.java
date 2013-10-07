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

import netscape.security.x509.CRLDistributionPoint;
import netscape.security.x509.Extension;
import netscape.security.x509.FreshestCRLExtension;
import netscape.security.x509.GeneralNames;
import netscape.security.x509.GeneralNamesException;
import netscape.security.x509.PKIXExtensions;
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
 * This represents a freshest CRL extension.
 *
 * @version $Revision$, $Date$
 */
public class CMSFreshestCRLExtension
        implements ICMSCRLExtension, IExtendedPluginInfo {
    public static final String PROP_NUM_POINTS = "numPoints";
    public static final String PROP_POINTTYPE = "pointType";
    public static final String PROP_POINTNAME = "pointName";
    public static final String PROP_DIRNAME = "DirectoryName";
    public static final String PROP_URINAME = "URI";

    private ILogger mLogger = CMS.getLogger();

    public CMSFreshestCRLExtension() {
    }

    public Extension setCRLExtensionCriticality(Extension ext,
            boolean critical) {
        FreshestCRLExtension freshestCRLExt = (FreshestCRLExtension) ext;

        freshestCRLExt.setCritical(critical);

        return freshestCRLExt;
    }

    public Extension getCRLExtension(IConfigStore config, Object ip,
            boolean critical) {
        FreshestCRLExtension freshestCRLExt = null;

        int numPoints = 0;

        try {
            numPoints = config.getInteger("numPoints", 0);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_ISSUER_INVALID_NUM_NAMES", e.toString()));
        }

        if (numPoints > 0) {

            for (int i = 0; i < numPoints; i++) {
                CRLDistributionPoint crlDP = new CRLDistributionPoint();
                GeneralNames names = new GeneralNames();
                String pointType = null;

                try {
                    pointType = config.getString(PROP_POINTTYPE + i);
                } catch (EPropertyNotFound e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_UNDEFINED", e.toString()));
                } catch (EBaseException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_INVALID", e.toString()));
                }

                if (pointType != null) {
                    String pointName = null;

                    try {
                        pointName = config.getString(PROP_POINTNAME + i);
                    } catch (EPropertyNotFound e) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_UNDEFINED", e.toString()));
                    } catch (EBaseException e) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_INVALID", e.toString()));
                    }

                    if (pointName != null && pointName.length() > 0) {
                        if (pointType.equalsIgnoreCase(PROP_DIRNAME)) {
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

                if (names.size() > 0) {
                    try {
                        crlDP.setFullName(names);
                    } catch (IOException e) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CANNOT_SET_NAME", e.toString()));
                    } catch (GeneralNamesException e) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CANNOT_SET_NAME", e.toString()));
                    }
                }

                if (i > 0) {
                    freshestCRLExt.addPoint(crlDP);
                } else {
                    freshestCRLExt = new FreshestCRLExtension(crlDP);
                }
            }
        }

        return freshestCRLExt;
    }

    public String getCRLExtOID() {
        return PKIXExtensions.FreshestCRL_Id.toString();
    }

    public void getConfigParams(IConfigStore config, NameValuePairs nvp) {

        int numPoints = 0;

        try {
            numPoints = config.getInteger(PROP_NUM_POINTS, 0);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, "Invalid numPoints property for CRL " +
                    "Freshest CRL extension - " + e);
        }
        nvp.put(PROP_NUM_POINTS, String.valueOf(numPoints));

        for (int i = 0; i < numPoints; i++) {
            String pointType = null;

            try {
                pointType = config.getString(PROP_POINTTYPE + i);
            } catch (EPropertyNotFound e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_UNDEFINED", e.toString()));
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_INVALID", e.toString()));
            }

            if (pointType != null && pointType.length() > 0) {
                nvp.put(PROP_POINTTYPE + i, pointType);
            } else {
                nvp.put(PROP_POINTTYPE + i, "");
            }

            String pointName = null;

            try {
                pointName = config.getString(PROP_POINTNAME + i);
            } catch (EPropertyNotFound e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_UNDEFINED", e.toString()));
            } catch (EBaseException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_DIST_POINT_INVALID", e.toString()));
            }

            if (pointName != null && pointName.length() > 0) {
                nvp.put(PROP_POINTNAME + i, pointName);
            } else {
                nvp.put(PROP_POINTNAME + i, "");
            }
        }
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                "enable;boolean;Check to enable Freshest CRL extension.",
                "critical;boolean;Set criticality for Freshest CRL extension.",
                PROP_NUM_POINTS + ";number;Set number of CRL distribution points.",
                PROP_POINTTYPE + "0;choice(" + PROP_DIRNAME + "," + PROP_URINAME +
                        ");Select CRL distribution point name type.",
                PROP_POINTNAME + "0;string;Enter CRL distribution point name " +
                        "corresponding to the selected point type.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ca-edit-crlextension-issuingdistributionpoint",
                PROP_POINTTYPE + "1;choice(" + PROP_DIRNAME + "," + PROP_URINAME +
                        ");Select CRL distribution point name type.",
                PROP_POINTNAME + "1;string;Enter CRL distribution point name " +
                        "corresponding to the selected point type.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ca-edit-crlextension-issuingdistributionpoint",
                PROP_POINTTYPE + "2;choice(" + PROP_DIRNAME + "," + PROP_URINAME +
                        ");Select CRL distribution point name type.",
                PROP_POINTNAME + "2;string;Enter CRL distribution point name " +
                        "corresponding to the selected point type.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ca-edit-crlextension-issuingdistributionpoint",
                IExtendedPluginInfo.HELP_TEXT +
                        ";The Freshest CRL is a non critical CRL extension " +
                        "that identifies the delta CRL distribution points for a particular CRL."
            };

        return params;
    }

    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_CA, level,
                "CMSFreshestCRLExtension - " + msg);
    }
}
