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
import java.util.Date;
import java.util.Locale;

import netscape.security.x509.Extension;
import netscape.security.x509.InvalidityDateExtension;
import netscape.security.x509.PKIXExtensions;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ca.ICMSCRLExtension;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.logging.ILogger;

/**
 * This represents a invalidity date extension.
 *
 * @version $Revision$, $Date$
 */
public class CMSInvalidityDateExtension
        implements ICMSCRLExtension, IExtendedPluginInfo {
    private ILogger mLogger = CMS.getLogger();

    public CMSInvalidityDateExtension() {
    }

    public Extension setCRLExtensionCriticality(Extension ext,
            boolean critical) {
        InvalidityDateExtension invalidityDateExt = null;

        try {
            Date invalidityDate = ((InvalidityDateExtension) ext).getInvalidityDate();

            invalidityDateExt = new InvalidityDateExtension(Boolean.valueOf(critical),
                        invalidityDate);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CRL_CREATE_INVALIDITY_DATE_EXT", e.toString()));
        }
        return invalidityDateExt;
    }

    public Extension getCRLExtension(IConfigStore config,
            Object crlIssuingPoint,
            boolean critical) {
        InvalidityDateExtension invalidityDateExt = null;

        return invalidityDateExt;
    }

    public String getCRLExtOID() {
        return PKIXExtensions.InvalidityDate_Id.toString();
    }

    public void getConfigParams(IConfigStore config, NameValuePairs nvp) {
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                //"type;choice(CRLExtension,CRLEntryExtension);"+
                //"CRL Entry Extension type. This field is not editable.",
                "enable;boolean;Check to enable Invalidity Date CRL entry extension.",
                "critical;boolean;Set criticality for Invalidity Date CRL entry extension.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ca-edit-crlextension-invaliditydate",
                IExtendedPluginInfo.HELP_TEXT +
                        ";The invalidity date is a non-critical CRL entry extension " +
                        "that provides the date on which it is known or suspected " +
                        "that the private key was compromised or that the certificate" +
                        " otherwise became invalid."
            };

        return params;
    }

    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_CA, level,
                "CMSInvalidityDateExtension - " + msg);
    }
}
