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
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.RevocationReason;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.cmscore.apps.CMS;

/**
 * This represents a CRL reason extension.
 *
 * @version $Revision$, $Date$
 */
public class CMSCRLReasonExtension
        implements ICMSCRLExtension, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMSCRLReasonExtension.class);

    public CMSCRLReasonExtension() {
    }

    @Override
    public Extension setCRLExtensionCriticality(Extension ext,
            boolean critical) {
        RevocationReason reason = null;
        CRLReasonExtension crlReasonExt = null;

        try {
            reason = (RevocationReason) ((CRLReasonExtension) ext).get(CRLReasonExtension.REASON);
            crlReasonExt = new CRLReasonExtension(Boolean.valueOf(critical), reason);
        } catch (IOException e) {
            logger.warn(CMS.getLogMessage("CRL_CREATE_CRL_REASON_EXT", e.toString()), e);
        }
        return crlReasonExt;
    }

    @Override
    public Extension getCRLExtension(IConfigStore config,
            Object crlIssuingPoint,
            boolean critical) {
        CRLReasonExtension crlReasonExt = null;

        return crlReasonExt;
    }

    @Override
    public String getCRLExtOID() {
        return PKIXExtensions.ReasonCode_Id.toString();
    }

    @Override
    public void getConfigParams(IConfigStore config, NameValuePairs nvp) {
    }

    @Override
    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                //"type;choice(CRLExtension,CRLEntryExtension);"+
                //"CRL Entry Extension type. This field is not editable.",
                "enable;boolean;Check to enable reason code CRL entry extension.",
                "critical;boolean;Set criticality for reason code CRL entry extension.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ca-edit-crlextension-crlreason",
                IExtendedPluginInfo.HELP_TEXT +
                        ";The CRL reason code is a non-critical CRL entry extension " +
                        "that identifies the reason for the certificate revocation."
            };

        return params;
    }
}
