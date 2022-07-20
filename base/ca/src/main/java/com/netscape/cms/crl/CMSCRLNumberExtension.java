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
import java.math.BigInteger;

import org.dogtagpki.server.ca.ICMSCRLExtension;
import org.mozilla.jss.netscape.security.x509.CRLNumberExtension;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;

import com.netscape.ca.CRLIssuingPoint;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;

/**
 * This represents a CRL number extension.
 *
 * @version $Revision$, $Date$
 */
public class CMSCRLNumberExtension
        implements ICMSCRLExtension, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMSCRLNumberExtension.class);

    public CMSCRLNumberExtension() {
    }

    @Override
    public Extension setCRLExtensionCriticality(Extension ext,
            boolean critical) {
        BigInteger crlNumber = null;
        CRLNumberExtension crlNumberExt = null;

        try {
            crlNumber = (BigInteger)
                    ((CRLNumberExtension) ext).get(CRLNumberExtension.NUMBER);
            crlNumberExt = new CRLNumberExtension(Boolean.valueOf(critical),
                        crlNumber);
        } catch (IOException e) {
            logger.warn(CMS.getLogMessage("CRL_CREATE_CRL_NUMBER_EXT", e.toString()), e);
        }
        return crlNumberExt;
    }

    @Override
    public Extension getCRLExtension(ConfigStore config, Object ip, boolean critical) {
        CRLNumberExtension crlNumberExt = null;
        CRLIssuingPoint crlIssuingPoint = (CRLIssuingPoint) ip;

        try {
            crlNumberExt = new CRLNumberExtension(Boolean.valueOf(critical),
                        crlIssuingPoint.getNextCRLNumber());
        } catch (IOException e) {
            logger.warn(CMS.getLogMessage("CRL_CREATE_CRL_NUMBER_EXT", e.toString()), e);
        }
        return crlNumberExt;
    }

    @Override
    public String getCRLExtOID() {
        return PKIXExtensions.CRLNumber_Id.toString();
    }

    @Override
    public void getConfigParams(ConfigStore config, NameValuePairs nvp) {
    }

    @Override
    public String[] getExtendedPluginInfo() {
        String[] params = {
                //"type;choice(CRLExtension,CRLEntryExtension);"+
                //"CRL Extension type. This field is not editable.",
                "enable;boolean;Check to enable CRL Number extension.",
                "critical;boolean;Set criticality for CRL Number extension.",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ca-edit-crlextension-crlnumber",
                IExtendedPluginInfo.HELP_TEXT +
                        ";The CRL number is a non-critical CRL extension " +
                        "which conveys a monotonically increasing sequence number " +
                        "for each CRL issued by a CA"
            };

        return params;
    }
}
