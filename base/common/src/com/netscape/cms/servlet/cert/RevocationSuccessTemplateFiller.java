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
package com.netscape.cms.servlet.cert;

import java.util.Locale;

import javax.servlet.http.HttpServletRequest;

import netscape.security.x509.RevokedCertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;

/**
 * Certificates Template filler.
 * must have list of certificates in result.
 * looks at inputs: certtype.
 * outputs:
 * - cert type from http input (if any)
 * - CA chain
 * - authority name (RM, CM, DRM)
 * - scheme:host:port of server.
 * array of one or more
 * - cert serial number
 * - cert pretty print
 * - cert in base 64 encoding.
 * - cmmf blob to import
 *
 * @version $Revision$, $Date$
 */
class RevocationSuccessTemplateFiller implements ICMSTemplateFiller {
    public final static String SERIAL_NO = "serialNo";

    public RevocationSuccessTemplateFiller() {
    }

    /**
     * @param cmsReq CMS Request
     * @param authority this authority
     * @param locale locale of template.
     * @param e unexpected exception e. ignored.
     */
    public CMSTemplateParams getTemplateParams(
            CMSRequest cmsReq, IAuthority authority, Locale locale, Exception e)
            throws Exception {
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams params = new CMSTemplateParams(null, fixed);

        // set host name and port.
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        String host = httpReq.getServerName();
        int port = httpReq.getServerPort();
        String scheme = httpReq.getScheme();

        fixed.set(ICMSTemplateFiller.HOST, host);
        fixed.set(ICMSTemplateFiller.PORT, Integer.valueOf(port));
        fixed.set(ICMSTemplateFiller.SCHEME, scheme);

        // this authority
        fixed.set(ICMSTemplateFiller.AUTHORITY, authority.getOfficialName());

        // XXX CA chain.

        RevokedCertImpl[] revoked =
                (RevokedCertImpl[]) cmsReq.getResult();

        // revoked certs.
        for (int i = 0; i < revoked.length; i++) {
            IArgBlock repeat = CMS.createArgBlock();

            repeat.set(SERIAL_NO, revoked[i].getSerialNumber());
            params.addRepeatRecord(repeat);
        }

        return params;
    }
}
