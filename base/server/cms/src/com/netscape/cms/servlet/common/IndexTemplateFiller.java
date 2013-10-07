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
package com.netscape.cms.servlet.common;

import java.util.Locale;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.ISubsystem;

/**
 * A class represents a certificate server kernel. This
 * kernel contains a list of resident subsystems such
 * as logging, security, remote administration. Additional
 * subsystems can be loaded into this kernel by specifying
 * parameters in the configuration store.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class IndexTemplateFiller implements ICMSTemplateFiller {

    // input parameters

    // output parameters
    private final static String OUT_TYPE = "type";
    private final static String OUT_ID = "id";
    private final static String OUT_TOTAL_COUNT = "totalCount";

    public IndexTemplateFiller() {
    }

    public CMSTemplateParams getTemplateParams(
            CMSRequest cmsReq, IAuthority mAuthority, Locale locale, Exception e) {
        IArgBlock header = CMS.createArgBlock();
        IArgBlock ctx = CMS.createArgBlock();
        CMSTemplateParams params = new CMSTemplateParams(header, ctx);

        ISubsystem ca = CMS.getSubsystem("ca");
        ISubsystem ra = CMS.getSubsystem("ra");
        ISubsystem kra = CMS.getSubsystem("kra");
        ISubsystem ocsp = CMS.getSubsystem("ocsp");
        ISubsystem tks = CMS.getSubsystem("tks");

        IArgBlock rarg = null;
        int count = 0;

        if (ca != null) {
            rarg = CMS.createArgBlock();
            rarg.addStringValue(OUT_TYPE, "CertificateAuthority");
            rarg.addStringValue(OUT_ID, "ca");
            params.addRepeatRecord(rarg);
            count++;
        }
        if (ra != null) {
            rarg = CMS.createArgBlock();
            rarg.addStringValue(OUT_TYPE, "RegistrationAuthority");
            rarg.addStringValue(OUT_ID, "ra");
            params.addRepeatRecord(rarg);
            count++;
        }
        if (ocsp != null) {
            rarg = CMS.createArgBlock();
            rarg.addStringValue(OUT_TYPE, "OCSPAuthority");
            rarg.addStringValue(OUT_ID, "ocsp");
            params.addRepeatRecord(rarg);
            count++;
        }
        if (kra != null) {
            rarg = CMS.createArgBlock();
            rarg.addStringValue(OUT_TYPE, "KeyRecoveryAuthority");
            rarg.addStringValue(OUT_ID, "kra");
            params.addRepeatRecord(rarg);
            count++;
        }
        if (tks != null) {
            rarg = CMS.createArgBlock();
            rarg.addStringValue(OUT_TYPE, "TKSAuthority");
            rarg.addStringValue(OUT_ID, "tks");
            params.addRepeatRecord(rarg);
            count++;
        }
        // information about what is selected is provided
        // from the caller. This parameter (selected) is used
        // by header servlet
        try {
            header.addStringValue("selected",
                    cmsReq.getHttpParams().getValueAsString("selected"));
        } catch (EBaseException ex) {
        }
        header.addIntegerValue(OUT_TOTAL_COUNT, count);
        return params;
    }
}
