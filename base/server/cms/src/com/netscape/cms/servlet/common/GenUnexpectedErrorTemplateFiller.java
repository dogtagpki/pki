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
import com.netscape.certsrv.common.ICMSRequest;

/**
 * default unexpected error template filler
 *
 * @version $Revision$, $Date$
 */
public class GenUnexpectedErrorTemplateFiller implements ICMSTemplateFiller {

    public GenUnexpectedErrorTemplateFiller() {
    }

    /**
     * fill error details and description if any.
     *
     * @param cmsReq CMS Request
     * @param authority this authority
     * @param locale locale of template.
     * @param e unexpected exception e. ignored.
     */
    public CMSTemplateParams getTemplateParams(
            CMSRequest cmsReq, IAuthority authority, Locale locale, Exception e) {
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams params = new CMSTemplateParams(null, fixed);

        // When an exception occurs the exit is non-local which probably
        // will leave the requestStatus value set to something other
        // than CMSRequest.EXCEPTION, so force the requestStatus to
        // EXCEPTION since it must be that if we're here.
        Integer sts = ICMSRequest.EXCEPTION;
        if (cmsReq != null)
            cmsReq.setStatus(sts);
        fixed.set(ICMSTemplateFiller.REQUEST_STATUS, sts.toString());

        // the unexpected error (exception)
        if (e == null)
            e = new EBaseException(CMS.getLogMessage("BASE_UNKNOWN_ERROR"));
        String errMsg = null;

        if (e instanceof EBaseException)
            errMsg = ((EBaseException) e).toString(locale);
        else
            errMsg = e.toString();
        fixed.set(ICMSTemplateFiller.EXCEPTION, errMsg);

        // this authority
        if (authority != null)
            fixed.set(ICMSTemplateFiller.AUTHORITY,
                    authority.getOfficialName());
        return params;
    }
}
