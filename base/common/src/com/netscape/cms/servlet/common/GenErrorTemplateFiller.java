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

import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;

/**
 * Default error template filler
 *
 * @version $Revision$, $Date$
 */
public class GenErrorTemplateFiller implements ICMSTemplateFiller {
    public GenErrorTemplateFiller() {
    }

    /**
     * fill error details and description if any.
     *
     * @param cmsReq the CMS Request.
     * @param authority the authority
     * @param locale the locale of template.
     * @param e unexpected error. ignored.
     */
    public CMSTemplateParams getTemplateParams(
            CMSRequest cmsReq, IAuthority authority, Locale locale, Exception e) {
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams params = new CMSTemplateParams(null, fixed);

        // request status if any.
        if (cmsReq != null) {
            Integer sts = cmsReq.getStatus();

            if (sts != null)
                fixed.set(ICMSTemplateFiller.REQUEST_STATUS, sts.toString());
        } else {
            CMS.debug("GenErrorTemplateFiller::getTemplateParams() - " +
                       "cmsReq is null!");
            return null;
        }

        // error
        String ex = cmsReq.getError();

        // Changed by beomsuk
        /*if (ex == null)
         ex = new EBaseException(CMS.getLogMessage("BASE_UNKNOWN_ERROR"));
         fixed.set(ICMSTemplateFiller.ERROR, ex.toString(locale));
         */
        if ((ex == null) && (cmsReq.getReason() == null))
            ex = new EBaseException(CMS.getLogMessage("BASE_UNKNOWN_ERROR")).toString();
        else if (ex != null)
            fixed.set(ICMSTemplateFiller.ERROR, ex);
        else if (cmsReq.getReason() != null)
            fixed.set(ICMSTemplateFiller.ERROR, cmsReq.getReason());
        // Change end

        // error description if any.
        Vector<String> descr = cmsReq.getErrorDescr();

        if (descr != null) {
            Enumeration<String> num = descr.elements();

            while (num.hasMoreElements()) {
                String elem = num.nextElement();
                //System.out.println("Setting description "+elem.toString());
                IArgBlock argBlock = CMS.createArgBlock();

                argBlock.set(ICMSTemplateFiller.ERROR_DESCR,
                        elem);
                params.addRepeatRecord(argBlock);
            }
        }

        // this authority
        if (authority != null)
            fixed.set(ICMSTemplateFiller.AUTHORITY,
                    authority.getOfficialName());
        return params;
    }
}
