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

import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.base.ArgBlock;

/**
 * default Service Pending template filler
 *
 * @version $Revision$, $Date$
 */
public class GenRejectedTemplateFiller implements ICMSTemplateFiller {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GenRejectedTemplateFiller.class);

    public final static String POLICY_MESSAGE = "policyMessage";

    public GenRejectedTemplateFiller() {
    }

    /**
     * @param cmsReq CMS Request
     * @param authority this authority
     * @param locale locale of template.
     * @param e unexpected exception e. ignored.
     */
    public CMSTemplateParams getTemplateParams(
            CMSRequest cmsReq, IAuthority authority, Locale locale, Exception e) {
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams params = new CMSTemplateParams(null, fixed);

        // request status if any.
        if (cmsReq != null) {
            Integer sts = cmsReq.getStatus();

            if (sts != null)
                fixed.set(ICMSTemplateFiller.REQUEST_STATUS, sts.toString());
        } else {
            logger.warn("GenRejectedTemplateFiller::getTemplateParams() - cmsReq is null!");
            return null;
        }

        // request id
        IRequest req = cmsReq.getIRequest();

        if (req != null) {
            fixed.set(ICMSTemplateFiller.REQUEST_ID, req.getRequestId());

            // policy errors (rejection reasons)
            Vector<String> messages = req.getExtDataInStringVector(IRequest.ERRORS);

            if (messages != null) {
                Enumeration<String> msgs = messages.elements();

                while (msgs.hasMoreElements()) {
                    String ex = msgs.nextElement();
                    ArgBlock messageArgBlock = new ArgBlock();

                    messageArgBlock.set(POLICY_MESSAGE, ex);
                    params.addRepeatRecord(messageArgBlock);
                }
            }
        }

        // this authority

        if (authority != null)
            fixed.set(ICMSTemplateFiller.AUTHORITY,
                    authority.getOfficialName());
        return params;
    }
}
