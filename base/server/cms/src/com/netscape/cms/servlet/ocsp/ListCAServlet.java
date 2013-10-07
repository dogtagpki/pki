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
package com.netscape.cms.servlet.ocsp;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Show the list of CA's that the OCSP responder can service
 *
 * @version $Revision$ $Date$
 */
public class ListCAServlet extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = 3764395161795483452L;
    public static final String BEGIN_HEADER =
            "-----BEGIN CERTIFICATE-----";
    public static final String END_HEADER =
            "-----END CERTIFICATE-----";

    private final static String TPL_FILE = "listCAs.template";
    private String mFormPath = null;
    private IOCSPAuthority mOCSPAuthority = null;

    public ListCAServlet() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "listCAs.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success to display own output.

        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
        mTemplates.remove(ICMSRequest.SUCCESS);
        mOCSPAuthority = (IOCSPAuthority) mAuthority;
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Process the HTTP request.
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "list");
        } catch (Exception e) {
            // do nothing for now
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        IDefStore defStore = mOCSPAuthority.getDefaultStore();
        Enumeration<ICRLIssuingPointRecord> recs = defStore.searchAllCRLIssuingPointRecord(100);

        // show the current CRL number if present
        header.addStringValue("stateCount",
                Integer.toString(defStore.getStateCount()));

        while (recs.hasMoreElements()) {
            ICRLIssuingPointRecord rec = recs.nextElement();
            IArgBlock rarg = CMS.createArgBlock();
            String thisId = rec.getId();

            rarg.addStringValue("Id", thisId);
            Date thisUpdate = rec.getThisUpdate();

            if (thisUpdate == null) {
                rarg.addStringValue("ThisUpdate", "UNKNOWN");
            } else {
                rarg.addStringValue("ThisUpdate", thisUpdate.toString());
            }
            Date nextUpdate = rec.getNextUpdate();

            if (nextUpdate == null) {
                rarg.addStringValue("NextUpdate", "UNKNOWN");
            } else {
                rarg.addStringValue("NextUpdate", nextUpdate.toString());
            }
            Long rc = rec.getCRLSize();

            if (rc == null) {
                rarg.addLongValue("NumRevoked", 0);
            } else {
                if (rc.longValue() == -1) {
                    rarg.addStringValue("NumRevoked", "UNKNOWN");
                } else {
                    rarg.addLongValue("NumRevoked", rc.longValue());
                }
            }

            BigInteger crlNumber = rec.getCRLNumber();
            if (crlNumber == null || crlNumber.equals(new BigInteger("-1"))) {
                rarg.addStringValue("CRLNumber", "UNKNOWN");
            } else {
                rarg.addStringValue("CRLNumber", crlNumber.toString());
            }

            rarg.addLongValue("ReqCount", defStore.getReqCount(thisId));
            argSet.addRepeatRecord(rarg);
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

            String xmlOutput = req.getParameter("xml");
            if (xmlOutput != null && xmlOutput.equals("true")) {
                outputXML(resp, argSet);
            } else {
                resp.setContentType("text/html");
                form.renderOutput(out, argSet);
                cmsReq.setStatus(ICMSRequest.SUCCESS);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }
}
