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


import com.netscape.cms.servlet.common.*;
import com.netscape.cms.servlet.base.*;

import java.math.*;
import java.util.Vector;
import java.io.InputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;

import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.asn1.BIT_STRING;

import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.ocsp.*;
import com.netscape.certsrv.authority.*;
import com.netscape.cmsutil.util.*;
import com.netscape.cms.servlet.*;
import com.netscape.certsrv.apps.*;

import netscape.security.pkcs.*;
import netscape.security.x509.*;
import java.security.cert.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;


/**
 * Show the list of CA's that the OCSP responder can service
 *
 * $Revision: 14561 $ $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class ListCAServlet extends CMSServlet {

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
        mTemplates.remove(CMSRequest.SUCCESS);
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
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
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
        Enumeration recs = defStore.searchAllCRLIssuingPointRecord(100);

        // show the current CRL number if present
        header.addStringValue("stateCount", 
            Integer.toString(defStore.getStateCount()));

        while (recs.hasMoreElements()) {
            ICRLIssuingPointRecord rec = 
                (ICRLIssuingPointRecord) recs.nextElement();
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
            String error = null;

            if (error == null) {
                String xmlOutput = req.getParameter("xml");
                if (xmlOutput != null && xmlOutput.equals("true")) {
                  outputXML(resp, argSet);
                } else {
                  resp.setContentType("text/html");
                  form.renderOutput(out, argSet);
                  cmsReq.setStatus(CMSRequest.SUCCESS);
                }
            } else {
                cmsReq.setStatus(CMSRequest.ERROR);
                //  cmsReq.setError(error);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }
}
