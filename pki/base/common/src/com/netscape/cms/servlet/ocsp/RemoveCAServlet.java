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

import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.ocsp.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;
import com.netscape.cms.servlet.*;
import com.netscape.cmsutil.util.*;

import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;


/**
 * Configure the CA to no longer respond to OCSP requests for a CA
 *
 * @version $Revision: 1274 $ $Date: 2010-09-07 22:14:41 -0700 (Tue, 07 Sep 2010) $
 */
public class RemoveCAServlet extends CMSServlet {

    private final static String TPL_FILE = "removeCA.template";
    private String mFormPath = null;
    private IOCSPAuthority mOCSPAuthority = null;

    private final static String LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST =
        "LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_3";
    private final static String LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_SUCCESS =
        "LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_SUCCESS_3";

    private final static String LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_FAILURE =
        "LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_FAILURE_3";

    public RemoveCAServlet() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "addCA.template" to process the response.
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
     * <ul>
     * <li>http.param  ca id. The format is string.
     * <li>signed.audit LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST used when
     * a CA is attempted to be removed from the OCSP responder
     * <li>signed.audit LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_SUCCESS
     * and LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_FAILURE are used when 
     * a remove CA request to the OCSP Responder is processed successfully or not.
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq)
        throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditCA = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        String auditCASubjectDN = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "add");
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

        if (auditSubjectID.equals(ILogger.NONROLEUSER) ||
               auditSubjectID.equals(ILogger.UNIDENTIFIED))  {
            String uid = authToken.getInString(IAuthToken.USER_ID);
            if (uid != null) {
                CMS.debug("RemoveCAServlet: auditSubjectID set to "+uid);
                auditSubjectID = uid;
            }
        }

       String caID = cmsReq.getHttpReq().getParameter("caID");


       if (caID == null) {
           auditMessage = CMS.getLogMessage(
               LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_FAILURE,
               auditSubjectID,
               ILogger.FAILURE,
               ILogger.SIGNED_AUDIT_EMPTY_VALUE);

           throw new ECMSGWException(CMS.getUserMessage(getLocale(req), "CMS_GW_MISSING_CA_ID"));
       }

       auditMessage = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST,
                auditSubjectID,
                ILogger.SUCCESS,
                caID);

       audit( auditMessage );

       IDefStore defStore = mOCSPAuthority.getDefaultStore();

       try { 
        defStore.deleteCRLIssuingPointRecord(caID);

       } catch (EBaseException e) {

           auditMessage = CMS.getLogMessage(
               LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_FAILURE,
               auditSubjectID,
               ILogger.FAILURE,
               caID);
           audit( auditMessage );

           CMS.debug("RemoveCAServlet::process: Error deleting CRL IssuingPoint: " + caID);
           throw new EBaseException(e.toString());
        }

        CMS.debug("RemoveCAServlet::process: CRL IssuingPoint for CA successfully removed: " + caID);

        auditMessage = CMS.getLogMessage(
             LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_SUCCESS,
             auditSubjectID,
             ILogger.SUCCESS,
             caID);
        audit( auditMessage );

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
