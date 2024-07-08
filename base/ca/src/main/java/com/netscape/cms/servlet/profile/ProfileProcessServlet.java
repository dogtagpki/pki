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
package com.netscape.cms.servlet.profile;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Locale;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileOutput;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.template.ArgList;
import com.netscape.certsrv.template.ArgSet;
import com.netscape.certsrv.template.ArgString;
import com.netscape.cms.servlet.cert.RequestProcessor;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * This servlet approves profile-based request.
 */
@WebServlet(
        name = "caProfileProcess",
        urlPatterns = "/agent/ca/profileProcess",
        initParams = {
                @WebInitParam(name="GetClientCert",        value="true"),
                @WebInitParam(name="AuthzMgr",             value="BasicAclAuthz"),
                @WebInitParam(name="authorityId",          value="ca"),
                @WebInitParam(name="interface",            value="agent"),
                @WebInitParam(name="ID",                   value="caProfileProcess"),
                @WebInitParam(name="unauthorizedTemplate", value="/GenUnauthorized.template"),
                @WebInitParam(name="templatePath",         value="/agent/ca/ProfileProcess.template"),
                @WebInitParam(name="AuthMgr",              value="certUserDBAuthMgr"),
                @WebInitParam(name="resourceID",           value="certServer.ca.request.profile")
        }
)
public class ProfileProcessServlet extends ProfileServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileProcessServlet.class);

    private static final long serialVersionUID = 5244627530516577838L;

    public ProfileProcessServlet() {
    }

    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
    }

    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest request = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();

        Locale locale = getLocale(request);
        ArgSet args = new ArgSet();
        args.set(ARG_ERROR_CODE, "0");
        args.set(ARG_ERROR_REASON, "");

        CAEngine engine = (CAEngine) getCMSEngine();

        RequestProcessor processor = new RequestProcessor("caProfileProcess", locale);
        processor.setCMSEngine(engine);
        processor.init();

        String op = request.getParameter("op");
        logger.debug("ProfileProcessServlet: request operation: " + op);

        if (op == null) {
            logger.error("ProfileProcessServlet: Missing request operation");
            setError(args, CMS.getUserMessage(locale, "CMS_OP_NOT_FOUND"), request, response);
            return;
        }

        String requestId = request.getParameter("requestId");
        logger.debug("ProfileProcessServlet: request ID: " + requestId);

        if (requestId == null || requestId.equals("")) {
            logger.error("ProfileProcessServlet: Missing request ID");
            setError(args, CMS.getUserMessage(locale, "CMS_REQUEST_ID_NOT_FOUND"), request, response);
            return;
        }

        Request req = processor.getRequest(requestId);

        if (req == null) {
            logger.error("ProfileProcessServlet: Request not found: " + requestId);
            setError(args, CMS.getUserMessage(locale, "CMS_REQUEST_NOT_FOUND", CMSTemplate.escapeJavaScriptStringHTML(requestId)), request, response);
            return;
        }

        String profileId = req.getExtDataInString(Request.PROFILE_ID);
        logger.debug("ProfileProcessServlet: profile ID: " + profileId);

        if (profileId == null || profileId.equals("")) {
            logger.error("ProfileProcessServlet: Missing profile ID");
            setError(args, CMS.getUserMessage(locale, "CMS_PROFILE_ID_NOT_FOUND",CMSTemplate.escapeJavaScriptStringHTML(profileId)), request, response);
            return;
        }

        logger.info("ProfileProcessServlet: Processing " + op + " operation for request " + requestId);
        // set request in cmsReq for later retrieval
        cmsReq.setRequest(req);

        CertReviewResponse data = null;
        try {
            data = processor.processRequest(cmsReq, op);

        } catch (ForbiddenException e) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            setError(args, e.getMessage(), request, response);
            return;

        } catch (EAuthException e) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            setError(args, e.getMessage(), request, response);
            return;

        } catch (EAuthzException e) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            setError(args, e.getMessage(), request, response);
            return;

        } catch (BadRequestDataException e) {
            logger.error("ProfileProcessServlet: " + e.getMessage(), e);
            setError(args, e.getMessage(), request, response);
            return;

        } catch (ERejectException e) {
            logger.info("ProfileProcessServlet: Request rejected: " + e.getMessage());
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale, "CMS_PROFILE_REJECTED", e.toString()));

        } catch (EDeferException e) {
            logger.info("ProfileProcessServlet: Request defered: " + e.getMessage());
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale, "CMS_PROFILE_DEFERRED", e.toString()));

        } catch (EPropertyException e) {
            String message = CMS.getUserMessage(locale, "CMS_PROFILE_PROPERTY_ERROR", e.toString());
            logger.error("ProfileProcessServlet: " + message, e);
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, message);

        } catch (EProfileException e) {
            logger.error("ProfileProcessServlet: " + e.getMessage(), e);
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));

        } catch (EBaseException e) {
            logger.error("ProfileProcessServlet: " + e.getMessage(), e);
            setError(args, e.getMessage(), request, response);
            return;
        }

        args.set(ARG_OP, op);
        args.set(ARG_REQUEST_ID, req.getRequestId().toString());
        args.set(ARG_REQUEST_STATUS, req.getRequestStatus().toString());
        args.set(ARG_REQUEST_TYPE, req.getRequestType());
        args.set(ARG_PROFILE_ID, profileId);

        String errorCode = ((ArgString) args.get(ARG_ERROR_CODE)).getValue();

        if (op.equals("approve") && errorCode.equals("0") && (data != null)) {
            ArgList outputlist = new ArgList();
            for (ProfileOutput output: data.getOutputs()) {
                for (ProfileAttribute attr: output.getAttrs()){
                    ArgSet outputset = new ArgSet();
                    IDescriptor desc = attr.getDescriptor();
                    outputset.set(ARG_OUTPUT_ID, attr.getName());
                    outputset.set(ARG_OUTPUT_SYNTAX, desc.getSyntax());
                    outputset.set(ARG_OUTPUT_CONSTRAINT, desc.getConstraint());
                    outputset.set(ARG_OUTPUT_NAME, desc.getDescription(locale));
                    outputset.set(ARG_OUTPUT_VAL, attr.getValue());
                    outputlist.add(outputset);
                }
            }
            args.set(ARG_OUTPUT_LIST, outputlist);
        }

        try {
            String p12Str = req.getExtDataInString("req_issued_p12");
            if (p12Str == null) {
                logger.info("ProfileProcessServlet: No server-side keygen");
                outputTemplate(request, response, args);

            } else {
                logger.info("ProfileProcessServlet: Processing PKCS #12 output for server-side keygen");
                byte[] p12blob = Utils.base64decode(p12Str);

                HttpServletResponse p12_response = cmsReq.getHttpResp();
                p12_response.setContentType("application/x-pkcs12");
                p12_response.setContentLength(p12blob.length);
                p12_response.setHeader("Content-disposition", "attachment; filename="+  "serverKeyGenCert.p12");

                OutputStream bos = p12_response.getOutputStream();
                bos.write(p12blob);
                bos.flush();
                bos.close();
            }

        } catch (IOException e) {
            logger.error("ProfileProcessServlet: Unable to process PKCS #12 output: " + e.getMessage(), e);
            setError(args, e.getMessage(), request, response);
            return;
        }
    }

    private void setError(ArgSet args, String reason, HttpServletRequest request, HttpServletResponse response)
            throws EBaseException {
        args.set(ARG_ERROR_CODE, "1");
        args.set(ARG_ERROR_REASON, reason);
        outputTemplate(request, response, args);
    }
}
