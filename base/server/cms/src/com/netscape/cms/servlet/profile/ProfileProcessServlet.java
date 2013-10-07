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

import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileOutput;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.template.ArgList;
import com.netscape.certsrv.template.ArgSet;
import com.netscape.certsrv.template.ArgString;
import com.netscape.cms.servlet.cert.RequestProcessor;
import com.netscape.cms.servlet.common.CMSRequest;

/**
 * This servlet approves profile-based request.
 *
 * @version $Revision$, $Date$
 */
public class ProfileProcessServlet extends ProfileServlet {

    private static final long serialVersionUID = 5244627530516577838L;

    public ProfileProcessServlet() {
    }

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
    }

    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest request = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();

        Locale locale = getLocale(request);
        ArgSet args = new ArgSet();
        args.set(ARG_ERROR_CODE, "0");
        args.set(ARG_ERROR_REASON, "");

        RequestProcessor processor = new RequestProcessor("caProfileProcess", locale);

        String op = request.getParameter("op");
        if (op == null) {
            CMS.debug("ProfileProcessServlet: No op found");
            setError(args, CMS.getUserMessage(locale, "CMS_OP_NOT_FOUND"), request, response);
            return;
        }

        String requestId = request.getParameter("requestId");
        if (requestId == null || requestId.equals("")) {
            CMS.debug("ProfileProcessServlet: Request Id not found");
            setError(args, CMS.getUserMessage(locale, "CMS_REQUEST_ID_NOT_FOUND"), request, response);
            return;
        }

        IRequest req = processor.getRequest(requestId);
        if (req == null) {
            setError(args, CMS.getUserMessage(locale, "CMS_REQUEST_NOT_FOUND", requestId), request, response);
            return;
        }

        String profileId = req.getExtDataInString("profileId");
        if (profileId == null || profileId.equals("")) {
            CMS.debug("ProfileProcessServlet: Profile Id not found");
            setError(args, CMS.getUserMessage(locale, "CMS_PROFILE_ID_NOT_FOUND"), request, response);
            return;
        }
        CMS.debug("ProfileProcessServlet: profileId=" + profileId);

        // set request in cmsReq for later retrieval
        cmsReq.setIRequest(req);

        CertReviewResponse data = null;
        try {
            data = processor.processRequest(cmsReq, req, op);

        } catch (ForbiddenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
            setError(args, e.getMessage(), request, response);
            return;
        } catch (EAuthException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
            setError(args, e.getMessage(), request, response);
            return;
        } catch (EAuthzException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
            setError(args, e.getMessage(), request, response);
            return;
        } catch (BadRequestDataException e) {
            setError(args, e.getMessage(), request, response);
            return;
        } catch (ERejectException e) {
            CMS.debug("ProfileProcessServlet: execution rejected " + e.toString());
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale, "CMS_PROFILE_REJECTED", e.toString()));
        } catch (EDeferException e) {
            CMS.debug("ProfileProcessServlet: execution defered " + e.toString());
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale, "CMS_PROFILE_DEFERRED", e.toString()));
        } catch (EPropertyException e) {
            CMS.debug("ProfileProcessServlet: execution error " + e.toString());
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale, "CMS_PROFILE_PROPERTY_ERROR", e.toString()));
        } catch (EProfileException e) {
            CMS.debug("ProfileProcessServlet: execution error " + e.toString());
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
        } catch (EBaseException e) {
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

        outputTemplate(request, response, args);
    }

    private void setError(ArgSet args, String reason, HttpServletRequest request, HttpServletResponse response)
            throws EBaseException {
        args.set(ARG_ERROR_CODE, "1");
        args.set(ARG_ERROR_REASON, reason);
        outputTemplate(request, response, args);
    }
}
