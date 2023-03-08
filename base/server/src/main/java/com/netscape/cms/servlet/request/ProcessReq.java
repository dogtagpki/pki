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
package com.netscape.cms.servlet.request;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;

import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.request.Request;

/**
 * Display Generic Request detail to the user.
 *
 * @version $Revision$, $Date$
 */
public class ProcessReq extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProcessReq.class);

    protected final static String SEQNUM = "seqNum";
    protected final static String DO_ASSIGN = "doAssign";
    protected final static String TPL_FILE = "processReq.template";
    protected final static String PROP_PARSER = "parser";

    protected String mFormPath;
    protected ReqParser mParser;

    /**
     * Process request.
     */
    public ProcessReq() {
    }

    /**
     * Initialize the servlet. This servlet uses the template file
     * "processReq.template" to process the response.
     * The initialization parameter 'parser' is read from the
     * servlet configuration, and is used to set the type of request.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {

        super.init(sc);

        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

        // override success and error templates to null -
        // handle templates locally.
        mTemplates.remove(CMSRequest.SUCCESS);
        mTemplates.remove(CMSRequest.ERROR);
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param seqNum
     * <li>http.param doAssign reassign request. Value can be reassignToMe reassignToNobody
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {
        BigInteger seqNum = BigInteger.ONE.negate();

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        AuthToken authToken = authenticate(cmsReq);

        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        String doAssign = null;
        EBaseException error = null;

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            logger.error("ProcessReq: Unable to get template " + mFormPath + ": " + e.getMessage(), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }

        try {
            if (req.getParameter(SEQNUM) != null) {
                seqNum = new BigInteger(req.getParameter(SEQNUM));
            }
            doAssign = req.getParameter(DO_ASSIGN);

            if (seqNum.compareTo(BigInteger.ONE.negate()) > 0) {
                // start authorization
                AuthzToken authzToken = null;

                try {
                    if (doAssign == null) {
                        authzToken = authorize(mAclMethod, authToken,
                                    mAuthzResourceName, "read");
                    } else if (doAssign.equals("toMe") ||
                            doAssign.equals("reassignToMe")) {
                        authzToken = authorize(mAclMethod, authToken,
                                    mAuthzResourceName, "assign");
                    } else if (doAssign.equals("reassignToNobody")) {
                        authzToken = authorize(mAclMethod, authToken,
                                    mAuthzResourceName, "unassign");
                    }
                } catch (EAuthzAccessDenied e) {
                    logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);

                } catch (Exception e) {
                    logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
                }

                if (authzToken == null) {
                    cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
                    return;
                }

                process(argSet, header, seqNum, req, resp,
                        doAssign, locale[0]);
            } else {
                logger.warn("ProcessReq: Invalid sequence number " + seqNum);
                error = new ECMSGWException(CMS.getUserMessage("CMS_GW_INVALID_REQUEST_ID", String.valueOf(seqNum)));
            }
        } catch (EBaseException e) {
            error = e;
        } catch (NumberFormatException e) {
            error = new EBaseException(CMS.getUserMessage(locale[0], "CMS_BASE_INVALID_NUMBER_FORMAT"));
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

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
                cmsReq.setError(error);
                cmsReq.setStatus(CMSRequest.ERROR);
            }
        } catch (IOException e) {
            logger.error("ProcessReq: Error getting servlet output stream for rendering template: " + e.getMessage(), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }
    }

    public void addAuthorityName(ArgBlock header) throws EBaseException {
    }

    public void addSigningAlgorithm(ArgBlock header) throws EBaseException {
    }

    /**
     * Sends request information to the calller.
     * returns whether there was an error or not.
     */
    private void process(CMSTemplateParams argSet, ArgBlock header,
            BigInteger seqNum, HttpServletRequest req,
            HttpServletResponse resp,
            String doAssign, Locale locale)
            throws EBaseException {

        header.addBigIntegerValue("seqNum", seqNum, 10);

        Request r = requestRepository.readRequest(new RequestId(seqNum));

        if (r != null) {
            if (doAssign != null) {
                if ((doAssign.equals("toMe"))
                        || (doAssign.equals("reassignToMe"))) {
                    SessionContext ctx = SessionContext.getContext();
                    String id = (String) ctx.get(SessionContext.USER_ID);

                    r.setRequestOwner(id);
                    requestRepository.updateRequest(r);
                } else if (doAssign.equals("reassignToNobody")) {
                    r.setRequestOwner(null);
                    requestRepository.updateRequest(r);
                }
            }

            // add authority names to know what privileges can be requested.
            addAuthorityName(header);
            addSigningAlgorithm(header);

            mParser.fillRequestIntoArg(locale, r, argSet, header);
        } else {
            logger.error("ProcessReq: Invalid sequence number " + seqNum.toString());
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_INVALID_REQUEST_ID", seqNum.toString()));
        }
    }
}
