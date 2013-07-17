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

import netscape.security.x509.AlgorithmId;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Display Generic Request detail to the user.
 *
 * @version $Revision$, $Date$
 */
public class ProcessReq extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -6941843162486565610L;
    private final static String SEQNUM = "seqNum";
    private final static String DO_ASSIGN = "doAssign";
    private final static String TPL_FILE = "processReq.template";
    private final static String PROP_PARSER = "parser";

    private IRequestQueue mQueue = null;
    private String mFormPath = null;
    private IReqParser mParser = null;
    private String[] mSigningAlgorithms = null;

    /**
     * Process request.
     */
    public ProcessReq() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "processReq.template" to process the response.
     * The initialization parameter 'parser' is read from the
     * servlet configration, and is used to set the type of request.
     * The value of this parameter can be:
     * <UL>
     * <LI><B>CertReqParser.NODETAIL_PARSER</B> - Show certificate Summary
     * <LI><B>CertReqParser.DETAIL_PARSER</B> - Show certificate detail
     * <LI><B>KeyReqParser.PARSER</B> - Show key archival detail
     * </UL>
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mQueue = mAuthority.getRequestQueue();
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

        String tmp = sc.getInitParameter(PROP_PARSER);

        if (tmp != null) {
            if (tmp.trim().equals("CertReqParser.NODETAIL_PARSER"))
                mParser = CertReqParser.NODETAIL_PARSER;
            else if (tmp.trim().equals("CertReqParser.DETAIL_PARSER"))
                mParser = CertReqParser.DETAIL_PARSER;
            else if (tmp.trim().equals("KeyReqParser.PARSER"))
                mParser = KeyReqParser.PARSER;
        }

        // override success and error templates to null -
        // handle templates locally.
        mTemplates.remove(ICMSRequest.SUCCESS);
        mTemplates.remove(ICMSRequest.ERROR);
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
    public void process(CMSRequest cmsReq) throws EBaseException {
        BigInteger seqNum = BigInteger.ONE.negate();

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        String doAssign = null;
        EBaseException error = null;

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    "Error getting template " + mFormPath + " Error " + e);
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
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
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
                } catch (Exception e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
                }

                if (authzToken == null) {
                    cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
                    return;
                }

                process(argSet, header, seqNum, req, resp,
                        doAssign, locale[0]);
            } else {
                log(ILogger.LL_FAILURE, "Invalid sequence number " + seqNum);
                error = new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_INVALID_REQUEST_ID",
                                String.valueOf(seqNum)));
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
                    cmsReq.setStatus(ICMSRequest.SUCCESS);
                }
            } else {
                cmsReq.setError(error);
                cmsReq.setStatus(ICMSRequest.ERROR);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    "Error getting servlet output stream for rendering template. " +
                            "Error " + e);
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
        return;
    }

    /**
     * Sends request information to the calller.
     * returns whether there was an error or not.
     */
    private void process(CMSTemplateParams argSet, IArgBlock header,
            BigInteger seqNum, HttpServletRequest req,
            HttpServletResponse resp,
            String doAssign, Locale locale)
            throws EBaseException {

        header.addBigIntegerValue("seqNum", seqNum, 10);

        IRequest r = mQueue.findRequest(new RequestId(seqNum));

        if (r != null) {
            if (doAssign != null) {
                if ((doAssign.equals("toMe"))
                        || (doAssign.equals("reassignToMe"))) {
                    SessionContext ctx = SessionContext.getContext();
                    String id = (String) ctx.get(SessionContext.USER_ID);

                    r.setRequestOwner(id);
                    mQueue.updateRequest(r);
                } else if (doAssign.equals("reassignToNobody")) {
                    r.setRequestOwner(null);
                    mQueue.updateRequest(r);
                }
            }

            // add authority names to know what privileges can be requested.
            if (CMS.getSubsystem("kra") != null)
                header.addStringValue("localkra", "yes");
            if (CMS.getSubsystem("ca") != null)
                header.addStringValue("localca", "yes");
            if (CMS.getSubsystem("ra") != null)
                header.addStringValue("localra", "yes");

            // DONT NEED TO DO THIS FOR DRM
            if (mAuthority instanceof ICertAuthority) {
                // Check/set signing algorithms dynamically.
                // In RA mSigningAlgorithms could be null at startup if CA is not
                // up and set later when CA comes back up.
                // Once it's set assumed that it won't change.
                String[] allAlgorithms = mSigningAlgorithms;

                if (allAlgorithms == null) {
                    allAlgorithms = mSigningAlgorithms =
                                    ((ICertAuthority) mAuthority).getCASigningAlgorithms();
                    if (allAlgorithms == null) {
                        CMS.debug(
                                "ProcessReq: signing algorithms set to All algorithms");
                        allAlgorithms = AlgorithmId.ALL_SIGNING_ALGORITHMS;
                    } else
                        CMS.debug(
                                "ProcessReq: First signing algorithms is " + allAlgorithms[0]);
                }
                String validAlgorithms = null;
                StringBuffer sb = new StringBuffer();
                for (int i = 0; i < allAlgorithms.length; i++) {
                    if (i > 0) {
                        sb.append("+");
                        sb.append(allAlgorithms[i]);
                    } else {
                        sb.append(allAlgorithms[i]);
                    }
                }
                validAlgorithms = sb.toString();
                if (validAlgorithms != null)
                    header.addStringValue("validAlgorithms", validAlgorithms);
                if (mAuthority instanceof ICertificateAuthority) {
                    String signingAlgorithm = ((ICertificateAuthority) mAuthority).getDefaultAlgorithm();

                    if (signingAlgorithm != null)
                        header.addStringValue("caSigningAlgorithm", signingAlgorithm);
                    header.addLongValue("defaultValidityLength",
                            ((ICertificateAuthority) mAuthority).getDefaultValidity() / 1000);
                } else if (mAuthority instanceof IRegistrationAuthority) {
                    header.addLongValue("defaultValidityLength",
                            ((IRegistrationAuthority) mAuthority).getDefaultValidity() / 1000);
                }
                X509CertImpl caCert = ((ICertAuthority) mAuthority).getCACert();

                if (caCert != null) {
                    int caPathLen = caCert.getBasicConstraints();

                    header.addIntegerValue("caPathLen", caPathLen);
                }
            }

            mParser.fillRequestIntoArg(locale, r, argSet, header);
        } else {
            log(ILogger.LL_FAILURE, "Invalid sequence number " + seqNum.toString());
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_INVALID_REQUEST_ID",
                            seqNum.toString()));
        }

        return;
    }
}
