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


import com.netscape.cms.servlet.common.*;
import com.netscape.cms.servlet.base.*;
import java.io.*;
import java.util.*;
import java.net.*;
import java.util.*;
import java.text.*;
import java.math.*;
import java.security.*;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.security.x509.*;
import netscape.security.provider.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.authority.*;
import com.netscape.cms.servlet.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;
import com.netscape.certsrv.request.*;


/**
 * XXX Search for certificates matching complex query filter
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class SearchReqs extends CMSServlet {

    private final static String TPL_FILE = "queryReq.template";
    private final static String INFO = "QueryReq";
    private final static String PROP_MAX_SEARCH_RETURNS = "maxSearchReqReturns";
    private final static String PROP_PARSER = "parser";
    private final static String CURRENT_TIME = "currentTime";
    private final static BigInteger MINUS_ONE = new BigInteger("-1");
    private final static String OUT_AUTHORITY_ID = "authorityid";
    private final static String OUT_REQUESTING_USER = "requestingUser";
    private final static String OUT_SEQNUM_FROM = "seqNumFrom";
    private final static String OUT_MAXCOUNT = "maxCount";
    private final static String OUT_TOTALCOUNT = "totalRecordCount";
    private final static String OUT_CURRENTCOUNT = "currentRecordCount";
    private final static String OUT_SENTINEL = "querySentinel";
    private final static String OUT_ERROR = "error";

    private IRequestQueue mQueue = null;
    private IReqParser mParser = null;
    private String mFormPath = null;
    private int mMaxReturns = 100;
    private int mTimeLimits = 30; /* in seconds */

    /**
     * Constructs query key servlet.
     */
    public SearchReqs() {
        super();
    }

    /**
	 * initialize the servlet. This servlet uses queryReq.template
	 * to render the response
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success to render own template.
        mTemplates.remove(CMSRequest.SUCCESS);

        if (mAuthority instanceof ISubsystem) {
            ISubsystem sub = (ISubsystem) mAuthority;
            IConfigStore authConfig = sub.getConfigStore();

            if (authConfig != null) {
                try {
                    mMaxReturns = authConfig.getInteger(PROP_MAX_SEARCH_RETURNS, 100);
                } catch (EBaseException e) {
                    // do nothing
                }
            }
        }
        if (mAuthority instanceof ICertificateAuthority) {
            ICertificateAuthority ca = (ICertificateAuthority) mAuthority;
            mQueue = ca.getRequestQueue();
        }

        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

        /* Server-Side time limit */
        try {
            int maxResults = Integer.parseInt(sc.getInitParameter("maxResults"));
            if (maxResults < mMaxReturns)
                mMaxReturns = maxResults;
        } catch (Exception e) {
            /* do nothing, just use the default if integer parsing failed */
        }
        try {
            mTimeLimits = Integer.parseInt(sc.getInitParameter("timeLimits"));
        } catch (Exception e) {
            /* do nothing, just use the default if integer parsing failed */
        }

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
        mTemplates.remove(CMSRequest.SUCCESS);
        mTemplates.remove(CMSRequest.ERROR);

        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Serves HTTP request. This format of this request is as follows:
     *   queryCert?
     *     [maxCount=<number>]
     *     [queryFilter=<filter>]
     *     [revokeAll=<filter>]
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "list");
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        String revokeAll = null;
        EBaseException error = null;
        int maxResults = -1;
        int timeLimit = -1;

        IArgBlock header = CMS.createArgBlock();
        IArgBlock ctx = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", e.toString()));
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        try {
            String maxResultsStr = req.getParameter("maxResults");

            if (maxResultsStr != null && maxResultsStr.length() > 0)
                maxResults = Integer.parseInt(maxResultsStr);
            String timeLimitStr = req.getParameter("timeLimit");

            if (timeLimitStr != null && timeLimitStr.length() > 0)
                timeLimit = Integer.parseInt(timeLimitStr);

            process(argSet, header, req.getParameter("queryRequestFilter"), authToken,
                maxResults, timeLimit, req, resp, locale[0]);
        } catch (NumberFormatException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("BASE_INVALID_NUMBER_FORMAT"));
            error = new EBaseException(CMS.getUserMessage(getLocale(req),"CMS_BASE_INVALID_NUMBER_FORMAT"));
        } catch (EBaseException e) {
            error = e;
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

            if (error == null) {
                String xmlOutput = req.getParameter("xml");
                if (xmlOutput != null && xmlOutput.equals("true")) {
                  outputXML(resp, argSet);
                } else {
                  cmsReq.setStatus(CMSRequest.SUCCESS);
                  resp.setContentType("text/html");
                  form.renderOutput(out, argSet);
                }
            } else {
                cmsReq.setStatus(CMSRequest.ERROR);
                cmsReq.setError(error);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }

    /**
     * Process the key search.
     */
    private void process(CMSTemplateParams argSet, IArgBlock header, 
        String filter, IAuthToken token,
        int maxResults, int timeLimit,
        HttpServletRequest req, HttpServletResponse resp,
        Locale locale)
        throws EBaseException {

        try {
            long startTime = CMS.getCurrentDate().getTime();

            if (filter.indexOf(CURRENT_TIME, 0) > -1) {
                filter = insertCurrentTime(filter);
            }

            String owner = req.getParameter("owner");
            String requestowner_filter = "";
            if (owner.equals("self")) {
                String self_uid = token.getInString(IAuthToken.USER_ID);
                requestowner_filter = "(requestowner="+self_uid+")";
            } else {
                String uid = req.getParameter("uid");
                requestowner_filter = "(requestowner="+uid+")";
            }
            String newfilter = "(&"+requestowner_filter+filter.substring(2);
            // xxx the filter includes serial number range???
            if (maxResults == -1 || maxResults > mMaxReturns) {
                CMS.debug("Resetting maximum of returned results from " + maxResults + " to " + mMaxReturns);
                maxResults = mMaxReturns;
            }
            if (timeLimit == -1 || timeLimit > mTimeLimits) {
                CMS.debug("Resetting timelimit from " + timeLimit + " to " + mTimeLimits);
                timeLimit = mTimeLimits;
            }
            IRequestList list = (timeLimit > 0) ?
                mQueue.listRequestsByFilter(newfilter, maxResults, timeLimit) :
                mQueue.listRequestsByFilter(newfilter, maxResults);

            int count = 0;

            while (list != null && list.hasMoreElements()) {
                IRequest request = (IRequest) list.nextRequestObject();

                if (request != null) {
                    count++;
                    IArgBlock rarg = CMS.createArgBlock();
                    mParser.fillRequestIntoArg(locale, request, argSet, rarg);
                    argSet.addRepeatRecord(rarg);
                    long endTime = CMS.getCurrentDate().getTime();

                    header.addIntegerValue(OUT_CURRENTCOUNT, count);
                    header.addStringValue("time", Long.toString(endTime - startTime));
                }
            }
            header.addIntegerValue(OUT_TOTALCOUNT, count);
        } catch (EBaseException e) {
            CMS.getLogMessage("CMSGW_ERROR_LISTCERTS", e.toString());
            throw e;
        }
        return;
    }

    private String insertCurrentTime(String filter) {
        Date now = null;
        StringBuffer newFilter = new StringBuffer();
        int k = 0;
        int i = filter.indexOf(CURRENT_TIME, k);

        while (i > -1) {
            if (now == null) now = new Date();
            newFilter.append(filter.substring(k, i));
            newFilter.append(now.getTime());
            k = i + CURRENT_TIME.length();
            i = filter.indexOf(CURRENT_TIME, k);
        }
        if (k > 0) {
            newFilter.append(filter.substring(k, filter.length()));
        }
        return newFilter.toString();
    }
}
