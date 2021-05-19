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
package com.netscape.cms.servlet.key;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authorization.AuthzToken;
import org.mozilla.jss.netscape.security.x509.X500Name;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * Retrieve archived keys matching search criteria
 *
 * @version $Revision$, $Date$
 */
public class SrchKey extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SrchKey.class);
    private static final long serialVersionUID = -6404955402865756665L;
    private final static String TPL_FILE = "srchKey.template";
    private final static String INFO = "srchKey";
    private final static String PROP_MAX_SEARCH_RETURNS = "maxSearchReturns";

    // input parameters
    private final static String IN_MAXCOUNT = "maxCount";
    private final static String IN_FILTER = "queryFilter";
    private final static String IN_SENTINEL = "querySentinel";
    private final static String REALM = "realm";

    // output parameters
    private final static String OUT_FILTER = IN_FILTER;
    private final static String OUT_MAXCOUNT = IN_MAXCOUNT;
    private final static String OUT_SENTINEL = IN_SENTINEL;
    private final static String OUT_OP = "op";
    private final static String OUT_ERROR = "errorDetails";
    private final static String OUT_ARCHIVER = "archiverName";
    private final static String OUT_SERVICE_URL = "serviceURL";
    private final static String OUT_TOTAL_COUNT = "totalRecordCount";
    private final static String OUT_TEMPLATE = "templateName";

    private KeyRepository mKeyDB;
    private X500Name mAuthName = null;
    private String mFormPath = null;
    private int mMaxReturns = 100;
    private int mTimeLimits = 30; /* in seconds */

    /**
     * Constructs query key servlet.
     */
    public SrchKey() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "srchKey.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

        /* maxReturns doesn't seem to do anything useful in this
           servlet!!! */
        try {
            String tmp =
                    sc.getInitParameter(PROP_MAX_SEARCH_RETURNS);

            if (tmp == null)
                mMaxReturns = 100;
            else
                mMaxReturns = Integer.parseInt(tmp);
        } catch (Exception e) {
            // do nothing
        }

        mKeyDB = ((KeyRecoveryAuthority) mAuthority).getKeyRepository();
        mAuthName = ((KeyRecoveryAuthority) mAuthority).getX500Name();

        mTemplates.remove(ICMSRequest.SUCCESS);
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;

        /* Server-Side time limit */
        try {
            mTimeLimits = Integer.parseInt(sc.getInitParameter("timeLimits"));
        } catch (Exception e) {
            /* do nothing, just use the default if integer parsing failed */
        }
    }

    /**
     * Returns serlvet information.
     */
    @Override
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param maxCount maximum number of matches to show in result
     * <li>http.param maxResults maximum number of matches to run in ldapsearch
     * <li>http.param queryFilter ldap-style filter to search with
     * <li>http.param querySentinel ID of first request to show
     * <li>http.param timeLimit number of seconds to limit ldap search to
     * <li>http.param realm authorization realm to search
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "list");
        } catch (EAuthzAccessDenied e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);

        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        String realm = req.getParameter(REALM);
        try {
            mAuthz.checkRealm(realm, authToken, null, mAuthzResourceName, "list");

        } catch (EAuthzException e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;

        } catch (EBaseException e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            cmsReq.setStatus(ICMSRequest.EXCEPTION);
            return;
        }


        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        // process query if authentication is successful
        ArgBlock header = new ArgBlock();
        ArgBlock ctx = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        int maxCount = -1;
        int sentinel = 0;
        int maxResults = -1;
        int timeLimit = -1;

        try {
            if (req.getParameter(IN_MAXCOUNT) != null) {
                maxCount = Integer.parseInt(
                            req.getParameter(IN_MAXCOUNT));
            }
            if (req.getParameter(IN_SENTINEL) != null) {
                sentinel = Integer.parseInt(
                            req.getParameter(IN_SENTINEL));
            }
            String maxResultsStr = req.getParameter("maxResults");

            if (maxResultsStr != null && maxResultsStr.length() > 0)
                maxResults = Integer.parseInt(maxResultsStr);
            String timeLimitStr = req.getParameter("timeLimit");

            if (timeLimitStr != null && timeLimitStr.length() > 0)
                timeLimit = Integer.parseInt(timeLimitStr);

            process(argSet, header, ctx, maxCount, maxResults,
                    timeLimit, sentinel,
                    req.getParameter(IN_FILTER), req, resp, locale[0], realm);
        } catch (NumberFormatException e) {
            header.addStringValue(OUT_ERROR,
                    CMS.getUserMessage(locale[0], "CMS_BASE_INTERNAL_ERROR", e.toString()));
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

            resp.setContentType("text/html");
            form.renderOutput(out, argSet);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
        cmsReq.setStatus(ICMSRequest.SUCCESS);
    }

    /**
     * Process the key search.
     */
    private void process(CMSTemplateParams argSet,
            IArgBlock header, IArgBlock ctx,
            int maxCount, int maxResults, int timeLimit, int sentinel, String filter,
            HttpServletRequest req, HttpServletResponse resp, Locale locale, String realm) {

        try {
            if (filter.contains("(realm=")) {
                throw new EBaseException("Query filter cannot contain realm");
            }

            if (realm != null) {
                filter = "(&" + filter + "(realm=" + LDAPUtil.escapeFilter(realm) +"))";
            } else {
                filter = "(&" + filter + "(!(realm=*)))";
            }

            // Fill header
            header.addStringValue(OUT_OP,
                    req.getParameter(OUT_OP));
            header.addStringValue(OUT_ARCHIVER,
                    mAuthName.toString());
            // STRANGE: IE does not like the following:
            //      header.addStringValue(OUT_SERVICE_URL,
            //	req.getRequestURI());
            // XXX
            header.addStringValue(OUT_SERVICE_URL,
                    "/kra?");
            header.addStringValue(OUT_TEMPLATE,
                    TPL_FILE);
            header.addStringValue(OUT_FILTER,
                    filter);

            if (timeLimit == -1 || timeLimit > mTimeLimits) {
                logger.debug("Resetting timelimit from " + timeLimit + " to " + mTimeLimits);
                timeLimit = mTimeLimits;
            }

            logger.debug("Start searching ... timelimit=" + timeLimit);
            Enumeration<IKeyRecord> e = mKeyDB.searchKeys(filter,
                    maxResults, timeLimit);
            int count = 0;

            if (e == null) {
                header.addStringValue(OUT_SENTINEL,
                        null);
            } else {
                while (e.hasMoreElements()) {
                    IKeyRecord rec = e.nextElement();
                    // rec is null when we specify maxResults
                    // DS will return an err=4, which triggers
                    // a LDAPException.SIZE_LIMIT_ExCEEDED
                    // in DSSearchResults.java
                    if (rec != null) {
                        ArgBlock rarg = new ArgBlock();

                        KeyRecordParser.fillRecordIntoArg(rec, rarg);
                        argSet.addRepeatRecord(rarg);
                        count++;
                    }
                }
            }

            header.addIntegerValue("maxSize", mMaxReturns);
            header.addIntegerValue(OUT_TOTAL_COUNT, count);
            ctx.addIntegerValue(OUT_MAXCOUNT, maxCount);
        } catch (EBaseException e) {
            header.addStringValue(OUT_ERROR, e.toString(locale));
        }
    }
}
