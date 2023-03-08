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
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;

import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.IRequestVirtualList;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRepository;

/**
 * Show paged list of requests matching search criteria.
 */
public class QueryReq extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(QueryReq.class);

    // constants
    protected final static String IN_SHOW_ALL = "showAll";
    protected final static String IN_SHOW_WAITING = "showWaiting";
    protected final static String IN_SHOW_IN_SERVICE = "showInService";
    protected final static String IN_SHOW_PENDING = "showPending";
    protected final static String IN_SHOW_CANCELLED = "showCancelled";
    protected final static String IN_SHOW_REJECTED = "showRejected";
    protected final static String IN_SHOW_COMPLETED = "showCompleted";
    protected final static String IN_MAXCOUNT = "maxCount";
    protected final static String IN_TOTALCOUNT = "totalRecordCount";
    protected final static String PROP_PARSER = "parser";
    protected final static String REALM = "realm";

    protected final static String TPL_FILE = "queryReq.template";

    protected final static String OUT_TOTALCOUNT = IN_TOTALCOUNT;
    protected final static String OUT_CURRENTCOUNT = "currentRecordCount";
    protected final static String OUT_REQUESTING_USER = "requestingUser";
    //keeps track of where to begin if page down
    protected final static String OUT_FIRST_ENTRY_ON_PAGE = "firstEntryOnPage";
    //keeps track of where to begin if page up
    protected final static String OUT_LAST_ENTRY_ON_PAGE = "lastEntryOnPage";
    protected final static String OUT_ERROR = "error";
    protected final static String OUT_AUTHORITY_ID = "authorityid";

    // variables
    protected ReqParser mParser;
    protected RequestQueue mQueue;
    protected String mFormPath;
    protected int mMaxReturns = 2000;

    @Override
    public CMSRequest newCMSRequest() {
        return new CMSRequest();
    }

    /**
     * Constructor
     */
    public QueryReq() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "queryReq.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {

        super.init(sc);

        CMSEngine engine = getCMSEngine();
        mQueue = engine.getRequestQueue();
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

        try {
            mMaxReturns = Integer.parseInt(sc.getInitParameter("maxResults"));
        } catch (Exception e) {
            /* do nothing, just use the default if integer parsing failed */
        }

        // override success and error templates to null -
        // handle templates locally.
        mTemplates.remove(CMSRequest.SUCCESS);
        mTemplates.remove(CMSRequest.ERROR);

        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    protected String getRequestType(String p) {
        String filter = "(requestType=*)";

        if (p == null)
            return filter;
        if (p.equals(Request.ENROLLMENT_REQUEST)) {
            filter = "(requestType=" + Request.ENROLLMENT_REQUEST + ")";
        } else if (p.equals(Request.RENEWAL_REQUEST)) {
            filter = "(requestType=" + Request.RENEWAL_REQUEST + ")";
        } else if (p.equals(Request.REVOCATION_REQUEST)) {
            filter = "(requestType=" + Request.REVOCATION_REQUEST + ")";
        } else if (p.equals(Request.UNREVOCATION_REQUEST)) {
            filter = "(requestType=" + Request.UNREVOCATION_REQUEST + ")";
        } else if (p.equals(Request.KEYARCHIVAL_REQUEST)) {
            filter = "(requestType=" + Request.KEYARCHIVAL_REQUEST + ")";
        } else if (p.equals(Request.KEYRECOVERY_REQUEST)) {
            filter = "(requestType=" + Request.KEYRECOVERY_REQUEST + ")";
        } else if (p.equals(Request.GETCACHAIN_REQUEST)) {
            filter = "(requestType=" + Request.GETCACHAIN_REQUEST + ")";
        } else if (p.equals(Request.GETREVOCATIONINFO_REQUEST)) {
            filter = "(requestType=" + Request.GETREVOCATIONINFO_REQUEST + ")";
        } else if (p.equals(Request.GETCRL_REQUEST)) {
            filter = "(requestType=" + Request.GETCRL_REQUEST + ")";
        } else if (p.equals(Request.GETCERTS_REQUEST)) {
            filter = "(requestType=" + Request.GETCERTS_REQUEST + ")";
        } else if (p.equals(Request.NETKEY_KEYGEN_REQUEST)) {
            filter = "(requestType=" + Request.NETKEY_KEYGEN_REQUEST + ")";
        } else if (p.equals(Request.NETKEY_KEYRECOVERY_REQUEST)) {
            filter = "(requestType=" + Request.NETKEY_KEYRECOVERY_REQUEST + ")";
        } else if (p.equals(IN_SHOW_ALL)) {
            filter = "(requestType=*)";
        }
        return filter;
    }

    protected String getRequestState(String p) {
        String filter = "(requeststate=*)";

        if (p == null)
            return filter;
        if (p.equals(IN_SHOW_WAITING)) {
            filter = "(requeststate=pending)";
        } else if (p.equals(IN_SHOW_IN_SERVICE)) {
            filter = "(requeststate=svc_pending)";
        } else if (p.equals(IN_SHOW_PENDING)) {
            filter = "(requeststate=pending)";
        } else if (p.equals(IN_SHOW_CANCELLED)) {
            filter = "(requeststate=canceled)";
        } else if (p.equals(IN_SHOW_REJECTED)) {
            filter = "(requeststate=rejected)";
        } else if (p.equals(IN_SHOW_COMPLETED)) {
            filter = "(requeststate=complete)";
        } else if (p.equals(IN_SHOW_ALL)) {
            filter = "(requeststate=*)";
        }
        return filter;
    }

    public void validateAuthToken(HttpServletRequest request, AuthToken authToken) throws EBaseException {
    }

    public String getFilter(HttpServletRequest request) {

        String reqState = request.getParameter("reqState");
        String reqType = request.getParameter("reqType");

        String filter;

        if (reqState == null || reqType == null) {
            filter = "(requeststate=*)";

        } else if (reqState.equals(IN_SHOW_ALL) && reqType.equals(IN_SHOW_ALL)) {
            filter = "(requeststate=*)";

        } else if (reqState.equals(IN_SHOW_ALL)) {
            filter = getRequestType(reqType);

        } else if (reqType.equals(IN_SHOW_ALL)) {
            filter = getRequestState(reqState);

        } else {
            filter = "(&" + getRequestState(reqState) + getRequestType(reqType) + ")";
        }

        return filter;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param reqState request state (one of showAll, showWaiting, showInService, showCancelled, showRejected,
     * showCompleted)
     * <li>http.param reqType
     * <li>http.param seqNumFromDown request ID to start at (decimal, or hex if when paging down seqNumFromDown starts
     * with 0x)
     * <li>http.param seqNumFromUp request ID to start at (decimal, or hex if when paging up seqNumFromUp starts with
     * 0x)
     * <li>http.param maxCount maximum number of records to show
     * <li>http.param totalCount total number of records in set of pages
     * <li>http.param direction "up", "down", "begin", or "end"
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {

        logger.info("QueryReq: Searching for requests");

        // Authentication / Authorization

        HttpServletRequest req = cmsReq.getHttpReq();
        AuthToken authToken = authenticate(cmsReq);
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
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        try {
            validateAuthToken(req, authToken);

        } catch (EAuthzException e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            // if get a EBaseException we just throw it.
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }

        /**
         * WARNING:
         *
         * PLEASE DO NOT TOUCH THE FILTER HERE. ALL FILTERS ARE INDEXED.
         *
         **/
        String filter = getFilter(req);
        logger.info("QueryReq: - filter: " + filter);

        String reqState = req.getParameter("reqState");
        logger.info("QueryReq: - state: " + reqState);

        String reqType = req.getParameter("reqType");
        logger.info("QueryReq: - type: " + reqType);

        String direction = "begin";
        if (req.getParameter("direction") != null) {
            direction = req.getParameter("direction").trim();
        }
        logger.info("QueryReq: - direction: " + direction);

        BigInteger top = BigInteger.ZERO;
        BigInteger bottom = BigInteger.ZERO;

        try {
            String top_s = req.getParameter(OUT_FIRST_ENTRY_ON_PAGE);
            if (top_s == null)
                top_s = "0";

            String bottom_s = req.getParameter(OUT_LAST_ENTRY_ON_PAGE);
            if (bottom_s == null)
                bottom_s = "0";

            if (top_s.trim().startsWith("0x")) {
                top = new BigInteger(top_s.trim().substring(2), 16);
            } else {
                top = new BigInteger(top_s.trim());
            }
            if (bottom_s.trim().startsWith("0x")) {
                bottom = new BigInteger(bottom_s.trim().substring(2), 16);
            } else {
                bottom = new BigInteger(bottom_s.trim());
            }

        } catch (NumberFormatException e) {
            logger.warn("QueryReq: " + e.getMessage(), e);
        }

        // avoid NumberFormatException to the user interface
        int maxCount = 10;
        try {
            maxCount = Integer.parseInt(req.getParameter(IN_MAXCOUNT));
        } catch (Exception e) {
            logger.warn("QueryReq: " + e.getMessage(), e);
        }
        if (maxCount > mMaxReturns) {
            logger.debug("Resetting page size from " + maxCount + " to " + mMaxReturns);
            maxCount = mMaxReturns;
        }
        logger.info("QueryReq: - max count: " + maxCount);

        HttpServletResponse resp = cmsReq.getHttpResp();
        CMSTemplateParams argset = doSearch(locale[0], filter, maxCount, direction, top, bottom);

        argset.getFixed().addStringValue("reqType", reqType);
        argset.getFixed().addStringValue("reqState", reqState);
        argset.getFixed().addIntegerValue("maxCount", maxCount);

        try {
            form.getOutput(argset);
            resp.setContentType("text/html");
            form.renderOutput(resp.getOutputStream(), argset);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }

        cmsReq.setStatus(CMSRequest.SUCCESS);
    }

    /**
     * Perform search based on direction button pressed
     *
     * @param filter ldap filter indicating which VLV to search through. This can be
     *            'all requests', 'pending', etc
     * @param count the number of requests to show per page
     * @param direction either 'begin', 'end', 'previous' or 'next' (defaults to end)
     * @param top the number of the request shown on at the top of the current page
     * @param bottom the number of the request shown on at the bottom of the current page
     * @return
     */

    protected CMSTemplateParams doSearch(Locale l, String filter,
            int count, String direction, BigInteger top, BigInteger bottom) {
        CMSTemplateParams ctp = null;
        if (direction.equals("previous")) {
            ctp = doSearch(l, filter, -count, top);
        } else if (direction.equals("next")) {
            bottom = bottom.add(BigInteger.ONE);
            ctp = doSearch(l, filter, count, bottom);
        } else if (direction.equals("begin")) {
            ctp = doSearch(l, filter, count, BigInteger.ZERO);
        } else if (direction.equals("first")) {
            ctp = doSearch(l, filter, count, bottom);
        } else { // if 'direction is 'end', default here
            ctp = doSearch(l, filter, -count, BigInteger.ONE.negate());
        }
        return ctp;
    }

    /**
     *
     * @param locale
     * @param filter the types of requests to return - this must match the VLV index
     * @param count maximum number of records to return
     * @param marker indication of the request ID where the page is anchored
     * @return
     */

    private CMSTemplateParams doSearch(
            Locale locale,
            String filter,
            int count,
            BigInteger marker) {

        CMSEngine engine = getCMSEngine();

        ArgBlock header = new ArgBlock();
        ArgBlock context = new ArgBlock();
        CMSTemplateParams argset = new CMSTemplateParams(header, context);

        try {
            long startTime = new Date().getTime();
            // preserve the type of request that we are
            // requesting.

            header.addStringValue(OUT_AUTHORITY_ID, mAuthority.getId());
            header.addStringValue(OUT_REQUESTING_USER, "admin");

            boolean jumptoend = false;
            if (marker.toString().equals("-1")) {
                marker = BigInteger.ZERO; // I think this is inconsequential
                jumptoend = true; // override  to '99' during search
            }

            RequestId id = new RequestId(marker);
            RequestRepository requestRepository = engine.getRequestRepository();
            IRequestVirtualList list = requestRepository.getPagedRequestsByFilter(
                    id,
                    jumptoend,
                    filter,
                    ((count < 0) ? count - 1 : count + 1),
                    "requestId");

            int maxCount = 0;
            if (count < 0 && jumptoend) {
                maxCount = -count;
            } else if (count < 0) {
                maxCount = -count + 1;
            } else {
                maxCount = count;
            }
            int totalCount = (jumptoend) ? maxCount :
                    (list.getSize() - list.getCurrentIndex());
            header.addIntegerValue(OUT_TOTALCOUNT, totalCount);
            header.addIntegerValue(OUT_CURRENTCOUNT, list.getSize());

            Vector<Request> v = fetchRecords(list, maxCount);
            v = normalizeOrder(v);
            trim(v, id);

            int currentCount = 0;
            BigInteger curNum = BigInteger.ZERO;
            BigInteger firstNum = BigInteger.ONE.negate();
            Enumeration<Request> requests = v.elements();

            logger.info("QueryReq: Requests:");
            while (requests.hasMoreElements()) {
                Request request = null;
                try {
                    request = requests.nextElement();
                } catch (Exception e) {
                    logger.warn("Error displaying request:" + e.getMessage(), e);
                    // handled below
                }
                if (request == null) {
                    logger.warn("QueryReq: Error display request on page");
                    continue;
                }

                logger.info("QueryReq: - " + request.getRequestId());
                curNum = new BigInteger(request.getRequestId().toString());

                if (firstNum.equals(BigInteger.ONE.negate())) {
                    firstNum = curNum;
                }

                ArgBlock rec = new ArgBlock();
                mParser.fillRequestIntoArg(locale, request, argset, rec);
                mQueue.releaseRequest(request);
                argset.addRepeatRecord(rec);

                currentCount++;

            }// while
            long endTime = new Date().getTime();

            header.addIntegerValue(OUT_CURRENTCOUNT, currentCount);
            header.addStringValue("time", Long.toString(endTime - startTime));
            header.addBigIntegerValue(OUT_FIRST_ENTRY_ON_PAGE, firstNum, 10);
            header.addBigIntegerValue(OUT_LAST_ENTRY_ON_PAGE, curNum, 10);

        } catch (EBaseException e) {
            logger.warn("QueryReq: " + e.getMessage(), e);
            header.addStringValue(OUT_ERROR, e.toString(locale));
        } catch (Exception e) {
            logger.warn("QueryReq: " + e.getMessage(), e);
        }
        return argset;
    }

    /**
     * If the vector contains the marker element at the end, remove it.
     *
     * @param v The vector to trim
     * @param marker the marker to look for.
     */
    private void trim(Vector<Request> v, RequestId marker) {
        int i = v.size() - 1;

        if (i == 0) {
            // do not remove the only element in the list
            return;
        }

        if (v.elementAt(i).getRequestId().toString().equals(
                marker.toString())) {
            v.remove(i);
        }
    }

    /**
     * Sometimes the list comes back from LDAP in reverse order. This function makes
     * sure the results are in 'forward' order.
     *
     * @param list
     * @return
     */
    private Vector<Request> fetchRecords(IRequestVirtualList list, int maxCount) {

        Vector<Request> v = new Vector<>();
        int count = list.getSize();
        logger.info("QueryReq: Fetching " + count + " request(s)");

        int c = 0;
        for (int i = 0; i < count; i++) {
            Request request = list.getElementAt(i);
            if (request != null) {
                v.add(request);
                c++;
            }
            if (c >= maxCount)
                break;
        }

        return v;

    }

    /**
     * If the requests are in backwards order, reverse the list
     *
     * @param list
     * @return
     */
    private Vector<Request> normalizeOrder(Vector<Request> list) {

        BigInteger firstrequestnum = new BigInteger(list.elementAt(0)
                .getRequestId().toString());
        BigInteger lastrequestnum = new BigInteger(list.elementAt(list
                .size() - 1).getRequestId().toString());
        boolean reverse = false;
        if (firstrequestnum.compareTo(lastrequestnum) > 0) {
            reverse = true; // if the order is backwards, place items at the beginning
        }
        Vector<Request> v = new Vector<>();
        int count = list.size();
        for (int i = 0; i < count; i++) {
            Request request = list.elementAt(i);
            if (request != null) {
                if (reverse)
                    v.add(0, request);
                else
                    v.add(request);
            }
        }

        return v;
    }
}
