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
package com.netscape.cms.servlet.cert;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.X500Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.IRequestRecord;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Provide statistical queries of request and certificate records.
 *
 * @version $Revision$, $Date$
 */
public class Monitor extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -8492837942132357692L;
    private final static String TPL_FILE = "monitor.template";

    private ICertificateRepository mCertDB = null;
    private IRequestQueue mQueue = null;
    private X500Name mAuthName = null;
    private String mFormPath = null;

    private int mTotalCerts = 0;
    private int mTotalReqs = 0;

    /**
     * Constructs query servlet.
     */
    public Monitor() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * 'monitor.template' to render the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success to render own template.
        mTemplates.remove(ICMSRequest.SUCCESS);

        if (mAuthority instanceof ICertificateAuthority) {
            ICertificateAuthority ca = (ICertificateAuthority) mAuthority;

            mCertDB = ca.getCertificateRepository();
            mAuthName = ca.getX500Name();
        }
        mQueue = mAuthority.getRequestQueue();

        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param startTime start of time period to query
     * <li>http.param endTime end of time period to query
     * <li>http.param interval time between queries
     * <li>http.param numberOfIntervals number of queries to run
     * <li>http.param maxResults =number
     * <li>http.param timeLimit =time
     * </ul>
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "read");
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

        String startTime = null;
        String endTime = null;
        String interval = null;
        String numberOfIntervals = null;

        EBaseException error = null;

        IArgBlock header = CMS.createArgBlock();
        IArgBlock ctx = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        try {
            startTime = req.getParameter("startTime");
            endTime = req.getParameter("endTime");
            interval = req.getParameter("interval");
            numberOfIntervals = req.getParameter("numberOfIntervals");

            process(argSet, header, startTime, endTime, interval, numberOfIntervals, locale[0]);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_PROCESSING_REQ", e.toString()));
            error = e;
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
                cmsReq.setStatus(ICMSRequest.ERROR);
                cmsReq.setError(error);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE",
                            e.toString()));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }

    private void process(CMSTemplateParams argSet, IArgBlock header,
            String startTime, String endTime,
            String interval, String numberOfIntervals,
            Locale locale)
            throws EBaseException {
        if (interval == null || interval.length() == 0) {
            header.addStringValue("error", "Invalid interval: " + interval);
            return;
        }
        if (numberOfIntervals == null || numberOfIntervals.length() == 0) {
            header.addStringValue("error", "Invalid number of intervals: " + numberOfIntervals);
            return;
        }

        Date startDate = StringToDate(startTime);

        if (startDate == null) {
            header.addStringValue("error", "Invalid start time: " + startTime);
            return;
        }

        int iInterval = 0;

        try {
            iInterval = Integer.parseInt(interval);
        } catch (NumberFormatException nfe) {
            header.addStringValue("error", "Invalid interval: " + interval);
            return;
        }

        int iNumberOfIntervals = 0;

        try {
            iNumberOfIntervals = Integer.parseInt(numberOfIntervals);
        } catch (NumberFormatException nfe) {
            header.addStringValue("error", "Invalid number of intervals: " + numberOfIntervals);
            return;
        }

        header.addStringValue("startDate", startDate.toString());
        header.addStringValue("startTime", startTime);
        header.addIntegerValue("interval", iInterval);
        header.addIntegerValue("numberOfIntervals", iNumberOfIntervals);

        mTotalCerts = 0;
        mTotalReqs = 0;

        Date d1 = startDate;

        for (int i = 0; i < iNumberOfIntervals; i++) {
            Date d2 = nextDate(d1, iInterval - 1);
            IArgBlock rarg = CMS.createArgBlock();
            String e = getIntervalInfo(rarg, d1, d2);

            if (e != null) {
                header.addStringValue("error", e);
                return;
            }
            argSet.addRepeatRecord(rarg);
            d1 = nextDate(d2, 1);
        }

        header.addIntegerValue("totalNumberOfCertificates", mTotalCerts);
        header.addIntegerValue("totalNumberOfRequests", mTotalReqs);

        if (mAuthName != null)
            header.addStringValue("issuerName", mAuthName.toString());

        return;
    }

    Date nextDate(Date d, int seconds) {
        return new Date(d.getTime() + seconds * 1000);
    }

    String getIntervalInfo(IArgBlock arg, Date startDate, Date endDate) {
        if (startDate != null && endDate != null) {
            String startTime = DateToZString(startDate);
            String endTime = DateToZString(endDate);
            String filter = null;

            arg.addStringValue("startTime", startTime);
            arg.addStringValue("endTime", endTime);

            try {
                if (mCertDB != null) {
                    filter = Filter(ICertRecord.ATTR_CREATE_TIME, startTime, endTime);

                    Enumeration<Object> e = mCertDB.findCertRecs(filter);

                    int count = 0;

                    while (e != null && e.hasMoreElements()) {
                        ICertRecord rec = (ICertRecord) e.nextElement();

                        if (rec != null) {
                            count++;
                        }
                    }
                    arg.addIntegerValue("numberOfCertificates", count);
                    mTotalCerts += count;
                }

                if (mQueue != null) {
                    filter = Filter(IRequestRecord.ATTR_CREATE_TIME, startTime, endTime);

                    IRequestList reqList = mQueue.listRequestsByFilter(filter);

                    int count = 0;

                    while (reqList != null && reqList.hasMoreElements()) {
                        IRequestRecord rec = (IRequestRecord) reqList.nextRequest();

                        if (rec != null) {
                            if (count == 0) {
                                arg.addStringValue("firstRequest", rec.getRequestId().toString());
                            }
                            count++;
                        }
                    }
                    arg.addIntegerValue("numberOfRequests", count);
                    mTotalReqs += count;
                }
            } catch (Exception ex) {
                return "Exception: " + ex;
            }

            return null;
        } else {
            return "Missing start or end date";
        }
    }

    Date StringToDate(String z) {
        Date d = null;

        if (z != null && (z.length() == 14 ||
                z.length() == 15 && (z.charAt(14) == 'Z' || z.charAt(14) == 'z'))) {
            // 20020516132030Z or 20020516132030
            try {
                int year = Integer.parseInt(z.substring(0, 4));
                int month = Integer.parseInt(z.substring(4, 6)) - 1;
                int date = Integer.parseInt(z.substring(6, 8));
                int hour = Integer.parseInt(z.substring(8, 10));
                int minute = Integer.parseInt(z.substring(10, 12));
                int second = Integer.parseInt(z.substring(12, 14));
                Calendar calendar = Calendar.getInstance();
                calendar.set(year, month, date, hour, minute, second);
                d = calendar.getTime();
            } catch (NumberFormatException nfe) {
            }
        } else if (z != null && z.length() > 1 && z.charAt(0) == '-') { // -5
            try {
                int i = Integer.parseInt(z);

                d = new Date();
                d = nextDate(d, i);
            } catch (NumberFormatException nfe) {
            }
        }

        return d;
    }

    String DateToZString(Date d) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(d);

        String time = "" + (calendar.get(Calendar.YEAR));
        int i = calendar.get(Calendar.MONTH) + 1;

        if (i < 10)
            time += "0";
        time += i;
        i = calendar.get(Calendar.DAY_OF_MONTH);
        if (i < 10)
            time += "0";
        time += i;
        i = calendar.get(Calendar.HOUR_OF_DAY);
        if (i < 10)
            time += "0";
        time += i;
        i = calendar.get(Calendar.MINUTE);
        if (i < 10)
            time += "0";
        time += i;
        i = calendar.get(Calendar.SECOND);
        if (i < 10)
            time += "0";
        time += i + "Z";
        return time;
    }

    String Filter(String name, String start, String end) {
        String filter = "(&(" + name + ">=" + start + ")(" + name + "<=" + end + "))";

        return filter;
    }

    String uriFilter(String name, String start, String end) {
        String filter = "(%26(" + name + "%3e%3d" + start + ")(" + name + "%3c%3d" + end + "))";

        return filter;
    }
}
