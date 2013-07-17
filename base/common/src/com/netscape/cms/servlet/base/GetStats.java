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
package com.netscape.cms.servlet.base;

import java.io.IOException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.certsrv.util.StatsEvent;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Retrieve information.
 *
 * @version $Revision$, $Date$
 */
public class GetStats extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = -3336253558044271816L;
    private final static String TPL_FILE = "getStats.template";
    private String mFormPath = null;

    public GetStats() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template
     * file "getOCSPInfo.template" to render the result page.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success to display own output.

        // coming from agent
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;

        mTemplates.remove(ICMSRequest.SUCCESS);
    }

    /**
     * Process the HTTP request.
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

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

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, httpReq, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            cmsReq.setError(new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR")));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        StatsEvent st = statsSub.getMainStatsEvent();

        String op = httpReq.getParameter("op");
        if (op != null && op.equals("clear")) {
            statsSub.resetCounters();
        }

        header.addStringValue("startTime", statsSub.getStartTime().toString());
        header.addStringValue("curTime", (new Date()).toString());
        parse(argSet, st, 0);

        try {
            ServletOutputStream out = httpResp.getOutputStream();

            httpResp.setContentType("text/html");
            form.renderOutput(out, argSet);
            cmsReq.setStatus(ICMSRequest.SUCCESS);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            cmsReq.setError(new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR")));
            cmsReq.setStatus(ICMSRequest.ERROR);
        }
        cmsReq.setStatus(ICMSRequest.SUCCESS);
        return;
    }

    public String getSep(int level) {
        StringBuffer s = new StringBuffer();
        for (int i = 0; i < level; i++) {
            s.append("-");
        }
        return s.toString();
    }

    public void parse(CMSTemplateParams argSet, StatsEvent st, int level) {
        Enumeration<String> names = st.getSubEventNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            StatsEvent subSt = st.getSubEvent(name);

            IArgBlock rarg = CMS.createArgBlock();
            rarg.addStringValue("name", getSep(level) + " " + subSt.getName());
            rarg.addLongValue("noOfOp", subSt.getNoOfOperations());
            rarg.addLongValue("timeTaken", subSt.getTimeTaken());
            rarg.addLongValue("max", subSt.getMax());
            rarg.addLongValue("min", subSt.getMin());
            rarg.addLongValue("percentage", subSt.getPercentage());
            rarg.addLongValue("avg", subSt.getAvg());
            rarg.addLongValue("stddev", subSt.getStdDev());
            argSet.addRepeatRecord(rarg);

            parse(argSet, subSt, level + 1);
        }
    }
}
