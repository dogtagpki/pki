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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.template.ArgList;
import com.netscape.certsrv.template.ArgSet;
import com.netscape.certsrv.template.ArgString;
import com.netscape.certsrv.template.IArgValue;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ServletUtils;

/**
 * This servlet is the base class of all profile servlets.
 *
 * @version $Revision$, $Date$
 */
public class ProfileServlet extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -7011378748671762375L;
    public final static String ARG_ERROR_CODE = "errorCode";
    public final static String ARG_ERROR_REASON = "errorReason";
    public final static String ARG_RECORD = "record";
    public final static String ARG_OP = "op";

    public final static String ARG_REQUEST_LIST = "requestList";
    public final static String ARG_REQUEST_ID = "requestId";
    public final static String ARG_REQUEST_TYPE = "requestType";
    public final static String ARG_REQUEST_STATUS = "requestStatus";
    public final static String ARG_REQUEST_OWNER =
            "requestOwner";
    public final static String ARG_REQUEST_CREATION_TIME =
            "requestCreationTime";
    public final static String ARG_REQUEST_MODIFICATION_TIME =
            "requestModificationTime";
    public final static String ARG_REQUEST_NONCE = "nonce";

    public final static String ARG_AUTH_ID = "authId";
    public final static String ARG_AUTH_SYNTAX = "authSyntax";
    public final static String ARG_AUTH_CONSTRAINT = "authConstraint";
    public final static String ARG_AUTH_NAME = "authName";
    public final static String ARG_AUTH_LIST = "authList";
    public final static String ARG_AUTH_DESC = "authDesc";
    public final static String ARG_AUTH_IS_SSL = "authIsSSLClientRequired";
    public final static String ARG_PROFILE = "profile";
    public final static String ARG_REQUEST_NOTES = "requestNotes";
    public final static String ARG_PROFILE_ID = "profileId";
    public final static String ARG_RENEWAL_PROFILE_ID = "rprofileId";
    public final static String ARG_PROFILE_IS_ENABLED = "profileIsEnable";
    public final static String ARG_PROFILE_IS_VISIBLE = "profileIsVisible";
    public final static String ARG_PROFILE_ENABLED_BY = "profileEnableBy";
    public final static String ARG_PROFILE_APPROVED_BY = "profileApprovedBy";
    public final static String ARG_PROFILE_NAME = "profileName";
    public final static String ARG_PROFILE_DESC = "profileDesc";
    public final static String ARG_PROFILE_REMOTE_HOST = "profileRemoteHost";
    public final static String ARG_PROFILE_REMOTE_ADDR = "profileRemoteAddr";
    public final static String ARG_DEF_ID = "defId";
    public final static String ARG_DEF_SYNTAX = "defSyntax";
    public final static String ARG_DEF_CONSTRAINT = "defConstraint";
    public final static String ARG_DEF_NAME = "defName";
    public final static String ARG_DEF_VAL = "defVal";
    public final static String ARG_DEF_DESC = "defDesc";
    public final static String ARG_DEF_LIST = "defList";
    public final static String ARG_CON_DESC = "conDesc";
    public final static String ARG_CON_LIST = "constraint";
    public final static String ARG_CON_NAME = "name";
    public final static String ARG_CON_VALUE = "value";
    public final static String ARG_PROFILE_SET_ID = "profileSetId";
    public final static String ARG_POLICY_SET_ID = "setId";
    public final static String ARG_POLICY = "policy";
    public final static String ARG_POLICY_ID = "policyId";
    public final static String ARG_POLICY_SET_LIST = "policySetList";
    public final static String ARG_INPUT_PLUGIN_LIST = "inputPluginList";
    public final static String ARG_INPUT_PLUGIN_ID = "inputPluginId";
    public final static String ARG_INPUT_PLUGIN_NAME = "inputPluginName";
    public final static String ARG_INPUT_PLUGIN_DESC = "inputPluginDesc";
    public final static String ARG_INPUT_LIST = "inputList";
    public final static String ARG_INPUT_ID = "inputId";
    public final static String ARG_INPUT_SYNTAX = "inputSyntax";
    public final static String ARG_INPUT_CONSTRAINT = "inputConstraint";
    public final static String ARG_INPUT_NAME = "inputName";
    public final static String ARG_INPUT_VAL = "inputVal";
    public final static String ARG_IS_RENEWAL = "renewal";
    public final static String ARG_XML_OUTPUT = "xmlOutput";
    public final static String ARG_OUTPUT_LIST = "outputList";
    public final static String ARG_OUTPUT_ID = "outputId";
    public final static String ARG_OUTPUT_SYNTAX = "outputSyntax";
    public final static String ARG_OUTPUT_CONSTRAINT = "outputConstraint";
    public final static String ARG_OUTPUT_NAME = "outputName";
    public final static String ARG_OUTPUT_VAL = "outputVal";

    private static final String PROP_TEMPLATE = "templatePath";
    private final static String PROP_AUTHMGR = "AuthMgr";
    private final static String PROP_CLIENTAUTH = "GetClientCert";
    private static final String PROP_PROFILE_SUB_ID = "profileSubId";
    private static final String PROP_ID = "ID";
    public final static String PROP_RESOURCEID = "resourceID";
    public final static String AUTHZ_SRC_LDAP = "ldap";
    public final static String AUTHZ_SRC_TYPE = "sourceType";
    public final static String AUTHZ_CONFIG_STORE = "authz";
    public final static String AUTHZ_SRC_XML = "web.xml";
    public final static String PROP_AUTHZ_MGR = "AuthzMgr";
    public final static String PROP_ACL = "ACLinfo";
    public final static String AUTHZ_MGR_BASIC = "BasicAclAuthz";
    public final static String AUTHZ_MGR_LDAP = "DirAclAuthz";

    private final static String HDR_LANG = "accept-language";

    private String mTemplate = null;

    protected String mId = null;
    protected String mGetClientCert = "false";
    protected String mAuthMgr = null;
    protected IAuthzSubsystem mAuthz = null;
    protected String mAclMethod = null;
    protected String mAuthzResourceName = null;
    protected ILogger mLogger = CMS.getLogger();
    protected int mLogCategory = ILogger.S_OTHER;
    protected String mProfileSubId = null;

    protected ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();

    // stats
    protected LinkedHashSet<String> statEvents = new LinkedHashSet<String>();

    public ProfileServlet() {
        super();
    }

    /**
     * initialize the servlet. Servlets implementing this method
     * must specify the template to use as a parameter called
     * "templatePath" in the servletConfig
     *
     * @param sc servlet configuration, read from the web.xml file
     */

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mTemplate = sc.getServletContext().getRealPath(
                    sc.getInitParameter(PROP_TEMPLATE));
        mGetClientCert = sc.getInitParameter(PROP_CLIENTAUTH);
        mAuthMgr = sc.getInitParameter(PROP_AUTHMGR);
        mAuthz = (IAuthzSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTHZ);
        mAuthzResourceName = sc.getInitParameter(PROP_RESOURCEID);
        mProfileSubId = sc.getInitParameter(PROP_PROFILE_SUB_ID);
        mId = sc.getInitParameter(PROP_ID);

        try {
            mAclMethod = ServletUtils.initializeAuthz(sc, mAuthz, mId);
        } catch (ServletException e) {
            log(ILogger.LL_FAILURE, e.toString());
            throw e;
        }
    }

    protected String escapeXML(String v) {
        if (v == null) {
            return "";
        }
        v = v.replaceAll("&", "&amp;");
        return v;
    }

    protected void outputArgValueAsXML(PrintStream ps, String name, IArgValue v) {
        ps.println("<" + name + ">");
        if (v != null) {
            if (v instanceof ArgList) {
                ArgList list = (ArgList) v;
                ps.println("<list>");
                for (int i = 0; i < list.size(); i++) {
                    outputArgValueAsXML(ps, name, list.get(i));
                }
                ps.println("</list>");
            } else if (v instanceof ArgString) {
                ArgString str = (ArgString) v;
                ps.println(escapeXML(str.getValue()));
            } else if (v instanceof ArgSet) {
                ArgSet set = (ArgSet) v;
                ps.println("<set>");
                Enumeration<String> names = set.getNames();
                while (names.hasMoreElements()) {
                    String n = names.nextElement();
                    outputArgValueAsXML(ps, n, set.get(n));
                }
                ps.println("</set>");
            } else {
                ps.println(v);
            }
        }
        ps.println("</" + name + ">");
    }

    protected void outputThisAsXML(ByteArrayOutputStream bos, ArgSet args) {
        PrintStream ps = new PrintStream(bos);
        ps.println("<xml>");
        outputArgValueAsXML(ps, "output", args);
        ps.println("</xml>");
        ps.flush();
    }

    public void outputTemplate(HttpServletRequest request,
                   HttpServletResponse response, ArgSet args)
            throws EBaseException {

        String xmlOutput = request.getParameter("xml");
        if (xmlOutput != null && xmlOutput.equals("true")) {
            response.setContentType("text/xml");
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            outputThisAsXML(bos, args);
            try {
                response.setContentLength(bos.size());
                bos.writeTo(response.getOutputStream());
            } catch (Exception e) {
                CMS.debug("outputTemplate error " + e);
            }
            return;
        }
        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        if (statsSub != null) {
            statsSub.startTiming("output_template");
        }
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(
                    new FileReader(mTemplate));

            response.setContentType("text/html; charset=UTF-8");

            PrintWriter writer = response.getWriter();

            // output template
            String line = null;

            do {
                line = reader.readLine();
                if (line != null) {
                    if (line.indexOf("<CMS_TEMPLATE>") == -1) {
                        writer.println(line);
                    } else {
                        // output javascript parameters
                        writer.println("<script type=\"text/javascript\">");
                        outputData(writer, args);
                        writer.println("</script>");
                    }
                }
            } while (line != null);
            reader.close();
        } catch (IOException e) {
            CMS.debug(e);
            throw new EBaseException(e.toString());
        } finally {
            if (statsSub != null) {
                statsSub.endTiming("output_template");
            }
        }
    }

    public void outputTemplate(boolean isXML, HttpServletResponse response, ArgSet args)
            throws EBaseException {
        if (isXML) {
            response.setContentType("text/xml");
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            outputThisAsXML(bos, args);
            try {
                response.setContentLength(bos.size());
                bos.writeTo(response.getOutputStream());
            } catch (Exception e) {
                CMS.debug("outputTemplate error " + e);
            }
            return;
        }
        startTiming("output_template");

        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(mTemplate));

            response.setContentType("text/html; charset=UTF-8");

            PrintWriter writer = response.getWriter();

            // output template
            String line = null;

            do {
                line = reader.readLine();
                if (line != null) {
                    if (line.indexOf("<CMS_TEMPLATE>") == -1) {
                        writer.println(line);
                    } else {
                        // output javascript parameters
                        writer.println("<script type=\"text/javascript\">");
                        outputData(writer, args);
                        writer.println("</script>");
                    }
                }
            } while (line != null);
            reader.close();
        } catch (IOException e) {
            CMS.debug(e);
            throw new EBaseException(e.toString());
        } finally {
            endTiming("output_template");
        }
    }

    protected void outputArgList(PrintWriter writer, String name, ArgList list)
            throws IOException {

        String h_name = null;

        if (name.indexOf('.') == -1) {
            h_name = name;
        } else {
            h_name = name.substring(name.indexOf('.') + 1);
        }
        writer.println(name + "Set = new Array;");
        //		writer.println(h_name + "Count = 0;");

        for (int i = 0; i < list.size(); i++) {
            writer.println(h_name + " = new Object;");
            IArgValue val = list.get(i);

            if (val instanceof ArgString) {
                ArgString str = (ArgString) val;

                outputArgString(writer, name, str);
            } else if (val instanceof ArgSet) {
                ArgSet set = (ArgSet) val;

                outputArgSet(writer, h_name, set);
                writer.println(name + "Set[" + i + "] = " + h_name + ";");
            }
        }
    }

    public void startTiming(String event) {
        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        if (statsSub != null) {
            statsSub.startTiming(event, true);
        }
        statEvents.add(event);
    }

    public void endTiming(String event) {
        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        if (statsSub != null) {
            statsSub.endTiming(event);
        }
        statEvents.remove(event);
    }

    protected String escapeJavaScriptString(String v) {
        int l = v.length();
        char in[] = new char[l];
        char out[] = new char[l * 4];
        int j = 0;

        v.getChars(0, l, in, 0);

        for (int i = 0; i < l; i++) {
            char c = in[i];

            /* presumably this gives better performance */
            if ((c > 0x23) && (c != 0x5c) && (c != 0x3c) && (c != 0x3e)) {
                out[j++] = c;
                continue;
            }

            /* some inputs are coming in as '\' and 'n' */
            /* see BZ 500736 for details */
            if ((c == 0x5c) && ((i + 1) < l) && (in[i + 1] == 'n' ||
                    in[i + 1] == 'r' || in[i + 1] == 'f' || in[i + 1] == 't' ||
                    in[i + 1] == '<' || in[i + 1] == '>' ||
                    in[i + 1] == '\"' || in[i + 1] == '\'' || in[i + 1] == '\\')) {
                if (in[i + 1] == 'x' && ((i + 3) < l) && in[i + 2] == '3' &&
                        (in[i + 3] == 'c' || in[i + 3] == 'e')) {
                    out[j++] = '\\';
                    out[j++] = in[i + 1];
                    out[j++] = in[i + 2];
                    out[j++] = in[i + 3];
                    i += 3;
                } else {
                    out[j++] = '\\';
                    out[j++] = in[i + 1];
                    i++;
                }
                continue;
            }

            switch (c) {
            case '\n':
                out[j++] = '\\';
                out[j++] = 'n';
                break;

            case '\\':
                out[j++] = '\\';
                out[j++] = '\\';
                break;

            case '\"':
                out[j++] = '\\';
                out[j++] = '\"';
                break;

            case '\r':
                out[j++] = '\\';
                out[j++] = 'r';
                break;

            case '\f':
                out[j++] = '\\';
                out[j++] = 'f';
                break;

            case '\t':
                out[j++] = '\\';
                out[j++] = 't';
                break;

            case '<':
                out[j++] = '\\';
                out[j++] = 'x';
                out[j++] = '3';
                out[j++] = 'c';
                break;

            case '>':
                out[j++] = '\\';
                out[j++] = 'x';
                out[j++] = '3';
                out[j++] = 'e';
                break;

            default:
                out[j++] = c;
            }
        }
        return new String(out, 0, j);
    }

    protected void outputArgString(PrintWriter writer, String name, ArgString str)
            throws IOException {
        String s = str.getValue();

        // sub \n with "\n"
        if (s != null) {
            s = escapeJavaScriptString(s);
        }
        writer.println(name + "=\"" + s + "\";");
    }

    protected void outputArgSet(PrintWriter writer, String name, ArgSet set)
            throws IOException {
        Enumeration<String> e = set.getNames();

        while (e.hasMoreElements()) {
            String n = e.nextElement();
            IArgValue val = set.get(n);

            if (val instanceof ArgSet) {
                ArgSet set1 = (ArgSet) val;

                outputArgSet(writer, name + "." + n, set1);
            } else if (val instanceof ArgList) {
                ArgList list = (ArgList) val;

                outputArgList(writer, name + "." + n, list);
            } else if (val instanceof ArgString) {
                ArgString str = (ArgString) val;

                outputArgString(writer, name + "." + n, str);
            }
        }
    }

    protected void outputData(PrintWriter writer, ArgSet set)
            throws IOException {
        if (set == null)
            return;
        Enumeration<String> e = set.getNames();

        while (e.hasMoreElements()) {
            String n = e.nextElement();
            IArgValue val = set.get(n);

            if (val instanceof ArgSet) {
                ArgSet set1 = (ArgSet) val;

                outputArgSet(writer, n, set1);
            } else if (val instanceof ArgList) {
                ArgList list = (ArgList) val;

                outputArgList(writer, n, list);
            } else if (val instanceof ArgString) {
                ArgString str = (ArgString) val;

                outputArgString(writer, n, str);
            }
        }
    }

    /**
     * log according to authority category.
     */
    protected void log(int event, int level, String msg) {
        mLogger.log(event, mLogCategory, level,
                "Servlet " + mId + ": " + msg);
    }

    protected void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, mLogCategory, level,
                "Servlet " + mId + ": " + msg);
    }

    /**
     * Retrieves locale based on the request.
     */
    protected Locale getLocale(HttpServletRequest req) {
        Locale locale = null;
        String lang = req.getHeader(HDR_LANG);

        if (lang == null) {
            // use server locale
            locale = Locale.getDefault();
        } else {
            locale = new Locale(UserInfo.getUserLanguage(lang),
                        UserInfo.getUserCountry(lang));
        }
        return locale;
    }

    protected void renderResult(CMSRequest cmsReq)
            throws IOException {
        // do nothing
    }
}
