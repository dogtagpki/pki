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
package com.netscape.cms.servlet.wizard;

import java.io.IOException;
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.Template;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.context.Context;
import org.apache.velocity.servlet.VelocityServlet;

import com.netscape.certsrv.apps.CMS;
import com.netscape.cms.servlet.csadmin.Cert;
import com.netscape.cmsutil.crypto.Module;

/**
 * wizard?p=[panel number]&op=usage <= usage in xml
 * wizard?p=[panel number]&op=display
 * wizard?p=[panel number]&op=next&...[additional parameters]...
 * wizard?p=[panel number]&op=apply
 * wizard?p=[panel number]&op=back
 * wizard?op=menu
 * return menu options
 */
@SuppressWarnings("deprecation")
public class WizardServlet extends VelocityServlet {

    /**
     *
     */
    private static final long serialVersionUID = -4513510177445656799L;
    private String name = null;
    private Vector<IWizardPanel> mPanels = new Vector<IWizardPanel>();

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        /* load sequence map */
        name = config.getInitParameter("name");
        String panels = config.getInitParameter("panels");
        StringTokenizer st = new StringTokenizer(panels, ",");
        int pno = 0;
        while (st.hasMoreTokens()) {
            String p = st.nextToken();
            StringTokenizer st1 = new StringTokenizer(p, "=");
            String id = st1.nextToken();
            String pvalue = st1.nextToken();
            try {
                IWizardPanel panel = (IWizardPanel) Class.forName(pvalue).newInstance();
                panel.init(this, config, pno, id);
                CMS.debug("WizardServlet: panel name=" + panel.getName());
                mPanels.addElement(panel);
            } catch (Exception e) {
                CMS.debug("WizardServlet: " + e.toString());
            }
            pno++;
        }
        CMS.debug("WizardServlet: done");

    }

    public void exposePanels(HttpServletRequest request,
                            HttpServletResponse response,
                            Context context) {
        Enumeration<IWizardPanel> e = mPanels.elements();
        Vector<IWizardPanel> panels = new Vector<IWizardPanel>();
        while (e.hasMoreElements()) {
            IWizardPanel p = e.nextElement();
            panels.addElement(p);
        }
        context.put("panels", panels);
    }

    /**
     * Cleans up panels from a particular panel.
     */
    public void cleanUpFromPanel(int pno) throws IOException {
        /* panel number starts from zero */
        int s = mPanels.size();
        for (int i = pno; i < s; i++) {
            IWizardPanel panel = mPanels.elementAt(i);
            panel.cleanUp();
        }
    }

    public IWizardPanel getPanelByNo(int p) {
        IWizardPanel panel = mPanels.elementAt(p);
        if (panel.shouldSkip()) {
            panel = getPanelByNo(p + 1);
        }
        return panel;
    }

    public Template displayPanel(HttpServletRequest request,
                            HttpServletResponse response,
                            Context context) {
        CMS.debug("WizardServlet: in display");
        int p = getPanelNo(request);

        if (p == 0) {
            CMS.debug("WizardServlet: firstpanel");
            context.put("firstpanel", Boolean.TRUE);
        }
        if (p == (mPanels.size() - 1)) {
            CMS.debug("WizardServlet: lastpanel");
            context.put("lastpanel", Boolean.TRUE);
        }
        IWizardPanel panel = getPanelByNo(p);
        CMS.debug("WizardServlet: panel=" + panel);

        if (panel.showApplyButton() == true)
            context.put("showApplyButton", Boolean.TRUE);
        else
            context.put("showApplyButton", Boolean.FALSE);

        panel.display(request, response, context);
        context.put("p", Integer.toString(panel.getPanelNo()));

        try {
            return Velocity.getTemplate("admin/console/config/wizard.vm");
        } catch (Exception e) {
        }
        return null;
    }

    public String xml_value_flatten(Object v) {
        String ret = "";
        if (v instanceof String) {
            ret += v;
        } else if (v instanceof Integer) {
            ret += ((Integer) v).toString();
        } else if (v instanceof Vector) {
            ret += "<Vector>";
            Vector<?> v1 = (Vector<?>) v;
            Enumeration<?> e = v1.elements();
            StringBuffer sb = new StringBuffer();
            while (e.hasMoreElements()) {
                sb.append(xml_value_flatten(e.nextElement()));
            }
            ret += sb.toString();
            ret += "</Vector>";
        } else if (v instanceof Module) { // for hardware token
            Module m = (Module) v;
            ret += "<Module>";
            ret += "<CommonName>" + m.getCommonName() + "</CommonName>";
            ret += "<UserFriendlyName>" + m.getUserFriendlyName() + "</UserFriendlyName>";
            ret += "<ImagePath>" + m.getImagePath() + "</ImagePath>";
            ret += "</Module>";
        } else if (v instanceof Cert) {
            Cert m = (Cert) v;
            ret += "<CertReqPair>";
            ret += "<Nickname>" + m.getNickname() + "</Nickname>";
            ret += "<Tokenname>" + m.getTokenname() + "</Tokenname>";
            ret += "<Request>" + m.getRequest() + "</Request>";
            ret += "<Certificate>" + m.getCert() + "</Certificate>";
            ret += "<Type>" + m.getType() + "</Type>";
            ret += "<DN>" + m.getDN() + "</DN>";
            ret += "<CertPP>" + m.getCertpp() + "</CertPP>";
            ret += "<KeyOption>" + m.getKeyOption() + "</KeyOption>";
            ret += "</CertReqPair>";
        } else if (v instanceof IWizardPanel) {
            IWizardPanel m = (IWizardPanel) v;
            ret += "<Panel>";
            ret += "<Id>" + m.getId() + "</Id>";
            ret += "<Name>" + m.getName() + "</Name>";
            ret += "</Panel>";
        } else {
            CMS.debug("Error: unknown type " + v.getClass().getName());
        }
        return ret;
    }

    public String xml_flatten(Context context) {
        StringBuffer ret = new StringBuffer();
        Object o[] = context.getKeys();
        for (int i = 0; i < o.length; i++) {
            if (o[i] instanceof String) {
                String key = (String) o[i];
                if (key.startsWith("__")) {
                    continue;
                }
                ret.append("<");
                ret.append(key);
                ret.append(">");
                if (key.equals("bindpwd")) {
                    ret.append("(sensitive)");
                } else {
                    Object v = context.get(key);
                    ret.append(xml_value_flatten(v));
                }
                ret.append("</");
                ret.append(key);
                ret.append(">");
            }
        }
        return ret.toString();
    }

    public int getPanelNo(HttpServletRequest request) {
        int p = 0;

        // panel number can be identified by either
        //   panel no (p parameter) directly, or
        //   panel name (panelname parameter).
        if (request.getParameter("panelname") != null) {
            String name = request.getParameter("panelname");
            for (int i = 0; i < mPanels.size(); i++) {
                IWizardPanel panel = mPanels.elementAt(i);
                if (panel.getId().equals(name)) {
                    return i;
                }
            }
        } else if (request.getParameter("p") != null) {
            p = Integer.parseInt(request.getParameter("p"));
        }
        return p;
    }

    public String getNameFromPanelNo(int p) {
        IWizardPanel wp = mPanels.elementAt(p);
        return wp.getId();
    }

    public IWizardPanel getPreviousPanel(int p) {
        CMS.debug("getPreviousPanel input p=" + p);
        IWizardPanel backpanel = mPanels.elementAt(p - 1);
        if (backpanel.isSubPanel()) {
            backpanel = mPanels.elementAt(p - 1 - 1);
        }
        while (backpanel.shouldSkip()) {
            backpanel = mPanels.elementAt(backpanel.getPanelNo() - 1);
        }
        CMS.debug("getPreviousPanel output p=" + backpanel.getPanelNo());
        return backpanel;
    }

    public IWizardPanel getNextPanel(int p) {
        CMS.debug("getNextPanel input p=" + p);
        IWizardPanel panel = mPanels.elementAt(p);
        if (p == (mPanels.size() - 1)) {
            // p = p;
        } else if (panel.isSubPanel()) {
            if (panel.isLoopbackPanel()) {
                p = p - 1; // Login Panel is a loop back panel
            } else {
                p = p + 1;
            }
        } else if (panel.hasSubPanel()) {
            p = p + 2;
        } else {
            p = p + 1;
        }
        IWizardPanel nextpanel = getPanelByNo(p);
        CMS.debug("getNextPanel output p=" + p);
        return nextpanel;
    }

    public Template goApply(HttpServletRequest request,
                            HttpServletResponse response,
                            Context context) {
        return goNextApply(request, response, context, true);
    }

    public Template goNext(HttpServletRequest request,
                            HttpServletResponse response,
                            Context context) {
        return goNextApply(request, response, context, false);
    }

    /*
     * The parameter "stay" is used to indicate "apply" without
     * moving to the next panel
     */
    public Template goNextApply(HttpServletRequest request,
                            HttpServletResponse response,
                Context context, boolean stay) {
        int p = getPanelNo(request);
        if (stay == true)
            CMS.debug("WizardServlet: in reply " + p);
        else
            CMS.debug("WizardServlet: in next " + p);

        IWizardPanel panel = mPanels.elementAt(p);
        try {
            panel.validate(request, response, context);
            try {
                panel.update(request, response, context);
                if (stay == true) { // "apply"

                    if (panel.showApplyButton() == true)
                        context.put("showApplyButton", Boolean.TRUE);
                    else
                        context.put("showApplyButton", Boolean.FALSE);
                    panel.display(request, response, context);
                } else { // "next"
                    IWizardPanel nextpanel = getNextPanel(p);

                    if (nextpanel.showApplyButton() == true)
                        context.put("showApplyButton", Boolean.TRUE);
                    else
                        context.put("showApplyButton", Boolean.FALSE);
                    nextpanel.display(request, response, context);
                    panel = nextpanel;
                }
                context.put("errorString", "");
            } catch (Exception e) {
                context.put("errorString", e.getMessage());
                panel.displayError(request, response, context);
            }
        } catch (IOException eee) {
            context.put("errorString", eee.getMessage());
            panel.displayError(request, response, context);
        }
        p = panel.getPanelNo();
        CMS.debug("panel no=" + p);
        CMS.debug("panel name=" + getNameFromPanelNo(p));
        CMS.debug("total number of panels=" + mPanels.size());
        context.put("p", Integer.toString(p));
        context.put("panelname", getNameFromPanelNo(p));
        if (p == 0) {
            CMS.debug("WizardServlet: firstpanel");
            context.put("firstpanel", Boolean.TRUE);
        }
        if (p == (mPanels.size() - 1)) {
            CMS.debug("WizardServlet: lastpanel");
            context.put("lastpanel", Boolean.TRUE);
        }
        // this is where we handle the xml request
        String xml = request.getParameter("xml");
        if (xml != null && xml.equals("true")) {
            CMS.debug("WizardServlet: found xml");

            response.setContentType("application/xml");
            String xmlstr = xml_flatten(context);
            context.put("xml", xmlstr);
            try {
                return Velocity.getTemplate("admin/console/config/xml.vm");
            } catch (Exception e) {
                CMS.debug("Failing to get template" + e);
            }
        } else {
            try {
                return Velocity.getTemplate("admin/console/config/wizard.vm");
            } catch (Exception e) {
                CMS.debug("Failing to get template" + e);
            }
        }
        return null;
    }

    public Template goBack(HttpServletRequest request,
                            HttpServletResponse response,
                            Context context) {
        int p = getPanelNo(request);
        CMS.debug("WizardServlet: in back " + p);
        IWizardPanel backpanel = getPreviousPanel(p);

        if (backpanel.showApplyButton() == true)
            context.put("showApplyButton", Boolean.TRUE);
        else
            context.put("showApplyButton", Boolean.FALSE);
        backpanel.display(request, response, context);
        context.put("p", Integer.toString(backpanel.getPanelNo()));
        context.put("panelname", getNameFromPanelNo(backpanel.getPanelNo()));

        p = backpanel.getPanelNo();

        if (p == 0) {
            CMS.debug("WizardServlet: firstpanel");
            context.put("firstpanel", Boolean.TRUE);
        }
        if (p == (mPanels.size() - 1)) {
            CMS.debug("WizardServlet: lastpanel");
            context.put("lastpanel", Boolean.TRUE);
        }
        try {
            return Velocity.getTemplate("admin/console/config/wizard.vm");
        } catch (Exception e) {
        }
        return null;
    }

    public boolean authenticate(HttpServletRequest request,
                                   HttpServletResponse response,
                                   Context context) {
        String pin = (String) request.getSession().getAttribute("pin");
        if (pin == null) {
            try {
                response.sendRedirect("login");
            } catch (IOException e) {
            }
            return false;
        }
        return true;
    }

    public void outputHttpParameters(HttpServletRequest httpReq) {
        CMS.debug("WizardServlet:service() uri = " + httpReq.getRequestURI());
        Enumeration<String> paramNames = httpReq.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String pn = paramNames.nextElement();
            // added this facility so that password can be hidden,
            // all sensitive parameters should be prefixed with
            // __ (double underscores); however, in the event that
            // a security parameter slips through, we perform multiple
            // additional checks to insure that it is NOT displayed
            if (pn.startsWith("__") ||
                    pn.endsWith("password") ||
                    pn.endsWith("passwd") ||
                    pn.endsWith("pwd") ||
                    pn.equalsIgnoreCase("admin_password_again") ||
                    pn.equalsIgnoreCase("directoryManagerPwd") ||
                    pn.equalsIgnoreCase("bindpassword") ||
                    pn.equalsIgnoreCase("bindpwd") ||
                    pn.equalsIgnoreCase("passwd") ||
                    pn.equalsIgnoreCase("password") ||
                    pn.equalsIgnoreCase("pin") ||
                    pn.equalsIgnoreCase("pwd") ||
                    pn.equalsIgnoreCase("pwdagain") ||
                    pn.equalsIgnoreCase("uPasswd")) {
                CMS.debug("WizardServlet::service() param name='" + pn +
                         "' value='(sensitive)'");
            } else {
                CMS.debug("WizardServlet::service() param name='" + pn +
                         "' value='" + httpReq.getParameter(pn) + "'");
            }
        }
    }

    public Template handleRequest(HttpServletRequest request,
                            HttpServletResponse response,
                            Context context) {
        CMS.debug("WizardServlet: process");

        if (CMS.debugOn()) {
            outputHttpParameters(request);
        }

        if (!authenticate(request, response, context)) {
            CMS.debug("WizardServlet: authentication failure");
            return null;
        }

        String op = request.getParameter("op"); /* operation */
        if (op == null) {
            op = "display";
        }
        CMS.debug("WizardServlet: op=" + op);
        CMS.debug("WizardServlet: size=" + mPanels.size());

        context.put("name", name);
        context.put("size", Integer.toString(mPanels.size()));
        exposePanels(request, response, context);

        if (op.equals("display")) {
            return displayPanel(request, response, context);
        } else if (op.equals("next")) {
            return goNext(request, response, context);
        } else if (op.equals("apply")) {
            return goApply(request, response, context);
        } else if (op.equals("back")) {
            return goBack(request, response, context);
        }
        return null;
    }
}
