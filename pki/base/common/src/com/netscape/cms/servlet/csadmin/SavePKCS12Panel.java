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
package com.netscape.cms.servlet.csadmin;

import org.apache.velocity.Template;
import org.apache.velocity.servlet.VelocityServlet;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.context.Context;
import javax.servlet.*;
import javax.servlet.http.*;
import org.mozilla.jss.util.Password;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.property.*;
import java.io.*;
import java.net.URL;
import com.netscape.certsrv.base.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import java.security.KeyPair;
import netscape.security.util.*;
import netscape.security.pkcs.*;
import netscape.security.x509.*;
import org.mozilla.jss.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.pkcs12.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.crypto.PrivateKey;

import com.netscape.cms.servlet.wizard.*;

public class SavePKCS12Panel extends WizardPanelBase {

    public SavePKCS12Panel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Save Keys and Certificates");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
        throws ServletException {
        setPanelNo(panelno);
        setName("Save Keys and Certificates");
        setId(id);
    }

    public void cleanUp() throws IOException {
    }

    public boolean shouldSkip() {
        IConfigStore cs = CMS.getConfigStore();

        try {
            boolean enable = cs.getBoolean("preop.backupkeys.enable", false);
            if (!enable) 
                return true;
        } catch (Exception e) {
        }
 
        return false;
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.backupkeycert.done", "");
            if (s == null || s.equals("")) {
                return false;
            } else {
                return true;
            }
        } catch (EBaseException e) {}
        return false;
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();
                                                                                
        return set;
    }

    public boolean isSubPanel() {
        return true;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("title", "Save Keys and Certificates");
        IConfigStore config = CMS.getConfigStore();
        String subsystemtype = "";
        try {
            subsystemtype = config.getString("cs.type", "");
        } catch (Exception e) {
        }

        subsystemtype = toLowerCaseSubsystemType(subsystemtype);

        context.put("panel", "admin/console/config/savepkcs12panel.vm");
        context.put("subsystemtype", subsystemtype);
        context.put("errorString", "");
    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
      HttpServletResponse response, Context context) throws IOException {
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        context.put("title", "Save Keys and Certificates");
        context.put("panel", "admin/console/config/savepkcs12panel.vm");
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
        HttpServletResponse response,
        Context context)
    {
        context.put("title", "Save Keys and Certificates");
        context.put("panel", "admin/console/config/savepkcs12panel.vm");
    }
}
