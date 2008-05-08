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
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.cmsutil.crypto.*;
import com.netscape.certsrv.template.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.dbs.certdb.*;
import java.io.*;
import java.math.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.ldap.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;
import netscape.security.x509.*;

import org.mozilla.jss.asn1.*;
import com.netscape.cms.servlet.wizard.*;

public class ImportCAChainPanel extends WizardPanelBase {

    public ImportCAChainPanel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Import CA's Certificate Chain");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
        throws ServletException {
        setPanelNo(panelno);
        setName("Import CA's Certificate Chain");
        setId(id);
    }

    public boolean isSubPanel() {
        return false;
    }

    public void cleanUp() throws IOException {
    }

    public boolean isPanelDone() {
        return false;
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();

        return set;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        CMS.debug("ImportCACertChain: display");
        context.put("errorString", "");
        context.put("title", "Import CA's Certificate Chain");
        context.put("panel", "admin/console/config/importcachainpanel.vm");
        context.put("import", "true");

        IConfigStore cs = CMS.getConfigStore();


        ISubsystem ca = (ISubsystem) CMS.getSubsystem("ca");

        if (ca == null) {
            context.put("ca", "false");
        } else {
            context.put("ca", "true");
        }

    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        IConfigStore cs = CMS.getConfigStore();


        context.put("errorString", "");
        context.put("title", "Import CA's Certificate Chain");
        context.put("panel", "admin/console/config/importcachainpanel.vm");
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        /* This should never be called */
        context.put("title", "Import CA's Certificate Chain");
        context.put("panel", "admin/console/config/importcachainpanel.vm");
    }
}
