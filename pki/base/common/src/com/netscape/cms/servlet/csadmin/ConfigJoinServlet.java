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
import javax.servlet.http.*;

import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.profile.*;
import com.netscape.cmsutil.crypto.*;

import netscape.security.pkcs.*;
import netscape.security.x509.*;

import java.util.*;
import java.io.*;

import java.security.*;
import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.crypto.KeyPairGenerator;


public class ConfigJoinServlet extends ConfigBaseServlet {

    public boolean isDisplayMode(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        String cert = request.getParameter("cert");

        if (cert == null) {
            return true;
        } else {
            return false;
        }
    }

    public boolean isPanelModified() {
        IConfigStore config = CMS.getConfigStore();
      
        String cert = null;

        try {
            cert = config.getString("preop.join.cert", null);
        } catch (EBaseException e) {}
        if (cert == null || cert.equals("")) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * Displays panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response, 
            Context context) {
        IConfigStore config = CMS.getConfigStore();

        try {
            String pubKeyModulus = config.getString(
                    "preop.keysize.pubKeyModulus");
            String pubKeyPublicExponent = config.getString(
                    "preop.keysize.pubKeyPublicExponent");
            String dn = config.getString("preop.name.dn");
            String priKeyID = config.getString("preop.keysize.priKeyID");
            String pkcs10 = CryptoUtil.getPKCS10FromKey(dn,
                    CryptoUtil.string2byte(pubKeyModulus),
                    CryptoUtil.string2byte(pubKeyPublicExponent),
                    CryptoUtil.string2byte(priKeyID));
            context.put("certreq", pkcs10);
        } catch (Exception e) {}

        String select = "auto";
        boolean select_manual = true;

        if (isPanelModified()) {
            try {
                select = config.getString("preop.join.select", null);
            } catch (EBaseException e) {
                CMS.debug( "ConfigJoinServlet::display() - "
                         + "Exception="+e.toString() );
                return;
            }
            if (select.equals("auto")) {

                /* automated enrollment */
                select_manual = false;
            } else {
                try {

                    /* manual enrollment */
                    String cert = config.getString("preop.join.cert", "");

                    context.put("cert", cert);
                } catch (EBaseException e) {}
            }
        } else {
            context.put("cert", "");
        }
        if (select_manual) { 
            context.put("check_manual", "checked");
            context.put("check_auto", "");
        } else {
            context.put("check_manual", "");
            context.put("check_auto", "checked");
        }
        context.put("status", "display");
    }

    /**
     * Updates panel.
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response, 
            Context context) {
        CMS.debug("JoinServlet: update");
        IConfigStore config = CMS.getConfigStore();
        String select = request.getParameter("choice");

        try {
            if (select.equals("manual")) {

                /* manual enrollment */
                CMS.debug("JoinServlet: manual");
                String certchain = request.getParameter("cert");

                config.putString("preop.join.cert", certchain);
            } else if (select.equals("auto")) {
                CMS.debug("JoinServlet: auto");

                /* automated enrollment */
                String url = request.getParameter("url");
                String uid = request.getParameter("uid");
                String pwd = request.getParameter("__pwd");

                config.putString("preop.join.url", url);
                config.putString("preop.join.uid", uid);
                config.putString("preop.join.pwd", pwd);

                /* XXX - submit request to the CA, and import it automatically */
                config.putString(
                        "preop.join.cert", ""); /* store the chain */
            }
            config.putString("preop.join.select", select);
            config.commit(false);
        } catch (Exception e) {}
    }
                                                                                
    public Template getTemplate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        Template template = null;

        try {
            template = Velocity.getTemplate(
                    "admin/console/config/config_join.vm");
        } catch (Exception e) {
            System.err.println("Exception caught: " + e.getMessage());
        }

        return template;
    }
}
