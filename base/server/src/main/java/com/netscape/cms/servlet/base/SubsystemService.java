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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.servlet.base;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Map;
import java.util.ResourceBundle;

import javax.ws.rs.core.HttpHeaders;

import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.logging.Auditor;

public class SubsystemService extends PKIService {

    public String getSubsystemName() {
        // get web application path: /<subsystem>
        String path = servletContext.getContextPath();

        // get subsystem name by removing the / prefix from the path
        return path.startsWith("/") ? path.substring(1) : path;
    }

    public String getSubsystemConfDir() {
        return CMS.getInstanceDir() + File.separator + getSubsystemName() + File.separator + "conf";
    }

    public String getSharedSubsystemConfDir() {
        return File.separator + "usr" + File.separator + "share" + File.separator + "pki" +
                File.separator + getSubsystemName() + File.separator + "conf";
    }

    public ResourceBundle getResourceBundle(String name) throws Exception {

        // Look in <instance>/<subsystem>/conf first,
        // then fallback to /usr/share/pki/<subsystem>/conf.
        URL[] urls = {
                new File(getSubsystemConfDir()).toURI().toURL(),
                new File(getSharedSubsystemConfDir()).toURI().toURL()
        };

        ClassLoader loader = new URLClassLoader(urls);
        return ResourceBundle.getBundle(name, servletRequest.getLocale(), loader);
    }

    public String getUserMessage(String messageId, HttpHeaders headers, String... params) {
        return CMS.getUserMessage(getLocale(headers), messageId, params);
    }

    public void audit(String message, String scope, String type, String id, Map<String, String> params, String status) {

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();
        String auditMessage = CMS.getLogMessage(
                message,
                auditor.getSubjectID(),
                status,
                auditor.getParamString(scope, type, id, params));

        auditor.log(auditMessage);
    }

    public void auditConfigTokenGeneral(String status, String service, Map<String, String> params, String info) {

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_GENERAL,
                servletRequest.getUserPrincipal().getName(),
                status,
                service,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }
}
