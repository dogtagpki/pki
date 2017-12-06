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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.tomcat;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.logging.Logger;

import javax.servlet.ServletException;

import org.apache.catalina.Session;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;

public class ExternalAuthenticationValve extends ValveBase {

    final static Logger logger = Logger.getLogger(ExternalAuthenticationValve.class.getName());

    public void invoke(Request req, Response resp)
            throws IOException, ServletException {

        logger.info("ExternalAuthenticationValve: authType: " + req.getAuthType());
        logger.info("ExternalAuthenticationValve: principal: " + req.getUserPrincipal());
        //logger.info("ExternalAuthenticationValve: attributes: " + req.getCoyoteRequest().getAttributes());

        org.apache.coyote.Request coyoteReq = req.getCoyoteRequest();
        Principal principal = req.getUserPrincipal();

        if (principal != null) {
            Integer numGroups = 0;
            String numGroupsStr = (String)
                coyoteReq.getAttribute("REMOTE_USER_GROUP_N");
            if (numGroupsStr != null) {
                try {
                    numGroups = new Integer(numGroupsStr);
                } catch (NumberFormatException e) {
                    logger.warning("ExternalAuthenticationValve: invalid REMOTE_USER_GROUP_N value: " + e);
                }
            }

            ArrayList<String> groups = new ArrayList<>();
            for (int i = 1; i <= numGroups; i++) {
                String k = "REMOTE_USER_GROUP_" + i;
                String s = (String) coyoteReq.getAttribute(k);
                if (s != null && !s.isEmpty())
                    groups.add(s);
                else
                    logger.warning("ExternalAuthenticationValve: missing or empty attribute: " + k);
            }

            // replace the principal
            principal = new ExternalPrincipal(
                principal.getName(), null, groups, coyoteReq.getAttributes());
            logger.info("ExternalAuthenticationValve: setting new principal: " + principal);
            req.setUserPrincipal(principal);

            // cache principal in session
            Session session = req.getSessionInternal();
            session.setAuthType(req.getAuthType());
            session.setPrincipal(principal);
        }

        getNext().invoke(req, resp);
    }
}
