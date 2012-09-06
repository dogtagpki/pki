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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;

import java.net.InetAddress;
import java.util.Locale;
import java.util.Random;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.cms.servlet.processors.Processor;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainProcessor extends Processor {

    private final static String LOGGING_SIGNED_AUDIT_SECURITY_DOMAIN_UPDATE =
            "LOGGING_SIGNED_AUDIT_SECURITY_DOMAIN_UPDATE_1";

    Random random = new Random();

    public SecurityDomainProcessor(Locale locale) throws EPropertyNotFound, EBaseException {
        super("securitydomain", locale);
    }

    public InstallToken getInstallToken(
            String user,
            String hostname,
            String subsystem) throws EBaseException {

        String groupname = ConfigurationUtils.getGroupName(user, subsystem);

        if (groupname == null) {
            String message = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                    user,
                    ILogger.FAILURE,
                    "Enterprise " + subsystem + " Administrators");
            audit(message);

            throw new UnauthorizedException("Access denied.");
        }

        String message = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_ROLE_ASSUME,
                user,
                ILogger.SUCCESS,
                groupname);
        audit(message);

        String ip = "";
        try {
            ip = InetAddress.getByName(hostname).getHostAddress();
        } catch (Exception e) {
            CMS.debug("Unable to determine IP address for "+hostname);
        }

        // assign cookie
        Long num = random.nextLong();
        String cookie = num.toString();

        String auditParams = "operation;;issue_token+token;;" + cookie + "+ip;;" + ip +
                      "+uid;;" + user + "+groupname;;" + groupname;

        ISecurityDomainSessionTable ctable = CMS.getSecurityDomainSessionTable();
        int status = ctable.addEntry(cookie, ip, user, groupname);

        if (status == ISecurityDomainSessionTable.SUCCESS) {
            message = CMS.getLogMessage(
                               LOGGING_SIGNED_AUDIT_SECURITY_DOMAIN_UPDATE,
                               user,
                               ILogger.SUCCESS,
                               auditParams);
            audit(message);

        } else {
            message = CMS.getLogMessage(
                               LOGGING_SIGNED_AUDIT_SECURITY_DOMAIN_UPDATE,
                               user,
                               ILogger.FAILURE,
                               auditParams);
            audit(message);

            throw new PKIException("Failed to update security domain.");
        }


        return new InstallToken(cookie);
    }
}
