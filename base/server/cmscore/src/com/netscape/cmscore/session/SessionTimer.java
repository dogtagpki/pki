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
package com.netscape.cmscore.session;

import java.util.Date;
import java.util.Enumeration;
import java.util.TimerTask;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;

public class SessionTimer extends TimerTask {

    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    private ISecurityDomainSessionTable m_sessiontable = null;

    public SessionTimer(ISecurityDomainSessionTable table) {
        super();
        m_sessiontable = table;
    }

    public void run() {
        CMS.debug("SessionTimer: run()");
        try {
            runImpl();
        } catch (Exception e) {
            CMS.debug(e);
        }
    }

    public void runImpl() throws Exception {

        Enumeration<String> keys = m_sessiontable.getSessionIDs();
        while (keys.hasMoreElements()) {
            String sessionId = keys.nextElement();
            long beginTime = m_sessiontable.getBeginTime(sessionId);
            Date nowDate = new Date();
            long nowTime = nowDate.getTime();
            long timeToLive = m_sessiontable.getTimeToLive();
            if ((nowTime - beginTime) > timeToLive) {
                m_sessiontable.removeEntry(sessionId);
                CMS.debug("SessionTimer run: successfully remove the session id entry from the table.");

                // audit message
                String auditParams = "operation;;expire_token+token;;" + sessionId;
                String auditMessage = CMS.getLogMessage(
                                         AuditEvent.SECURITY_DOMAIN_UPDATE,
                                         "system",
                                         ILogger.SUCCESS,
                                         auditParams);

                signedAuditLogger.log(auditMessage);

            }
        }
    }
}
