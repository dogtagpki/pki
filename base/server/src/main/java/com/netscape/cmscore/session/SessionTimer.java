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

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.SecurityDomainSessionTable;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.logging.Auditor;

public class SessionTimer extends TimerTask {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SessionTimer.class);

    protected CMSEngine engine;
    private SecurityDomainSessionTable m_sessiontable = null;

    public SessionTimer(SecurityDomainSessionTable table) {
        super();
        m_sessiontable = table;
    }

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    @Override
    public void run() {
        try {
            runImpl();
        } catch (Exception e) {
            logger.warn("SessionTimer: " + e.getMessage(), e);
        }
    }

    public void runImpl() throws Exception {

        logger.info("SessionTimer: checking security domain sessions");

        Auditor auditor = engine.getAuditor();
        Enumeration<String> keys = m_sessiontable.getSessionIDs();

        while (keys.hasMoreElements()) {
            String sessionId = keys.nextElement();
            long beginTime = m_sessiontable.getBeginTime(sessionId);
            Date nowDate = new Date();
            long nowTime = nowDate.getTime();
            long timeToLive = m_sessiontable.getTimeToLive();

            if ((nowTime - beginTime) <= timeToLive) continue;

            logger.info("SessionTimer: Removing expired session: " + sessionId);
            String auditParams = "operation;;expire_token+token;;" + sessionId;

            try {
                m_sessiontable.removeEntry(sessionId);

                String message = CMS.getLogMessage(
                        AuditEvent.SECURITY_DOMAIN_UPDATE,
                        "system",
                        ILogger.SUCCESS,
                        auditParams);
                auditor.log(message);

            } catch (Exception e) {
                String message = CMS.getLogMessage(
                        AuditEvent.SECURITY_DOMAIN_UPDATE,
                        "system",
                        ILogger.FAILURE,
                        auditParams);
                 auditor.log(message);

                 throw new PKIException("Unable to remove expired session: " + e.getMessage(), e);
            }
        }
    }
}
