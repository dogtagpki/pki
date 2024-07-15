//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.dogtagpki.server.rest.v2.PKIServlet;
import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;

import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.User;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class TPSServlet extends PKIServlet {
    public static final long serialVersionUID = 1L;

    protected TPSEngine getTPSEngine() {
        ServletContext servletContext = getServletContext();
        return (TPSEngine) servletContext.getAttribute("engine");
    }

    protected TPSSubsystem getTPSSubsystem() {
        ServletContext servletContext = getServletContext();
        TPSEngine engine = (TPSEngine) servletContext.getAttribute("engine");

        return (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
    }

    /*
     * returns a list of TPS profiles allowed for the current user
     */
    protected List<String> getAuthorizedProfiles(HttpServletRequest req) {
        SessionContext context = SessionContext.getContext();
        User user = (User) context.get(SessionContext.USER);
        if (user == null) {
            return Collections.emptyList();
        }
        return user.getTpsProfiles();
    }

    @Override
    protected String getSubsystemName() {
        return getTPSEngine().getID();
    }


    protected void audit(String message, String scope, String type, String id, Map<String, String> params, String status) {

        CMSEngine engine = getTPSEngine();
        Auditor auditor = engine.getAuditor();
        String auditMessage = CMS.getLogMessage(
                message,
                auditor.getSubjectID(),
                status,
                auditor.getParamString(scope, type, id, params));

        auditor.log(auditMessage);
    }

    protected void auditConfigTokenGeneral(String status, String service, Map<String, String> params, String info) {

        SessionContext context = SessionContext.getContext();
        CMSEngine engine = getTPSEngine();
        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_GENERAL,
                context.get(SessionContext.USER_ID),
                status,
                service,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }

    /*
     * Service can be any of the methods offered
     */
    protected void auditConfigTokenRecord(String status, String service, String tokenID, Map<String, String> params,
            String info) {

        SessionContext context = SessionContext.getContext();
        CMSEngine engine = getTPSEngine();
        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_RECORD,
                context.get(SessionContext.USER_ID),
                status,
                service,
                tokenID,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }
    /*
    *
    */
    protected void auditTokenStateChange(String status, TokenStatus oldState, TokenStatus newState, String oldReason,
           String newReason, Map<String, String> params, String info) {
        SessionContext context = SessionContext.getContext();
        CMSEngine engine = getTPSEngine();
        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.TOKEN_STATE_CHANGE,
                context.get(SessionContext.USER_ID),
                status,
                (oldState==null)? "":oldState.toString(),
                oldReason,
                (newState==null)? "":newState.toString(),
                newReason,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }
}
