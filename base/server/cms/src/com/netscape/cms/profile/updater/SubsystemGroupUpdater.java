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
package com.netscape.cms.profile.updater;

import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileUpdater;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;

/**
 * This updater class will create the new user to the subsystem group and
 * then add the subsystem certificate to the user.
 *
 * @version $Revision$, $Date$
 */
public class SubsystemGroupUpdater implements IProfileUpdater {

    @SuppressWarnings("unused")
    private IProfile mProfile;
    private IConfigStore mConfig = null;
    private ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();
    private Vector<String> mConfigNames = new Vector<String>();

    private final static String LOGGING_SIGNED_AUDIT_CONFIG_ROLE =
            "LOGGING_SIGNED_AUDIT_CONFIG_ROLE_3";

    public SubsystemGroupUpdater() {
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        mConfig = config;
        mProfile = profile;
    }

    public Enumeration<String> getConfigNames() {
        return mConfigNames.elements();
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
        if (mConfig.getSubStore("params") == null) {
            //
        } else {
            mConfig.getSubStore("params").putString(name, value);
        }
    }

    public String getConfig(String name) {
        try {
            if (mConfig == null) {
                return null;
            }
            if (mConfig.getSubStore("params") != null) {
                return mConfig.getSubStore("params").getString(name);
            }
        } catch (EBaseException e) {
        }
        return "";
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public void update(IRequest req, RequestStatus status)
            throws EProfileException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        CMS.debug("SubsystemGroupUpdater update starts");
        if (status != req.getRequestStatus()) {
            return;
        }

        X509CertImpl cert = req.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);
        if (cert == null)
            return;

        IConfigStore mainConfig = CMS.getConfigStore();

        int num = 0;
        try {
            num = mainConfig.getInteger("subsystem.count", 0);
        } catch (Exception e) {
        }

        IUGSubsystem system = (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));

        String requestor_name = "subsystem";
        try {
            requestor_name = req.getExtDataInString("requestor_name");
        } catch (Exception e1) {
            // ignore
        }

        // i.e. tps-1.2.3.4-4
        String id = requestor_name;

        num++;
        mainConfig.putInteger("subsystem.count", num);

        try {
            mainConfig.commit(false);
        } catch (Exception e) {
        }
        String auditParams = "Scope;;users+Operation;;OP_ADD+source;;SubsystemGroupUpdater" +
                             "+Resource;;" + id +
                             "+fullname;;" + id +
                             "+state;;1" +
                             "+userType;;agentType+email;;<null>+password;;<null>+phone;;<null>";

        IUser user = null;
        CMS.debug("SubsystemGroupUpdater adduser");
        try {
            user = system.createUser(id);
            user.setFullName(id);
            user.setEmail("");
            user.setPassword("");
            user.setUserType("agentType");
            user.setState("1");
            user.setPhone("");
            X509CertImpl[] certs = new X509CertImpl[1];
            certs[0] = cert;
            user.setX509Certificates(certs);

            system.addUser(user);
            CMS.debug("SubsystemGroupUpdater update: successfully add the user");
            auditMessage = CMS.getLogMessage(
                               LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                               auditSubjectID,
                               ILogger.SUCCESS,
                               auditParams);
            audit(auditMessage);

            String b64 = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
            try {
                byte[] certEncoded = cert.getEncoded();
                b64 = CMS.BtoA(certEncoded).trim();

                // extract all line separators
                StringBuffer sb = new StringBuffer();
                for (int i = 0; i < b64.length(); i++) {
                    if (!Character.isWhitespace(b64.charAt(i))) {
                        sb.append(b64.charAt(i));
                    }
                }
                b64 = sb.toString();
            } catch (Exception ence) {
                CMS.debug("SubsystemGroupUpdater update: user cert encoding failed: " + ence);
            }

            auditParams = "Scope;;certs+Operation;;OP_ADD+source;;SubsystemGroupUpdater" +
                             "+Resource;;" + id +
                             "+cert;;" + b64;

            system.addUserCert(user);
            CMS.debug("SubsystemGroupUpdater update: successfully add the user certificate");
            auditMessage = CMS.getLogMessage(
                               LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                               auditSubjectID,
                               ILogger.SUCCESS,
                               auditParams);
            audit(auditMessage);

        } catch (ConflictingOperationException e) {
            CMS.debug("UpdateSubsystemGroup: update " + e.toString());
            // ignore

        } catch (Exception e) {
            CMS.debug("UpdateSubsystemGroup: update addUser " + e.toString());
            auditMessage = CMS.getLogMessage(
                               LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                               auditSubjectID,
                               ILogger.FAILURE,
                               auditParams);
            audit(auditMessage);
            throw new EProfileException(e.toString());
        }

        IGroup group = null;
        String groupName = "Subsystem Group";
        auditParams = "Scope;;groups+Operation;;OP_MODIFY+source;;SubsystemGroupUpdater" +
                      "+Resource;;" + groupName;

        try {
            group = system.getGroupFromName(groupName);

            auditParams += "+user;;";
            Enumeration<String> members = group.getMemberNames();
            while (members.hasMoreElements()) {
                auditParams += members.nextElement();
                if (members.hasMoreElements()) {
                    auditParams += ",";
                }
            }

            if (!group.isMember(id)) {
                auditParams += "," + id;
                group.addMemberName(id);
                system.modifyGroup(group);

                auditMessage = CMS.getLogMessage(
                               LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                               auditSubjectID,
                               ILogger.SUCCESS,
                               auditParams);
                audit(auditMessage);

                CMS.debug("UpdateSubsystemGroup: update: successfully added the user to the group.");
            } else {
                CMS.debug("UpdateSubsystemGroup: update: user already a member of the group");
            }
        } catch (Exception e) {
            CMS.debug("UpdateSubsystemGroup update: modifyGroup " + e.toString());
            auditMessage = CMS.getLogMessage(
                               LOGGING_SIGNED_AUDIT_CONFIG_ROLE,
                               auditSubjectID,
                               ILogger.FAILURE,
                               auditParams);
            audit(auditMessage);
        }
    }

    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_UPDATER_SUBSYSTEM_NAME");
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_UPDATER_SUBSYSTEM_TEXT");
    }

    private void audit(String msg) {
        if (mSignedAuditLogger == null) {
            return;
        }

        mSignedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                msg);
    }

    private String auditSubjectID() {
        if (mSignedAuditLogger == null) {
            return null;
        }

        String subjectID = null;

        // Initialize subjectID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            subjectID = (String)
                    auditContext.get(SessionContext.USER_ID);

            if (subjectID != null) {
                subjectID = subjectID.trim();
            } else {
                subjectID = ILogger.NONROLEUSER;
            }
        } else {
            subjectID = ILogger.UNIDENTIFIED;
        }
        return subjectID;
    }
}
