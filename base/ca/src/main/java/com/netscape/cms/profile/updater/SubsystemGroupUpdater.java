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

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigRoleEvent;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;

/**
 * This updater class will create the new user to the subsystem group and
 * then add the subsystem certificate to the user.
 *
 * This code is used in caInternalAuthSubsystemCert and
 * caECInternalAuthSubsystemCert profiles.
 *
 * See also UpdateConnector.
 */
public class SubsystemGroupUpdater extends ProfileUpdater {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SubsystemGroupUpdater.class);

    private ConfigStore mConfig;

    private Vector<String> mConfigNames = new Vector<>();

    public SubsystemGroupUpdater() {
    }

    @Override
    public void init(ConfigStore config) throws EProfileException {
        mConfig = config;
    }

    @Override
    public Enumeration<String> getConfigNames() {
        return mConfigNames.elements();
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    @Override
    public void setConfig(String name, String value)
            throws EPropertyException {
        if (mConfig.getSubStore("params") == null) {
            //
        } else {
            mConfig.getSubStore("params").putString(name, value);
        }
    }

    @Override
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

    @Override
    public ConfigStore getConfigStore() {
        return mConfig;
    }

    @Override
    public void update(Request req, RequestStatus status)
            throws EProfileException {

        CAEngine engine = CAEngine.getInstance();

        Auditor auditor = engine.getAuditor();
        String auditSubjectID = auditSubjectID();

        logger.info("SubsystemGroupUpdater: Updating Subsystem Group");
        if (status != req.getRequestStatus()) {
            return;
        }

        X509CertImpl cert = req.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
        if (cert == null)
            return;

        UGSubsystem system = engine.getUGSubsystem();

        String requestor_name = "subsystem";
        try {
            requestor_name = req.getExtDataInString("requestor_name");
        } catch (Exception e) {
            logger.warn("SubsystemGroupUpdater: Unable to get requestor name: " + e.getMessage(), e);
        }

        // i.e. tps-1.2.3.4-4
        String id = requestor_name;

        String auditParams = "Scope;;users+Operation;;OP_ADD+source;;SubsystemGroupUpdater" +
                             "+Resource;;" + id +
                             "+fullname;;" + id +
                             "+state;;1" +
                             "+userType;;agentType+email;;<null>+password;;<null>+phone;;<null>";

        logger.info("SubsystemGroupUpdater: Adding user " + id);

        try {
            User user = system.createUser(id);
            user.setFullName(id);
            user.setEmail("");
            user.setPassword("");
            user.setUserType("agentType");
            user.setState("1");
            user.setPhone("");

            system.addUser(user);

            auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.SUCCESS,
                               auditParams));

        } catch (ConflictingOperationException e) {
            logger.warn("UpdateSubsystemGroup: User already exists: " + e.getMessage(), e);

        } catch (Exception e) {
            logger.error("UpdateSubsystemGroup: Unable to add user: " + e.getMessage(), e);

            auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.FAILURE,
                               auditParams));

            throw new EProfileException("Unable to add user: " + e.getMessage(), e);
        }

        logger.info("SubsystemGroupUpdater: Adding certificate for user " + id);

        try {
            String b64 = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
            try {
                byte[] certEncoded = cert.getEncoded();
                b64 = Utils.base64encode(certEncoded, true).trim();

                // concatenate lines
                b64 = b64.replace("\r", "").replace("\n", "");

            } catch (Exception e) {
                logger.warn("SubsystemGroupUpdater: Unable to encode certificate: " + e.getMessage(), e);
            }

            auditParams = "Scope;;certs+Operation;;OP_ADD+source;;SubsystemGroupUpdater" +
                             "+Resource;;" + id +
                             "+cert;;" + b64;

            system.addUserCert(id, cert);

            auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.SUCCESS,
                               auditParams));

        } catch (ConflictingOperationException e) {
            logger.warn("UpdateSubsystemGroup: Certificate already exists: " + e.getMessage(), e);

        } catch (Exception e) {
            logger.error("UpdateSubsystemGroup: Unable to add certificate for user " + id + ": " + e.getMessage(), e);

            auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.FAILURE,
                               auditParams));

            throw new EProfileException("Unable to add certificate: " + e.getMessage(), e);
        }

        String groupName = "Subsystem Group";
        logger.info("SubsystemGroupUpdater: Adding user " + id + " into group " + groupName);

        auditParams = "Scope;;groups+Operation;;OP_MODIFY+source;;SubsystemGroupUpdater" +
                      "+Resource;;" + groupName;

        try {
            Group group = system.getGroupFromName(groupName);

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

                auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.SUCCESS,
                               auditParams));

            } else {
                logger.info("SubsystemGroupUpdater: User " + id + " already in group " + groupName);
            }

        } catch (Exception e) {
            logger.warn("SubsystemGroupUpdater: Unable to add user " + id + " into group " + groupName + ": " + e.getMessage(), e);

            auditor.log(new ConfigRoleEvent(
                               auditSubjectID,
                               ILogger.FAILURE,
                               auditParams));
        }
    }

    @Override
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_UPDATER_SUBSYSTEM_NAME");
    }

    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_UPDATER_SUBSYSTEM_TEXT");
    }

    private String auditSubjectID() {

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
