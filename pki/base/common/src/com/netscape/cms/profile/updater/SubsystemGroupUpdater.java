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

import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.base.*;
import com.netscape.cms.profile.common.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.request.*;
import netscape.security.x509.*;
import netscape.ldap.*;
import java.util.*;

/**
 * This updater class will create the new user to the subsystem group and
 * then add the subsystem certificate to the user.
 * 
 * @version $Revision: $, $Date: $
 */
public class SubsystemGroupUpdater implements IProfileUpdater {

    public IProfile mProfile = null;
    public EnrollProfile mEnrollProfile = null;
    public IConfigStore mConfig = null;
    public ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();
    public Vector mConfigNames = new Vector();
    public Vector mValueNames = new Vector();

    public SubsystemGroupUpdater() {
    }

    public void init(IProfile profile, IConfigStore config) 
      throws EProfileException {
        mConfig = config;
        mProfile = profile;
        mEnrollProfile = (EnrollProfile) profile;
    }

    public Enumeration getConfigNames() {
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
    
        CMS.debug("SubsystemGroupUpdater update starts");
        if (status != req.getRequestStatus()) {
            return;
        }

        X509CertImpl cert = req.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);
        if (cert == null)
            return;

        IConfigStore mainConfig = CMS.getConfigStore();
        
        int num=0;
        try {
            num = mainConfig.getInteger("subsystem.count", 0);
        } catch (Exception e) {}

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
            system.addUserCert(user);
            CMS.debug("SubsystemGroupUpdater update: successfully add the user certificate");
        } catch (LDAPException e) {
            CMS.debug("UpdateSubsystemGroup: update " + e.toString());
            if (e.getLDAPResultCode() != LDAPException.ENTRY_ALREADY_EXISTS) {
                throw new EProfileException(e.toString()); 
            }
        } catch (Exception e) {
            CMS.debug("UpdateSubsystemGroup: update addUser " + e.toString());
            throw new EProfileException(e.toString());
        }

        IGroup group = null;
        String groupName = "Subsystem Group";

        try {
            group = system.getGroupFromName(groupName);
            if (!group.isMember(id)) {
                group.addMemberName(id);
                system.modifyGroup(group);
                CMS.debug("UpdateSubsystemGroup: update: successfully added the user to the group.");
            }
        } catch (Exception e) {
            CMS.debug("UpdateSubsystemGroup update: modifyGroup " + e.toString());
        }
    }

    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_UPDATER_SUBSYSTEM_NAME");
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_UPDATER_SUBSYSTEM_TEXT");
    }
}
