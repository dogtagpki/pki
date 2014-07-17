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
// (C) 2007, 2014, 2015  Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.profile;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.certsrv.registry.IPluginRegistry;
import com.netscape.cmscore.base.LDAPConfigStore;

public class LDAPProfileSubsystem
        extends AbstractProfileSubsystem
        implements IProfileSubsystem {

    private String dn;
    private ILdapConnFactory dbFactory;

    /**
     * Initializes this subsystem with the given configuration
     * store.
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration store
     * @exception EBaseException failed to initialize
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        CMS.debug("LDAPProfileSubsystem: start init");

        // (re)init member collections
        mProfileIds = new Vector<String>();
        mProfiles = new Hashtable<String, IProfile>();
        mProfileClassIds = new Hashtable<String, String>();

        IPluginRegistry registry = (IPluginRegistry)
                CMS.getSubsystem(CMS.SUBSYSTEM_REGISTRY);

        IConfigStore cs = CMS.getConfigStore();
        IConfigStore dbCfg = cs.getSubStore("internaldb");
        dbFactory = CMS.getLdapBoundConnFactory();
        dbFactory.init(dbCfg);

        mConfig = config;
        mOwner = owner;

        // Configuration File Format:
        // *.list=profile1,profile2
        // *.profile1.class=com.netscape.cms.profile.common.BasicProfile
        // *.profile1.config=config/profiles/profile1.cfg
        // *.profile2.class=com.netscape.cms.profile.common.BasicProfile
        // *.profile2.config=config/profiles/profile2.cfg

        // read profile id, implementation, and its configuration files
        String basedn = cs.getString("internaldb.basedn");
        String dn = "ou=certificateProfiles,ou=ca," + basedn;
        LDAPConnection conn = dbFactory.getConn();

        String[] attrs = {"cn", "classId"};
        try {
            LDAPSearchResults ldapProfiles = conn.search(
                dn, LDAPConnection.SCOPE_ONE, "(objectclass=*)", attrs, false);

            while (ldapProfiles.hasMoreElements()) {
                String id = "<unknown>";
                try {
                    LDAPEntry ldapProfile = ldapProfiles.next();

                    id = (String)
                        ldapProfile.getAttribute("cn").getStringValues().nextElement();

                    String classid = (String)
                        ldapProfile.getAttribute("classId").getStringValues().nextElement();

                    IPluginInfo info = registry.getPluginInfo("profile", classid);
                    if (info == null) {
                        CMS.debug("Error loading profile: No plugins for type : profile, with id " + classid);
                    } else {
                        CMS.debug("Start Profile Creation - " + id + " " + classid + " " + info.getClassName());
                        createProfile(id, classid, info.getClassName());
                        CMS.debug("Done Profile Creation - " + id);
                    }
                } catch (LDAPException e) {
                    CMS.debug("Error reading profile '" + id + "'; skipping.");
                }
            }
        } catch (LDAPException e) {
            throw new EBaseException("Error reading profiles: " + e.toString());
        } finally {
            try {
                dbFactory.returnConn(conn);
            } catch (Exception e) {
                throw new EProfileException("Error releasing the ldap connection" + e.toString());
            }
        }

        Enumeration<String> ee = getProfileIds();

        while (ee.hasMoreElements()) {
            String id = ee.nextElement();

            CMS.debug("Registered Confirmation - " + id);
        }
    }

    /**
     * Creates a profile instance.
     */
    public IProfile createProfile(String id, String classid, String className)
            throws EProfileException {
        try {
            String[] objectClasses = {"top", "certProfile"};
            LDAPAttribute[] createAttrs = {
                new LDAPAttribute("objectclass", objectClasses),
                new LDAPAttribute("cn", id),
                new LDAPAttribute("classId", classid)
            };

            IConfigStore subStoreConfig = new LDAPConfigStore(
                dbFactory, createProfileDN(id), createAttrs, "certProfileConfig");

            CMS.debug("LDAPProfileSubsystem: initing " + className);
            IProfile profile = (IProfile) Class.forName(className).newInstance();
            profile.setId(id);
            profile.init(this, subStoreConfig);
            mProfileIds.addElement(id);
            mProfiles.put(id, profile);
            mProfileClassIds.put(id, classid);
            return profile;
        } catch (Exception e) {
            throw new EProfileException("Error creating or reading profile", e);
        }
    }

    public void deleteProfile(String id) throws EProfileException {
        if (isProfileEnable(id)) {
            throw new EProfileException("CMS_PROFILE_DELETE_ENABLEPROFILE");
        }

        LDAPConnection conn;
        try {
            conn = dbFactory.getConn();
        } catch (ELdapException e) {
            throw new EProfileException("Error acquiring the ldap connection", e);
        }
        try {
            conn.delete(createProfileDN(id));
        } catch (LDAPException e) {
            throw new EProfileException("CMS_PROFILE_DELETE_ERROR", e);
        } finally {
            try {
                dbFactory.returnConn(conn);
            } catch (Exception e) {
                throw new EProfileException("Error releasing the ldap connection", e);
            }
        }

        mProfileIds.removeElement(id);
        mProfiles.remove(id);
        mProfileClassIds.remove(id);
    }

    /**
     * Notifies this subsystem if owner is in running mode.
     */
    public void startup() throws EBaseException {
        CMS.debug("LDAPProfileSubsystem: startup");
    }

    /**
     * Stops this system. The owner may call shutdown
     * anytime after initialization.
     * <P>
     */
    public void shutdown() {
        mProfileIds.clear();
        mProfiles.clear();
        mProfileClassIds.clear();
    }

    /**
     * Compute the profile DN given an ID.
     */
    private String createProfileDN(String id) throws EProfileException {
        if (id == null) {
            throw new EProfileException("CMS_PROFILE_ID_NOT_FOUND");
        }
        String basedn;
        try {
            basedn = CMS.getConfigStore().getString("internaldb.basedn");
        } catch (EBaseException e) {
            throw new EProfileException("CMS_PROFILE_DELETE_UNKNOWNPROFILE");
        }
        return "cn=" + id + ",ou=certificateProfiles,ou=ca," + basedn;
    }
}
