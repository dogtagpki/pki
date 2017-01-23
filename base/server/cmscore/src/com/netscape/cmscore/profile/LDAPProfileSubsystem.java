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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPDN;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.controls.LDAPEntryChangeControl;
import netscape.ldap.controls.LDAPPersistSearchControl;
import netscape.ldap.util.DN;

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
import com.netscape.cmsutil.ldap.LDAPUtil;

public class LDAPProfileSubsystem
        extends AbstractProfileSubsystem
        implements IProfileSubsystem, Runnable {

    private String dn;
    private ILdapConnFactory dbFactory;

    private boolean stopped = false;
    private Thread monitor;

    /* Map of profileId -> entryUSN for the most recent view
     * of the profile entry that this instance has seen */
    private TreeMap<String,BigInteger> entryUSNs;

    private TreeMap<String,String> nsUniqueIds;

    /* Set of nsUniqueIds of deleted entries */
    private TreeSet<String> deletedNsUniqueIds;

    /* Variables to track initial loading of profiles */
    private Integer initialNumProfiles = null;
    private int numProfilesLoaded = 0;
    private CountDownLatch initialLoadDone = new CountDownLatch(1);

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
        mProfiles = new LinkedHashMap<String, IProfile>();
        mProfileClassIds = new Hashtable<String, String>();
        entryUSNs = new TreeMap<>();
        nsUniqueIds = new TreeMap<>();
        deletedNsUniqueIds = new TreeSet<>();

        IConfigStore cs = CMS.getConfigStore();
        IConfigStore dbCfg = cs.getSubStore("internaldb");
        dbFactory = CMS.getLdapBoundConnFactory("LDAPProfileSubsystem");
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
        dn = "ou=certificateProfiles,ou=ca," + basedn;

        monitor = new Thread(this, "profileChangeMonitor");
        monitor.start();
        try {
            initialLoadDone.await();
        } catch (InterruptedException e) {
            CMS.debug("LDAPProfileSubsystem: caught InterruptedException "
                    + "while waiting for initial load of profiles.");
        }
        CMS.debug("LDAPProfileSubsystem: finished init");
    }

    /**
     * Read the given LDAPEntry into the profile subsystem.
     */
    private synchronized void readProfile(LDAPEntry ldapProfile) {
        IPluginRegistry registry = (IPluginRegistry)
            CMS.getSubsystem(CMS.SUBSYSTEM_REGISTRY);

        String nsUniqueId =
            ldapProfile.getAttribute("nsUniqueId").getStringValueArray()[0];
        if (deletedNsUniqueIds.contains(nsUniqueId)) {
            CMS.debug("readProfile: ignoring entry with nsUniqueId '"
                    + nsUniqueId + "' due to deletion");
            return;
        }

        String profileId = null;
        String dn = ldapProfile.getDN();
        if (!dn.startsWith("cn=")) {
            CMS.debug("Error reading profile entry: DN " + dn + " does not start with 'cn='");
            return;
        }
        profileId = LDAPDN.explodeDN(dn, true)[0];

        BigInteger newEntryUSN = new BigInteger(
                ldapProfile.getAttribute("entryUSN").getStringValueArray()[0]);
        CMS.debug("readProfile: new entryUSN = " + newEntryUSN);

        BigInteger knownEntryUSN = entryUSNs.get(profileId);
        if (knownEntryUSN != null) {
            CMS.debug("readProfile: known entryUSN = " + knownEntryUSN);
            if (newEntryUSN.compareTo(knownEntryUSN) <= 0) {
                CMS.debug("readProfile: data is current");
                return;
            }
        }

        String classId = (String)
            ldapProfile.getAttribute("classId").getStringValues().nextElement();

        InputStream data = new ByteArrayInputStream(
                ldapProfile.getAttribute("certProfileConfig").getByteValueArray()[0]);

        IPluginInfo info = registry.getPluginInfo("profile", classId);
        if (info == null) {
            CMS.debug("Error loading profile: No plugins for type : profile, with classId " + classId);
        } else {
            try {
                CMS.debug("Start Profile Creation - " + profileId + " " + classId + " " + info.getClassName());
                createProfile(profileId, classId, info.getClassName(), data);
                entryUSNs.put(profileId, newEntryUSN);
                nsUniqueIds.put(profileId, nsUniqueId);
                CMS.debug("Done Profile Creation - " + profileId);
            } catch (EProfileException e) {
                CMS.debug("Error creating profile '" + profileId + "'; skipping.");
            }
        }
    }

    public synchronized IProfile createProfile(String id, String classid, String className)
            throws EProfileException {
        return createProfile(id, classid, className, null);
    }

    /**
     * Creates a profile instance.
     *
     * createProfile could theoretically be called simultaneously
     * with the same profileId from Monitor and ProfileService,
     * so the method is synchronized.
     */
    private synchronized IProfile createProfile(
            String id, String classid, String className, InputStream data)
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
            if (data != null)
                subStoreConfig.load(data);

            CMS.debug("LDAPProfileSubsystem: initing " + className);
            IProfile profile = (IProfile) Class.forName(className).newInstance();
            profile.setId(id);
            profile.init(this, subStoreConfig);
            mProfiles.put(id, profile);
            mProfileClassIds.put(id, classid);
            return profile;
        } catch (Exception e) {
            throw new EProfileException("Error creating or reading profile", e);
        }
    }

    public synchronized void deleteProfile(String id) throws EProfileException {
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

        deletedNsUniqueIds.add(nsUniqueIds.get(id));
        forgetProfile(id);
    }

    private synchronized void handleDELETE(LDAPEntry entry) {
        LDAPAttribute attr = entry.getAttribute("nsUniqueId");
        String nsUniqueId = null;
        if (attr != null)
            nsUniqueId = attr.getStringValueArray()[0];

       if (deletedNsUniqueIds.remove(nsUniqueId)) {
            CMS.debug("handleDELETE: delete was already effected");
            return;
        }

        String profileId = null;
        String dn = entry.getDN();
        if (!dn.startsWith("cn=")) {
            CMS.debug("handleDELETE: DN " + dn + " does not start with 'cn='");
            return;
        }
        profileId = LDAPDN.explodeDN(dn, true)[0];
        forgetProfile(profileId);
    }

    private synchronized void handleMODDN(DN oldDN, LDAPEntry entry) {
        DN profilesDN = new DN(dn);

        if (oldDN.isDescendantOf(profilesDN))
            forgetProfile(oldDN.explodeDN(true)[0]);

        if ((new DN(entry.getDN())).isDescendantOf(profilesDN))
            readProfile(entry);
    }

    @Override
    public synchronized void commitProfile(String id) throws EProfileException {
        LDAPConfigStore cs = (LDAPConfigStore) mProfiles.get(id).getConfigStore();

        // first create a *new* profile object from the configStore
        // and initialise it with the updated configStore
        //
        IPluginRegistry registry = (IPluginRegistry)
            CMS.getSubsystem(CMS.SUBSYSTEM_REGISTRY);
        String classId = mProfileClassIds.get(id);
        IPluginInfo info = registry.getPluginInfo("profile", classId);
        String className = info.getClassName();
        IProfile newProfile = null;
        try {
            newProfile = (IProfile) Class.forName(className).newInstance();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new EProfileException("Could not instantiate class '"
                    + classId + "' for profile '" + id + "': " + e);
        }
        newProfile.setId(id);
        try {
            newProfile.init(this, cs);
        } catch (EBaseException e) {
            throw new EProfileException(
                    "Failed to initialise profile '" + id + "': " + e);
        }

        // next replace the existing profile with the new profile;
        // this is to avoid any intermediate state where the profile
        // is not fully initialised with its inputs, outputs and
        // policy objects.
        //
        mProfiles.put(id, newProfile);

        // finally commit the configStore and track the resulting
        // entryUSN and (in case of add) the nsUniqueId
        //
        try {
            String[] attrs = {"entryUSN", "nsUniqueId"};
            LDAPEntry entry = cs.commitReturn(false, attrs);
            if (entry == null) {
                // shouldn't happen, but let's be sure not to crash anyway
                return;
            }

            BigInteger entryUSN = null;
            LDAPAttribute attr = entry.getAttribute("entryUSN");
            if (attr != null)
                entryUSN = new BigInteger(attr.getStringValueArray()[0]);
            entryUSNs.put(id, entryUSN);
            CMS.debug("commitProfile: new entryUSN = " + entryUSN);

            String nsUniqueId = null;
            attr = entry.getAttribute("nsUniqueId");
            if (attr != null)
                nsUniqueId = attr.getStringValueArray()[0];
            CMS.debug("commitProfile: nsUniqueId = " + nsUniqueId);
            nsUniqueIds.put(id, nsUniqueId);
        } catch (ELdapException e) {
            throw new EProfileException(
                "Failed to commit config store of profile '" + id + ": " + e);
        }
    }

    /**
     * Forget a profile without deleting it from the database.
     *
     * This method is used when the profile change monitor receives
     * notification that a profile was deleted.
     */
    private void forgetProfile(String id) {
        mProfiles.remove(id);
        mProfileClassIds.remove(id);
        entryUSNs.remove(id);
        nsUniqueIds.remove(id);
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
        stopped = true;
        monitor = null;
        forgetAllProfiles();
    }

    private void forgetAllProfiles() {
        mProfiles.clear();
        mProfileClassIds.clear();
        entryUSNs.clear();
        nsUniqueIds.clear();
        deletedNsUniqueIds.clear();
    }

    /**
     * Compute the profile DN given an ID.
     */
    private String createProfileDN(String id) throws EProfileException {
        if (id == null) {
            throw new EProfileException("CMS_PROFILE_ID_NOT_FOUND");
        }
        return "cn=" + id + "," + dn;
    }

    private void checkInitialLoadDone() {
        if (initialNumProfiles != null
                && numProfilesLoaded >= initialNumProfiles)
            initialLoadDone.countDown();
    }

    private void ensureProfilesOU(LDAPConnection conn) throws LDAPException {
        try {
            conn.search(dn, LDAPConnection.SCOPE_BASE, "(objectclass=*)", null, false);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                CMS.debug("Adding LDAP certificate profiles container");
                LDAPAttribute[] attrs = {
                    new LDAPAttribute("objectClass", "organizationalUnit"),
                    new LDAPAttribute("ou", "certificateProfiles")
                };
                LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);
                LDAPEntry entry = new LDAPEntry(dn, attrSet);
                conn.add(entry);
            }
        }
    }

    public void run() {
        int op = LDAPPersistSearchControl.ADD
            | LDAPPersistSearchControl.MODIFY
            | LDAPPersistSearchControl.DELETE
            | LDAPPersistSearchControl.MODDN;
        LDAPPersistSearchControl persistCtrl =
            new LDAPPersistSearchControl(op, false, true, true);

        LDAPConnection conn = null;

        CMS.debug("Profile change monitor: starting.");

        while (!stopped) {
            forgetAllProfiles();
            try {
                conn = dbFactory.getConn();
                ensureProfilesOU(conn);
                LDAPSearchConstraints cons = conn.getSearchConstraints();
                cons.setServerControls(persistCtrl);
                cons.setBatchSize(1);
                cons.setServerTimeLimit(0 /* seconds */);
                String[] attrs = {"*", "entryUSN", "nsUniqueId", "numSubordinates"};
                LDAPSearchResults results = conn.search(
                    dn, LDAPConnection.SCOPE_SUB, "(objectclass=*)",
                    attrs, false, cons);
                while (!stopped && results.hasMoreElements()) {
                    LDAPEntry entry = results.next();

                    String[] objectClasses =
                        entry.getAttribute("objectClass").getStringValueArray();
                    if (Arrays.asList(objectClasses).contains("organizationalUnit")) {
                        initialNumProfiles = new Integer(
                            entry.getAttribute("numSubordinates")
                                .getStringValueArray()[0]);
                        checkInitialLoadDone();
                        continue;
                    }

                    LDAPEntryChangeControl changeControl = (LDAPEntryChangeControl)
                        LDAPUtil.getControl(
                            LDAPEntryChangeControl.class, results.getResponseControls());
                    CMS.debug("Profile change monitor: Processed change controls.");
                    if (changeControl != null) {
                        int changeType = changeControl.getChangeType();
                        switch (changeType) {
                        case LDAPPersistSearchControl.ADD:
                            CMS.debug("Profile change monitor: ADD");
                            readProfile(entry);
                            break;
                        case LDAPPersistSearchControl.DELETE:
                            CMS.debug("Profile change monitor: DELETE");
                            handleDELETE(entry);
                            break;
                        case LDAPPersistSearchControl.MODIFY:
                            CMS.debug("Profile change monitor: MODIFY");
                            readProfile(entry);
                            break;
                        case LDAPPersistSearchControl.MODDN:
                            CMS.debug("Profile change monitor: MODDN");
                            handleMODDN(new DN(changeControl.getPreviousDN()), entry);
                            break;
                        default:
                            CMS.debug("Profile change monitor: unknown change type: " + changeType);
                            break;
                        }
                    } else {
                        CMS.debug("Profile change monitor: immediate result");
                        readProfile(entry);
                        numProfilesLoaded += 1;
                        checkInitialLoadDone();
                    }
                }
            } catch (ELdapException e) {
                CMS.debug("Profile change monitor: failed to get LDAPConnection. Retrying in 1 second.");
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            } catch (LDAPException e) {
                CMS.debug("Profile change monitor: Caught exception: " + e.toString());
            } finally {
                if (conn != null) {
                    try {
                        dbFactory.returnConn(conn);
                        conn = null;
                    } catch (Exception e) {
                        CMS.debug("Profile change monitor: Error releasing the LDAPConnection" + e.toString());
                    }
                }
            }
        }
        CMS.debug("Profile change monitor: stopping.");
    }
}
