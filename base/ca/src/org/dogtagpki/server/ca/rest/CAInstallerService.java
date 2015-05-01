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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.ca.rest;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.StringTokenizer;

import netscape.ldap.LDAPAttribute;

import org.dogtagpki.server.rest.SystemConfigService;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.certsrv.registry.IPluginRegistry;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.cms.servlet.csadmin.ConfigurationUtils;
import com.netscape.cmscore.base.LDAPConfigStore;
import com.netscape.cmscore.profile.LDAPProfileSubsystem;

/**
 * @author alee
 *
 */
public class CAInstallerService extends SystemConfigService {

    public CAInstallerService() throws EBaseException {
    }

    @Override
    public void finalizeConfiguration(ConfigurationRequest request) {

        super.finalizeConfiguration(request);

        try {
            if (!request.isClone()) {
                ConfigurationUtils.updateNextRanges();
            }

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Errors in updating next serial number ranges in DB: " + e);
        }

        try {
            if (request.isClone() && ConfigurationUtils.isSDHostDomainMaster(cs)) {
                // cloning a domain master CA, the clone is also master of its domain
                cs.putString("securitydomain.host", CMS.getEEHost());
                cs.putString("securitydomain.httpport", CMS.getEENonSSLPort());
                cs.putString("securitydomain.httpsadminport", CMS.getAdminPort());
                cs.putString("securitydomain.httpsagentport", CMS.getAgentPort());
                cs.putString("securitydomain.httpseeport", CMS.getEESSLPort());
                cs.putString("securitydomain.select", "new");
            }

            if (request.isClone()) {
                disableCRLCachingAndGenerationForClone(request);
            }

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Errors in determining if security domain host is a master CA");
        }

        try {
            CMS.enableSubsystem("profile");
        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Error enabling profile subsystem");
        }
    }

    @Override
    public void initializeDatabase(ConfigurationRequest data) {
        super.initializeDatabase(data);

        if (!data.isClone()
                && CMS.getSubsystem("profile") instanceof LDAPProfileSubsystem) {
            try {
                importProfiles("/usr/share/pki");
            } catch (Exception e) {
                throw new PKIException("Error importing profiles.");
            }
        }
    }

    /**
     * Import profiles from the filesystem into the database.
     *
     * @param configRoot Where to look for the profile files. For a
     *            fresh installation this should be
     *            "/usr/share/pki". For existing installations it
     *            should be CMS.getConfigStore().getString("instanceRoot").
     *
     */
    public void importProfiles(String configRoot)
            throws EBaseException, ELdapException {
        IPluginRegistry registry = (IPluginRegistry)
                CMS.getSubsystem(CMS.SUBSYSTEM_REGISTRY);
        IConfigStore profileCfg = cs.getSubStore("profile");
        String profileIds = profileCfg.getString("list", "");
        StringTokenizer st = new StringTokenizer(profileIds, ",");

        IConfigStore dbCfg = cs.getSubStore("internaldb");
        ILdapConnFactory dbFactory = CMS.getLdapBoundConnFactory();
        dbFactory.init(dbCfg);

        while (st.hasMoreTokens()) {
            String profileId = st.nextToken();
            IConfigStore profileSubCfg = profileCfg.getSubStore(profileId);
            String classId = profileSubCfg.getString("class_id", "");
            try {
                IPluginInfo info = registry.getPluginInfo("profile", classId);
                if (info == null) {
                    throw new EBaseException("No plugins for type : profile, with id " + classId);
                }

                String profilePath = configRoot + "/ca/profiles/ca/" + profileId + ".cfg";
                CMS.debug("Importing profile '" + profileId + "' from " + profilePath);
                importProfile(dbFactory, classId, profileId, profilePath);
            } catch (EBaseException e) {
                CMS.debug("Error importing profile '" + profileId + "': " + e.toString());
                CMS.debug("  Continuing with profile import procedure...");
            }
        }
    }

    /**
     * Import one profile from the filesystem into the database.
     *
     * @param dbFactory LDAP connection factory.
     * @param classId The profile class of the profile to import.
     * @param profileId The ID of the profile to import.
     * @param profilePath Path to the on-disk profile configuration.
     */
    public void importProfile(
            ILdapConnFactory dbFactory, String classId,
            String profileId, String profilePath)
            throws EBaseException {

        String basedn = cs.getString("internaldb.basedn", "");

        String dn = "cn=" + profileId + ",ou=certificateProfiles,ou=ca," + basedn;

        String[] objectClasses = { "top", "certProfile" };
        LDAPAttribute[] createAttrs = {
                new LDAPAttribute("objectclass", objectClasses),
                new LDAPAttribute("cn", profileId),
                new LDAPAttribute("classId", classId)
        };

        IConfigStore configStore = new LDAPConfigStore(
                dbFactory, dn, createAttrs, "certProfileConfig");

        try {
            FileInputStream input = new FileInputStream(profilePath);
            configStore.load(input);
        } catch (FileNotFoundException e) {
            throw new EBaseException("Could not find file for profile: " + profileId);
        } catch (IOException e) {
            throw new EBaseException("Error loading data for profile: " + profileId);
        }

        configStore.commit(false /* no backup */);
    }

    private void disableCRLCachingAndGenerationForClone(ConfigurationRequest data) throws MalformedURLException {

        CMS.debug("CAInstallerService:disableCRLCachingAndGenerationForClone entering.");
        if (!data.isClone())
            return;

        //Now add some well know entries that we need to disable CRL functionality.
        //With well known values to disable and well known master CRL ID.

        cs.putInteger("ca.certStatusUpdateInterval", 0);
        cs.putBoolean("ca.listenToCloneModifications", false);
        cs.putBoolean("ca.crl.MasterCRL.enableCRLCache", false);
        cs.putBoolean("ca.crl.MasterCRL.enableCRLUpdates", false);

        String cloneUri = data.getCloneUri();
        URL url = null;

        url = new URL(cloneUri);

        String masterHost = url.getHost();
        int masterPort = url.getPort();

        CMS.debug("CAInstallerService:disableCRLCachingAndGenerationForClone: masterHost: " + masterHost
                + " masterPort: " + masterPort);

        cs.putString("master.ca.agent.host", masterHost);
        cs.putInteger("master.ca.agent.port", masterPort);

    }
}
