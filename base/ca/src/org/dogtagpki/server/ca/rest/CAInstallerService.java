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
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.StringTokenizer;

import org.apache.commons.lang.StringUtils;
import org.dogtagpki.server.rest.SystemConfigService;

import com.netscape.ca.CertificateAuthority;
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
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.SubsystemInfo;
import com.netscape.cmscore.base.LDAPConfigStore;
import com.netscape.cmscore.cert.CrossCertPairSubsystem;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.profile.LDAPProfileSubsystem;
import com.netscape.cmscore.selftests.SelfTestSubsystem;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

/**
 * @author alee
 *
 */
public class CAInstallerService extends SystemConfigService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAInstallerService.class);

    public CAInstallerService() throws EBaseException {
    }

    @Override
    public void finalizeConfiguration(ConfigurationRequest request) throws Exception {

        CMSEngine engine = (CMSEngine) CMS.getCMSEngine();

        try {
            if (!request.isClone()) {
                ConfigurationUtils.updateNextRanges();
            }

        } catch (Exception e) {
            logger.error("Unable to update next serial number ranges: " + e.getMessage(), e);
            throw new PKIException("Unable to update next serial number ranges: " + e.getMessage(), e);
        }

        try {
            if (request.isClone() && ConfigurationUtils.isSDHostDomainMaster(cs)) {
                // cloning a domain master CA, the clone is also master of its domain
                cs.putString("securitydomain.host", CMS.getEEHost());
                cs.putString("securitydomain.httpport", CMS.getEENonSSLPort());
                cs.putString("securitydomain.httpsadminport", engine.getAdminPort());
                cs.putString("securitydomain.httpsagentport", engine.getAgentPort());
                cs.putString("securitydomain.httpseeport", CMS.getEESSLPort());
                cs.putString("securitydomain.select", "new");
            }

            if (request.isClone()) {
                disableCRLCachingAndGenerationForClone(request);
            }

            configureStartingCRLNumber(request);

        } catch (Exception e) {
            logger.error("Unable to determine if security domain host is a master CA: " + e.getMessage(), e);
            throw new PKIException("Unable to determine if security domain host is a master CA: " + e.getMessage(), e);
        }

        try {
            engine.setSubsystemEnabled("profile", true);
        } catch (Exception e) {
            logger.error("Unable to enable profile subsystem: " + e.getMessage(), e);
            throw new PKIException("Unable to enable profile subsystem: " + e.getMessage(), e);
        }

        if (! request.createSigningCertRecord()) {
            // This is the migration case.  In this case, we will delete the
            // record that was created during the install process.

            try {
                String serialNumber = request.getSigningCertSerialNumber();
                deleteSigningRecord(serialNumber);
            } catch (Exception e) {
                logger.error("Unable to delete signing cert record: " + e.getMessage(), e);
                throw new PKIException("Unable to delete signing cert record: " + e.getMessage(), e);
            }
        }

        super.finalizeConfiguration(request);
    }

    @Override
    public void initializeDatabase(ConfigurationRequest data) throws EBaseException {

        super.initializeDatabase(data);

        CMSEngine engine = (CMSEngine) CMS.getCMSEngine();

        if (!data.isClone()
                && engine.getSubsystem("profile") instanceof LDAPProfileSubsystem) {
            try {
                importProfiles("/usr/share/pki");
            } catch (Exception e) {
                logger.error("Unable to import profiles: " + e.getMessage(), e);
                throw new PKIException("Unable to import profiles: " + e.getMessage(), e);
            }
        }
    }

    public void reinitSubsystems() throws EBaseException {

        super.reinitSubsystems();

        // Enable subsystems after database initialization.
        CMSEngine engine = (CMSEngine) CMS.getCMSEngine();

        SubsystemInfo si = engine.dynSubsystems.get(CertificateAuthority.ID);
        si.enabled = true;

        si = engine.dynSubsystems.get(CrossCertPairSubsystem.ID);
        si.enabled = true;

        si = engine.dynSubsystems.get(SelfTestSubsystem.ID);
        si.enabled = true;

        engine.reinit(CertificateAuthority.ID);
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

        CMSEngine engine = (CMSEngine) CMS.getCMSEngine();
        IPluginRegistry registry = (IPluginRegistry)
                engine.getSubsystem(CMS.SUBSYSTEM_REGISTRY);
        IConfigStore profileCfg = cs.getSubStore("profile");
        String profileIds = profileCfg.getString("list", "");
        StringTokenizer st = new StringTokenizer(profileIds, ",");

        IConfigStore dbCfg = cs.getSubStore("internaldb");
        ILdapConnFactory dbFactory = new LdapBoundConnFactory("CAInstallerService");
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
                logger.info("Importing profile '" + profileId + "' from " + profilePath);
                importProfile(dbFactory, classId, profileId, profilePath);

            } catch (EBaseException e) {
                logger.warn("Unable to import profile '" + profileId + "': " + e.getMessage());
                logger.warn("Continuing with profile import procedure");
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
        } catch (IOException e) {
            logger.error("Unable to load data for profile " + profileId + ": " + e.getMessage(), e);
            throw new EBaseException("Unable to load data for profile " + profileId + ": " + e.getMessage(), e);
        }

        configStore.commit(false /* no backup */);
    }

    private void deleteSigningRecord(String serialNumber) throws EBaseException, LDAPException {

        if (StringUtils.isEmpty(serialNumber)) {
            throw new PKIException("signing certificate serial number not specified in configuration request");
        }

        LDAPConnection conn = null;
        try {
            IConfigStore dbCfg = cs.getSubStore("internaldb");
            ILdapConnFactory dbFactory = new LdapBoundConnFactory("CAInstallerService");
            dbFactory.init(dbCfg);
            conn = dbFactory.getConn();

            String basedn = dbCfg.getString("basedn", "");
            String dn = "cn=" + serialNumber + ",ou=certificateRepository,ou=ca," + basedn;

            conn.delete(dn);
        } finally {
            try {
                if (conn != null)
                    conn.disconnect();
            } catch (LDAPException e) {
                logger.warn("Unable to release connection: " + e.getMessage(), e);
            }
        }
    }

    private void configureStartingCRLNumber(ConfigurationRequest data) {
        logger.debug("CAInstallerService: configuring starting CRL number");
        cs.putString("ca.crl.MasterCRL.startingCrlNumber", data.getStartingCRLNumber());

    }
    private void disableCRLCachingAndGenerationForClone(ConfigurationRequest data) throws MalformedURLException {

        logger.debug("CAInstallerService: disabling CRL caching and generation for clone");

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

        logger.debug("CAInstallerService: master host: " + masterHost);
        logger.debug("CAInstallerService: master port: " + masterPort);

        cs.putString("master.ca.agent.host", masterHost);
        cs.putInteger("master.ca.agent.port", masterPort);

    }
}
