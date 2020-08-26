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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.ca;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X500Name;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CANotFoundException;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.util.AsyncLoader;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.cert.CrossCertPairSubsystem;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.selftests.SelfTestSubsystem;
import com.netscape.cmsutil.ldap.LDAPPostReadControl;
import com.netscape.cmsutil.ldap.LDAPUtil;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPConstraints;
import netscape.ldap.LDAPControl;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchResults;

@WebListener
public class CAEngine extends CMSEngine implements ServletContextListener {

    public static LdapBoundConnFactory connectionFactory =
            new LdapBoundConnFactory("CertificateAuthority");

    public static Map<AuthorityID, CertificateAuthority> authorities =
            Collections.synchronizedSortedMap(new TreeMap<AuthorityID, CertificateAuthority>());

    public static Map<AuthorityID, Thread> keyRetrievers =
            Collections.synchronizedSortedMap(new TreeMap<AuthorityID, Thread>());

    // Track authority updates to avoid race conditions and unnecessary reloads due to replication
    public static TreeMap<AuthorityID, BigInteger> entryUSNs = new TreeMap<>();
    public static TreeMap<AuthorityID, String> nsUniqueIds = new TreeMap<>();

    // Track authority deletions
    public static TreeSet<String> deletedNsUniqueIds = new TreeSet<>();

    public static AsyncLoader loader = new AsyncLoader(10 /*10s timeout*/);
    public static boolean foundHostCA;

    public CAEngine() throws Exception {
        super("CA");
    }

    public static CAEngine getInstance() {
        return (CAEngine) CMS.getCMSEngine();
    }

    public EngineConfig createConfig(ConfigStorage storage) throws Exception {
        return new CAEngineConfig(storage);
    }

    public CAEngineConfig getConfig() {
        return (CAEngineConfig) mConfig;
    }

    public CAConfigurator createConfigurator() throws Exception {
        return new CAConfigurator(this);
    }

    public void initDatabase() throws Exception {
        CAEngineConfig config = getConfig();
        LDAPConfig ldapConfig = config.getInternalDBConfig();
        connectionFactory.init(config, ldapConfig, getPasswordStore());
    }

    protected void loadSubsystems() throws EBaseException {

        super.loadSubsystems();

        if (isPreOpMode()) {
            // Disable some subsystems before database initialization
            // in pre-op mode to prevent misleading exceptions.

            setSubsystemEnabled(CertificateAuthority.ID, false);
            setSubsystemEnabled(CrossCertPairSubsystem.ID, false);
            setSubsystemEnabled(SelfTestSubsystem.ID, false);
        }
    }

    public X509Certificate[] getCertChain(X509Certificate cert) throws Exception {

        CertificateAuthority ca = getCA();
        CertificateChain caChain = ca.getCACertChain();
        X509Certificate[] caCerts = caChain.getChain();

        if (CertUtils.certInCertChain(caCerts, cert)) {
            return Arrays.copyOf(caCerts, caCerts.length);
        }

        X509Certificate[] certChain = new X509Certificate[caCerts.length + 1];
        certChain[0] = cert;
        System.arraycopy(caCerts, 0, certChain, 1, caCerts.length);

        return certChain;
    }

    public void startupSubsystems() throws EBaseException {

        super.startupSubsystems();

        // check serial number ranges
        CertificateAuthority ca = getCA();
        if (!isPreOpMode()) {
            logger.debug("CAEngine: checking request serial number ranges for the CA");
            ca.getRequestQueue().getRequestRepository().checkRanges();

            logger.debug("CAEngine: checking certificate serial number ranges");
            ca.getCertificateRepository().checkRanges();
        }
    }

    /**
     * Returns the main/host CA.
     */
    public CertificateAuthority getCA() {
        return (CertificateAuthority) getSubsystem(CertificateAuthority.ID);
    }

    /**
     * Enumerate all authorities (including host authority)
     */
    public List<CertificateAuthority> getCAs() {
        List<CertificateAuthority> list = new ArrayList<>();
        synchronized (authorities) {
            list.addAll(authorities.values());
        }
        return list;
    }

    /**
     * Get authority by ID.
     *
     * @param aid The ID of the CA to retrieve, or null
     *             to retreive the host authority.
     *
     * @return the authority, or null if not found
     */
    public CertificateAuthority getCA(AuthorityID aid) {
        return aid == null ? getCA() : authorities.get(aid);
    }

    public CertificateAuthority getCA(X500Name dn) {

        for (CertificateAuthority ca : getCAs()) {
            if (ca.getX500Name().equals(dn))
                return ca;
        }

        return null;
    }

    public void addCA(AuthorityID aid, CertificateAuthority ca) {
        authorities.put(aid, ca);
    }

    public void removeCA(AuthorityID aid) {
        authorities.remove(aid);
        entryUSNs.remove(aid);
        nsUniqueIds.remove(aid);
    }

    /**
     * Create a new certificate authority.
     *
     * @param subjectDN Subject DN for new CA
     * @param parentAID ID of parent CA
     * @param description Optional string description of CA
     */
    public CertificateAuthority createCA(
            IAuthToken authToken,
            String subjectDN,
            AuthorityID parentAID,
            String description)
            throws EBaseException {

        CertificateAuthority parentCA = getCA(parentAID);

        if (parentCA == null) {
            throw new CANotFoundException("Parent CA \"" + parentAID + "\" does not exist");
        }

        CertificateAuthority ca = parentCA.createSubCA(authToken, subjectDN, description);
        authorities.put(ca.getAuthorityID(), ca);

        return ca;
    }

    public boolean hasKeyRetriever(AuthorityID aid) {
        return keyRetrievers.containsKey(aid);
    }

    public void addKeyRetriever(AuthorityID aid, Thread thread) {
        keyRetrievers.put(aid, thread);
    }

    public void removeKeyRetriever(AuthorityID aid) {
        keyRetrievers.remove(aid);
    }

    public String getAuthorityBaseDN() {
        return "ou=authorities,ou=" + id + "," + DBSubsystem.getInstance().getBaseDN();
    }

    public boolean entryUSNPluginEnabled() throws Exception {

        LDAPConnection conn = connectionFactory.getConn();

        try {
            LDAPSearchResults results = conn.search(
                    "cn=usn,cn=plugins,cn=config",
                    LDAPConnection.SCOPE_BASE,
                    "(nsslapd-pluginEnabled=on)",
                    null,
                    false);

            return results != null && results.hasMoreElements();

        } catch (LDAPException e) {
            return false;

        } finally {
            connectionFactory.returnConn(conn);
        }
    }

    public LDAPConstraints getUpdateConstraints() {
        String[] attrs = {"entryUSN", "nsUniqueId"};
        LDAPConstraints cons = new LDAPConstraints();
        LDAPPostReadControl control = new LDAPPostReadControl(true, attrs);
        cons.setServerControls(control);
        return cons;
    }

    public synchronized void trackUpdate(AuthorityID aid, LDAPControl[] responseControls) {

        LDAPPostReadControl control = (LDAPPostReadControl)
            LDAPUtil.getControl(LDAPPostReadControl.class, responseControls);

        LDAPEntry entry = control.getEntry();

        LDAPAttribute attr = entry.getAttribute("entryUSN");
        if (attr != null) {
            BigInteger entryUSN = new BigInteger(attr.getStringValueArray()[0]);
            logger.debug("CAEngine: tracking entryUSN: " + entryUSN);
            entryUSNs.put(aid, entryUSN);
        }

        attr = entry.getAttribute("nsUniqueId");
        if (attr != null) {
            String nsUniqueId = attr.getStringValueArray()[0];
            logger.info("CAEngine: tracking nsUniqueId: " + nsUniqueId);
            nsUniqueIds.put(aid, nsUniqueId);
        }
    }

    public synchronized void addAuthorityEntry(AuthorityID aid, LDAPEntry entry) throws EBaseException {

        LDAPConnection conn = connectionFactory.getConn();
        LDAPControl[] responseControls;

        try {
            conn.add(entry, getUpdateConstraints());
            responseControls = conn.getResponseControls();

        } catch (LDAPException e) {
            throw new ELdapException("Unable to add authority: " + e.getMessage(), e);

        } finally {
            connectionFactory.returnConn(conn);
        }

        trackUpdate(aid, responseControls);
    }

    public synchronized void modifyAuthorityEntry(AuthorityID aid, LDAPModificationSet mods) throws EBaseException {

        String dn = "cn=" + aid + "," + getAuthorityBaseDN();
        LDAPConnection conn = connectionFactory.getConn();
        LDAPControl[] responseControls;

        try {
            conn.modify(dn, mods, getUpdateConstraints());
            responseControls = conn.getResponseControls();

        } catch (LDAPException e) {
            throw new ELdapException("Unable to modify authority: " + e.getMessage(), e);

        } finally {
            connectionFactory.returnConn(conn);
        }

        trackUpdate(aid, responseControls);
    }

    public synchronized void deleteAuthorityEntry(AuthorityID aid) throws EBaseException {

        String dn = "cn=" + aid + "," + getAuthorityBaseDN();
        LDAPConnection conn = connectionFactory.getConn();

        try {
            conn.delete(dn);

        } catch (LDAPException e) {
            throw new ELdapException("Unable to delete authority: " + e.getMessage(), e);

        } finally {
            connectionFactory.returnConn(conn);
        }

        String nsUniqueId = nsUniqueIds.get(aid);
        if (nsUniqueId != null) {
            deletedNsUniqueIds.add(nsUniqueId);
        }

        removeCA(aid);
    }

    public ProfileSubsystem getProfileSubsystem() {
        return (ProfileSubsystem) getSubsystem(ProfileSubsystem.ID);
    }

    public ProfileSubsystem getProfileSubsystem(String name) {
        if (StringUtils.isEmpty(name)) {
            name = ProfileSubsystem.ID;
        }
        return (ProfileSubsystem) getSubsystem(name);
    }

    public void shutdownDatabase() {
        try {
            connectionFactory.shutdown();
        } catch (Exception e) {
            logger.warn("CAEngine: Unable to shut down connection factory: " + e.getMessage(), e);
        }
    }
}
