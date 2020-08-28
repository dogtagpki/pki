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

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.ca.KeyRetrieverRunner;
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
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPConstraints;
import netscape.ldap.LDAPControl;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
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

    public boolean haveAuthorityContainer() throws EBaseException {

        LDAPConnection conn = connectionFactory.getConn();

        try {
            LDAPSearchResults results = conn.search(
                    getAuthorityBaseDN(),
                    LDAPConnection.SCOPE_BASE,
                    null,
                    null,
                    false);
            return results != null;

        } catch (LDAPException e) {
            return false;

        } finally {
            connectionFactory.returnConn(conn);
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
     * Create a CA signed by a parent CA.
     *
     * This method DOES NOT add the new CA to CAEngine; it is the
     * caller's responsibility.
     */
    public CertificateAuthority createCA(
            CertificateAuthority parentCA,
            IAuthToken authToken,
            String subjectDN,
            String description)
            throws Exception {

        parentCA.ensureReady();

        // check requested DN
        X500Name subjectX500Name = new X500Name(subjectDN);
        parentCA.ensureAuthorityDNAvailable(subjectX500Name);

        // generate authority ID and nickname
        AuthorityID aid = new AuthorityID();
        String aidString = aid.toString();

        CertificateAuthority hostCA = getCA();
        String nickname = hostCA.getNickname() + " " + aidString;

        // build database entry
        String dn = "cn=" + aidString + "," + getAuthorityBaseDN();
        logger.debug("CAEngine: DN: " + dn);
        String parentDNString = parentCA.getX500Name().toLdapDNString();

        String thisClone = getEEHost() + ":" + getEESSLPort();

        LDAPAttribute[] attrs = {
            new LDAPAttribute("objectclass", "authority"),
            new LDAPAttribute("cn", aidString),
            new LDAPAttribute("authorityID", aidString),
            new LDAPAttribute("authorityKeyNickname", nickname),
            new LDAPAttribute("authorityKeyHost", thisClone),
            new LDAPAttribute("authorityEnabled", "TRUE"),
            new LDAPAttribute("authorityDN", subjectDN),
            new LDAPAttribute("authorityParentDN", parentDNString)
        };

        LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);
        if (parentCA.getAuthorityID() != null) {
            attrSet.add(new LDAPAttribute("authorityParentID", parentCA.getAuthorityID().toString()));
        }

        if (description != null) {
            attrSet.add(new LDAPAttribute("description", description));
        }

        LDAPEntry ldapEntry = new LDAPEntry(dn, attrSet);
        addAuthorityEntry(aid, ldapEntry);

        X509CertImpl cert = null;

        try {
            logger.info("CAEngine: generating signing certificate");
            cert = parentCA.generateSigningCert(subjectX500Name, authToken);

            logger.info("CAEngine: importing signing certificate");
            CryptoManager cryptoManager = CryptoManager.getInstance();
            cryptoManager.importCertPackage(cert.getEncoded(), nickname);

        } catch (Exception e) {
            logger.error("Unable to generate signing certificate: " + e.getMessage(), e);

            // something went wrong; delete just-added entry
            deleteAuthorityEntry(aid);

            throw e;
        }

        CertificateAuthority ca = new CertificateAuthority(
            hostCA,
            subjectX500Name,
            aid,
            parentCA.getAuthorityID(),
            cert.getSerialNumber(),
            nickname,
            Collections.singleton(thisClone),
            description,
            true);

        updateAuthoritySerialNumber(aid, cert.getSerialNumber());

        return ca;
    }

    /**
     * Create a new certificate authority.
     *
     * @param subjectDN Subject DN for new CA
     * @param parentAID ID of parent CA
     * @param description Optional string description of CA
     */
    public CertificateAuthority createCA(
            AuthorityID parentAID,
            IAuthToken authToken,
            String subjectDN,
            String description)
            throws Exception {

        CertificateAuthority parentCA = getCA(parentAID);

        if (parentCA == null) {
            throw new CANotFoundException("Parent CA \"" + parentAID + "\" does not exist");
        }

        CertificateAuthority ca = createCA(parentCA, authToken, subjectDN, description);
        authorities.put(ca.getAuthorityID(), ca);

        return ca;
    }

    public boolean hasKeyRetriever(AuthorityID aid) {
        return keyRetrievers.containsKey(aid);
    }

    public void startKeyRetriever(CertificateAuthority ca) {
        KeyRetrieverRunner runner = new KeyRetrieverRunner(ca);
        Thread thread = new Thread(runner, "KeyRetrieverRunner-" + ca.getAuthorityID());
        thread.start();
        keyRetrievers.put(ca.getAuthorityID(), thread);
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

    public synchronized void readAuthority(LDAPEntry entry) throws Exception {

        CertificateAuthority hostCA = getCA();

        String nsUniqueId = entry.getAttribute("nsUniqueId").getStringValueArray()[0];
        if (deletedNsUniqueIds.contains(nsUniqueId)) {
            logger.warn("CAEngine: ignoring entry with nsUniqueId '"
                    + nsUniqueId + "' due to deletion");
            return;
        }

        LDAPAttribute aidAttr = entry.getAttribute("authorityID");
        LDAPAttribute nickAttr = entry.getAttribute("authorityKeyNickname");
        LDAPAttribute keyHostsAttr = entry.getAttribute("authorityKeyHost");
        LDAPAttribute dnAttr = entry.getAttribute("authorityDN");
        LDAPAttribute parentAIDAttr = entry.getAttribute("authorityParentID");
        LDAPAttribute parentDNAttr = entry.getAttribute("authorityParentDN");
        LDAPAttribute serialAttr = entry.getAttribute("authoritySerial");

        if (aidAttr == null || nickAttr == null || dnAttr == null) {
            logger.warn("Malformed authority object; required attribute(s) missing: " + entry.getDN());
            return;
        }

        AuthorityID aid = new AuthorityID(aidAttr.getStringValues().nextElement());

        X500Name dn = null;
        try {
            dn = new X500Name(dnAttr.getStringValues().nextElement());
        } catch (IOException e) {
            logger.warn("Malformed authority object; invalid authorityDN: " + entry.getDN() + ": " + e.getMessage(), e);
        }

        String desc = null;
        LDAPAttribute descAttr = entry.getAttribute("description");
        if (descAttr != null) {
            desc = descAttr.getStringValues().nextElement();
        }

        // Determine if it is the host authority's entry, by
        // comparing DNs.  DNs must be serialized in case different
        // encodings are used for AVA values, e.g. PrintableString
        // from LDAP vs UTF8String in certificate.

        if (dn.toString().equals(hostCA.getX500Name().toString())) {
            logger.debug("Found host authority");
            foundHostCA = true;
            hostCA.setAuthorityID(aid);
            hostCA.setAuthorityDescription(desc);
            addCA(aid, hostCA);
            return;
        }

        BigInteger newEntryUSN = null;
        LDAPAttribute entryUSNAttr = entry.getAttribute("entryUSN");

        if (entryUSNAttr == null) {
            logger.debug("CAEngine: no entryUSN");
            if (!entryUSNPluginEnabled()) {
                logger.warn("CAEngine: dirsrv USN plugin is not enabled; skipping entry");
                logger.warn("Lightweight authority entry has no"
                        + " entryUSN attribute and USN plugin not enabled;"
                        + " skipping.  Enable dirsrv USN plugin.");
                return;

            } else {
                logger.debug("CAEngine: dirsrv USN plugin is enabled; continuing");
                // entryUSN plugin is enabled, but no entryUSN attribute. We
                // can proceed because future modifications will result in the
                // entryUSN attribute being added.
            }

        } else {
            newEntryUSN = new BigInteger(entryUSNAttr.getStringValueArray()[0]);
            logger.debug("CAEngine: new entryUSN: " + newEntryUSN);
        }

        BigInteger knownEntryUSN = entryUSNs.get(aid);
        if (newEntryUSN != null && knownEntryUSN != null) {
            logger.debug("CAEngine: known entryUSN: " + knownEntryUSN);
            if (newEntryUSN.compareTo(knownEntryUSN) <= 0) {
                logger.debug("CAEngine: data is current");
                return;
            }
        }

        @SuppressWarnings("unused")
        X500Name parentDN = null;
        if (parentDNAttr != null) {
            try {
                parentDN = new X500Name(parentDNAttr.getStringValues().nextElement());
            } catch (IOException e) {
                logger.warn("Malformed authority object; invalid authorityParentDN: " + entry.getDN() + ": " + e.getMessage(), e);
                return;
            }
        }

        String keyNick = nickAttr.getStringValues().nextElement();

        Collection<String> keyHosts;
        if (keyHostsAttr == null) {
            keyHosts = Collections.emptyList();
        } else {
            @SuppressWarnings("unchecked")
            Enumeration<String> keyHostsEnum = keyHostsAttr.getStringValues();
            keyHosts = Collections.list(keyHostsEnum);
        }

        AuthorityID parentAID = null;
        if (parentAIDAttr != null) {
            parentAID = new AuthorityID(parentAIDAttr.getStringValues().nextElement());
        }

        BigInteger serial = null;
        if (serialAttr != null) {
            serial = new BigInteger(serialAttr.getStringValueArray()[0]);
        }

        boolean enabled = true;
        LDAPAttribute enabledAttr = entry.getAttribute("authorityEnabled");
        if (enabledAttr != null) {
            String enabledString = enabledAttr.getStringValues().nextElement();
            enabled = enabledString.equalsIgnoreCase("TRUE");
        }

        try {
            CertificateAuthority ca = new CertificateAuthority(
                hostCA, dn, aid, parentAID, serial,
                keyNick, keyHosts, desc, enabled);

            addCA(aid, ca);
            entryUSNs.put(aid, newEntryUSN);
            nsUniqueIds.put(aid, nsUniqueId);

        } catch (EBaseException e) {
            logger.warn("CAEngine: Error initializing lightweight CA: " + e.getMessage(), e);
        }
    }

    /**
     * Add an LDAP entry for the host authority.
     *
     * This method also sets the authorityID and authorityDescription
     * fields.
     *
     * It is the caller's responsibility to add the returned
     * AuthorityID to the CAEngine.
     */
    public AuthorityID addHostAuthorityEntry() throws EBaseException {

        CertificateAuthority hostCA = getCA();

        // generate authority ID
        AuthorityID aid = new AuthorityID();
        String aidString = aid.toString();

        // build database entry
        String dn = "cn=" + aidString + "," + getAuthorityBaseDN();
        String dnString = null;
        try {
            dnString = hostCA.getX500Name().toLdapDNString();

        } catch (IOException e) {
            throw new EBaseException("Unable to convert issuer DN to string: " + e.getMessage(), e);
        }

        String desc = "Host authority";
        LDAPAttribute[] attrs = {
            new LDAPAttribute("objectclass", "authority"),
            new LDAPAttribute("cn", aidString),
            new LDAPAttribute("authorityID", aidString),
            new LDAPAttribute("authorityKeyNickname", hostCA.getNickname()),
            new LDAPAttribute("authorityEnabled", "TRUE"),
            new LDAPAttribute("authorityDN", dnString),
            new LDAPAttribute("description", desc)
        };
        LDAPAttributeSet attrSet = new LDAPAttributeSet(attrs);
        LDAPEntry ldapEntry = new LDAPEntry(dn, attrSet);

        addAuthorityEntry(aid, ldapEntry);

        hostCA.setAuthorityID(aid);
        hostCA.setAuthorityDescription(desc);

        return aid;
    }

    public void updateAuthoritySerialNumber(AuthorityID aid, BigInteger serialNumber) throws Exception {

        LDAPModificationSet mods = new LDAPModificationSet();
        mods.add(LDAPModification.REPLACE, new LDAPAttribute(
                "authoritySerial",
                serialNumber.toString()));

        modifyAuthorityEntry(aid, mods);
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
