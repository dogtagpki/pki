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
package com.netscape.cms.servlet.csadmin;

import java.io.IOException;
import java.util.Enumeration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmsutil.ldap.LDAPUtil;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;

public class ReplicationUtil {

    public final static Logger logger = LoggerFactory.getLogger(ReplicationUtil.class);

    public static void setupReplication() throws EBaseException, IOException, LDAPException {

        logger.info("ReplicationUtil: setting up replication");

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();
        IConfigStore masterCfg = cs.getSubStore("preop.internaldb.master");
        IConfigStore replicaCfg = cs.getSubStore("internaldb");

        String machinename = cs.getString("machineName", "");
        String instanceId = cs.getInstanceID();
        String secure = cs.getString("internaldb.ldapconn.secureConn");
        String replicationSecurity = cs.getString("internaldb.ldapconn.replicationSecurity");

        int masterReplicationPort = cs.getInteger("internaldb.ldapconn.masterReplicationPort");
        int cloneReplicationPort = cs.getInteger("internaldb.ldapconn.cloneReplicationPort");

        String master_hostname = cs.getString("preop.internaldb.master.ldapconn.host", "");
        String master_replicationpwd = cs.getString("preop.internaldb.master.replication.password", "");

        String replica_hostname = cs.getString("internaldb.ldapconn.host", "");
        String replica_replicationpwd = cs.getString("preop.internaldb.replicationpwd", "");

        String basedn = cs.getString("internaldb.basedn");
        String suffix = cs.getString("internaldb.basedn", "");

        String masterAgreementName = "masterAgreement1-" + machinename + "-" + instanceId;
        cs.putString("internaldb.replication.master", masterAgreementName);

        String cloneAgreementName = "cloneAgreement1-" + machinename + "-" + instanceId;
        cs.putString("internaldb.replication.consumer", cloneAgreementName);

        cs.commit(false);

        LDAPConnection masterConn = null;
        LDAPConnection replicaConn = null;

        try {
            logger.info("ReplicationUtil: connecting to master");
            LdapBoundConnFactory masterFactory = new LdapBoundConnFactory("ReplicationUtil");
            masterFactory.init(cs, masterCfg, engine.getPasswordStore());
            masterConn = masterFactory.getConn();

            logger.info("ReplicationUtil: connecting to replica");
            LdapBoundConnFactory replicaFactory = new LdapBoundConnFactory("ReplicationUtil");
            replicaFactory.init(cs, replicaCfg, engine.getPasswordStore());
            replicaConn = replicaFactory.getConn();

            String replicadn = "cn=replica,cn=\"" + suffix + "\",cn=mapping tree,cn=config";
            logger.debug("ReplicationUtil: replica DN: " + replicadn);

            String masterBindUser = "Replication Manager " + masterAgreementName;
            logger.debug("ReplicationUtil: creating replication manager on master");
            createReplicationManager(masterConn, masterBindUser, master_replicationpwd);

            String cloneBindUser = "Replication Manager " + cloneAgreementName;
            logger.debug("ReplicationUtil: creating replication manager on replica");
            createReplicationManager(replicaConn, cloneBindUser, replica_replicationpwd);

            String dir1 = getInstanceDir(masterConn) + "/changelogs";
            logger.debug("ReplicationUtil: creating master changelog dir: " + dir1);
            createChangeLog(masterConn, dir1);

            String dir2 = getInstanceDir(replicaConn) + "/changelogs";
            logger.debug("ReplicationUtil: creating replica changelog dir: " + dir1);
            createChangeLog(replicaConn, dir2);

            int replicaId = cs.getInteger("dbs.beginReplicaNumber", 1);

            logger.debug("ReplicationUtil: enabling replication on master");
            replicaId = enableReplication(replicadn, masterConn, masterBindUser, basedn, replicaId);

            logger.debug("ReplicationUtil: enabling replication on replica");
            replicaId = enableReplication(replicadn, replicaConn, cloneBindUser, basedn, replicaId);

            logger.debug("ReplicationUtil: replica ID: " + replicaId);
            cs.putString("dbs.beginReplicaNumber", Integer.toString(replicaId));

            logger.debug("ReplicationUtil: creating master replication agreement");
            createReplicationAgreement(replicadn, masterConn, masterAgreementName,
                    replica_hostname, cloneReplicationPort, replica_replicationpwd, basedn,
                    cloneBindUser, secure, replicationSecurity);

            logger.debug("ReplicationUtil: creating replica replication agreement");
            createReplicationAgreement(replicadn, replicaConn, cloneAgreementName,
                    master_hostname, masterReplicationPort, master_replicationpwd, basedn,
                    masterBindUser, secure, replicationSecurity);

            logger.debug("ReplicationUtil: initializing replication consumer");
            initializeConsumer(replicadn, masterConn, masterAgreementName);

            while (!replicationDone(replicadn, masterConn, masterAgreementName)) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            String status = replicationStatus(replicadn, masterConn, masterAgreementName);
            if (!(status.startsWith("Error (0) ") || status.startsWith("0 "))) {
                String message = "ReplicationUtil: replication consumer initialization failed " +
                    "(against " + masterConn.getHost() + ":" + masterConn.getPort() + "): " + status;
                logger.error(message);
                throw new IOException(message);
            }

            // remove master ldap password from password.conf (if present)
            String passwordFile = cs.getString("passwordFile");
            IConfigStore psStore = engine.createFileConfigStore(passwordFile);
            psStore.remove("master_internaldb");
            psStore.commit(false);

            logger.debug("ReplicationUtil: replication setup complete");

        } catch (Exception e) {
            logger.error("ReplicationUtil: Unable to setup replication: " + e.getMessage(), e);
            throw new IOException("Unable to setup replication: " + e.getMessage(), e);

        } finally {
            if (masterConn != null) {
                masterConn.disconnect();
            }
            if (replicaConn != null) {
                replicaConn.disconnect();
            }
        }
    }

    public static String getInstanceDir(LDAPConnection conn) throws LDAPException {
        String instancedir = "";

        String baseDN = "cn=config,cn=ldbm database,cn=plugins,cn=config";
        logger.debug("ReplicationUtil: searching for nsslapd-directory in " + baseDN);

        String filter = "(objectclass=*)";
        String[] attrs = { "nsslapd-directory" };
        LDAPSearchResults results = conn.search(baseDN,
                LDAPv3.SCOPE_SUB, filter, attrs, false);

        while (results.hasMoreElements()) {
            LDAPEntry entry = results.next();
            String dn = entry.getDN();
            logger.debug("ReplicationUtil: checking " + dn);
            LDAPAttributeSet entryAttrs = entry.getAttributeSet();

            @SuppressWarnings("unchecked")
            Enumeration<LDAPAttribute> attrsInSet = entryAttrs.getAttributes();
            while (attrsInSet.hasMoreElements()) {
                LDAPAttribute nextAttr = attrsInSet.nextElement();
                String attrName = nextAttr.getName();
                logger.debug("ReplicationUtil: attribute name: " + attrName);

                @SuppressWarnings("unchecked")
                Enumeration<String> valsInAttr = nextAttr.getStringValues();
                while (valsInAttr.hasMoreElements()) {
                    String nextValue = valsInAttr.nextElement();

                    if (attrName.equalsIgnoreCase("nsslapd-directory")) {
                        logger.debug("ReplicationUtil: instanceDir: " + nextValue);
                        return nextValue.substring(0, nextValue.lastIndexOf("/db"));
                    }
                }
            }
        }

        return instancedir;
    }

    public static void createReplicationManager(LDAPConnection conn, String bindUser, String pwd)
            throws LDAPException {

        LDAPEntry entry = null;

        // for older subsystems, the container ou=csusers, cn=config may not yet exist
        String dn = "ou=csusers, cn=config";
        logger.debug("ReplicationUtil: creating " + dn);

        try {
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "organizationalUnit"));
            attrs.add(new LDAPAttribute("ou", "csusers"));
            entry = new LDAPEntry(dn, attrs);
            conn.add(entry);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                logger.warn("ReplicationUtil: Containing ou already exists");
            } else {
                logger.error("ReplicationUtil: Failed to create containing ou: " + e.getMessage(), e);
                throw e;
            }
        }

        dn = "cn=" + LDAPUtil.escapeRDNValue(bindUser) + ",ou=csusers,cn=config";
        logger.debug("ReplicationUtil: creating " + dn);

        try {
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "person"));
            attrs.add(new LDAPAttribute("userpassword", pwd));
            attrs.add(new LDAPAttribute("cn", bindUser));
            attrs.add(new LDAPAttribute("sn", "manager"));
            entry = new LDAPEntry(dn, attrs);
            conn.add(entry);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                logger.warn("ReplicationUtil: Replication Manager has already used");
                try {
                    conn.delete(dn);
                    conn.add(entry);
                } catch (LDAPException ee) {
                    logger.warn("ReplicationUtil: " + ee.getMessage());
                }

            } else {
                logger.error("ReplicationUtil: Unable to create replication manager: " + e.getMessage(), e);
                throw e;
            }
        }
    }

    public static void createChangeLog(LDAPConnection conn, String dir)
            throws LDAPException {

        LDAPEntry entry = null;

        String dn = "cn=changelog5,cn=config";
        logger.debug("ReplicationUtil: creating " + dn);

        try {
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectClass", "top"));
            attrs.add(new LDAPAttribute("objectClass", "extensibleObject"));
            attrs.add(new LDAPAttribute("cn", "changelog5"));
            attrs.add(new LDAPAttribute("nsslapd-changelogdir", dir));
            entry = new LDAPEntry(dn, attrs);
            conn.add(entry);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                logger.warn("ReplicationUtil: Changelog entry has already used");
                /* leave it, dont delete it because it will have operation error */

            } else {
                logger.error("ReplicationUtil: Failed to create changelog entry. Exception: " + e);
                throw e;
            }
        }
    }

    public static int enableReplication(String replicadn, LDAPConnection conn, String bindUser, String basedn, int id)
            throws LDAPException {

        LDAPEntry entry = null;

        String bindDN = "cn=" + LDAPUtil.escapeRDNValue(bindUser) + ",ou=csusers,cn=config";

        logger.debug("ReplicationUtil: creating " + replicadn);
        logger.debug("ReplicationUtil: nsDS5ReplicaRoot: " + basedn);
        logger.debug("ReplicationUtil: nsDS5ReplicaBindDN: " + bindDN);
        logger.debug("ReplicationUtil: nsDS5ReplicaId: " + id);

        try {
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "nsDS5Replica"));
            attrs.add(new LDAPAttribute("objectclass", "extensibleobject"));
            attrs.add(new LDAPAttribute("cn", "replica"));
            attrs.add(new LDAPAttribute("nsDS5ReplicaRoot", basedn));
            attrs.add(new LDAPAttribute("nsDS5ReplicaType", "3"));
            attrs.add(new LDAPAttribute("nsDS5ReplicaBindDN", bindDN));
            attrs.add(new LDAPAttribute("nsDS5ReplicaId", Integer.toString(id)));
            attrs.add(new LDAPAttribute("nsds5flags", "1"));
            entry = new LDAPEntry(replicadn, attrs);
            conn.add(entry);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                /* BZ 470918 -we cant just add the new dn.  We need to do a replace instead
                 * until the DS code is fixed */
                logger.warn("ReplicationUtil: " + replicadn + " has already been used");

                try {
                    entry = conn.read(replicadn);
                    LDAPAttribute attr = entry.getAttribute("nsDS5ReplicaBindDN");
                    attr.addValue("cn=" + LDAPUtil.escapeRDNValue(bindUser) + ",ou=csusers,cn=config");
                    LDAPModification mod = new LDAPModification(LDAPModification.REPLACE, attr);
                    conn.modify(replicadn, mod);


                } catch (LDAPException ee) {
                    logger.warn("ReplicationUtil: Unable to modify replica entry: " + ee.getMessage(), ee);
                }
                return id;

            } else {
                logger.warn("ReplicationUtil: Unable to create replica entry: " + e.getMessage(), e);
                return id;
            }
        }

        logger.info("ReplicationUtil: Successfully created " + replicadn + " entry.");
        return id + 1;
    }

    public static void createReplicationAgreement(String replicadn, LDAPConnection conn, String name,
            String replicahost, int replicaport, String replicapwd, String basedn, String bindUser,
            String secure, String replicationSecurity) throws LDAPException {

        LDAPEntry entry = null;

        String dn = "cn=" + LDAPUtil.escapeRDNValue(name) + "," + replicadn;
        String bindDN = "cn=" + LDAPUtil.escapeRDNValue(bindUser) + ",ou=csusers,cn=config";

        logger.debug("ReplicationUtil: creating " + dn);
        logger.debug("ReplicationUtil: nsDS5ReplicaRoot: " + basedn);
        logger.debug("ReplicationUtil: nsDS5ReplicaHost: " + replicahost);
        logger.debug("ReplicationUtil: nsDS5ReplicaPort: " + replicaport);
        logger.debug("ReplicationUtil: nsDS5ReplicaBindDN: " + bindDN);
        logger.debug("ReplicationUtil: nsDS5ReplicaTransportInfo: " + replicationSecurity);
        logger.debug("ReplicationUtil: description: " + name);

        try {
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", "top"));
            attrs.add(new LDAPAttribute("objectclass", "nsds5replicationagreement"));
            attrs.add(new LDAPAttribute("cn", name));
            attrs.add(new LDAPAttribute("nsDS5ReplicaRoot", basedn));
            attrs.add(new LDAPAttribute("nsDS5ReplicaHost", replicahost));

            attrs.add(new LDAPAttribute("nsDS5ReplicaPort", "" + replicaport));
            attrs.add(new LDAPAttribute("nsDS5ReplicaBindDN", bindDN));
            attrs.add(new LDAPAttribute("nsDS5ReplicaBindMethod", "Simple"));
            attrs.add(new LDAPAttribute("nsds5replicacredentials", replicapwd));

            if (replicationSecurity.equals("SSL")) {
                attrs.add(new LDAPAttribute("nsDS5ReplicaTransportInfo", "SSL"));
            } else if (replicationSecurity.equals("TLS")) {
                attrs.add(new LDAPAttribute("nsDS5ReplicaTransportInfo", "TLS"));
            }

            attrs.add(new LDAPAttribute("description", name));

            entry = new LDAPEntry(dn, attrs);
            conn.add(entry);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                logger.warn("ReplicationUtil: " + dn + " has already used");
                try {
                    conn.delete(dn);
                } catch (LDAPException ee) {
                    logger.error("ReplicationUtil: " + ee);
                    throw ee;
                }

                try {
                    conn.add(entry);
                } catch (LDAPException ee) {
                    logger.error("ReplicationUtil: " + ee);
                    throw ee;
                }
            } else {
                logger.error("ReplicationUtil: Unable to create replication agreement: " + e.getMessage(), e);
                throw e;
            }
        }

        logger.info("ReplicationUtil: Successfully created replication agreement " + name);
    }

    public static void initializeConsumer(String replicadn, LDAPConnection conn, String name) throws LDAPException {

        String dn = "cn=" + LDAPUtil.escapeRDNValue(name) + "," + replicadn;
        logger.debug("ReplicationUtil: initializing consumer " + dn);

        LDAPAttribute attr = new LDAPAttribute("nsds5beginreplicarefresh", "start");
        LDAPModification mod = new LDAPModification(LDAPModification.REPLACE, attr);
        conn.modify(dn, mod);
    }

    public static boolean replicationDone(String replicadn, LDAPConnection conn, String name)
            throws LDAPException, IOException {

        String dn = "cn=" + LDAPUtil.escapeRDNValue(name) + "," + replicadn;
        logger.debug("ReplicationUtil: checking " + dn);

        String filter = "(objectclass=*)";
        String[] attrs = { "nsds5beginreplicarefresh" };

        LDAPSearchResults results = conn.search(dn, LDAPConnection.SCOPE_BASE, filter, attrs, true);
        int count = results.getCount();

        if (count < 1) {
            throw new IOException("Replication entry not found: " + dn);
        }

        LDAPEntry entry = results.next();
        LDAPAttribute refresh = entry.getAttribute("nsds5beginreplicarefresh");

        if (refresh == null) {
            return true;
        }

        return false;
    }

    public static String replicationStatus(String replicadn, LDAPConnection conn, String name)
            throws IOException, LDAPException {

        String dn = "cn=" + LDAPUtil.escapeRDNValue(name) + "," + replicadn;
        logger.debug("ReplicationUtil: checking " + dn);

        String filter = "(objectclass=*)";
        String[] attrs = { "nsds5replicalastinitstatus" };

        LDAPSearchResults results = conn.search(dn, LDAPConnection.SCOPE_BASE, filter, attrs, false);

        int count = results.getCount();

        if (count < 1) {
            logger.error("ReplicationUtil: Missing replication entry: " + dn);
            throw new IOException("Missing replication entry: " + dn);
        }

        LDAPEntry entry = results.next();
        LDAPAttribute attr = entry.getAttribute("nsds5replicalastinitstatus");

        if (attr == null) {
            logger.error("ReplicationUtil: Missing attribute: nsds5replicalastinitstatus");
            throw new IOException("Missing attribute: nsDS5ReplicaLastInitStatus");
        }

        @SuppressWarnings("unchecked")
        Enumeration<String> valsInAttr = attr.getStringValues();

        if (!valsInAttr.hasMoreElements()) {
            logger.error("ReplicationUtil: Missing attribute: nsds5replicalastinitstatus");
            throw new IOException("Missing attribute value: nsds5replicalastinitstatus");
        }

        String status = valsInAttr.nextElement();
        logger.debug("ReplicationUtil: nsds5replicalastinitstatus: " + status);

        return status;
    }
}
