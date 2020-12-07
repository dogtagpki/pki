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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmsutil.ldap.LDAPUtil;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPDN;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;
import netscape.ldap.util.LDIF;
import netscape.ldap.util.LDIFAttributeContent;
import netscape.ldap.util.LDIFContent;
import netscape.ldap.util.LDIFModifyContent;
import netscape.ldap.util.LDIFRecord;

public class LDAPConfigurator {

    public final static Logger logger = LoggerFactory.getLogger(LDAPConfigurator.class);

    LDAPConnection connection;
    LDAPConfig config;
    String instanceID;

    Map<String, String> params = new HashMap<>();

    public LDAPConfigurator(LDAPConnection connection, LDAPConfig config) throws Exception {
        this.connection = connection;
        this.config = config;

        String baseDN = config.getBaseDN();
        params.put("rootSuffix", baseDN);

        String database = config.getDatabase();
        params.put("database", database);

        String dbuser = config.getDBUser("uid=pkidbuser,ou=people," + baseDN);
        params.put("dbuser", dbuser);
    }

    public LDAPConfigurator(LDAPConnection connection, LDAPConfig config, String instanceID) throws Exception {
        this(connection, config);

        this.instanceID = instanceID;
        params.put("instanceId", instanceID);
    }

    public LDAPConnection getConnection() {
        return connection;
    }

    public Map<String, String> getParams() throws Exception {
        return params;
    }

    public void initDatabase() throws Exception {
        logger.info("Initialize database");
        importLDIF("/usr/share/pki/server/conf/database.ldif", true);
    }

    public void setupSchema() throws Exception {
        logger.info("Setting up PKI schema");
        importSchemaFile("/usr/share/pki/server/conf/schema.ldif");
    }

    public void createContainers(String subsystem) throws Exception {
        logger.info("Creating container entries");
        importLDIF("/usr/share/pki/" + subsystem + "/conf/db.ldif", true);
    }

    public void setupACL(String subsystem) throws Exception {
        logger.info("Setting up ACL");
        importLDIF("/usr/share/pki/" + subsystem + "/conf/acl.ldif", true);
    }

    public void createIndexes(String subsystem) throws Exception {
        logger.info("Creating indexes");
        importLDIF("/usr/share/pki/" + subsystem + "/conf/index.ldif", true);
    }

    public void rebuildIndexes(String subsystem) throws Exception {

        logger.info("Rebuilding indexes");

        File file = new File("/usr/share/pki/" + subsystem + "/conf/indextasks.ldif");
        File tmpFile = File.createTempFile("pki-" + subsystem + "-reindex-", ".ldif");

        try {
            customizeFile(file, tmpFile);

            LDIF ldif = new LDIF(tmpFile.getAbsolutePath());
            LDIFRecord record = ldif.nextRecord();
            if (record == null) return;

            importLDIFRecord(record, false);

            String dn = record.getDN();
            waitForTask(dn);

        } finally {
            tmpFile.delete();
        }
    }

    public void setupDatabaseManager() throws Exception {
        logger.info("Setting up database manager");
        importLDIF("/usr/share/pki/server/conf/manager.ldif", true);
    }

    public List<LDAPEntry> findVLVs() throws Exception {

        String database = config.getDatabase();
        String baseDN = "cn=" + database + ",cn=ldbm database,cn=plugins,cn=config";

        logger.info("Searching " + baseDN);

        LDAPSearchResults results = connection.search(
                baseDN,
                LDAPConnection.SCOPE_SUB,
                "(|(objectClass=vlvSearch)(objectClass=vlvIndex))",
                null,
                false);

        List<LDAPEntry> entries = new ArrayList<>();

        while (results.hasMoreElements()) {
            LDAPEntry entry = results.next();
            entries.add(entry);
        }

        return entries;
    }

    public void addVLVs(String subsystem) throws Exception {
        logger.info("Add VLVs");
        importLDIF("/usr/share/pki/" + subsystem + "/conf/vlv.ldif", true);
    }

    public void reindexVLVs(String subsystem) throws Exception {

        logger.info("Reindex VLVs");

        Collection<LDIFRecord> records = importLDIF(
                "/usr/share/pki/" + subsystem + "/conf/vlvtasks.ldif", false);

        for (LDIFRecord record : records) {
            String dn = record.getDN();
            waitForTask(dn);
        }
    }

    public LDAPEntry getEntry(String dn) throws Exception {

        logger.info("Getting " + dn);

        try {
            return connection.read(dn);

        } catch (LDAPException e) {

            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                logger.info("Entry not found: " + dn);
                return null;

            } else {
                String message = "Unable to get " + dn + ": " + e;
                logger.error(message);
                throw new Exception(message, e);
            }
        }
    }

    public void validateDatabaseOwnership(String database, String baseDN) throws Exception {

        logger.info("Validating database " + database + " is owned by " + baseDN);

        LDAPSearchResults res = connection.search(
                "cn=mapping tree, cn=config",
                LDAPConnection.SCOPE_ONE,
                "(nsslapd-backend=" + LDAPUtil.escapeFilter(database) + ")",
                null,
                false,
                (LDAPSearchConstraints) null);

        while (res.hasMoreElements()) {
            LDAPEntry entry = res.next();
            LDAPAttribute cn = entry.getAttribute("cn");
            String dn = cn.getStringValueArray()[0];

            if (LDAPDN.equals(dn, baseDN)) {
                continue;
            }

            String message = "Database " + database + " is owned by " + dn;
            logger.error(message);
            throw new Exception(message);
        }
    }

    public void deleteEntry(String dn) throws Exception {

        try {
            LDAPSearchResults results = connection.search(
                    dn,
                    LDAPConnection.SCOPE_ONE,
                    "(objectClass=*)",
                    null,
                    true,
                    (LDAPSearchConstraints) null);

            while (results.hasMoreElements()) {
                LDAPEntry entry = results.next();
                deleteEntry(entry.getDN());
            }

            logger.info("Deleting " + dn);
            connection.delete(dn);

        } catch (LDAPException e) {

            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                logger.info("Entry not found: " + dn);

            } else {
                String message = "Unable to delete " + dn + ": " + e;
                logger.error(message);
                throw new Exception(message, e);
            }
        }
    }

    public void waitForTask(String dn) throws Exception {

        String returnCode = null;
        int count = 0;
        int maxCount = 0; // TODO: make it configurable

        while (maxCount <= 0 || count < maxCount) {

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                // restore the interrupted status
                Thread.currentThread().interrupt();
            }

            count++;
            logger.info("Waiting for task " + dn + " (" + count + "s)");

            try {
                LDAPEntry task = getEntry(dn);
                if (task == null) continue;

                LDAPAttribute attr = task.getAttribute("nsTaskExitCode");
                if (attr == null) continue;

                returnCode = attr.getStringValues().nextElement();
                break;

            } catch (Exception e) {
                logger.warn("Unable to read task " + dn + ": " + e);
            }
        }

        if (returnCode == null || !"0".equals(returnCode)) {
            String message = "Task " + dn + " failed: nsTaskExitCode=" + returnCode;
            logger.error(message);
            throw new Exception(message);
        }

        logger.info("Task " + dn + " complete");
    }

    public void createDatabaseEntry(String databaseDN, String database, String baseDN) throws Exception {

        logger.info("Adding " + databaseDN);

        LDAPAttributeSet attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectClass", new String[] {
                "top",
                "extensibleObject",
                "nsBackendInstance"
        }));
        attrs.add(new LDAPAttribute("cn", database));
        attrs.add(new LDAPAttribute("nsslapd-suffix", baseDN));

        LDAPEntry entry = new LDAPEntry(databaseDN, attrs);
        connection.add(entry);
    }

    public void createMappingEntry(String mappingDN, String database, String baseDN) throws Exception {

        logger.info("Adding " + mappingDN);

        LDAPAttributeSet attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectClass", new String[] {
                "top",
                "extensibleObject",
                "nsMappingTree"
        }));
        attrs.add(new LDAPAttribute("cn", baseDN));
        attrs.add(new LDAPAttribute("nsslapd-backend", database));
        attrs.add(new LDAPAttribute("nsslapd-state", "Backend"));

        LDAPEntry entry = new LDAPEntry(mappingDN, attrs);
        connection.add(entry);
    }

    public void createBaseEntry(String baseDN) throws Exception {

        logger.info("Adding " + baseDN);

        String[] rdns = LDAPDN.explodeDN(baseDN, false);

        StringTokenizer st = new StringTokenizer(rdns[0], "=");
        String name = st.nextToken();
        String value = st.nextToken();

        LDAPAttributeSet attrs = new LDAPAttributeSet();
        String[] oc = { "top", "domain" };
        if (name.equals("o")) {
            oc[1] = "organization";
        } else if (name.equals("ou")) {
            oc[1] = "organizationalUnit";
        }
        attrs.add(new LDAPAttribute("objectClass", oc));
        attrs.add(new LDAPAttribute(name, value));

        LDAPEntry entry = new LDAPEntry(baseDN, attrs);
        connection.add(entry);
    }

    public void customizeFile(File file, File tmpFile) throws Exception {

        logger.info("Creating " + tmpFile);

        try (BufferedReader in = new BufferedReader(new FileReader(file));
                PrintWriter out = new PrintWriter(new FileWriter(tmpFile))) {

            String line;

            while ((line = in.readLine()) != null) {

                int start = line.indexOf("{");

                if (start == -1) {
                    out.println(line);
                    continue;
                }

                boolean eol = false;

                while (start != -1) {

                    out.print(line.substring(0, start));

                    int end = line.indexOf("}");
                    String name = line.substring(start + 1, end);
                    String value = params.get(name);
                    out.print(value);

                    if ((line.length() + 1) == end) {
                        eol = true;
                        break;
                    }

                    line = line.substring(end + 1);
                    start = line.indexOf("{");
                }

                if (!eol) {
                    out.println(line);
                }
            }
        }
    }

    public Collection<LDIFRecord> importLDIF(String filename, boolean ignoreErrors) throws Exception {

        logger.info("Importing " + filename);

        File file = new File(filename);
        File tmpFile = File.createTempFile("pki-import-", ".ldif");

        Collection<LDIFRecord> records = new ArrayList<>();

        try {
            customizeFile(file, tmpFile);

            LDIF ldif = new LDIF(tmpFile.getAbsolutePath());

            while (true) {
                LDIFRecord record = ldif.nextRecord();
                if (record == null) break;

                records.add(record);
                importLDIFRecord(record, ignoreErrors);
            }

        } finally {
            tmpFile.delete();
        }

        return records;
    }

    public void importLDIFRecord(LDIFRecord record, boolean ignoreErrors) throws Exception {

        String dn = record.getDN();
        LDIFContent content = record.getContent();
        int type = content.getType();

        if (type == LDIFContent.ATTRIBUTE_CONTENT) {

            logger.info("Adding " + dn);

            LDIFAttributeContent c = (LDIFAttributeContent) content;
            LDAPAttributeSet attrs = new LDAPAttributeSet();

            for (LDAPAttribute attr : c.getAttributes()) {
                attrs.add(attr);
            }

            LDAPEntry entry = new LDAPEntry(dn, attrs);

            try {
                connection.add(entry);

            } catch (LDAPException e) {

                String message = "Unable to add " + dn + ": " + e;

                if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS && ignoreErrors) {
                    logger.info(message);

                } else {
                    logger.error(message);
                    throw new Exception(message, e);
                }
            }

        } else if (type == LDIFContent.MODIFICATION_CONTENT) {

            LDIFModifyContent c = (LDIFModifyContent) content;
            LDAPModification[] mods = c.getModifications();

            for (LDAPModification mod : mods) {
                int operation = mod.getOp();
                LDAPAttribute attr = mod.getAttribute();
                String name = attr.getName();
                String[] values = attr.getStringValueArray();

                switch (operation) {
                    case LDAPModification.ADD:
                        logger.info("Adding " + name + " into " + dn);
                        break;
                    case LDAPModification.REPLACE:
                        logger.info("Replacing " + name + " in " + dn);
                        break;
                    case LDAPModification.DELETE:
                        logger.info("Deleting " + name + " from " + dn);
                        break;
                }
            }

            try {
                connection.modify(dn, mods);

            } catch (LDAPException e) {

                String message = "Unable to modify " + dn + ": " + e;

                if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT && ignoreErrors) {
                    logger.info(message);

                } else if (e.getLDAPResultCode() == LDAPException.ATTRIBUTE_OR_VALUE_EXISTS && ignoreErrors) {
                    logger.info(message);

                } else {
                    logger.error(message);
                    throw new Exception(message, e);
                }
            }
        }
    }

    public void importSchemaFile(String filename) throws Exception {

        logger.info("Importing " + filename);

        LDIF ldif = new LDIF(filename);

        while (true) {

            LDIFRecord record = ldif.nextRecord();
            if (record == null) break;

            importSchemaRecord(record);
        }
    }

    public void importSchemaRecord(LDIFRecord record) throws Exception {

        String dn = record.getDN();
        LDIFContent content = record.getContent();

        if (!(content instanceof LDIFModifyContent)) {
            throw new Exception("Invalid record type: " + content.getClass().getSimpleName());
        }

        LDIFModifyContent c = (LDIFModifyContent) content;
        LDAPModification[] mods = c.getModifications();

        for (LDAPModification mod : mods) {
            int operation = mod.getOp();
            LDAPAttribute attr = mod.getAttribute();
            String name = attr.getName();
            String[] values = attr.getStringValueArray();

            switch (operation) {
                case LDAPModification.ADD:
                    for (String value : values) {
                        logger.info("Adding " + name + ": " + value);
                    }
                    break;
                case LDAPModification.REPLACE:
                    for (String value : values) {
                        logger.info("Replacing " + name + ": " + value);
                    }
                    break;
                case LDAPModification.DELETE:
                    if (values == null) {
                        logger.info("Deleting " + name);
                    } else {
                        for (String value : values) {
                            logger.info("Deleting " + name + ": " + value);
                        }
                    }
                    break;
            }
        }

        try {
            connection.modify(dn, mods);

        } catch (LDAPException e) {
            String message = "Unable to update " + dn + ": " + e.getMessage();
            logger.error(message);
            throw new Exception(message, e);
        }
    }

    public void deleteDatabase(String database, String baseDN) throws Exception {

        String databaseDN = "cn=" + LDAPUtil.escapeRDNValue(database) + ",cn=ldbm database, cn=plugins, cn=config";
        String mappingDN = "cn=\"" + baseDN + "\",cn=mapping tree, cn=config";

        logger.info("Validating database ownership");
        validateDatabaseOwnership(database, baseDN);

        logger.info("Deleting mapping entry " + mappingDN);
        deleteEntry(mappingDN);

        logger.info("Deleting database entry " + databaseDN);
        deleteEntry(databaseDN);
    }

    public void createSystemContainer() throws Exception {

        // for older subsystems, the container ou=csusers, cn=config may not yet exist
        String dn = "ou=csusers,cn=config";
        logger.info("Adding " + dn);

        LDAPAttributeSet attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectclass", "top"));
        attrs.add(new LDAPAttribute("objectclass", "organizationalUnit"));
        attrs.add(new LDAPAttribute("ou", "csusers"));

        LDAPEntry entry = new LDAPEntry(dn, attrs);

        try {
            connection.add(entry);

        } catch (LDAPException e) {
            String message = "Unable to add " + dn + ": " + e.getMessage();
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                logger.info(message);

            } else {
                logger.error(message, e);
                throw e;
            }
        }
    }

    public void createReplicationManager(String bindUser, String pwd) throws Exception {

        String dn = "cn=" + LDAPUtil.escapeRDNValue(bindUser) + ",ou=csusers,cn=config";
        logger.info("Adding " + dn);

        LDAPAttributeSet attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectclass", "top"));
        attrs.add(new LDAPAttribute("objectclass", "person"));
        attrs.add(new LDAPAttribute("userpassword", pwd));
        attrs.add(new LDAPAttribute("cn", bindUser));
        attrs.add(new LDAPAttribute("sn", "manager"));

        LDAPEntry entry = new LDAPEntry(dn, attrs);

        try {
            connection.add(entry);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                logger.warn("Entry already exists: " + dn);

                try {
                    logger.info("Deleting " + dn);
                    connection.delete(dn);

                    logger.info("Re-adding " + dn);
                    connection.add(entry);

                } catch (LDAPException ee) {
                    logger.warn("Unable to recreate " + dn + ": " + ee.getMessage());
                }

            } else {
                logger.error("Unable to add " + dn + ": " + e.getMessage(), e);
                throw e;
            }
        }
    }

    public String getInstanceDir() throws Exception {

        String baseDN = "cn=config,cn=ldbm database,cn=plugins,cn=config";
        logger.info("Searching for nsslapd-directory in " + baseDN);

        String filter = "(objectclass=*)";
        String[] attrNames = { "nsslapd-directory" };

        LDAPSearchResults results = connection.search(
                baseDN,
                LDAPv3.SCOPE_SUB,
                filter,
                attrNames,
                false);

        while (results.hasMoreElements()) {
            LDAPEntry entry = results.next();
            String dn = entry.getDN();
            logger.debug("Checking " + dn);

            LDAPAttributeSet attrSet = entry.getAttributeSet();
            Enumeration<LDAPAttribute> attrs = attrSet.getAttributes();

            while (attrs.hasMoreElements()) {
                LDAPAttribute attr = attrs.nextElement();
                String name = attr.getName();

                Enumeration<String> values = attr.getStringValues();
                while (values.hasMoreElements()) {
                    String value = values.nextElement();
                    logger.debug("- " + name + ": " + value);

                    if (name.equalsIgnoreCase("nsslapd-directory")) {
                        return value.substring(0, value.lastIndexOf("/db"));
                    }
                }
            }
        }

        return "";
    }

    public void createChangeLog() throws Exception {

        String dn = "cn=changelog5,cn=config";
        logger.info("Adding " + dn);

        String dir = getInstanceDir() + "/changelogs";

        LDAPAttributeSet attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectClass", "top"));
        attrs.add(new LDAPAttribute("objectClass", "extensibleObject"));
        attrs.add(new LDAPAttribute("cn", "changelog5"));
        attrs.add(new LDAPAttribute("nsslapd-changelogdir", dir));

        LDAPEntry entry = new LDAPEntry(dn, attrs);

        try {
            connection.add(entry);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                logger.warn("Changelog already exists: " + dn);
                // leave it, don't delete it because it will cause an operation error

            } else if (e.getLDAPResultCode() == LDAPException.UNWILLING_TO_PERFORM) {
                // Since Fedora 33 the DS changelog has moved and will be created
                // automatically when the replication is enabled. Also, the operation
                // to add the old changelog will fail with LDAP error 53. However, in
                // older DS versions the old changelog still needs to be added manually.
                // To support all DS versions the code will now ignore LDAP error 53.
                //
                // https://github.com/dogtagpki/pki/issues/3379
                dn = "cn=changelog,cn=" + config.getDatabase() + ",cn=ldbm database,cn=plugins,cn=config";
                logger.warn("Changelog has moved to " + dn);

            } else {
                logger.error("Unable to add " + dn + ": " + e.getMessage(), e);
                throw e;
            }
        }
    }

    public boolean createReplicaObject(String bindUser, int id) throws Exception {

        String baseDN = config.getBaseDN();
        String replicaDN = "cn=replica,cn=\"" + baseDN + "\",cn=mapping tree,cn=config";
        String bindDN = "cn=" + LDAPUtil.escapeRDNValue(bindUser) + ",ou=csusers,cn=config";

        logger.info("Adding " + replicaDN);
        logger.info("- nsDS5ReplicaRoot: " + baseDN);
        logger.info("- nsDS5ReplicaBindDN: " + bindDN);
        logger.info("- nsDS5ReplicaId: " + id);

        LDAPAttributeSet attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectclass", "top"));
        attrs.add(new LDAPAttribute("objectclass", "nsDS5Replica"));
        attrs.add(new LDAPAttribute("objectclass", "extensibleobject"));
        attrs.add(new LDAPAttribute("cn", "replica"));
        attrs.add(new LDAPAttribute("nsDS5ReplicaRoot", baseDN));
        attrs.add(new LDAPAttribute("nsDS5ReplicaType", "3"));
        attrs.add(new LDAPAttribute("nsDS5ReplicaBindDN", bindDN));
        attrs.add(new LDAPAttribute("nsDS5ReplicaId", Integer.toString(id)));
        attrs.add(new LDAPAttribute("nsds5flags", "1"));

        LDAPEntry entry = new LDAPEntry(replicaDN, attrs);

        try {
            connection.add(entry);

        } catch (LDAPException e) {

            if (e.getLDAPResultCode() != LDAPException.ENTRY_ALREADY_EXISTS) {
                logger.warn("Unable to add " + replicaDN + ": " + e.getMessage(), e);
                return false;
            }

            // BZ 470918: We can't just add the new dn.
            // We need to do a replace until the bug is fixed.
            logger.warn("Entry already exists: " + replicaDN);

            entry = connection.read(replicaDN);
            LDAPAttribute attr = entry.getAttribute("nsDS5ReplicaBindDN");
            attr.addValue(bindDN);

            LDAPModification mod = new LDAPModification(LDAPModification.REPLACE, attr);

            try {
                connection.modify(replicaDN, mod);

            } catch (LDAPException ee) {
                if (e.getLDAPResultCode() != LDAPException.ENTRY_ALREADY_EXISTS) {
                    logger.warn("Unable to modify " + replicaDN + ": " + ee.getMessage(), ee);
                    return false;
                }
            }
        }

        return true;
    }

    public void createReplicationAgreement(
            String name,
            String replicaHostname,
            int replicaPort,
            String bindUser,
            String replicaPassword,
            String replicationSecurity) throws Exception {

        String baseDN = config.getBaseDN();
        String replicaDN = "cn=replica,cn=\"" + baseDN + "\",cn=mapping tree,cn=config";
        String dn = "cn=" + LDAPUtil.escapeRDNValue(name) + "," + replicaDN;
        String bindDN = "cn=" + LDAPUtil.escapeRDNValue(bindUser) + ",ou=csusers,cn=config";

        logger.info("Adding " + dn);
        logger.info("- description: " + name);
        logger.info("- nsDS5ReplicaRoot: " + baseDN);
        logger.info("- nsDS5ReplicaHost: " + replicaHostname);
        logger.info("- nsDS5ReplicaPort: " + replicaPort);
        logger.info("- nsDS5ReplicaBindDN: " + bindDN);

        LDAPAttributeSet attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectclass", "top"));
        attrs.add(new LDAPAttribute("objectclass", "nsds5replicationagreement"));
        attrs.add(new LDAPAttribute("cn", name));
        attrs.add(new LDAPAttribute("description", name));
        attrs.add(new LDAPAttribute("nsDS5ReplicaRoot", baseDN));
        attrs.add(new LDAPAttribute("nsDS5ReplicaHost", replicaHostname));
        attrs.add(new LDAPAttribute("nsDS5ReplicaPort", "" + replicaPort));
        attrs.add(new LDAPAttribute("nsDS5ReplicaBindDN", bindDN));
        attrs.add(new LDAPAttribute("nsDS5ReplicaBindMethod", "Simple"));
        attrs.add(new LDAPAttribute("nsds5replicacredentials", replicaPassword));

        if (replicationSecurity != null && !replicationSecurity.equalsIgnoreCase("None")) {
            logger.info("- nsDS5ReplicaTransportInfo: " + replicationSecurity);
            attrs.add(new LDAPAttribute("nsDS5ReplicaTransportInfo", replicationSecurity));
        }

        LDAPEntry entry = new LDAPEntry(dn, attrs);

        try {
            connection.add(entry);

        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                logger.warn("Entry already exists: " + dn);

                try {
                    connection.delete(dn);
                } catch (LDAPException ee) {
                    logger.error("Unable to delete " + dn + ": " + ee.getMessage(), ee);
                    throw ee;
                }

                try {
                    connection.add(entry);
                } catch (LDAPException ee) {
                    logger.error("Unable to add " + dn + ": " + ee.getMessage(), ee);
                    throw ee;
                }

            } else {
                logger.error("Unable to add " + dn + ": " + e.getMessage(), e);
                throw e;
            }
        }
    }

    public boolean setupReplicationAgreement(
            String agreementName,
            String bindUser,
            String bindPassword,
            String peerHostname,
            int peerPort,
            String peerBindUser,
            String peerBindPassword,
            String security,
            int replicaID)
            throws Exception {

        createSystemContainer();
        createReplicationManager(bindUser, bindPassword);
        createChangeLog();

        boolean created = createReplicaObject(bindUser, replicaID);

        createReplicationAgreement(
                agreementName,
                peerHostname,
                peerPort,
                peerBindUser,
                peerBindPassword,
                security);

        return created;
    }

    public void initializeConsumer(String agreementName) throws Exception {

        String baseDN = config.getBaseDN();
        String replicaDN = "cn=replica,cn=\"" + baseDN + "\",cn=mapping tree,cn=config";
        String dn = "cn=" + LDAPUtil.escapeRDNValue(agreementName) + "," + replicaDN;
        logger.info("Initializing consumer " + dn);

        LDAPAttribute attr = new LDAPAttribute("nsds5beginreplicarefresh", "start");
        LDAPModification mod = new LDAPModification(LDAPModification.REPLACE, attr);
        connection.modify(dn, mod);

        while (!isReplicationDone(replicaDN, agreementName)) {
            Thread.sleep(1000);
        }

        String status = getReplicationStatus(replicaDN, agreementName);
        if (!status.startsWith("Error (0) ") && !status.startsWith("0 ")) {
            String message = "Replication consumer initialization failed " +
                "(against " + connection.getHost() + ":" + connection.getPort() + "): " + status;
            logger.error(message);
            throw new Exception(message);
        }
    }

    public boolean isReplicationDone(String replicaDN, String agreementName) throws Exception {

        String dn = "cn=" + LDAPUtil.escapeRDNValue(agreementName) + "," + replicaDN;
        logger.info("Checking " + dn);

        String filter = "(objectclass=*)";
        String[] attrs = { "nsds5beginreplicarefresh" };

        LDAPSearchResults results = connection.search(
                dn,
                LDAPConnection.SCOPE_BASE,
                filter,
                attrs,
                true);

        int count = results.getCount();

        if (count < 1) {
            throw new Exception("Entry not found: " + dn);
        }

        LDAPEntry entry = results.next();
        LDAPAttribute refresh = entry.getAttribute("nsds5beginreplicarefresh");

        if (refresh != null) {
            String name = refresh.getName();
            for (String value : refresh.getStringValueArray()) {
                logger.debug("- " + name + ": " + value);
            }
            return false;
        }

        return true;
    }

    public String getReplicationStatus(String replicaDN, String agreementName) throws Exception {

        String dn = "cn=" + LDAPUtil.escapeRDNValue(agreementName) + "," + replicaDN;
        logger.info("Checking " + dn);

        String filter = "(objectclass=*)";
        String[] attrNames = { "nsds5replicalastinitstatus" };

        LDAPSearchResults results = connection.search(
                dn,
                LDAPConnection.SCOPE_BASE,
                filter,
                attrNames,
                false);

        int count = results.getCount();

        if (count < 1) {
            throw new Exception("Entry not found: " + dn);
        }

        LDAPEntry entry = results.next();
        LDAPAttribute attr = entry.getAttribute("nsds5replicalastinitstatus");

        if (attr == null) {
            throw new Exception("Attribute not found: nsDS5ReplicaLastInitStatus");
        }

        Enumeration<String> attrs = attr.getStringValues();

        if (!attrs.hasMoreElements()) {
            throw new Exception("Attribute value not found: nsds5replicalastinitstatus");
        }

        String status = attrs.nextElement();
        logger.debug("- nsds5replicalastinitstatus: " + status);

        return status;
    }
}
