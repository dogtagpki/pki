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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;
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
import netscape.ldap.util.LDIF;
import netscape.ldap.util.LDIFAttributeContent;
import netscape.ldap.util.LDIFContent;
import netscape.ldap.util.LDIFModifyContent;
import netscape.ldap.util.LDIFRecord;

public class LDAPConfigurator {

    public final static Logger logger = LoggerFactory.getLogger(LDAPConfigurator.class);

    EngineConfig engineConfig;
    LDAPConnection connection;

    Map<String, String> params = new HashMap<>();

    public LDAPConfigurator(EngineConfig engineConfig, LDAPConnection connection) throws Exception {
        this.engineConfig = engineConfig;
        this.connection = connection;

        PreOpConfig preopConfig = engineConfig.getPreOpConfig();
        LDAPConfig ldapConfig = engineConfig.getInternalDBConfig();

        String baseDN = ldapConfig.getBaseDN();
        params.put("rootSuffix", baseDN);

        String database = ldapConfig.getString("database");
        params.put("database", database);

        String instanceId = engineConfig.getInstanceID();
        params.put("instanceId", instanceId);

        String dbuser = preopConfig.getString(
                "internaldb.dbuser",
                "uid=pkidbuser,ou=people," + baseDN);
        params.put("dbuser", dbuser);
    }

    public LDAPConnection getConnection() {
        return connection;
    }

    public String getParam(String name) {
        return params.get(name);
    }

    public LDAPEntry getEntry(String dn) throws Exception {

        logger.info("LDAPConfigurator: Getting " + dn);

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

        logger.info("LDAPConfigurator: Validating database " + database + " is owned by " + baseDN);

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

            logger.info("LDAPConfigurator: Deleting " + dn);
            connection.delete(dn);

        } catch (LDAPException e) {

            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                logger.info("LDAPConfigurator: Entry not found: " + dn);

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
            logger.info("LDAPConfigurator: Waiting for task " + dn + " (" + count + "s)");

            try {
                LDAPEntry task = getEntry(dn);
                if (task == null) continue;

                LDAPAttribute attr = task.getAttribute("nsTaskExitCode");
                if (attr == null) continue;

                returnCode = attr.getStringValues().nextElement();
                break;

            } catch (Exception e) {
                logger.warn("LDAPConfigurator: Unable to read task " + dn + ": " + e);
            }
        }

        if (returnCode == null || !"0".equals(returnCode)) {
            String message = "Task " + dn + " failed: nsTaskExitCode=" + returnCode;
            logger.error(message);
            throw new Exception(message);
        }

        logger.info("LDAPConfigurator: Task " + dn + " complete");
    }

    public void createDatabaseEntry(String databaseDN, String database, String baseDN) throws Exception {

        logger.debug("LDAPConfigurator: Adding " + databaseDN);

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

        logger.debug("LDAPConfigurator: Adding " + mappingDN);

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

    public void checkParentExists(String baseDN) throws Exception {

        String[] rdns = LDAPDN.explodeDN(baseDN, false);

        if (rdns.length == 1) {
            String message = "Base entry has no parent: " + baseDN;
            logger.error(message);
            throw new EBaseException(message);
        }

        String parentDN = Arrays.toString(Arrays.copyOfRange(rdns, 1, rdns.length));
        parentDN = parentDN.substring(1, parentDN.length() - 1);

        logger.debug("LDAPConfigurator: Checking parent entry " + parentDN);
        LDAPEntry parentEntry = getEntry(parentDN);

        if (parentEntry == null) {
            throw new Exception("Parent entry " + parentDN + " does not exist");
        }
    }

    public void createBaseEntry(String baseDN) throws Exception {

        logger.debug("LDAPConfigurator: Adding " + baseDN);

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

        logger.info("LDAPConfigurator: Creating " + tmpFile);

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

    public void importLDIFFile(String filename, boolean ignoreErrors) throws Exception {

        logger.info("LDAPConfigurator: Importing " + filename);

        LDIF ldif = new LDIF(filename);

        while (true) {

            LDIFRecord record = ldif.nextRecord();
            if (record == null) break;

            importLDIFRecord(record, ignoreErrors);
        }
    }

    public void importLDIFRecord(LDIFRecord record, boolean ignoreErrors) throws Exception {

        String dn = record.getDN();
        LDIFContent content = record.getContent();
        int type = content.getType();

        if (type == LDIFContent.ATTRIBUTE_CONTENT) {

            logger.info("LDAPConfigurator: Adding " + dn);

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

                if (ignoreErrors) {
                    logger.warn(message);

                } else {
                    logger.error(message);
                    throw new Exception(message, e);
                }
            }

        } else if (type == LDIFContent.MODIFICATION_CONTENT) {

            logger.info("LDAPConfigurator: Modifying " + dn);

            LDIFModifyContent c = (LDIFModifyContent) content;
            LDAPModification[] mods = c.getModifications();

            for (LDAPModification mod : mods) {
                int operation = mod.getOp();
                LDAPAttribute attr = mod.getAttribute();
                String name = attr.getName();

                switch (operation) {
                    case LDAPModification.ADD:
                        logger.info("- add: " + name);
                        break;
                    case LDAPModification.REPLACE:
                        logger.info("- replace: " + name);
                        break;
                    case LDAPModification.DELETE:
                        logger.info("- delete: " + name);
                        break;
                }

                String[] values = attr.getStringValueArray();
                if (values != null) {
                    for (String value : values) {
                        logger.info("  " + name + ": " + value);
                    }
                }
            }

            try {
                connection.modify(dn, mods);

            } catch (LDAPException e) {

                String message = "Unable to modify " + dn + ": " + e;

                if (ignoreErrors) {
                    logger.warn(message);

                } else {
                    logger.error(message);
                    throw new Exception(message, e);
                }
            }
        }
    }

    public void deleteDatabase(String database, String baseDN) throws Exception {

        String databaseDN = "cn=" + LDAPUtil.escapeRDNValue(database) + ",cn=ldbm database, cn=plugins, cn=config";
        String mappingDN = "cn=\"" + baseDN + "\",cn=mapping tree, cn=config";

        logger.info("LDAPConfigurator: Validating database ownership");
        validateDatabaseOwnership(database, baseDN);

        logger.info("LDAPConfigurator: Deleting mapping entry " + mappingDN);
        deleteEntry(mappingDN);

        logger.info("LDAPConfigurator: Deleting database entry " + databaseDN);
        deleteEntry(databaseDN);
    }
}
