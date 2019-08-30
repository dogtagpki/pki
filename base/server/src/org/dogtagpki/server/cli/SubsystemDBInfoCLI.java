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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.cli;

import java.io.File;
import java.util.Enumeration;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.Level;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmsutil.password.IPasswordStore;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBInfoCLI extends CLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemDBInfoCLI.class);

    public SubsystemDBInfoCLI(CLI parent) {
        super("info", "Display " + parent.getParent().getName().toUpperCase() + " database info", parent);

        createOptions();
    }

    public void createOptions() {

        Option option = new Option("d", true, "NSS database location");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("f", true, "NSS database password configuration");
        option.setArgName("password config");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args, true);

        if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(Level.INFO);

        } else if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);
        }

        String catalinaBase = System.getProperty("catalina.base");
        String serverXml = catalinaBase + "/conf/server.xml";

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadTomcatConfig(serverXml);
        tomcatjss.init();

        String subsystem = parent.getParent().getName();
        String configFile = catalinaBase + File.separator + subsystem + File.separator +
                "conf" + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStore(configFile);
        IConfigStore cs = new PropConfigStore(storage);
        cs.load();
        IConfigStore ldapConfig = cs.getSubStore("internaldb");

        String instanceId = cs.getString("instanceId");
        String pwdClass = cs.getString("passwordClass");
        String pwdPath = cs.getString("passwordFile", null);

        logger.info("Creating " + pwdClass);
        IPasswordStore passwordStore = (IPasswordStore) Class.forName(pwdClass).newInstance();
        passwordStore.init(pwdPath);
        passwordStore.setId(instanceId);

        IConfigStore connConfig = ldapConfig.getSubStore("ldapconn");
        IConfigStore authConfig = ldapConfig.getSubStore("ldapauth");

        LdapConnInfo connInfo = new LdapConnInfo(connConfig);

        LdapAuthInfo authInfo = new LdapAuthInfo();
        authInfo.setPasswordStore(passwordStore);
        authInfo.init(
                authConfig,
                connInfo.getHost(),
                connInfo.getPort(),
                connInfo.getSecure());

        PKISocketFactory socketFactory;
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory = new PKISocketFactory(authInfo.getClientCertNickname());
        } else {
            socketFactory = new PKISocketFactory(connInfo.getSecure());
        }
        socketFactory.init(cs);

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);

        try {
            LDAPSearchResults results = conn.search(
                    "",
                    LDAPv3.SCOPE_BASE,
                    "(objectClass=*)",
                    new String[] { "*", "+" },
                    false);

            LDAPEntry entry = results.next();
            LDAPAttributeSet attrs = entry.getAttributeSet();

            Enumeration<LDAPAttribute> e1 = attrs.getAttributes();
            while (e1.hasMoreElements()) {

                LDAPAttribute attr = e1.nextElement();
                String name = attr.getName();

                Enumeration<String> e2 = attr.getStringValues();
                while (e2.hasMoreElements()) {

                    String value = e2.nextElement();
                    System.out.println("  " + name + ": " + value);
                }
            }

        } finally {
            conn.disconnect();
        }
    }
}
