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

import org.apache.commons.cli.CommandLine;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmsutil.password.IPasswordStore;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBUpgradeCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemDBUpgradeCLI.class);

    public SubsystemDBUpgradeCLI(CLI parent) {
        this("upgrade", "Upgrade " + parent.parent.name.toUpperCase() + " database", parent);
    }

    public SubsystemDBUpgradeCLI(String name, String description, CLI parent) {
        super(name, description, parent);
   }

    public void execute(CommandLine cmd) throws Exception {

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
        EngineConfig cs = new EngineConfig(storage);
        cs.load();
        LDAPConfig ldapConfig = cs.getInternalDatabase();

        String instanceId = cs.getInstanceID();
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
            String nickname = authInfo.getClientCertNickname();
            logger.info("Authenticating with " + nickname + " certificate");
            socketFactory = new PKISocketFactory(nickname);

        } else if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_BASICAUTH) {
            String bindDN = authInfo.getBindDN();
            logger.info("Authenticating as " + bindDN);
            socketFactory = new PKISocketFactory(connInfo.getSecure());

        } else {
            logger.info("No authentication");
            socketFactory = new PKISocketFactory(connInfo.getSecure());
        }

        socketFactory.init(cs);

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);

        try {
            upgrade(ldapConfig, conn);

        } finally {
            conn.disconnect();
        }

        System.out.println(parent.parent.name.toUpperCase() + " database upgraded");
    }

    public void upgrade(LDAPConfig ldapConfig, LdapBoundConnection conn) throws Exception {
    }
}
