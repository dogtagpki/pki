//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.jss.tomcat.TomcatJSS;

import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SDSubsystemRemoveCLI extends CommandCLI {

    public SDSubsystemRemoveCLI(CLI parent) {
        super("del", "Remove security domain subsystem", parent);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing host ID");
        }

        String subsystemID = cmdArgs[0];

        // Host ID: <type> <hostname> <port>
        Pattern pattern = Pattern.compile("^(\\S+) (\\S+) (\\d+)$");
        Matcher matcher = pattern.matcher(subsystemID);

        if (!matcher.find()) {
            throw new CLIException("Invalid security domain subsystem: " + subsystemID);
        }

        String type = matcher.group(1);
        logger.debug("SDSubsystemRemoveCLI: type: " + type);

        String hostname = matcher.group(2);
        logger.debug("SDSubsystemRemoveCLI: hostname: " + hostname);

        String port = matcher.group(3);
        logger.debug("SDSubsystemRemoveCLI: port: " + port);

        String instanceDir = CMS.getInstanceDir();

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String subsystem = parent.getParent().getParent().getName();
        String subsystemDir = instanceDir + File.separator + subsystem;
        String subsystemConfDir = subsystemDir + File.separator + "conf";
        String configFile = subsystemConfDir + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStorage(configFile);
        EngineConfig cs = new EngineConfig(storage);
        cs.load();
        LDAPConfig ldapConfig = cs.getInternalDBConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = PasswordStore.create(psc);

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();
        LDAPAuthenticationConfig authConfig = ldapConfig.getAuthenticationConfig();

        LdapConnInfo connInfo = new LdapConnInfo(connConfig);

        LdapAuthInfo authInfo = new LdapAuthInfo();
        authInfo.setPasswordStore(passwordStore);
        authInfo.init(
                authConfig,
                connInfo.getHost(),
                connInfo.getPort(),
                connInfo.getSecure());

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setSecure(connInfo.getSecure());
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory.setClientCertNickname(authInfo.getClientCertNickname());
        }
        socketFactory.init(socketConfig);

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);

        try {
            String domainDN = "ou=Security Domain," + ldapConfig.getBaseDN();
            String listDN = "cn=" + type + "List," + domainDN;

            String hostCN = hostname + ":" + port;
            String hostDN = "cn=" + LDAPUtil.escapeRDNValue(hostCN) + "," + listDN;

            logger.info("Removing " + hostDN);
            conn.delete(hostDN);

        } finally {
            conn.disconnect();
        }
    }
}
