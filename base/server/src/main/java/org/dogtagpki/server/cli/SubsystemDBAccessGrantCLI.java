//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.LogLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.servlet.csadmin.LDAPConfigurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBAccessGrantCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemDBAccessGrantCLI.class);

    public SubsystemDBAccessGrantCLI(CLI parent) {
        super("grant", "Grant " + parent.parent.parent.getName().toUpperCase() + " database access", parent);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(LogLevel.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(LogLevel.INFO);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("Missing DN");
        }

        String dn = cmdArgs[0];

        initializeTomcatJSS();
        String subsystem = parent.parent.parent.getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        LDAPConfig ldapConfig = cs.getInternalDBConfig();
        String database = ldapConfig.getDatabase();
        String baseDN = ldapConfig.getBaseDN();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = CMS.createPasswordStore(psc);

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();
        LdapConnInfo connInfo = new LdapConnInfo(connConfig);
        LdapAuthInfo authInfo = getAuthInfo(passwordStore, connInfo, ldapConfig);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setSecure(connInfo.getSecure());
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory.setClientCertNickname(authInfo.getClientCertNickname());
        }
        socketFactory.init(socketConfig);

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);
        LDAPConfigurator ldapConfigurator = new LDAPConfigurator(conn, ldapConfig);

        try {
            ldapConfigurator.grantDatabaseAccess(dn);

        } finally {
            conn.disconnect();
        }
    }
}
