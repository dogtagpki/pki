//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.io.File;

import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.jss.tomcat.TomcatJSS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.ServerConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmsutil.password.PasswordStore;

/**
 * @author Chris S. Kelley
 */
public abstract class SubsystemCLI extends CommandCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemCLI.class);
    private static final String SERVER_XML = "server.xml";

    protected SubsystemCLI(String name, String description, CLI parent) {
        super(name, description, parent);
    }

    protected void initializeTomcatJSS() throws Exception {
        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();
    }

    protected EngineConfig getEngineConfig(String subsystem) throws Exception {

        // use subsystem conf folder: /var/lib/pki/<instance>/conf/<subsystem>
        String confDir = CMS.getInstanceDir() + File.separator + "conf" + File.separator + subsystem;
        String configFile = confDir + File.separator + CMS.CONFIG_FILE;
        logger.debug("{}: Loading {}", getClass().getSimpleName(), configFile);

        ConfigStorage storage = new FileConfigStorage(configFile);
        return new EngineConfig(storage);
    }

    protected LdapAuthInfo getAuthInfo(PasswordStore passwordStore, LdapConnInfo connInfo, LDAPConfig ldapConfig)
            throws EBaseException {
        LDAPAuthenticationConfig authConfig = ldapConfig.getAuthenticationConfig();
        LdapAuthInfo authInfo = new LdapAuthInfo();
        authInfo.setPasswordStore(passwordStore);
        authInfo.init(
                authConfig,
                connInfo.getHost(),
                connInfo.getPort(),
                connInfo.getSecure());
        return authInfo;
    }

    protected String getSecurePort(EngineConfig config) throws Exception {

        String path = CMS.getInstanceDir() + File.separator + "conf" + File.separator + SERVER_XML;

        ServerConfig serverConfig = ServerConfig.load(path);
        String securePort = serverConfig.getSecurePort();

        String port = config.getString("proxy.securePort", "");
        if (!port.equals("")) {
            securePort = port;
        }
        return securePort;
    }
}
