//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.io.File;

import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmsutil.password.IPasswordStore;

/**
 * @author Chris S. Kelley
 */
public abstract class SubsystemCLI extends CommandCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemCLI.class);

    protected SubsystemCLI(String name, String description, CLI parent) {
        super(name, description, parent);
    }

    protected void initializeTomcatJSS() throws Exception {
        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();
    }

    protected EngineConfig getEngineConfig(String subsystem) throws Exception {
        String catalinaBase = System.getProperty("catalina.base");
        String configDir = catalinaBase + File.separator + subsystem;
        String configFile = configDir + File.separator + "conf" + File.separator + CMS.CONFIG_FILE;
        logger.info("Loading {}", configFile);
        ConfigStorage storage = new FileConfigStore(configFile);
        EngineConfig engineConfig = new EngineConfig(storage);
        engineConfig.load();
        return engineConfig;
    }

    protected LdapAuthInfo getAuthInfo(IPasswordStore passwordStore, LdapConnInfo connInfo, LDAPConfig ldapConfig)
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
}
