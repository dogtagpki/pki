//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import java.io.File;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.jss.tomcat.TomcatJSS;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.LogLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.CRLRepository;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class CACRLRecordShowCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(CACRLRecordShowCLI.class);

    public CACRLRecordShowCLI(CLI parent) {
        super("show", "Show CRL record", parent);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.LogLevel.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(LogLevel.INFO);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("Missing CRL record ID");
        }

        String ipID = cmdArgs[0];

        String instanceDir = CMS.getInstanceDir();

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String subsystem = parent.getParent().getParent().getName();
        String confDir = instanceDir + File.separator + subsystem + File.separator + "conf";
        String configFile = confDir + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStorage(configFile);
        CAEngineConfig cs = new CAEngineConfig(storage);
        cs.load();

        DatabaseConfig dbConfig = cs.getDatabaseConfig();
        LDAPConfig ldapConfig = dbConfig.getLDAPConfig();
        ldapConfig.setMinConnections(0);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = CMS.createPasswordStore(psc);

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();
        LDAPAuthenticationConfig authConfig = ldapConfig.getAuthenticationConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setSecure(connConfig.isSecure());
        if (LdapAuthInfo.LDAP_SSLCLIENTAUTH_STR.equals(authConfig.getAuthType())) {
            socketFactory.setClientCertNickname(authConfig.getClientCertNickname());
        }
        socketFactory.init(socketConfig);

        DBSubsystem dbSubsystem = new DBSubsystem();
        dbSubsystem.setEngineConfig(cs);
        dbSubsystem.setSocketFactory(socketFactory);
        dbSubsystem.init(dbConfig, ldapConfig, passwordStore);

        logger.info("Initializing cert repository");

        try {
            CRLRepository crlRepository = new CRLRepository(dbSubsystem);
            crlRepository.init();

            CRLIssuingPointRecord record = crlRepository.readCRLIssuingPointRecord(ipID);

            long crlSize = record.getCRLSize();
            if (crlSize >= 0) {
                CertId crlNumber = new CertId(record.getCRLNumber());
                System.out.println("  CRL Number: " + crlNumber.toHexString());
                System.out.println("  CRL Size: " + crlSize);
            }

            long deltaCRLSize = record.getDeltaCRLSize();
            if (deltaCRLSize >= 0) {
                CertId deltaCRLNumber = new CertId(record.getDeltaCRLNumber());
                System.out.println("  Delta CRL Number: " + deltaCRLNumber.toHexString());
                System.out.println("  Delta CRL Size: " + deltaCRLSize);
            }

            System.out.println("  This Update: " + record.getThisUpdate());
            System.out.println("  Next Update: " + record.getNextUpdate());

        } finally {
            dbSubsystem.shutdown();
        }
    }
}
