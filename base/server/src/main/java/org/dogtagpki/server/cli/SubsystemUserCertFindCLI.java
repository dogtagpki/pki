//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.security.cert.X509Certificate;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CLIException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemUserCertFindCLI extends SubsystemCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemUserCertFindCLI.class);

    public SubsystemUserCertFindCLI(CLI parent) {
        super("find", "Find " + parent.getParent().getParent().getName().toUpperCase() + " user certificates", parent);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing user ID");
        }

        String userID = cmdArgs[0];

        initializeTomcatJSS();

        String subsystem = parent.getParent().getParent().getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        UGSubsystemConfig ugConfig = cs.getUGSubsystemConfig();
        LDAPConfig ldapConfig = ugConfig.getLDAPConfig();
        ldapConfig.putInteger("minConns", 1);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        IPasswordStore passwordStore = IPasswordStore.create(psc);

        UGSubsystem ugSubsystem = new UGSubsystem();

        try {
            ugSubsystem.init(ldapConfig, socketConfig, passwordStore);

            User user = ugSubsystem.getUser(userID);
            X509Certificate[] certs = user.getX509Certificates();

            if (certs != null) {
                boolean first = true;
                for (X509Certificate cert : certs) {

                    if (first) {
                        first = false;
                    } else {
                        System.out.println();
                    }

                    UserCertData userCertData = new UserCertData();

                    userCertData.setVersion(cert.getVersion());
                    userCertData.setSerialNumber(new CertId(cert.getSerialNumber()));
                    userCertData.setIssuerDN(cert.getIssuerDN().toString());
                    userCertData.setSubjectDN(cert.getSubjectDN().toString());

                    SubsystemUserCertCLI.printCert(userCertData, false, false);
                }
            }

        } finally {
            ugSubsystem.shutdown();
        }
    }
}
