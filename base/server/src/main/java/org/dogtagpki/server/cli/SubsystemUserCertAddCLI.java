//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.dogtagpki.cli.CLI;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemUserCertAddCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemUserCertAddCLI.class);

    public SubsystemUserCertAddCLI(CLI parent) {
        super("add", "Add " + parent.getParent().getParent().getName().toUpperCase() + " user cert", parent);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "cert", true, "Certificate to add");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        options.addOption(null, "ignore-duplicate", false, "Ignore duplicate.");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing user ID");
        }

        String userID = cmdArgs[0];

        String filename = cmd.getOptionValue("cert");
        String format = cmd.getOptionValue("format");
        boolean ignoreDuplicate = cmd.hasOption("ignore-duplicate");

        initializeTomcatJSS();

        byte[] bytes;
        if (filename == null) {
            // read from standard input
            bytes = IOUtils.toByteArray(System.in);

        } else {
            // read from file
            bytes = Files.readAllBytes(Paths.get(filename));
        }

        if (format == null || "PEM".equalsIgnoreCase(format)) {
            bytes = Cert.parseCertificate(new String(bytes));

        } else if ("DER".equalsIgnoreCase(format)) {
            // nothing to do

        } else {
            throw new Exception("Unsupported format: " + format);
        }

        X509CertImpl cert = new X509CertImpl(bytes);

        String subsystem = parent.getParent().getParent().getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        UGSubsystemConfig ugConfig = cs.getUGSubsystemConfig();
        LDAPConfig ldapConfig = ugConfig.getLDAPConfig();
        ldapConfig.setMinConnections(0);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = CMS.createPasswordStore(psc);

        UGSubsystem ugSubsystem = new UGSubsystem();

        try {
            ugSubsystem.init(ldapConfig, socketConfig, passwordStore);
            ugSubsystem.addUserCert(userID, cert);

        } catch (ConflictingOperationException e) {
            if (!ignoreDuplicate) {
                throw e;
            }

        } finally {
            ugSubsystem.shutdown();
        }
    }
}
