//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.tks;

import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.tks.TKSClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class TKSCertTransportImportCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TKSCertTransportImportCLI.class);

    public TKSCertCLI certCLI;

    public TKSCertTransportImportCLI(TKSCertCLI certCLI) {
        super("transport-import", "Import TKS transport certificate", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "security-domain", true, "Security domain URL");
        option.setArgName("URL");
        options.addOption(option);

        option = new Option(null, "session", true, "Session ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "install-token", true, "Install token");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "input-format", true, "Input format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "input-file", true, "Input file");
        option.setArgName("file");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();
        String nickname = null;

        if (cmdArgs.length >= 1) {
            nickname = cmdArgs[0];
        }

        String url = cmd.getOptionValue("security-domain");

        if (url == null) {
            throw new Exception("Missing security domain URL");
        }

        URI uri = new URL(url).toURI();

        String installToken = cmd.getOptionValue("install-token");
        String sessionID;

        if (installToken != null) {
            sessionID = new String(Files.readAllBytes(Paths.get(installToken)));
        } else {
            sessionID = cmd.getOptionValue("session");
        }

        if (sessionID == null) {
            throw new Exception("Missing session ID or install token");
        }

        String filename = cmd.getOptionValue("input-file");

        byte[] bytes;
        if (filename == null) {
            // read from standard input
            bytes = IOUtils.toByteArray(System.in);

        } else {
            // read from file
            bytes = Files.readAllBytes(Paths.get(filename));
        }

        String format = cmd.getOptionValue("input-format");

        if (format == null || "PEM".equalsIgnoreCase(format)) {
            bytes = Cert.parseCertificate(new String(bytes));

        } else if ("DER".equalsIgnoreCase(format)) {
            // nothing to do

        } else {
            throw new Exception("Unsupported format: " + format);
        }

        String b64cert = Utils.base64encodeSingleLine(bytes);

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        TKSClient tksClient = new TKSClient(client);
        tksClient.importTransportCert(uri, nickname, b64cert, sessionID);
    }
}
