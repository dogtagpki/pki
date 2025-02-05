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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.pkcs12;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.codec.binary.Hex;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.netscape.security.pkcs.PKCS12;
import org.mozilla.jss.netscape.security.pkcs.PKCS12CertInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS12Util;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.util.Password;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class PKCS12CertExportCLI extends CommandCLI {

    public PKCS12CertCLI certCLI;

    public PKCS12CertExportCLI(PKCS12CertCLI certCLI) {
        super("export", "Export certificate from PKCS #12 file", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] [nickname]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "pkcs12-file", true, "PKCS #12 file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "pkcs12-password", true, "PKCS #12 password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "pkcs12-password-file", true, "PKCS #12 password file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "cert-file", true, "Certificate file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "cert-id", true, "Certificate ID to export");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "cert-format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();
        String id = cmd.getOptionValue("cert-id");

        if (cmdArgs.length < 1 && id == null) {
            throw new Exception("Missing certificate nickname or ID.");
        }

        if (cmdArgs.length >= 1 && id != null) {
            throw new Exception("Certificate nickname and ID are mutually exclusive.");
        }

        String nickname = null;
        byte[] certID = null;

        if (cmdArgs.length >= 1) {
            nickname = cmdArgs[0];
        } else {
            if (id.startsWith("0x")) id = id.substring(2);
            certID = Hex.decodeHex(id);
        }

        String pkcs12File = cmd.getOptionValue("pkcs12-file");

        if (pkcs12File == null) {
            throw new Exception("Missing PKCS #12 file.");
        }

        String passwordString = cmd.getOptionValue("pkcs12-password");

        if (passwordString == null) {

            String passwordFile = cmd.getOptionValue("pkcs12-password-file");
            if (passwordFile != null) {
                try (BufferedReader in = new BufferedReader(new FileReader(passwordFile))) {
                    passwordString = in.readLine();
                }
            }
        }

        if (passwordString == null) {
            throw new Exception("Missing PKCS #12 password.");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        Password password = new Password(passwordString.toCharArray());
        Collection<X509Certificate> certs = new ArrayList<>();

        try {
            PKCS12Util util = new PKCS12Util();
            PKCS12 pkcs12 = util.loadFromFile(pkcs12File, password);

            if (nickname != null) {
                for (PKCS12CertInfo certInfo : pkcs12.getCertInfosByFriendlyName(nickname)) {
                    certs.add(certInfo.getCert());
                }

            } else {
                PKCS12CertInfo certInfo = pkcs12.getCertInfoByID(certID);
                if (certInfo != null) {
                    certs.add(certInfo.getCert());
                }
            }

        } finally {
            password.clear();
        }

        if (certs.isEmpty()) {
            throw new Exception("Certificate not found");
        }

        String format = cmd.getOptionValue("cert-format", "PEM").toUpperCase();
        byte[] output = null;

        if (format.equals("PEM")) {
            StringWriter sw = new StringWriter();
            try (PrintWriter out = new PrintWriter(sw, true)) {
                for (X509Certificate cert : certs) {
                    out.println(Cert.HEADER);
                    out.print(Utils.base64encodeMultiLine(cert.getEncoded()));
                    out.println(Cert.FOOTER);
                }
            }
            output = sw.toString().getBytes();

        } else if (format.equals("DER")) {
            for (X509Certificate cert : certs) {
                output = cert.getEncoded();
            }

        } else {
            throw new CLIException("Unsupported format: " + format);
        }

        String certFile = cmd.getOptionValue("cert-file");
        if (certFile == null) {
            System.out.write(output);

        } else {
            try (FileOutputStream os = new FileOutputStream(certFile)) {
                os.write(output);
            }
        }
    }
}
