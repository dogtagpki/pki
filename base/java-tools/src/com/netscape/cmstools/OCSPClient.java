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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmstools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.PosixParser;
import org.dogtagpki.util.logging.PKILogger;
import org.mozilla.jss.CryptoManager;

import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.CertStatus;
import com.netscape.cmsutil.ocsp.GoodInfo;
import com.netscape.cmsutil.ocsp.OCSPProcessor;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.ResponseBytes;
import com.netscape.cmsutil.ocsp.ResponseData;
import com.netscape.cmsutil.ocsp.RevokedInfo;
import com.netscape.cmsutil.ocsp.SingleResponse;
import com.netscape.cmsutil.ocsp.UnknownInfo;

/**
 * This class implements an OCSP command line interface.
 *
 * @version $Revision$, $Date$
 */
public class OCSPClient {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OCSPClient.class);

    public Options createOptions() throws UnknownHostException {

        Options options = new Options();

        Option option = new Option("d", true, "Security database location (default: current directory)");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("h", true, "OCSP server hostname (default: "+ InetAddress.getLocalHost().getCanonicalHostName() + ")");
        option.setArgName("hostname");
        options.addOption(option);

        option = new Option("p", true, "OCSP server port number (default: 8080)");
        option.setArgName("port");
        options.addOption(option);

        option = new Option("t", true, "OCSP service path (default: /ocsp/ee/ocsp)");
        option.setArgName("path");
        options.addOption(option);

        option = new Option("c", true, "CA certificate nickname (default: CA Signing Certificate)");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option("n", true, "Number of submissions (default: 1)");
        option.setArgName("times");
        options.addOption(option);

        option = new Option(null, "serial", true, "Serial number of certificate to be checked");
        option.setArgName("serial");
        options.addOption(option);

        option = new Option(null, "input", true, "Input file containing DER-encoded OCSP request");
        option.setArgName("input");
        options.addOption(option);

        option = new Option(null, "output", true, "Output file to store DER-encoded OCSP response");
        option.setArgName("output");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");

        return options;
    }

    public static void printHelp() throws Exception {
        System.out.println("Usage: OCSPClient [OPTIONS]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -d <database>        Security database location (default: current directory)");
        System.out.println("  -h <hostname>        OCSP server hostname (default: "+ InetAddress.getLocalHost().getCanonicalHostName() + ")");
        System.out.println("  -p <port>            OCSP server port number (default: 8080)");
        System.out.println("  -t <path>            OCSP service path (default: /ocsp/ee/ocsp)");
        System.out.println("  -c <nickname>        CA certificate nickname (defaut: CA Signing Certificate)");
        System.out.println("  -n <times>           Number of submissions (default: 1)");
        System.out.println();
        System.out.println("  --serial <serial>    Serial number of certificate to be checked");
        System.out.println("  --input <input>      Input file containing DER-encoded OCSP request");
        System.out.println("  --output <output>    Output file to store DER-encoded OCSP response");
        System.out.println();
        System.out.println("  -v, --verbose        Run in verbose mode.");
        System.out.println("      --debug          Run in debug mode.");
        System.out.println("      --help           Show help message.");
    }

    public void execute(String args[]) throws Exception {

        Options options = createOptions();

        CommandLineParser parser = new PosixParser();
        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.Level.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(PKILogger.Level.INFO);
        }

        String databaseDir = cmd.getOptionValue("d", ".");
        String hostname = cmd.getOptionValue("h", InetAddress.getLocalHost().getCanonicalHostName());
        int port = Integer.parseInt(cmd.getOptionValue("p", "8080"));
        String path = cmd.getOptionValue("t", "/ocsp/ee/ocsp");
        String caNickname = cmd.getOptionValue("c", "CA Signing Certificate");
        int times = Integer.parseInt(cmd.getOptionValue("n", "1"));

        String input = cmd.getOptionValue("input");
        String serial = cmd.getOptionValue("serial");
        String output = cmd.getOptionValue("output");

        if (times < 1) {
            throw new Exception("Invalid number of submissions");
        }

        try {
            logger.info("Initializing security database: " + databaseDir);
            CryptoManager.initialize(databaseDir);

            String url = "http://" + hostname + ":" + port + path;

            OCSPProcessor processor = new OCSPProcessor();
            processor.setVerbose(logger.isInfoEnabled());

            OCSPRequest request;
            if (serial != null) {
                logger.info("Creating request for serial number " + serial);

                BigInteger serialNumber = new BigInteger(serial);
                request = processor.createRequest(caNickname, serialNumber);

            } else if (input != null) {
                logger.info("Loading request from " + input);

                try (FileInputStream in = new FileInputStream(input)) {
                    byte[] data = new byte[in.available()];
                    in.read(data);
                    request = processor.createRequest(data);
                }

            } else {
                throw new Exception("Missing serial number or input file.");
            }

            OCSPResponse response = null;
            for (int i = 0; i < times; i++) {

                logger.info("Submitting OCSP request");
                response = processor.submitRequest(url, request);

                ResponseBytes bytes = response.getResponseBytes();
                BasicOCSPResponse basic = (BasicOCSPResponse)BasicOCSPResponse.getTemplate().decode(
                        new ByteArrayInputStream(bytes.getResponse().toByteArray()));

                ResponseData rd = basic.getResponseData();
                for (int j = 0; j < rd.getResponseCount(); j++) {
                    SingleResponse sr = rd.getResponseAt(j);

                    if (sr == null) {
                        throw new Exception("No OCSP Response data.");
                    }

                    System.out.println("CertID.serialNumber=" +
                            sr.getCertID().getSerialNumber());

                    CertStatus status = sr.getCertStatus();
                    if (status instanceof GoodInfo) {
                        System.out.println("CertStatus=Good");

                    } else if (status instanceof UnknownInfo) {
                        System.out.println("CertStatus=Unknown");

                    } else if (status instanceof RevokedInfo) {
                        System.out.println("CertStatus=Revoked");
                    }
                }
            }

            if (output != null) {
                logger.info("Storing response into " + output);

                try (FileOutputStream out = new FileOutputStream(output)) {
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    response.encode(os);
                    out.write(os.toByteArray());
                }

                System.out.println("Success: Output " + output);
            }

        } catch (Exception e) {
            throw e;
        }
    }

    public static void main(String args[]) throws Exception {
        try {
            OCSPClient client = new OCSPClient();
            client.execute(args);

        } catch (Exception e) {

            String message = e.getClass().getSimpleName();
            if (e.getMessage() != null) {
                message += ": " + e.getMessage();
            }

            if (logger.isInfoEnabled()) {
                logger.error(message, e);
            } else {
                logger.error(message);
            }

            System.exit(1);
        }
    }
}
