//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.ocsp;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLIException;
import org.mozilla.jss.asn1.GeneralizedTime;
import org.mozilla.jss.asn1.INTEGER;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.CertID;
import com.netscape.cmsutil.ocsp.CertStatus;
import com.netscape.cmsutil.ocsp.OCSPProcessor;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.ResponseData;
import com.netscape.cmsutil.ocsp.RevokedInfo;
import com.netscape.cmsutil.ocsp.SingleResponse;

/**
 * @author Endi S. Dewata
 */
public class OCSPCertVerifyCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OCSPCertVerifyCLI.class);

    public OCSPCertCLI certCLI;

    public OCSPCertVerifyCLI(OCSPCertCLI certCLI) {
        super("verify", "Verify certificate", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [serial number] [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "ca-cert", true, "CA certificate nickname");
        option.setArgName("nickname");
        options.addOption(option);

        option = new Option(null, "path", true, "Path to OCSP responder (default: /ocsp/ee/ocsp");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "request", true, "Path to DER-encoded OCSP request");
        option.setArgName("path");
        options.addOption(option);
    }

    public void printSingleResponse(SingleResponse sr) {
        CertID certID = sr.getCertID();
        INTEGER serialNumber = certID.getSerialNumber();
        System.out.println("  Serial Number: " + new CertId(serialNumber).toHexString());

        CertStatus status = sr.getCertStatus();
        System.out.println("  Status: " + status.getLabel());

        if (status instanceof RevokedInfo info) {
            System.out.println("  Revoked On: " + info.getRevocationTime().toDate());
        }

        GeneralizedTime thisUpdate = sr.getThisUpdate();
        if (thisUpdate != null) {
            System.out.println("  This Update: " + thisUpdate.toDate());
        }

        GeneralizedTime nextUpdate = sr.getNextUpdate();
        if (nextUpdate != null) {
            System.out.println("  Next Update: " + nextUpdate.toDate());
        }
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        String caCertNickname = cmd.getOptionValue("ca-cert");
        String ocspPath = cmd.getOptionValue("path", "/ocsp/ee/ocsp");
        String requestPath = cmd.getOptionValue("request");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ClientConfig config = getConfig();
        String ocspURL = config.getServerURL() + ocspPath;

        OCSPProcessor processor = new OCSPProcessor();
        processor.setURL(ocspURL);

        OCSPRequest request;

        if (requestPath != null) {
            logger.info("Loading OCSP request from " + requestPath);
            byte[] data = Files.readAllBytes(Paths.get(requestPath));
            request = processor.createRequest(data);

        } else {
            if (cmdArgs.length < 1) {
                throw new Exception("Missing certificate serial number");
            }

            if (caCertNickname == null) {
                throw new Exception("Missing CA signing certificate nickname");
            }

            CertId certID = new CertId(cmdArgs[0]);

            logger.info("Creating OCSP request for cert " + certID.toHexString());
            request = processor.createRequest(caCertNickname, certID.toBigInteger());
        }

        logger.info("Submitting OCSP request to " + ocspURL);
        OCSPResponse response;
        try {
            response = processor.submitRequest(request);
        } catch (Exception e) {
            throw new CLIException("Unable to submit OCSP request: " + e.getMessage());
        }

        logger.info("Parsing OCSP response");
        byte[] bytes = response.getResponseBytes().getResponse().toByteArray();
        BasicOCSPResponse basic;

        try (InputStream is = new ByteArrayInputStream(bytes)) {
            basic = (BasicOCSPResponse) BasicOCSPResponse.getTemplate().decode(is);
        }

        ResponseData rd = basic.getResponseData();
        int count = rd.getResponseCount();

        for (int i = 0; i < count; i++) {
            if (i > 0) System.out.println();
            printSingleResponse(rd.getResponseAt(i));
        }
    }
}
