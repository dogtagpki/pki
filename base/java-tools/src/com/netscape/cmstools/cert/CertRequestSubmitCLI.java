package com.netscape.cmstools.cert;

import java.io.Console;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.Scanner;

import javax.xml.bind.JAXBException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class CertRequestSubmitCLI extends CLI {

    CertCLI certCLI;

    public CertRequestSubmitCLI(CertCLI certCLI) {
        super("request-submit", "Submit certificate request", certCLI);
        this.certCLI = certCLI;

        Option option = new Option(null, "username", true, "Username for request authentication");
        option.setArgName("username");
        options.addOption(option);

        option = new Option(null, "password", false, "Prompt password for request authentication");
        options.addOption(option);
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <filename> [OPTIONS...]", options);
    }

    @Override
    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            // Display usage
            printHelp();
            System.exit(0);
        }

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            System.err.println("Error: No filename specified.");
            printHelp();
            System.exit(-1);
        }

        CertEnrollmentRequest request = getEnrollmentRequest(cmdArgs[0]);

        String certRequestUsername = cmd.getOptionValue("username");
        if (certRequestUsername != null) {
            request.setAttribute("uid", certRequestUsername);
        }

        if (cmd.hasOption("password")) {
            Console console = System.console();
            String certRequestPassword = new String(console.readPassword("Password: "));
            request.setAttribute("pwd", certRequestPassword);
        }

        CertRequestInfos cri = certCLI.certClient.enrollRequest(request);
        MainCLI.printMessage("Submitted certificate request");
        CertCLI.printCertRequestInfos(cri);
    }

    private CertEnrollmentRequest getEnrollmentRequest(String fileName) throws JAXBException, FileNotFoundException {
        try (Scanner scanner = new Scanner(new File(fileName))) {
            String xml = scanner.useDelimiter("\\A").next();
            return CertEnrollmentRequest.fromXML(xml);
        }
    }
}
