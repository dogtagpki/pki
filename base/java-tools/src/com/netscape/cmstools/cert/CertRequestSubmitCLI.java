package com.netscape.cmstools.cert;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Collection;
import java.util.Scanner;

import javax.xml.bind.JAXBException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class CertRequestSubmitCLI extends CLI {

    CertCLI certCLI;

    public CertRequestSubmitCLI(CertCLI certCLI) {
        super("request-submit", "Submit certificate request", certCLI);
        this.certCLI = certCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <filename>", options);
    }

    @Override
    public void execute(String[] args) {
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cLineArgs = cmd.getArgs();

        if (cLineArgs.length < 1) {
            System.err.println("Error: No filename specified.");
            printHelp();
            System.exit(-1);
        }

        try {
            CertEnrollmentRequest erd = getEnrollmentRequest(cLineArgs[0]);
            CertRequestInfos cri = certCLI.certClient.enrollRequest(erd);
            MainCLI.printMessage("Submitted certificate request");
            printRequestInformation(cri);

        } catch (FileNotFoundException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(-1);

        } catch (JAXBException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(-1);
        }
    }

    private CertEnrollmentRequest getEnrollmentRequest(String fileName) throws JAXBException, FileNotFoundException {
        try (Scanner scanner = new Scanner(new File(fileName))) {
            String xml = scanner.useDelimiter("\\A").next();
            return CertEnrollmentRequest.fromXML(xml);
        }
    }

    private void printRequestInformation(CertRequestInfos cri) {
        Collection<CertRequestInfo> allRequests = cri.getEntries();
        boolean first = true;
        for (CertRequestInfo x : allRequests) {
            if (first) {
                first = false;
            } else {
                System.out.println();
            }
            CertCLI.printCertRequestInfo(x);
        }
    }
}
