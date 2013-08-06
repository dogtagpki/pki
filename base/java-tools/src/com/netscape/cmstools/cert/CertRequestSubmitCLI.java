package com.netscape.cmstools.cert;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Collection;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

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

        CertEnrollmentRequest erd = null;

        try {
            erd = getEnrollmentRequest(cLineArgs[0]);
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
        CertEnrollmentRequest erd = null;
        JAXBContext context = JAXBContext.newInstance(CertEnrollmentRequest.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        FileInputStream fis = new FileInputStream(fileName);
        erd = (CertEnrollmentRequest) unmarshaller.unmarshal(fis);
        return erd;
    }

    private void printRequestInformation(CertRequestInfos cri) {
        Collection<CertRequestInfo> allRequests = cri.getRequests();
        for (CertRequestInfo x : allRequests) {
            CertCLI.printCertRequestInfo(x);
        }
        System.out.println();
    }
}
