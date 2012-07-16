package com.netscape.cms.client.cert;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Collection;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

import com.netscape.cms.client.cli.CLI;
import com.netscape.cms.client.cli.MainCLI;
import com.netscape.cms.servlet.request.model.CertRequestInfo;
import com.netscape.cms.servlet.request.model.CertRequestInfos;
import com.netscape.cms.servlet.request.model.EnrollmentRequestData;

public class CertRequestSubmitCLI extends CLI {

    CertCLI parent;

    public CertRequestSubmitCLI(CertCLI parent) {
        super("request-submit", "Submit certificate request");
        this.parent = parent;
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

        EnrollmentRequestData erd = null;

        try {
            erd = getEnrollmentRequest(cLineArgs[0]);
            CertRequestInfos cri = parent.client.enrollRequest(erd);
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

    private EnrollmentRequestData getEnrollmentRequest(String fileName) throws JAXBException, FileNotFoundException {
        EnrollmentRequestData erd = null;
        JAXBContext context = JAXBContext.newInstance(EnrollmentRequestData.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        FileInputStream fis = new FileInputStream(fileName);
        erd = (EnrollmentRequestData) unmarshaller.unmarshal(fis);
        return erd;
    }

    private void printRequestInformation(CertRequestInfos cri) {
        Collection<CertRequestInfo> allRequests = cri.getRequests();
        for (CertRequestInfo x : allRequests) {
            CertCLI.printCertRequestInfo(x);
        }
        System.out.println();
    }

    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " <filename>", options);
    }
}
