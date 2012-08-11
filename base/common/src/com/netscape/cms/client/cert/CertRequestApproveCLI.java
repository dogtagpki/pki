package com.netscape.cms.client.cert;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.cms.client.cli.CLI;
import com.netscape.cms.client.cli.MainCLI;

public class CertRequestApproveCLI extends CLI {
    CertCLI parent;

    public CertRequestApproveCLI(CertCLI parent) {
        super("request-approve", "Approve certificate request");
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
            System.err.println("Error: No file name specified.");
            printHelp();
            System.exit(-1);
        }
        CertReviewResponse reviewInfo = null;
        try {
            JAXBContext context = JAXBContext.newInstance(CertReviewResponse.class);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            FileInputStream fis = new FileInputStream(cLineArgs[0].trim());
            reviewInfo = (CertReviewResponse) unmarshaller.unmarshal(fis);
            parent.client.approveRequest(reviewInfo.getRequestId(), reviewInfo);
        } catch (PKIException e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        } catch (JAXBException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(-1);
        } catch (FileNotFoundException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(-1);
        }
        MainCLI.printMessage("Approved certificate request " + reviewInfo.getRequestId().toString());
    }

    @Override
    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " <file name>", options);
    }
}
