package com.netscape.cmstools.cert;

import java.io.FileInputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class CertRequestApproveCLI extends CLI {
    CertCLI parent;

    public CertRequestApproveCLI(CertCLI parent) {
        super("request-approve", "Approve certificate request");
        this.parent = parent;
    }

    @Override
    public void execute(String[] args) throws Exception {
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

        FileInputStream fis = new FileInputStream(cLineArgs[0].trim());

        JAXBContext context = JAXBContext.newInstance(CertReviewResponse.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        CertReviewResponse reviewInfo = (CertReviewResponse) unmarshaller.unmarshal(fis);

        parent.client.approveRequest(reviewInfo.getRequestId(), reviewInfo);

        MainCLI.printMessage("Approved certificate request " + reviewInfo.getRequestId().toString());
    }

    @Override
    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " <file name>", options);
    }
}
