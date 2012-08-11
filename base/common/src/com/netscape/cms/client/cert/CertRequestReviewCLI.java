package com.netscape.cms.client.cert;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.client.cli.CLI;
import com.netscape.cms.client.cli.MainCLI;

public class CertRequestReviewCLI extends CLI {

    CertCLI parent;

    public CertRequestReviewCLI(CertCLI parent) {
        super("request-review", "Review certificate request");
        this.parent = parent;
    }

    @Override
    public void execute(String[] args) {
        CommandLine cmd = null;

        Option output = new Option(null, "output", true, "Output Filename");
        options.addOption(output);

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cLineArgs = cmd.getArgs();

        if (cLineArgs.length < 1) {
            System.err.println("Error: No request id specified.");
            printHelp();
            System.exit(-1);
        }
        String filename = null;
        if (cmd.hasOption("output")) {
            filename = cmd.getOptionValue("output");
        } else {
            System.err.println("No output option specified.");
            printHelp();
            System.exit(-1);
        }

        if (filename == null || filename.trim().length() == 0) {
            System.err.println("Specify the filename to write the request information");
            printHelp();
            System.exit(-1);
        }

        RequestId reqId = null;
        try {
            reqId = new RequestId(cLineArgs[0]);
        } catch (NumberFormatException e) {
            System.err.println("Error: Invalid RequestID: " + cLineArgs[0]);
            System.exit(-1);
        }

        CertReviewResponse reviewInfo = null;
        try {
            reviewInfo = parent.client.reviewRequest(reqId);
        } catch (PKIException e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }

        try {
            JAXBContext context = JAXBContext.newInstance(CertReviewResponse.class);
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            FileOutputStream stream = new FileOutputStream(filename);

            marshaller.marshal(reviewInfo, stream);
            MainCLI.printMessage("Downloaded certificate request " + cLineArgs[0]);
        } catch (JAXBException e) {
            System.err.println("Cannot write to the file. " + e);
        } catch (FileNotFoundException e) {
            System.err.println("File not found at " + filename);
        }

    }

    @Override
    public void printHelp() {
        formatter.printHelp(parent.name + "-" + name + " <request id>", options);
    }
}
