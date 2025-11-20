package com.netscape.cmstools.ca;

import java.io.Console;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.Vector;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.util.cert.CRMFUtil;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

import netscape.ldap.util.DN;
import netscape.ldap.util.RDN;

public class CACertRequestSubmitCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertRequestSubmitCLI.class);

    CACertRequestCLI certRequestCLI;

    public CACertRequestSubmitCLI(CACertRequestCLI CACertRequestCLI) {
        super("submit", "Submit certificate request", CACertRequestCLI);
        this.certRequestCLI = CACertRequestCLI;
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "issuer-id", true, "Authority ID (host authority if omitted)");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "issuer-dn", true, "Authority DN (host authority if omitted)");
        option.setArgName("DN");
        options.addOption(option);

        option = new Option(null, "password-file", true, "File containing enrollment password");
        options.addOption(option);

        option = new Option(null, "password", false, "Prompt for enrollment password");
        options.addOption(option);

        option = new Option(null, "pin-file", true, "File containing enrollment PIN");
        options.addOption(option);

        option = new Option(null, "pin", false, "Prompt for enrollment PIN");
        options.addOption(option);

        option = new Option(null, "profile", true, "Certificate profile");
        option.setArgName("profile");
        options.addOption(option);

        option = new Option(null, "request-type", true, "Request type: pkcs10 (default), crmf");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "request-format", true, "Request type: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "renewal", false, "Submit renewal request");
        options.addOption(option);

        option = new Option(null, "csr-file", true, "File containing the CSR");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "serial", true, "Serial number of certificate for renewal");
        option.setArgName("number");
        options.addOption(option);

        option = new Option(null, "subject", true, "Subject DN");
        option.setArgName("DN");
        options.addOption(option);

        option = new Option(null, "dns-names", true, "Comma-separated list of DNS names");
        option.setArgName("names");
        options.addOption(option);

        option = new Option(null, "username", true, "Username for enrollment");
        option.setArgName("username");
        options.addOption(option);

        option = new Option(null, "requestor", true, "Requestor");
        option.setArgName("requestor");
        options.addOption(option);

        option = new Option(null, "session", true, "DEPRECATED: Session ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "install-token", true, "DEPRECATED: Install token");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);

        option = new Option(null, "output-file", true, "Output file");
        option.setArgName("file");
        options.addOption(option);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <filename> [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        String requestFilename = cmdArgs.length > 0 ? cmdArgs[0] : null;
        String profileID = cmd.getOptionValue("profile");

        if (requestFilename == null && profileID == null) {
            throw new Exception("Missing request file or profile ID.");
        }

        if (requestFilename != null && profileID != null) {
            throw new Exception("Request file and profile ID are mutually exclusive.");
        }

        AuthorityID aid = null;
        if (cmd.hasOption("issuer-id")) {
            String aidString = cmd.getOptionValue("issuer-id");
            try {
                aid = new AuthorityID(aidString);
            } catch (IllegalArgumentException e) {
                throw new Exception("Bad AuthorityID: " + aidString, e);
            }
        }

        X500Name adn = null;
        if (cmd.hasOption("issuer-dn")) {
            String adnString = cmd.getOptionValue("issuer-dn");
            try {
                adn = new X500Name(adnString);
            } catch (IOException e) {
                throw new Exception("Bad DN: " + adnString, e);
            }
        }

        if (aid != null && adn != null) {
            throw new Exception("--issuer-id and --issuer-dn options are mutually exclusive");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        CACertClient certClient = certRequestCLI.getCertClient(client);

        String requestType = cmd.getOptionValue("request-type");

        CertEnrollmentRequest request;
        if (requestFilename == null) { // if no request file specified, generate new request from profile

            logger.info("Retrieving " + profileID + " profile");

            request = certClient.getEnrollmentTemplate(profileID);

            // set default request type for new request
            if (requestType == null) requestType = "pkcs10";

        } else { // otherwise, load request from file

            logger.info("Loading request from " + requestFilename);

            String xml = loadFile(requestFilename);
            request = CertEnrollmentRequest.fromXML(xml);
        }

        if (requestType != null) {

            logger.info("Request type: " + requestType);

            for (ProfileInput input : request.getInputs()) {
                ProfileAttribute typeAttr = input.getAttribute("cert_request_type");
                if (typeAttr != null) {
                    typeAttr.setValue(requestType);
                }
            }
        }

        boolean renewal = cmd.hasOption("renewal");
        request.setRenewal(renewal);

        String csrFilename = cmd.getOptionValue("csr-file");
        String csr = null;

        PKCS10 pkcs10 = null;
        SEQUENCE crmfMsgs = null;

        if (csrFilename != null) {

            byte[] bytes = Files.readAllBytes(Paths.get(csrFilename));

            String requestFormat = cmd.getOptionValue("request-format");
            if (requestFormat == null || "PEM".equalsIgnoreCase(requestFormat)) {
                bytes = CertUtil.parseCSR(new String(bytes));

            } else if ("DER".equalsIgnoreCase(requestFormat)) {
                // nothing to do

            } else {
                throw new Exception("Unsupported request format: " + requestFormat);
            }

            if ("pkcs10".equals(requestType)) {
                pkcs10 = new PKCS10(bytes);
                csr = CertUtil.toPEM(pkcs10);

            } else if ("crmf".equals(requestType)) {
                crmfMsgs = CRMFUtil.parseCRMFMsgs(bytes);
                csr = CRMFUtil.encodeCRMF(crmfMsgs);

            } else {
                throw new Exception("Unsupported request type: " + requestType);
            }

            logger.debug("CSR:\n" + csr);

            for (ProfileInput input : request.getInputs()) {
                ProfileAttribute csrAttr = input.getAttribute("cert_request");
                if (csrAttr != null) {
                    csrAttr.setValue(csr);
                }
            }
        }

        String serial = cmd.getOptionValue("serial");
        if (serial != null) {

            logger.info("Serial: " + serial);

            request.setSerialNum(new CertId(serial));

            // store serial number in profile input if available
            for (ProfileInput input : request.getInputs()) {
                ProfileAttribute serialAttr = input.getAttribute("serial_num");
                if (serialAttr != null) {
                    serialAttr.setValue(serial);
                }
            }
        }

        String subjectDN = cmd.getOptionValue("subject");

        if (subjectDN == null) {
            // if no subject DN provided, get from CSR
            if (pkcs10 != null) {
                subjectDN = pkcs10.getSubjectName().toLdapDNString();
            }
        }

        if (subjectDN != null) {
            DN dn = new DN(subjectDN);
            Vector<?> rdns = dn.getRDNs();

            Map<String, String> subjectAttributes = new HashMap<>();
            for (int i=0; i< rdns.size(); i++) {
                RDN rdn = (RDN)rdns.elementAt(i);
                String type = rdn.getTypes()[0].toLowerCase();
                String value = rdn.getValues()[0];
                subjectAttributes.put(type, value);
            }

            ProfileInput sn = request.getInput("Subject Name");
            if (sn != null) {
                logger.info("Subject Name:");

                for (ProfileAttribute attribute : sn.getAttributes()) {
                    String name = attribute.getName();
                    String value = null;

                    if (name.equals("subject")) {
                        // get the whole subject DN
                        value = subjectDN;

                    } else if (name.startsWith("sn_")) {
                        // get value from subject DN
                        value = subjectAttributes.get(name.substring(3));

                    } else {
                        // unknown attribute, ignore
                        logger.info("- " + name);
                        continue;
                    }

                    if (value == null) continue;

                    logger.info("- " + name + ": " + value);
                    attribute.setValue(value);
                }
            }
        }

        String enrollmentUsername = cmd.getOptionValue("username");
        if (enrollmentUsername != null) {
            request.setAttribute("uid", enrollmentUsername);
        }

        String passwordFile = cmd.getOptionValue("password-file");
        if (passwordFile != null) {
            String enrollmentPassword = Files.readString(Paths.get(passwordFile)).trim();
            request.setAttribute("pwd", enrollmentPassword);

        } else if (cmd.hasOption("password")) {
            Console console = System.console();
            String enrollmentPassword = new String(console.readPassword("Password: "));
            request.setAttribute("pwd", enrollmentPassword);
        }

        String pinFile = cmd.getOptionValue("pin-file");
        if (pinFile != null) {
            String enrollmentPIN = Files.readString(Paths.get(pinFile)).trim();
            request.setAttribute("pin", enrollmentPIN);

        } else if (cmd.hasOption("pin")) {
            Console console = System.console();
            String enrollmentPIN = new String(console.readPassword("PIN: "));
            request.setAttribute("pin", enrollmentPIN);
        }

        logger.info("Request:\n" + request);

        String list = cmd.getOptionValue("dns-names");
        logger.info("DNS names: " + list);

        String[] dnsNames = null;
        if (list != null) {
            dnsNames = list.split(",");
        }

        String requestor = cmd.getOptionValue("requestor");
        logger.info("Requestor: " + requestor);

        String installToken = cmd.getOptionValue("install-token");
        String sessionID = cmd.getOptionValue("session");

        if (sessionID != null) {
            logger.warn("The --session option has been deprecated. Use pki ca-cert-issue instead.");

        } else if (installToken != null) {
            logger.warn("The --install-token option has been deprecated. Use pki ca-cert-issue instead.");
            sessionID = new String(Files.readAllBytes(Paths.get(installToken)));
        }

        if (sessionID == null) {
            CertRequestInfos cri = certClient.enrollRequest(request, aid, adn);
            MainCLI.printMessage("Submitted certificate request");
            CACertRequestCLI.printCertRequestInfos(cri);
            return;
        }

        X509CertImpl cert = certClient.submitRequest(
                requestType,
                csr,
                renewal,
                profileID,
                subjectDN,
                dnsNames,
                enrollmentUsername,
                requestor,
                sessionID);
        byte[] bytes = cert.getEncoded();

        String outputFormat = cmd.getOptionValue("output-format");
        if (outputFormat == null || "PEM".equalsIgnoreCase(outputFormat)) {
            StringWriter sw = new StringWriter();

            try (PrintWriter out = new PrintWriter(sw, true)) {
                out.println(Cert.HEADER);
                out.print(Utils.base64encodeMultiLine(cert.getEncoded()));
                out.println(Cert.FOOTER);
            }

            bytes = sw.toString().getBytes();

        } else if ("DER".equalsIgnoreCase(outputFormat)) {
            bytes = cert.getEncoded();

        } else {
            throw new Exception("Unsupported format: " + outputFormat);
        }

        String outputFile = cmd.getOptionValue("output-file");
        if (outputFile != null) {
            try (FileOutputStream out = new FileOutputStream(outputFile)) {
                out.write(bytes);
            }

        } else {
            System.out.write(bytes);
        }
    }

    private String loadFile(String fileName) throws FileNotFoundException {
        try (Scanner scanner = new Scanner(new File(fileName))) {
            return scanner.useDelimiter("\\A").next();
        }
    }
}
