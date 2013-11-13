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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.test;

import java.util.Collection;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertDataInfo;
import com.netscape.certsrv.cert.CertDataInfos;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertNotFoundException;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.cert.CertSearchRequest;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.cms.servlet.cert.FilterBuilder;

public class CATest {

    private static String clientCertNickname;

    public static void main(String args[]) {
        String host = null;
        String port = null;
        String token_pwd = null;
        String db_dir = "./";
        String protocol = "http";

        // parse command line arguments
        Options options = new Options();
        options.addOption("h", true, "Hostname of the CA");
        options.addOption("p", true, "Port of the CA");
        options.addOption("s", true, "Attempt Optional Secure SSL connection");
        options.addOption("w", true, "Token password");
        options.addOption("d", true, "Directory for tokendb");
        options.addOption("c", true, "Optional SSL Client cert Nickname");

        try {
            CommandLineParser parser = new PosixParser();
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("h")) {
                host = cmd.getOptionValue("h");
            } else {
                System.err.println("Error: no hostname provided.");
                usage(options);
            }

            if (cmd.hasOption("p")) {
                port = cmd.getOptionValue("p");
            } else {
                System.err.println("Error: no port provided");
                usage(options);
            }

            if (cmd.hasOption("w")) {
                token_pwd = cmd.getOptionValue("w");
            } else {
                log("Notice: no token password provided");
            }

            if (cmd.hasOption("d")) {
                db_dir = cmd.getOptionValue("d");
            }

            if (cmd.hasOption("s")) {
                if (cmd.getOptionValue("s") != null && cmd.getOptionValue("s").equals("true")) {
                    protocol = "https";
                }
            }

            if (cmd.hasOption("c")) {
                String nick = cmd.getOptionValue("c");

                if (nick != null && protocol.equals("https")) {
                    clientCertNickname = nick;
                }
            }

        } catch (ParseException e) {
            System.err.println("Error in parsing command line options: " + e.getMessage());
            usage(options);
        }

        CryptoManager manager = null;
        CryptoToken token = null;

        // Initialize token
        try {
            CryptoManager.initialize(db_dir);
        } catch (AlreadyInitializedException e) {
            // it is ok if it is already initialized
        } catch (Exception e) {
            log("INITIALIZATION ERROR: " + e.toString());
            System.exit(1);
        }

        // log into token
        try {
            manager = CryptoManager.getInstance();
            token = manager.getInternalKeyStorageToken();
            Password password = new Password(token_pwd.toCharArray());
            try {
                token.login(password);
            } catch (Exception e) {
                log("login Exception: " + e.toString());
                if (!token.isLoggedIn()) {
                    token.initPassword(password, password);
                }
            }
        } catch (Exception e) {
            log("Exception in logging into token:" + e.toString());
        }

        CAClient client;
        CertClient certClient;
        try {
            ClientConfig config = new ClientConfig();
            config.setServerURI(protocol + "://" + host + ":" + port);
            config.setCertNickname(clientCertNickname);

            client = new CAClient(new PKIClient(config));
            certClient = (CertClient)client.getClient("cert");
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        Collection<CertRequestInfo> list = null;
        try {
            list = certClient.listRequests("complete", null, null, null, null, null).getEntries();
        } catch (Exception e) {
            e.printStackTrace();
        }

        printRequests(list);

        //Get a CertInfo
        int certIdToPrint = 1;
        CertId id = new CertId(certIdToPrint);
        CertData certData = null;
        try {
            certData = certClient.getCert(id);
        } catch (CertNotFoundException e) {
            e.printStackTrace();
            log("Cert: " + certIdToPrint + " not found. \n" + e.toString());
        }

        printCertificate(certData);

        //Try an invalid Cert to print out
        //Get a CertInfo
        int certIdBadToPrint = 9999999;
        CertId certIdBad = new CertId(certIdBadToPrint);
        CertData certDataBad = null;
        try {
            certDataBad = certClient.getCert(certIdBad);
        } catch (CertNotFoundException e) {
            e.printStackTrace();
            log("Cert: " + certIdBadToPrint + " not found. \n" + e.toString());
        }

        printCertificate(certDataBad);

        //Get a CertInfoList

        CertDataInfos infos = null;
        try {
            infos = certClient.listCerts("VALID", null, null, null, null);
        } catch (Exception e) {
            e.printStackTrace();
        }

        printCertInfos(infos, "no search filter:");

        //Initiate a Certificate Enrollment

        CertEnrollmentRequest data = createUserCertEnrollment();
        enrollAndApproveCertRequest(certClient, data);

        // submit a RA authenticated user cert request
        CertEnrollmentRequest rdata = createRAUserCertEnrollment();
        enrollCertRequest(certClient, rdata);

        // now try a manually approved server cert
        CertEnrollmentRequest serverData = createServerCertEnrollment();
        enrollAndApproveCertRequest(certClient,serverData);

        // submit using an agent approval profile
        serverData.setProfileId("caAgentServerCert");
        enrollCertRequest(certClient, serverData);

        //Perform a sample certificate search with advanced search terms

        CertSearchRequest searchData = new CertSearchRequest();
        searchData.setSerialNumberRangeInUse(true);
        searchData.setSerialFrom("9999");
        searchData.setSerialTo("99990");

        infos = certClient.findCerts(searchData, 100, 10);

        printCertInfos(infos, new FilterBuilder(searchData).buildFilter());

        // Try to get a non existing request

        RequestId idBad = new RequestId("999999");

        CertRequestInfo infoBad = null;

        try {
            infoBad = certClient.getRequest(idBad);
        } catch (RequestNotFoundException e) {
            e.printStackTrace();
            log("Exception getting request #: " + idBad.toString() + "\n" + e.toString());
        }

        printRequestInfo(infoBad);

        //Perform another sample certificate search with advanced search terms

        searchData = new CertSearchRequest();
        searchData.setSubjectInUse(true);
        searchData.setEmail("jmagne@redhat.com");
        searchData.setMatchExactly(true);

        infos = certClient.findCerts(searchData, 100, 10);

        printCertInfos(infos, new FilterBuilder(searchData).buildFilter());

        //Get a list of Profiles

        ProfileDataInfos pInfos = client.listProfiles(null, null);

        printProfileInfos(pInfos);

        // Get a specific profile
        String pId = "caUserCert";
        ProfileData pData = client.getProfile(pId);

        printProfileData(pData);

    }

    private static void enrollAndApproveCertRequest(CertClient client, CertEnrollmentRequest data) {
        CertRequestInfos reqInfo = null;
        try {
            reqInfo = client.enrollRequest(data);
        } catch (Exception e) {
            e.printStackTrace();
            log(e.toString());
        }

        for (CertRequestInfo info : reqInfo.getEntries()) {
            printRequestInfo(info);

            CertReviewResponse reviewData = client.reviewRequest(info.getRequestId());
            log(reviewData.toString());

            reviewData.setRequestNotes("This is an approval message");
            client.approveRequest(reviewData.getRequestId(), reviewData);
        }
    }

    private static void enrollCertRequest(CertClient client, CertEnrollmentRequest data) {
        CertRequestInfos reqInfo = null;
        try {
            reqInfo = client.enrollRequest(data);
        } catch (Exception e) {
            e.printStackTrace();
            log(e.toString());
        }

        for (CertRequestInfo info : reqInfo.getEntries()) {
            printRequestInfo(info);
        }
    }

    private static CertEnrollmentRequest createUserCertEnrollment() {
        CertEnrollmentRequest data = new CertEnrollmentRequest();
        data.setProfileId("caUserCert");
        data.setRenewal(false);

        //Simulate a "caUserCert" Profile enrollment

        ProfileInput certReq = data.createInput("Key Generation");
        certReq.addAttribute(new ProfileAttribute("cert_request_type", "crmf", null));
        certReq.addAttribute(new ProfileAttribute(
                "cert_request",
                "MIIBozCCAZ8wggEFAgQBMQp8MIHHgAECpQ4wDDEKMAgGA1UEAxMBeKaBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2NgaPHp0jiohcP4M+ufrJOZEqH8GV+liu5JLbT8nWpkfhC+8EUBqT6g+n3qroSxIcNVGNdcsBEqs1utvpItzyslAbpdyat3WwQep1dWMzo6RHrPDuIoxNA0Yka1n3qEX4U//08cLQtUv2bYglYgN/hOCNQemLV6vZWAv0n7zelkCAwEAAakQMA4GA1UdDwEB/wQEAwIF4DAzMBUGCSsGAQUFBwUBAQwIcmVnVG9rZW4wGgYJKwYBBQUHBQECDA1hdXRoZW50aWNhdG9yoYGTMA0GCSqGSIb3DQEBBQUAA4GBAJ1VOQcaSEhdHa94s8kifVbSZ2WZeYE5//qxL6wVlEst20vq4ybj13CetnbN3+WT49Zkwp7Fg+6lALKgSk47suTg3EbbQDm+8yOrC0nc/q4PTRoHl0alMmUxIhirYc1t3xoCMqJewmjX1bNP8lpVIZAYFZo4eZCpZaiSkM5BeHhz", null));

        ProfileInput subjectName = data.createInput("Subject Name");
        subjectName.addAttribute(new ProfileAttribute("sn_uid", "jmagne", null));
        subjectName.addAttribute(new ProfileAttribute("sn_e", "jmagne@redhat.com", null));
        subjectName.addAttribute(new ProfileAttribute("sn_c", "US", null));
        subjectName.addAttribute(new ProfileAttribute("sn_ou", "Development", null));
        subjectName.addAttribute(new ProfileAttribute("sn_ou1", "IPA", null));
        subjectName.addAttribute(new ProfileAttribute("sn_ou2", "Dogtag", null));
        subjectName.addAttribute(new ProfileAttribute("sn_ou3", "CA", null));
        subjectName.addAttribute(new ProfileAttribute("sn_cn", "Common", null));
        subjectName.addAttribute(new ProfileAttribute("sn_o", "RedHat", null));

        ProfileInput submitter = data.createInput("Requestor Information");
        submitter.addAttribute(new ProfileAttribute("requestor_name", "admin", null));
        submitter.addAttribute(new ProfileAttribute("requestor_email", "admin@redhat.com", null));
        submitter.addAttribute(new ProfileAttribute("requestor_phone", "650-555-5555", null));
        return data;
    }

    private static CertEnrollmentRequest createRAUserCertEnrollment() {
        CertEnrollmentRequest data = new CertEnrollmentRequest();
        data.setProfileId("caDualRAuserCert");
        data.setRenewal(false);

        //Simulate a "caUserCert" Profile enrollment

        ProfileInput certReq = data.createInput("Key Generation");
        certReq.addAttribute(new ProfileAttribute("cert_request_type", "crmf", null));
        certReq.addAttribute(new ProfileAttribute(
                "cert_request",
                "MIIB5DCCAeAwggFGAgQTosnaMIIBB4ABAqVOMEwxETAPBgNVBAMTCGFsZWUgcmEzMR4wHAYJKoZIhvcNAQkBFg9hbGVlQHJlZGhhdC5jb20xFzAVBgoJkiaJk/IsZAEBEwdhbGVlcmEzpoGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkQh3k+1323YgQD+oA9yzftqxbGQlsbz0f2OEeOL5h0uhg/qPlSNMjRN3mAeuaNyF0n/Bdxv4699gRTsyEaVJu7HX+kauSCZv+J0tvHiYuHQz1/TSscU9TNLyQjgXVKQFHEdjZa2cQNdmMDUFWrftAK6BFnsP3Tu712qZPAuBH9QIDAQABqRAwDgYDVR0PAQH/BAQDAgXgMDMwFQYJKwYBBQUHBQEBDAhyZWdUb2tlbjAaBgkrBgEFBQcFAQIMDWF1dGhlbnRpY2F0b3KhgZMwDQYJKoZIhvcNAQEFBQADgYEATNi3vMxn9KMto999sR4ik851jqbb6L0GL1KKgQ/hjIAACQb2H+0OpqeZ2+DcGd+oAQn1YZe8aPoFu+HOWjHlY1E2tm7TI1B6JpCL3TMag3mYryROX7l7LFEa1P730aGOWJF874bG8UWisU190zhCBQUqUjsd9DwaP42qM0gnzas=", null));

        ProfileInput subjectName = data.createInput("Subject Name");
        subjectName.addAttribute(new ProfileAttribute("sn_uid", "aleera3", null));
        subjectName.addAttribute(new ProfileAttribute("sn_e", "alee@redhat.com", null));
        subjectName.addAttribute(new ProfileAttribute("sn_cn", "alee ra3", null));

        ProfileInput submitter = data.createInput("Requestor Information");
        submitter.addAttribute(new ProfileAttribute("requestor_name", "admin", null));
        submitter.addAttribute(new ProfileAttribute("requestor_email", "admin@redhat.com", null));
        submitter.addAttribute(new ProfileAttribute("requestor_phone", "650-555-1234", null));
        return data;
    }

    private static CertEnrollmentRequest createServerCertEnrollment() {
        CertEnrollmentRequest data = new CertEnrollmentRequest();
        data.setProfileId("caServerCert");
        data.setRenewal(false);

        //Simulate a "caUserCert" Profile enrollment

        ProfileInput certReq = data.createInput("Key Generation");
        certReq.addAttribute(new ProfileAttribute("cert_request_type", "pkcs10", null));
        certReq.addAttribute(new ProfileAttribute(
                "cert_request",
                "MIIBZjCB0AIBADAnMQ8wDQYDVQQKEwZyZWRoYXQxFDASBgNVBAMTC2FsZWUtd29ya3BjMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJtuKg9osJEBUwz8LoMQwwm1m7D97NNJEmvEhvBMet+VCtbd/erAFMoVXEgSKks/XFK2ViTeZYpp0A2pe4bm4yxowZm0b6von9BKGQ0jNtLemoOkGRWC/PP+fYP16aH62xu4z8MH1pBubdlAEp3Ppnr93aB1lzQaPVmcR3B4OWhwIDAQABoAAwDQYJKoZIhvcNAQEFBQADgYEAgZhZOe0LqQD5iywAO7sY0PANVGzzdcmoLZJjjASY3kU5E3K8u3FKh24WJxcWzdC+/FysDkJixJb7xGUm697QwZvGxmAIQH4yIebWJ2KLHQQgRJytjVYySrRo2Fuo/dm2zzf3+o8WBuD2eMsEjsZfuKxhz7EahvyC2y/CuTBA08s=",
                null)
        );
        ProfileInput subjectName = data.createInput("Subject Name");
        subjectName.addAttribute(new ProfileAttribute("sn_cn", "alee-workpc", null));
        subjectName.addAttribute(new ProfileAttribute("sn_o", "redhat", null));

        ProfileInput submitter = data.createInput("Requestor Information");
        submitter.addAttribute(new ProfileAttribute("requestor_name", "admin", null));
        submitter.addAttribute(new ProfileAttribute("requestor_email", "admin@redhat.com", null));
        submitter.addAttribute(new ProfileAttribute("requestor_phone", "650-555-5555", null));
        return data;
    }

    private static void printProfileInfos(ProfileDataInfos pInfos) {

        if (pInfos == null) {
            log("No ProfileInfos found. \n");
            return;
        }

        Collection<ProfileDataInfo> listProfiles = pInfos.getEntries();
        if (listProfiles != null) {
            log("\nProfiles found. \n");
            for (ProfileDataInfo info: listProfiles) {
                printProfileDataInfo(info);
            }
        }
    }

    private static void printProfileDataInfo(ProfileDataInfo info) {
        if (info == null) {
            log("No Profile Data Information. \n");
        }

        log(" \n Profile Information: \n");
        log("ProfileURL: " + info.getProfileURL());
        log("ProfileID: " + info.getProfileId());
        log("ProfileName: " + info.getProfileName());
        log("ProfileDescription: " + info.getProfileDescription());
    }

    private static void printProfileData(ProfileData info) {
        if (info == null) {
            log("\n No ProfileInformation. \n");
        }

        log("Profile Information: \n");
        log("ProfileID: " + info.getId());
        log("Name: " + info.getName());
        log("Description: " + info.getDescription());
        log("EnabledBy: " + info.getEnabledBy());
        log("Enabled: " + info.isEnabled());
        log("Visible: " + info.isVisible() + "\n\n");

        log("Profile Input Information: \n");

        List<ProfileInput> inputs = info.getInputs();
        for (ProfileInput input : inputs) {
            log("Input Id: " + input.getId());
            for (ProfileAttribute attr : input.getAttributes()) {
                log("Input Attribute Name: " + attr.getName() + "\n");
                log("Input Attribute Value: " + attr.getValue() + "\n");
            }
        }
    }

    private static void printCertInfos(CertDataInfos infos, String filter) {

        if (infos == null) {
            log("No CertInfos found. \n");
            return;
        }

        Collection<CertDataInfo> listCerts = infos.getEntries();
        if (listCerts != null) {
            log("\nCertificates found with search filter: " + filter + "\n");
            for (CertDataInfo info: listCerts) {
                if (info != null) printCertInfo(info);
            }
        }
    }

    private static void printCertInfo(CertDataInfo info) {

        if (info == null) {
            log("No CertInfo: ");
            return;
        }
        log("CertId: " + info.getID().toString());
        log("CertUrl: " + info.getLink().getHref());

    }

    private static void printCertificate(CertData info) {

        if (info == null) {
            log("No CertificateData: ");
            return;
        }

        log("CertificateInfo: " + "\n");
        log("-----------------");

        log("CertSerialNo:  \n" + info.getSerialNumber() + "\n");
        log("CertSubject:  \n" + info.getSubjectDN() + "\n");
        log("CertIssuer: \n" + info.getIssuerDN() + "\n");
        log("NotBefore:  \n" + info.getNotBefore() + "\n");
        log("NotAfter: \n" + info.getNotAfter() + "\n");
        log("CertBase64: \n" + info.getEncoded() + "\n");
        log("CertPKCS7Chain: \n" + info.getPkcs7CertChain() + "\n");
        log("CertPrettyPrint: \n" + info.getPrettyPrint());

    }

    private static void printRequests(Collection<CertRequestInfo> list) {
        if (list == null) {
            log("No requests found");
            return;
        }
        for (CertRequestInfo info: list) {
            printRequestInfo(info);
        }
    }

    private static void printRequestInfo(CertRequestInfo info) {
        if (info == null) {
            log("No RequestInfo: ");
            return;
        }

        log("CertRequestURL: " + info.getRequestURL());
        log("CertId: " + ((info.getCertId() != null) ? info.getCertId() : ""));
        log("RequestType: " + info.getCertRequestType());
        log("Status:        " + info.getRequestStatus());
        log("Type:          " + info.getRequestType());
        log("CertURL: " + ((info.getCertURL() != null) ? info.getCertURL(): "") + "\n");
    }

    private static void log(String string) {
        System.out.println(string);
    }

    private static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("CAClient Test:", options);
        System.exit(1);
    }

}
