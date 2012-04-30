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
import java.util.Iterator;
import java.util.List;
import java.util.Map;

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

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.cert.CertNotFoundException;
import com.netscape.cms.servlet.cert.model.CertDataInfo;
import com.netscape.cms.servlet.cert.model.CertDataInfos;
import com.netscape.cms.servlet.cert.model.CertSearchData;
import com.netscape.cms.servlet.cert.model.CertificateData;
import com.netscape.cms.servlet.profile.model.ProfileData;
import com.netscape.cms.servlet.profile.model.ProfileDataInfo;
import com.netscape.cms.servlet.profile.model.ProfileDataInfos;
import com.netscape.cms.servlet.profile.model.ProfileInput;
import com.netscape.cms.servlet.request.RequestNotFoundException;
import com.netscape.cms.servlet.request.model.CertRequestInfo;
import com.netscape.cms.servlet.request.model.EnrollmentRequestData;

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

        String baseUri = protocol + "://" + host + ":" + port + "/ca/pki";
        CARestClient client;
        try {
            client = new CARestClient(baseUri, clientCertNickname);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        Collection<CertRequestInfo> list = null;
        try {
            list = client.listRequests("complete", null);
        } catch (Exception e) {
            e.printStackTrace();
        }

        printRequests(list);

        //Get a CertInfo
        int certIdToPrint = 1;
        CertId id = new CertId(certIdToPrint);
        CertificateData certData = null;
        try {
            certData = client.getCertData(id);
        } catch (CertNotFoundException e) {
            e.printStackTrace();
            log("Cert: " + certIdToPrint + " not found. \n" + e.toString());
        }

        printCertificate(certData);

        //Try an invalid Cert to print out
        //Get a CertInfo
        int certIdBadToPrint = 9999999;
        CertId certIdBad = new CertId(certIdBadToPrint);
        CertificateData certDataBad = null;
        try {
            certDataBad = client.getCertData(certIdBad);
        } catch (CertNotFoundException e) {
            e.printStackTrace();
            log("Cert: " + certIdBadToPrint + " not found. \n" + e.toString());
        }

        printCertificate(certDataBad);

        //Get a CertInfoList

        CertDataInfos infos = null;
        try {
            infos = client.listCerts("VALID");
        } catch (Exception e) {
            e.printStackTrace();
        }

        printCertInfos(infos, "no search filter:");

        //Initiate a Certificate Enrollment

        EnrollmentRequestData data = new EnrollmentRequestData();
        data.setProfileId("caUserCert");
        data.setIsRenewal(false);

        //Simulate a "caUserCert" Profile enrollment

        ProfileInput certReq = data.addInput("Key Generation");
        certReq.setInputAttr("cert_request_type", "crmf");
        certReq.setInputAttr(
                "cert_request",
                "MIIBozCCAZ8wggEFAgQBMQp8MIHHgAECpQ4wDDEKMAgGA1UEAxMBeKaBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2NgaPHp0jiohcP4M+ufrJOZEqH8GV+liu5JLbT8nWpkfhC+8EUBqT6g+n3qroSxIcNVGNdcsBEqs1utvpItzyslAbpdyat3WwQep1dWMzo6RHrPDuIoxNA0Yka1n3qEX4U//08cLQtUv2bYglYgN/hOCNQemLV6vZWAv0n7zelkCAwEAAakQMA4GA1UdDwEB/wQEAwIF4DAzMBUGCSsGAQUFBwUBAQwIcmVnVG9rZW4wGgYJKwYBBQUHBQECDA1hdXRoZW50aWNhdG9yoYGTMA0GCSqGSIb3DQEBBQUAA4GBAJ1VOQcaSEhdHa94s8kifVbSZ2WZeYE5//qxL6wVlEst20vq4ybj13CetnbN3+WT49Zkwp7Fg+6lALKgSk47suTg3EbbQDm+8yOrC0nc/q4PTRoHl0alMmUxIhirYc1t3xoCMqJewmjX1bNP8lpVIZAYFZo4eZCpZaiSkM5BeHhz");

        ProfileInput subjectName = data.addInput("Subject Name");
        subjectName.setInputAttr("sn_uid", "jmagne");
        subjectName.setInputAttr("sn_e", "jmagne@redhat.com");
        subjectName.setInputAttr("sn_c", "US");
        subjectName.setInputAttr("sn_ou", "Development");
        subjectName.setInputAttr("sn_ou1", "IPA");
        subjectName.setInputAttr("sn_ou2", "Dogtag");
        subjectName.setInputAttr("sn_ou3", "CA");
        subjectName.setInputAttr("sn_cn", "Common");
        subjectName.setInputAttr("sn_o", "RedHat");

        ProfileInput submitter = data.addInput("Requestor Information");
        submitter.setInputAttr("requestor_name", "admin");
        submitter.setInputAttr("requestor_email", "admin@redhat.com");
        submitter.setInputAttr("requestor_phone", "650-555-5555");

        CertRequestInfo reqInfo = null;

        try {
            reqInfo = client.enrollCertificate(data);
        } catch (Exception e) {
            e.printStackTrace();
            log(e.toString());
        }

        printRequestInfo(reqInfo);

        //Perform a sample certificate search with advanced search terms

        CertSearchData searchData = new CertSearchData();
        searchData.setSerialNumberRangeInUse(true);
        searchData.setSerialFrom("9999");
        searchData.setSerialTo("99990");

        infos = client.searchCerts(searchData);

        printCertInfos(infos, searchData.buildFilter());

        // Try to get a non existing request

        RequestId idBad = new RequestId("999999");

        CertRequestInfo infoBad = null;

        try {
            infoBad = client.getRequest(idBad);
        } catch (RequestNotFoundException e) {
            e.printStackTrace();
            log("Exception getting request #: " + idBad.toString() + "\n" + e.toString());
        }

        printRequestInfo(infoBad);

        //Perform another sample certificate search with advanced search terms

        searchData = new CertSearchData();
        searchData.setSubjectInUse(true);
        searchData.setEmail("jmagne@redhat.com");
        searchData.setMatchExactly(true);

        infos = client.searchCerts(searchData);

        printCertInfos(infos, searchData.buildFilter());

        //Get a list of Profiles

        ProfileDataInfos pInfos = client.listProfiles();

        printProfileInfos(pInfos);

        // Get a specific profile
        String pId = "caUserCert";
        ProfileData pData = client.getProfile(pId);

        printProfileData(pData);

    }

    private static void printProfileInfos(ProfileDataInfos pInfos) {

        if (pInfos == null) {
            log("No ProfileInfos found. \n");
            return;
        }

        Collection<ProfileDataInfo> listProfiles = pInfos.getProfileInfos();
        Iterator<ProfileDataInfo> iter = null;

        if (listProfiles != null) {
            iter = listProfiles.iterator();
        }

        log("\nProfiles found. \n");

        while (iter != null && iter.hasNext()) {
            ProfileDataInfo info = iter.next();

            if (info != null) {
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
        log("IsEnabled: " + info.getIsEnabled());
        log("IsVisible: " + info.getIsVisible() + "\n\n");

        log("Profile Input Information: \n");

        List<ProfileInput> inputs = info.getProfileInputsList();

        if (inputs != null) {
            Iterator<ProfileInput> it = inputs.iterator();

            ProfileInput curInput = null;
            while (it.hasNext()) {
                curInput = it.next();

                if (curInput != null) {

                    log("Input Name: " + curInput.getInputId());

                    Map<String, String> attrs = curInput.getAttributes();

                    if (!attrs.isEmpty()) {
                        for (String key : attrs.keySet()) {
                            String value = attrs.get(key);

                            log("Input Attribute Name: " + key + "\n");
                            log("Input Attribute Value: " + value + "\n");
                        }
                    }

                }
            }

        }

    }

    private static void printCertInfos(CertDataInfos infos, String filter) {

        if (infos == null) {
            log("No CertInfos found. \n");
            return;
        }

        Collection<CertDataInfo> listCerts = infos.getCertInfos();
        Iterator<CertDataInfo> iter = null;

        if (listCerts != null) {
            iter = listCerts.iterator();
        }

        log("\nCertificates found with search filter: " + filter + "\n");

        while (iter != null && iter.hasNext()) {
            CertDataInfo info = iter.next();
            if (info != null) {
                printCertInfo(info);
            }
        }
    }

    private static void printCertInfo(CertDataInfo info) {

        if (info == null) {
            log("No CertInfo: ");
            return;
        }
        log("CertId: " + info.getCertId().toString());
        log("CertUrl: " + info.getCertURL());

    }

    private static void printCertificate(CertificateData info) {

        if (info == null) {
            log("No CertificateData: ");
            return;
        }

        log("CertificateInfo: " + "\n");
        log("-----------------");

        log("CertSerialNo:  \n" + info.getSerialNo() + "\n");
        log("CertSubject:  \n" + info.getSubjectName() + "\n");
        log("CertIssuer: \n" + info.getIssuerName() + "\n");
        log("NotBefore:  \n" + info.getNotBefore() + "\n");
        log("NotAfter: \n" + info.getNotAfter() + "\n");
        log("CertBase64: \n" + info.getB64() + "\n");
        log("CertPKCS7Chain: \n" + info.getPkcs7CertChain() + "\n");
        log("CertPrettyPrint: \n" + info.getPrettyPrint());

    }

    private static void printRequests(Collection<CertRequestInfo> list) {
        if (list == null) {
            log("No requests found");
            return;
        }

        Iterator<CertRequestInfo> iter = list.iterator();

        while (iter != null && iter.hasNext()) {
            CertRequestInfo info = iter.next();
            printRequestInfo(info);
        }
    }

    private static void printRequestInfo(CertRequestInfo info) {
        if (info == null) {
            log("No RequestInfo: ");
            return;
        }

        log("CertRequestURL: " + info.getRequestURL());
        log("CertId: " +         info.getCertId());
        log("RequestType: " + info.getCertRequestType());
        log("Status:        " + info.getRequestStatus());
        log("Type:          " + info.getRequestType());
        log("CertURL: "     + info.getCertURL() + "\n");
    }

    private static void log(String string) {
        System.out.println(string);
    }

    private static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("CARestClient Test:", options);
        System.exit(1);
    }

}
