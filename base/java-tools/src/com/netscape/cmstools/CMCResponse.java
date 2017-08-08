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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmstools;

import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cmc.CMCStatusInfoV2;
import org.mozilla.jss.pkix.cmc.EncryptedPOP;
import org.mozilla.jss.pkix.cmc.OtherInfo;
import org.mozilla.jss.pkix.cmc.PendInfo;
import org.mozilla.jss.pkix.cmc.ResponseBody;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;
import org.mozilla.jss.pkix.cms.EncapsulatedContentInfo;

import netscape.security.pkcs.PKCS7;
import netscape.security.util.CertPrettyPrint;
import netscape.security.x509.X509CertImpl;

/**
 * Tool for parsing a CMC response
 *
 * <P>
 *
 * @version $Revision$, $Date$
 *
 */
public class CMCResponse {

    static Options options = new Options();
    static HelpFormatter formatter = new HelpFormatter();

    public CMCResponse() {
    }

    public static void printOutput(byte[] bb) {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(bb);
            org.mozilla.jss.pkix.cms.ContentInfo cii = (org.mozilla.jss.pkix.cms.ContentInfo)
                    org.mozilla.jss.pkix.cms.ContentInfo.getTemplate().decode(bis);

            org.mozilla.jss.pkix.cms.SignedData cmcFullResp =
                    (org.mozilla.jss.pkix.cms.SignedData) cii.getInterpretedContent();

            StringBuffer content = new StringBuffer();

            if (cmcFullResp.hasCertificates()) {
                SET certs = cmcFullResp.getCertificates();
                int numCerts = certs.size();

                for (int i = 0; i < numCerts; i++) {
                    Certificate cert = (Certificate) certs.elementAt(i);
                    X509CertImpl certImpl = new X509CertImpl(ASN1Util.encode(cert));
                    CertPrettyPrint print = new CertPrettyPrint(certImpl);
                    content.append(print.toString(Locale.getDefault()));
                }
            }

            System.out.println("Certificates: ");
            System.out.println(content.toString());
            System.out.println("");
            EncapsulatedContentInfo ci = cmcFullResp.getContentInfo();
            OBJECT_IDENTIFIER id = ci.getContentType();
            OBJECT_IDENTIFIER dataid = new OBJECT_IDENTIFIER("1.2.840.113549.1.7.1");
            if (!id.equals(OBJECT_IDENTIFIER.id_cct_PKIResponse) && !id.equals(dataid)) {
                System.out.println("Invalid CMC Response Format");
            }

            if (!ci.hasContent())
                return;

            OCTET_STRING content1 = ci.getContent();
            ByteArrayInputStream bbis = new ByteArrayInputStream(content1.toByteArray());
            ResponseBody responseBody = (ResponseBody) (new ResponseBody.Template()).decode(bbis);
            SEQUENCE controlSequence = responseBody.getControlSequence();

            int numControls = controlSequence.size();
            System.out.println("Number of controls is " + numControls);

            for (int i = 0; i < numControls; i++) {
                TaggedAttribute taggedAttr = (TaggedAttribute) controlSequence.elementAt(i);
                OBJECT_IDENTIFIER type = taggedAttr.getType();

                if (type.equals(OBJECT_IDENTIFIER.id_cmc_statusInfoV2)) {
                    System.out.println("Control #" + i + ": CMCStatusInfoV2");
                    System.out.println("   OID: " + type.toString());
                    SET sts = taggedAttr.getValues();
                    int numSts = sts.size();
                    for (int j = 0; j < numSts; j++) {
                        CMCStatusInfoV2 cst = (CMCStatusInfoV2) ASN1Util.decode(CMCStatusInfoV2.getTemplate(),
                                ASN1Util.encode(sts.elementAt(j)));
                        SEQUENCE seq = cst.getBodyList();

                        StringBuilder s = new StringBuilder("   BodyList: ");
                        for (int k = 0; k < seq.size(); k++) {
                            INTEGER n = (INTEGER) seq.elementAt(k);
                            s.append(n.toString() + " ");
                        }
                        System.out.println(s);
                        int st = cst.getStatus();
                        if (st != CMCStatusInfoV2.SUCCESS && st != CMCStatusInfoV2.CONFIRM_REQUIRED) {
                            String stString = cst.getStatusString();
                            if (stString != null)
                                System.out.println("   Status String: " + stString);
                            OtherInfo oi = cst.getOtherInfo();
                            OtherInfo.Type t = oi.getType();
                            if (t == OtherInfo.FAIL) {
                                System.out.println("   OtherInfo type: FAIL");
                                INTEGER failInfo = oi.getFailInfo();
                                if (failInfo == null) {
                                    System.out.println("failInfo null...skipping");
                                    continue;
                                }

                                System.out.println("     failInfo=" +
                                        OtherInfo.FAIL_INFO[failInfo.intValue()]);
                            } else if (t == OtherInfo.PEND) {
                                System.out.println("   OtherInfo type: PEND");
                                PendInfo pi = oi.getPendInfo();
                                if (pi == null) {
                                    System.out.println("PendInfo null...skipping");
                                    continue;
                                } else
                                    System.out.println("PendInfo present...processing...");
                                if (pi.getPendTime() != null) {
                                    String datePattern = "dd/MMM/yyyy:HH:mm:ss z";
                                    SimpleDateFormat dateFormat = new SimpleDateFormat(datePattern);
                                    Date d = pi.getPendTime().toDate();
                                    System.out.println("   Date: " + dateFormat.format(d));
                                }
                                OCTET_STRING pendToken = pi.getPendToken();
                                if (pendToken != null) {
                                    byte reqId[] = pendToken.toByteArray();
                                    String reqIdString = new String(reqId);
                                    System.out.println("   Pending request id: " + reqIdString);
                                } else {
                                    System.out.println("pendToken not in response");
                                    System.exit(1);
                                }

                            }
                        } else if (st == CMCStatusInfoV2.SUCCESS) {
                            System.out.println("   Status: SUCCESS");
                        }
                    }
                } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_transactionId)) {
                    System.out.println("Control #" + i + ": CMC Transaction Id");
                    System.out.println("   OID: " + type.toString());
                    SET transIds = taggedAttr.getValues();
                    INTEGER num = (INTEGER) (ASN1Util.decode(INTEGER.getTemplate(),
                            ASN1Util.encode(transIds.elementAt(0))));
                    System.out.println("   INTEGER: " + num);
                } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_recipientNonce)) {
                    System.out.println("Control #" + i + ": CMC Recipient Nonce");
                    System.out.println("   OID: " + type.toString());
                    SET recipientN = taggedAttr.getValues();
                    OCTET_STRING str =
                            (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
                                    ASN1Util.encode(recipientN.elementAt(0))));
                    byte b[] = str.toByteArray();
                    StringBuilder s = new StringBuilder("   Value: ");
                    for (int m = 0; m < b.length; m++) {
                        s.append(b[m]);
                        s.append(" ");
                    }
                    System.out.println(s);
                } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_senderNonce)) {
                    System.out.println("Control #" + i + ": CMC Sender Nonce");
                    System.out.println("   OID: " + type.toString());
                    SET senderN = taggedAttr.getValues();
                    OCTET_STRING str =
                            (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
                                    ASN1Util.encode(senderN.elementAt(0))));
                    byte b[] = str.toByteArray();
                    StringBuilder s = new StringBuilder("   Value: ");
                    for (int m = 0; m < b.length; m++) {
                        s.append(b[m]);
                        s.append(" ");
                    }
                    System.out.println(s);
                } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_dataReturn)) {
                    System.out.println("Control #" + i + ": CMC Data Return");
                    System.out.println("   OID: " + type.toString());
                    SET dataReturn = taggedAttr.getValues();
                    OCTET_STRING str =
                            (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
                                    ASN1Util.encode(dataReturn.elementAt(0))));
                    byte b[] = str.toByteArray();
                    StringBuilder s = new StringBuilder("   Value: ");
                    for (int m = 0; m < b.length; m++) {
                        s.append(b[m]);
                        s.append(" ");
                    }
                    System.out.println(s);
                } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_encryptedPOP)) {
                    System.out.println("Control #" + i + ": CMC encrypted POP");
                    System.out.println("   OID: " + type.toString());
                    SET encryptedPOPvals = taggedAttr.getValues();

                    EncryptedPOP encryptedPOP =
                        (EncryptedPOP) (ASN1Util.decode(EncryptedPOP.getTemplate(),
                            ASN1Util.encode(encryptedPOPvals.elementAt(0))));
                    System.out.println("     encryptedPOP decoded");

                } else if (type.equals(OBJECT_IDENTIFIER.id_cmc_responseInfo)) {
                    System.out.println("Control #" + i + ": CMC ResponseInfo");
                    SET riVals = taggedAttr.getValues();
                    OCTET_STRING reqIdOS = (OCTET_STRING) (ASN1Util.decode(OCTET_STRING.getTemplate(),
                           ASN1Util.encode(riVals.elementAt(0))));
                    byte[] reqIdBA = reqIdOS.toByteArray();
                    BigInteger reqIdBI = new BigInteger(reqIdBA);

                    System.out.println("   requestID: " + reqIdBI.toString());
                }
            }
        } catch (Exception e) {
            System.out.println("Error found in the response. Exception: " + e.toString());
            System.exit(1);

        }
    }

    private static void printUsage() {
        formatter.printHelp("CMCResponse [OPTIONS..]", options);
    }

    public static void main(String args[]) throws Exception {

        Option option = new Option("d", true, "NSS database location");
        option.setArgName("path");
        options.addOption(option);

        option = new Option("i", true, "Input file containing CMC response in binary format");
        option.setArgName("path");
        options.addOption(option);

        option = new Option("o", true, "Output file to store certificate chain in PKCS #7 PEM format");
        option.setArgName("path");
        options.addOption(option);

        options.addOption(null, "help", false, "Show help message.");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args, true);

        @SuppressWarnings("unused")
        String database = cmd.getOptionValue("d");

        String input = cmd.getOptionValue("i");
        String output = cmd.getOptionValue("o");

        if (cmd.hasOption("help")) {
            printUsage();
            System.exit(1);
        }

        if (input == null) {
            System.err.println("ERROR: Missing input CMC response");
            System.exit(1);
        }

        // load CMC response
        byte[] data = Files.readAllBytes(Paths.get(input));

        // display CMC response
        printOutput(data);

        // export PKCS #7 if requested
        if (output != null) {
            PKCS7 pkcs7 = new PKCS7(data);

            try (FileWriter fw = new FileWriter(output)) {
                fw.write(pkcs7.toPEMString());
            }
        }
    }
}
