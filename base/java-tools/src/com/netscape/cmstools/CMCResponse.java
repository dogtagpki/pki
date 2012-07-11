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
import java.io.FileInputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import netscape.security.util.CertPrettyPrint;
import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cmc.CMCStatusInfo;
import org.mozilla.jss.pkix.cmc.OtherInfo;
import org.mozilla.jss.pkix.cmc.PendInfo;
import org.mozilla.jss.pkix.cmc.ResponseBody;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;
import org.mozilla.jss.pkix.cms.EncapsulatedContentInfo;

/**
 * Tool for parsing a CMC response
 *
 * <P>
 *
 * @version $Revision$, $Date$
 *
 */
public class CMCResponse {

    public CMCResponse() {
    }

    public static void printOutput(String path, String filename) {
        byte[] bb = new byte[10000];
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(filename);
            while (fis.available() > 0)
                fis.read(bb, 0, 10000);
        } catch (Exception e) {
            System.out.println("Error reading the response. Exception: " + e.toString());
            System.exit(1);
        }

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

                if (type.equals(OBJECT_IDENTIFIER.id_cmc_cMCStatusInfo)) {
                    System.out.println("Control #" + i + ": CMCStatusInfo");
                    System.out.println("   OID: " + type.toString());
                    SET sts = taggedAttr.getValues();
                    int numSts = sts.size();
                    for (int j = 0; j < numSts; j++) {
                        CMCStatusInfo cst = (CMCStatusInfo) ASN1Util.decode(CMCStatusInfo.getTemplate(),
                                ASN1Util.encode(sts.elementAt(j)));
                        SEQUENCE seq = cst.getBodyList();

                        StringBuilder s = new StringBuilder("   BodyList: ");
                        for (int k = 0; k < seq.size(); k++) {
                            INTEGER n = (INTEGER) seq.elementAt(k);
                            s.append(n.toString() + " ");
                        }
                        System.out.println(s);
                        int st = cst.getStatus();
                        if (st != CMCStatusInfo.SUCCESS && st != CMCStatusInfo.CONFIRM_REQUIRED) {
                            String stString = cst.getStatusString();
                            if (stString != null)
                                System.out.println("   Status String: " + stString);
                            OtherInfo oi = cst.getOtherInfo();
                            OtherInfo.Type t = oi.getType();
                            if (t == OtherInfo.FAIL)
                                System.out.println("   OtherInfo type: FAIL");
                            else if (t == OtherInfo.PEND) {
                                System.out.println("   OtherInfo type: PEND");
                                PendInfo pi = oi.getPendInfo();
                                if (pi.getPendTime() != null) {
                                    String datePattern = "dd/MMM/yyyy:HH:mm:ss z";
                                    SimpleDateFormat dateFormat = new SimpleDateFormat(datePattern);
                                    Date d = pi.getPendTime().toDate();
                                    System.out.println("   Date: " + dateFormat.format(d));
                                }
                            }
                        } else if (st == CMCStatusInfo.SUCCESS) {
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
                }
            }
        } catch (Exception e) {
            System.out.println("Error found in the response. Exception: " + e.toString());
            System.exit(1);

        }
    }

    private static void printUsage() {
        System.out.println("");
        System.out.println(
                "Usage: CMCResponse -d <pathname for cert8.db> -i <pathname for CMC response in binary format> ");
    }

    public static void main(String args[]) {
        String filename = null, path = null;
        if (args.length != 4) {
            printUsage();
            System.exit(1);
        }

        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-d"))
                path = args[i + 1];
            else if (args[i].equals("-i"))
                filename = args[i + 1];
        }

        if (filename == null || path == null) {
            printUsage();
            System.exit(1);
        }
        printOutput(path, filename);
    }
}
