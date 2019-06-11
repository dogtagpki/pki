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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.ca;

import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertDataInfo;
import com.netscape.certsrv.cert.CertDataInfos;
import com.netscape.certsrv.cert.CertSearchRequest;
import com.netscape.cmstools.cli.MainCLI;

import org.mozilla.jss.netscape.security.x509.RevocationReason;

/**
 * @author Endi S. Dewata
 */
public class CACertFindCLI extends CLI {

    public CACertCLI certCLI;

    public CACertFindCLI(CACertCLI certCLI) {
        super("find", "Find certificates", certCLI);
        this.certCLI = certCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = null;

        //pagination options
        option = new Option(null, "start", true, "Page start");
        option.setArgName("start");
        options.addOption(option);

        option = new Option(null, "size", true, "Page size");
        option.setArgName("size");
        options.addOption(option);

        //file input
        option = new Option(null, "input", true, "File containing the search constraints");
        option.setArgName("file path");
        options.addOption(option);

        //serialNumberinUse
        option = new Option(null, "minSerialNumber", true, "Minimum serial number");
        option.setArgName("serial number");
        options.addOption(option);
        option = new Option(null, "maxSerialNumber", true, "Maximum serial number");
        option.setArgName("serial number");
        options.addOption(option);

        //subjectNameinUse
        option = new Option(null, "name", true, "Subject's common name");
        option.setArgName("name");
        options.addOption(option);
        option = new Option(null, "email", true, "Subject's email address");
        option.setArgName("email");
        options.addOption(option);
        option = new Option(null, "uid", true, "Subject's userid");
        option.setArgName("user id");
        options.addOption(option);
        option = new Option(null, "org", true, "Subject's organization");
        option.setArgName("name");
        options.addOption(option);
        option = new Option(null, "orgUnit", true, "Subject's organization unit");
        option.setArgName("name");
        options.addOption(option);
        option = new Option(null, "locality", true, "Subject's locality");
        option.setArgName("name");
        options.addOption(option);
        option = new Option(null, "state", true, "Subject's state");
        option.setArgName("name");
        options.addOption(option);
        option = new Option(null, "country", true, "Subject's country");
        option.setArgName("name");
        options.addOption(option);
        options.addOption(null, "matchExactly", false, "Match exactly with the details provided");

        //status
        option = new Option(null, "status", true, "Certificate status: VALID, INVALID, REVOKED, EXPIRED, REVOKED_EXPIRED");
        option.setArgName("status");
        options.addOption(option);

        //revokedByInUse
        option = new Option(null, "revokedBy", true, "Certificate revoked by");
        option.setArgName("user id");
        options.addOption(option);

        //revocationPeriod
        option = new Option(null, "revokedOnFrom", true, "Revoked on or after this date");
        option.setArgName("YYYY-MM-DD");
        options.addOption(option);
        option = new Option(null, "revokedOnTo", true, "Revoked on or before this date");
        option.setArgName("YYYY-MM-DD");
        options.addOption(option);

        //revocationReason
        option = new Option(null, "revocationReason", true,
                "Reason for revocation: Unspecified(0), Key_compromise(1), CA_Compromise(2), Affiliation_Changed(3), " +
                "Superseded(4), Cessation_of_Operation(5), Certificate_Hold(6), Remove_from_CRL(8), " +
                "Privilege_Withdrawn(9), AA_Compromise(10)");
        option.setArgName("reason");
        options.addOption(option);

        //issuedBy
        option = new Option(null, "issuedBy", true, "Issued by");
        option.setArgName("user id");
        options.addOption(option);

        //issuedOn
        option = new Option(null, "issuedOnFrom", true,
                "Issued on or after this date");
        option.setArgName("YYYY-MM-DD");
        options.addOption(option);

        option = new Option(null, "issuedOnTo", true,
                "Issued on or before this date");
        option.setArgName("YYYY-MM-DD");
        options.addOption(option);

        //certTypeinUse
        option = new Option(null, "certTypeSubEmailCA", true, "Certifiate type: Subject Email CA");
        option.setArgName("on|off");
        options.addOption(option);
        option = new Option(null, "certTypeSubSSLCA", true, "Certificate type: Subject SSL CA");
        option.setArgName("on|off");
        options.addOption(option);
        option = new Option(null, "certTypeSecureEmail", true, "Certifiate Type: Secure Email");
        option.setArgName("on|off");
        options.addOption(option);
        option = new Option(null, "certTypeSSLClient", true, "Certifiate Type: SSL Client");
        option.setArgName("on|off");
        options.addOption(option);
        option = new Option(null, "certTypeSSLServer", true, "Certifiate Type: SSL Server");
        option.setArgName("on|off");
        options.addOption(option);

        //validationNotBeforeInUse
        option = new Option(null, "validNotBeforeFrom", true, "Valid not before start date");
        option.setArgName("YYYY-MM-DD");
        options.addOption(option);
        option = new Option(null, "validNotBeforeTo", true, "Valid not before end date");
        option.setArgName("YYYY-MM-DD");
        options.addOption(option);

        //validityNotAfterinUse
        option = new Option(null, "validNotAfterFrom", true, "Valid not after start date");
        option.setArgName("YYYY-MM-DD");
        options.addOption(option);
        option = new Option(null, "validNotAfterTo", true, "Valid not after end date");
        option.setArgName("YYYY-MM-DD");
        options.addOption(option);

        //validityLengthinUse
        option = new Option(null, "validityOperation", true, "Validity duration operation: \"<=\" or \">=\"");
        option.setArgName("operation");
        options.addOption(option);
        option = new Option(null, "validityCount", true, "Validity duration count");
        option.setArgName("count");
        options.addOption(option);
        option = new Option(null, "validityUnit", true, "Validity duration unit: day, week, month (default), year");
        option.setArgName("day|week|month|year");
        options.addOption(option);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        CertSearchRequest searchData = null;
        String fileName = null;

        if (cmd.hasOption("input")) {
            fileName = cmd.getOptionValue("input");
            if (fileName == null || fileName.length() < 1) {
                throw new Exception("No file name specified.");
            }
        }

        if (fileName != null) {
            FileReader reader = null;
            try {
                reader = new FileReader(fileName);
                searchData = CertSearchRequest.valueOf(reader);

            } finally {
                if (reader != null)
                    try {
                        reader.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
            }

        } else {
            searchData = new CertSearchRequest();
        }

        String s = cmd.getOptionValue("start");
        Integer start = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("size");
        Integer size = s == null ? null : Integer.valueOf(s);

        addSearchAttribute(cmd, searchData);

        CACertClient certClient = certCLI.getCertClient();
        CertDataInfos certs = certClient.findCerts(searchData, start, size);

        MainCLI.printMessage(certs.getTotal() + " entries found");
        if (certs.getTotal() == 0) return;

        boolean first = true;

        Collection<CertDataInfo> entries = certs.getEntries();
        for (CertDataInfo cert : entries) {
            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            CACertCLI.printCertInfo(cert);
        }

        MainCLI.printMessage("Number of entries returned " + certs.getEntries().size());
    }

    public Long convertValidityDurationUnit(String unit) throws Exception {

        if (unit.equalsIgnoreCase("day")) {
            return 86400000l;

        } else if (unit.equalsIgnoreCase("week")) {
            return 604800000l;

        } else if (unit.equalsIgnoreCase("month")) {
            return 2592000000l;

        } else if (unit.equalsIgnoreCase("year")) {
            return 31536000000l;

        } else {
            throw new Exception("Invalid validity duration unit: " + unit);
        }
    }

    public void addSearchAttribute(CommandLine cmd, CertSearchRequest csd)
            throws Exception {

        if (cmd.hasOption("minSerialNumber")) {
            csd.setSerialNumberRangeInUse(true);
            csd.setSerialFrom(cmd.getOptionValue("minSerialNumber"));
        }
        if (cmd.hasOption("maxSerialNumber")) {
            csd.setSerialNumberRangeInUse(true);
            csd.setSerialTo(cmd.getOptionValue("maxSerialNumber"));
        }
        if (cmd.hasOption("name")) {
            csd.setSubjectInUse(true);
            csd.setCommonName(cmd.getOptionValue("name"));
        }
        if (cmd.hasOption("email")) {
            csd.setSubjectInUse(true);
            csd.setEmail(cmd.getOptionValue("email"));
        }
        if (cmd.hasOption("uid")) {
            csd.setSubjectInUse(true);
            csd.setUserID(cmd.getOptionValue("uid"));
        }
        if (cmd.hasOption("org")) {
            csd.setSubjectInUse(true);
            csd.setOrg(cmd.getOptionValue("org"));
        }
        if (cmd.hasOption("orgUnit")) {
            csd.setSubjectInUse(true);
            csd.setOrgUnit(cmd.getOptionValue("orgUnit"));
        }
        if (cmd.hasOption("locality")) {
            csd.setSubjectInUse(true);
            csd.setLocality(cmd.getOptionValue("locality"));
        }
        if (cmd.hasOption("state")) {
            csd.setSubjectInUse(true);
            csd.setState(cmd.getOptionValue("state"));
        }
        if (cmd.hasOption("country")) {
            csd.setSubjectInUse(true);
            csd.setCountry(cmd.getOptionValue("country"));
        }
        if (cmd.hasOption("matchExactly")) {
            csd.setMatchExactly(true);
        }
        if (cmd.hasOption("status")) {
            csd.setStatus(cmd.getOptionValue("status"));
        }
        if (cmd.hasOption("revokedBy")) {
            csd.setRevokedByInUse(true);
            csd.setRevokedBy(cmd.getOptionValue("revokedBy"));
        }
        if (cmd.hasOption("revokedOnFrom")) {
            csd.setRevokedOnInUse(true);
            Date date = CACertCLI.dateFormat.parse(cmd.getOptionValue("revokedOnFrom"));
            csd.setRevokedOnFrom(""+date.getTime());
        }
        if (cmd.hasOption("revokedOnTo")) {
            csd.setRevokedOnInUse(true);
            Date date = CACertCLI.dateFormat.parse(cmd.getOptionValue("revokedOnTo"));
            csd.setRevokedOnTo(""+date.getTime());
        }
        if (cmd.hasOption("revocationReason")) {
            csd.setRevocationReasonInUse(true);
            String value = cmd.getOptionValue("revocationReason");
            RevocationReason reason = null;
            try {
                // accept integer reason codes
                int val = Integer.parseInt(value);
                reason = RevocationReason.valueOf(val);
            } catch (NumberFormatException e) {
                // accept reason labels
                reason = RevocationReason.valueOf(value);
            }
            if (reason != null) {
                csd.setRevocationReason(Integer.toString(reason.getCode()));
            } else {
                throw new Exception("Invalid revocation reason");
            }
        }
        if (cmd.hasOption("issuedBy")) {
            csd.setIssuedByInUse(true);
            csd.setIssuedBy(cmd.getOptionValue("issuedBy"));
        }
        if (cmd.hasOption("issuedOnFrom")) {
            csd.setIssuedOnInUse(true);
            Date date = CACertCLI.dateFormat.parse(cmd.getOptionValue("issuedOnFrom"));
            csd.setIssuedOnFrom(""+date.getTime());
        }
        if (cmd.hasOption("issuedOnTo")) {
            csd.setIssuedOnInUse(true);
            Date date = CACertCLI.dateFormat.parse(cmd.getOptionValue("issuedOnTo"));
            csd.setIssuedOnTo(""+date.getTime());
        }
        if (cmd.hasOption("certTypeSubEmailCA")) {
            csd.setCertTypeInUse(true);
            csd.setCertTypeSubEmailCA(cmd.getOptionValue("certTypeSubEmailCA"));
        }
        if (cmd.hasOption("certTypeSubSSLCA")) {
            csd.setCertTypeInUse(true);
            csd.setCertTypeSubSSLCA(cmd.getOptionValue("certTypeSubSSLCA"));
        }
        if (cmd.hasOption("certTypeSecureEmail")) {
            csd.setCertTypeInUse(true);
            csd.setCertTypeSecureEmail(cmd.getOptionValue("certTypeSecureEmail"));
        }
        if (cmd.hasOption("certTypeSSLClient")) {
            csd.setCertTypeInUse(true);
            csd.setCertTypeSSLClient(cmd.getOptionValue("certTypeSSLCllient"));
        }
        if (cmd.hasOption("certTypeSSLServer")) {
            csd.setCertTypeInUse(true);
            csd.setCertTypeSSLServer(cmd.getOptionValue("certTypeSSLServer"));
        }
        if (cmd.hasOption("validNotBeforeFrom")) {
            csd.setValidNotBeforeInUse(true);
            Date date = CACertCLI.dateFormat.parse(cmd.getOptionValue("validNotBeforeFrom"));
            csd.setValidNotBeforeFrom(""+date.getTime());
        }
        if (cmd.hasOption("validNotBeforeTo")) {
            csd.setValidNotBeforeInUse(true);
            Date date = CACertCLI.dateFormat.parse(cmd.getOptionValue("validNotBeforeTo"));
            csd.setValidNotBeforeTo(""+date.getTime());
        }
        if (cmd.hasOption("validNotAfterFrom")) {
            csd.setValidNotAfterInUse(true);
            Date date = CACertCLI.dateFormat.parse(cmd.getOptionValue("validNotAfterFrom"));
            csd.setValidNotAfterFrom(""+date.getTime());
        }
        if (cmd.hasOption("validNotAfterTo")) {
            csd.setValidNotAfterInUse(true);
            Date date = CACertCLI.dateFormat.parse(cmd.getOptionValue("validNotAfterTo"));
            csd.setValidNotAfterTo(""+date.getTime());
        }

        if (cmd.hasOption("validityOperation")) {
            csd.setValidityLengthInUse(true);
            csd.setValidityOperation(cmd.getOptionValue("validityOperation"));
        }

        if (cmd.hasOption("validityCount")) {
            csd.setValidityLengthInUse(true);
            String count = cmd.getOptionValue("validityCount");
            csd.setValidityCount(Integer.parseInt(count));
        }

        if (cmd.hasOption("validityUnit")) {
            csd.setValidityLengthInUse(true);
            String unit = cmd.getOptionValue("validityUnit");
            Long value = convertValidityDurationUnit(unit);
            csd.setValidityUnit(value);
        }

        if (csd.getValidityLengthInUse()) {

            if (csd.getValidityOperation() == null) {
                throw new Exception("Mising validity duration operation");
            }

            if (csd.getValidityCount() == null) {
                throw new Exception("Mising validity duration count");
            }

            if (csd.getValidityUnit() == null) {
                Long value = convertValidityDurationUnit("month");
                csd.setValidityUnit(value);
            }
        }
    }
}
