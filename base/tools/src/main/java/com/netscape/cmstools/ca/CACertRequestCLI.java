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

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCLI;

/**
 * @author Endi S. Dewata
 */
public class CACertRequestCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertRequestCLI.class);

    public CACertClient certClient;

    public CACertRequestCLI(CLI parent) {
        super("request", "Certificate request management commands", parent);

        addModule(new CACertRequestFindCLI(this));
        addModule(new CACertRequestShowCLI(this));
        addModule(new CACertRequestSubmitCLI(this));
        addModule(new CACertRequestReviewCLI(this));
        addModule(new CACertRequestApproveCLI(this));
        addModule(new CACertRequestRejectCLI(this));
        addModule(new CACertRequestCancelCLI(this));
        addModule(new CACertRequestUpdateCLI(this));
        addModule(new CACertRequestValidateCLI(this));
        addModule(new CACertRequestAssignCLI(this));
        addModule(new CACertRequestUnassignCLI(this));

        addModule(new CACertRequestProfileFindCLI(this));
        addModule(new CACertRequestProfileShowCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }

    @Override
    public String getManPage() {
        return "pki-cert";
    }

    public CACertClient getCertClient() throws Exception {

        if (certClient != null) return certClient;

        PKIClient client = getClient();

        // determine the subsystem
        String subsystem;
        if (parent instanceof SubsystemCLI) {
            SubsystemCLI subsystemCLI = (SubsystemCLI)parent;
            subsystem = subsystemCLI.getName();
        } else {
            subsystem = "ca";
        }

        // create new cert client
        certClient = new CACertClient(client, subsystem);

        return certClient;
    }

    public static void printCertRequestInfos(CertRequestInfos infos) {
        boolean first = true;
        for (CertRequestInfo info : infos.getEntries()) {
            if (first) {
                first = false;
            } else {
                System.out.println();
            }
            printCertRequestInfo(info);
        }
    }

    public static void printCertRequestInfo(CertRequestInfo info) {
        System.out.println("  Request ID: " + info.getRequestId());
        System.out.println("  Type: " + info.getRequestType());
        System.out.println("  Request Status: " + info.getRequestStatus());
        System.out.println("  Operation Result: " + info.getOperationResult());

        String error = info.getErrorMessage();
        if (error != null) {
            System.out.println("  Reason: " + error);
        }

        if (info.getCertId() != null) {
            System.out.println("  Certificate ID: " + info.getCertId().toHexString());
        }
    }

    public static void printCertReviewResponse(CertReviewResponse response) {

        System.out.println("  Request ID: " + response.getRequestId());
        System.out.println("  Profile: " + response.getProfileName());
        System.out.println("  Type: " + response.getRequestType());
        System.out.println("  Status: " + response.getRequestStatus());

        for (ProfileInput input : response.getInputs()) {

            System.out.println();
            System.out.println("  " + input.getName() + ":");
            boolean inputProvided = false;

            for (ProfileAttribute attribute : input.getAttributes()) {

                String name = attribute.getName();
                String value = attribute.getValue().trim();

                if (!StringUtils.isEmpty(value)) {
                    System.out.println("    " + name + ": " + value);
                    inputProvided = true;
                }
            }

            if (!inputProvided) {
                System.out.println("    none");
            }
        }
    }
}
