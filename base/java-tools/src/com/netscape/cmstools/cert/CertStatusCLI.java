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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.cert;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.cert.CertClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.CLIException;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.CertStatus;
import com.netscape.cmsutil.ocsp.GoodInfo;
import com.netscape.cmsutil.ocsp.OCSPProcessor;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.ResponseData;
import com.netscape.cmsutil.ocsp.RevokedInfo;
import com.netscape.cmsutil.ocsp.SingleResponse;
import com.netscape.cmsutil.ocsp.UnknownInfo;
import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.Utils;

import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509Key;

/**
 * @author Endi S. Dewata
 */
public class CertStatusCLI extends CLI {

    public CertCLI certCLI;

    public CertStatusCLI(CertCLI certCLI) {
        super("status", "Check certificate status", certCLI);
        this.certCLI = certCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <serial number> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "ocsp", true, "OCSP URL");
        option.setArgName("URL");
        options.addOption(option);

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmd.hasOption("help")) {
            printHelp();
            return;
        }

        if (cmdArgs.length < 1) {
            throw new Exception("Missing certificate serial number.");
        }

        CertId certID = new CertId(cmdArgs[0]);

        PKIClient client = getClient();
        CertClient certClient = new CertClient(client, "ca");
        AuthorityClient authorityClient = new AuthorityClient(client, "ca");

        ClientConfig config = getConfig();
        String ocspURL = cmd.getOptionValue("ocsp", config.getServerURL() + "/ca/ocsp");

        OCSPProcessor processor = new OCSPProcessor();
        processor.setVerbose(verbose);
        processor.setURL(ocspURL);

        // get certificate data
        CertData certData = certClient.getCert(certID);
        String subjectDN = certData.getSubjectDN();
        String issuerDN = certData.getIssuerDN();

        // find the CA data by issuer DN
        List<AuthorityData> authorities = authorityClient.findCAs(null, null, null, issuerDN);

        if (authorities.size() == 0) {
            throw new CLIException("Unknown certificate issuer: " + issuerDN, 1);
        }

        // retrieve CA certificate
        AuthorityData authorityData = authorities.iterator().next();
        BigInteger issuerSerialNumber = authorityData.getSerial();
        CertData caCertData = certClient.getCert(new CertId(issuerSerialNumber));

        // parse CA certificate
        String pemCert = caCertData.getEncoded();
        String oneLineCert = Cert.normalizeCertStrAndReq(pemCert);
        String b64Cert = Cert.stripBrackets(oneLineCert);
        byte[] binCert = Utils.base64decode(b64Cert);

        X509CertImpl caCert = new X509CertImpl(binCert);
        X500Name caDN = (X500Name)caCert.getSubjectDN();
        X509Key caKey = (X509Key)caCert.getPublicKey();

        // submit OCSP request
        OCSPRequest request = processor.createRequest(caDN, caKey, certID.toBigInteger());
        OCSPResponse response = processor.submitRequest(request);

        // parse OCSP response
        byte[] binResponse = response.getResponseBytes().getResponse().toByteArray();
        BasicOCSPResponse basic = (BasicOCSPResponse)BasicOCSPResponse.getTemplate().decode(
                new ByteArrayInputStream(binResponse));

        ResponseData rd = basic.getResponseData();
        SingleResponse sr = rd.getResponseAt(0);
        CertStatus status = sr.getCertStatus();

        System.out.println("  Serial Number: " + certID.toHexString());
        System.out.println("  Subject DN: " + subjectDN);
        System.out.println("  Issuer DN: " + issuerDN);

        if (status instanceof GoodInfo) {
            System.out.println("  Status: Good");

        } else if (status instanceof UnknownInfo) {
            System.out.println("  Status: Unknown");

        } else if (status instanceof RevokedInfo) {
            System.out.println("  Status: Revoked");
            RevokedInfo info = (RevokedInfo) status;
            System.out.println("  Revoked On: " + info.getRevocationTime().toDate());
        }
    }
}
