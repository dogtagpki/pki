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

package com.netscape.cmstools.ca;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLIException;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.CertID;
import com.netscape.cmsutil.ocsp.CertStatus;
import com.netscape.cmsutil.ocsp.OCSPProcessor;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.ResponseData;
import com.netscape.cmsutil.ocsp.RevokedInfo;
import com.netscape.cmsutil.ocsp.SingleResponse;

/**
 * @author Endi S. Dewata
 */
public class CACertStatusCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CACertStatusCLI.class);

    public CACertCLI certCLI;

    public CACertStatusCLI(CACertCLI certCLI) {
        super("status", "Check certificate status", certCLI);
        this.certCLI = certCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <serial number> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "ocsp", true, "OCSP URL");
        option.setArgName("URL");
        options.addOption(option);
    }

    public void printSingleResponse(SingleResponse sr, String subjectDN, String issuerDN) {
        CertID certID = sr.getCertID();
        INTEGER serialNumber = certID.getSerialNumber();

        System.out.println("  Serial Number: " + new CertId(serialNumber).toHexString());
        System.out.println("  Subject DN: " + subjectDN);
        System.out.println("  Issuer DN: " + issuerDN);

        CertStatus status = sr.getCertStatus();
        System.out.println("  Status: " + status.getLabel());

        if (status instanceof RevokedInfo info) {
            System.out.println("  Revoked On: " + info.getRevocationTime().toDate());
        }
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing certificate serial number.");
        }

        CertId certID = new CertId(cmdArgs[0]);

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        CAClient caClient = new CAClient(client);
        CACertClient certClient = new CACertClient(caClient);
        AuthorityClient authorityClient = new AuthorityClient(caClient);

        ClientConfig config = getConfig();
        String ocspURL = cmd.getOptionValue("ocsp", config.getServerURL() + "/ca/ocsp");

        OCSPProcessor processor = new OCSPProcessor();
        processor.setURL(ocspURL);

        // get certificate data
        CertData certData = certClient.getCert(certID);
        String subjectDN = certData.getSubjectDN();
        String issuerDN = certData.getIssuerDN();

        // find CA that issued the cert
        Collection<AuthorityData> authorities = authorityClient.findCAs(null, null, issuerDN, null);

        if (authorities.size() == 0) {
            throw new CLIException("Unknown certificate issuer: " + issuerDN, 1);
        }

        // retrieve CA certificate
        AuthorityData authorityData = authorities.iterator().next();
        BigInteger issuerSerialNumber = authorityData.getSerial();
        CertData caCertData = certClient.getCert(new CertId(issuerSerialNumber));

        // parse CA certificate
        String pemCert = caCertData.getEncoded();
        byte[] binCert = Cert.parseCertificate(pemCert);

        X509CertImpl caCert = new X509CertImpl(binCert);
        X500Name caDN = caCert.getSubjectName();
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

        printSingleResponse(sr, subjectDN, issuerDN);
    }
}
