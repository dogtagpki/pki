package com.netscape.beakertests;

import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertNotFoundException;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;

public class CATestJunit extends PKIJUnitTest {

    CryptoManager manager = null;
    CryptoToken token = null;
    CAClient client;
    CertClient certClient;

    public CATestJunit() {
        super();
    }

    @Before
    public void initializeDB() {

        String host = getParameter("host");
        String port = getParameter("CA_SECURE_PORT");
        String token_pwd = getParameter("nss_db_password");
        String db_dir = getParameter("nss_db_dir");
        String protocol = "https";
        String clientCertNickname = getParameter("admin_cert_nickname");

        log("Host " + host);
        log("NSS DB_DIR " + db_dir);
        log("NSS DB_PWD " + token_pwd);

        // Initialize token
        try {
            CryptoManager.initialize(db_dir);
        } catch (AlreadyInitializedException e) {
            // it is ok if it is already initialized
        } catch (Exception e) {
            log(("INITIALIZATION ERROR: " + e.toString()));
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
        try {
            ClientConfig config = new ClientConfig();
            config.setServerURI(protocol + "://" + host + ":" + port + "/ca");
            config.setCertNickname(clientCertNickname);
            log("URI::: " + config.getServerURI().toString());
            client = new CAClient(new PKIClient(config));
            certClient = (CertClient)client.getClient("cert");
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }

    @Test
    public void listCompleteCertRequests() {

        Collection<CertRequestInfo> list = null;
        try {
            list = certClient.listRequests("complete", null, null, null, null, null).getEntries();
        } catch (Exception e) {
            e.printStackTrace();
        }

        printRequests(list);
    }

    @Test
    public void getACert() {
        // Get a CertInfo
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
    }

    @Test(expected = CertNotFoundException.class)
    public void getABadCert() {
        // Try an invalid Cert to print out
        // Get a CertInfo
        int certIdBadToPrint = 9999999;
        CertId certIdBad = new CertId(certIdBadToPrint);
        CertData certDataBad = null;
        try {
            certDataBad = certClient.getCert(certIdBad);
        } catch (Exception e) {
            e.printStackTrace();
            log("Cert: " + certIdBadToPrint + " not found. \n" + e.toString());
            throw e;
        }

        printCertificate(certDataBad);
    }

    private void printRequests(Collection<CertRequestInfo> list) {
        if (list == null) {
            log("No requests found");
            return;
        }
        for (CertRequestInfo info : list) {
            printRequestInfo(info);
        }
    }

    private void printRequestInfo(CertRequestInfo info) {
        if (info == null) {
            log("No RequestInfo: ");
            return;
        }

        log("CertRequestURL: " + info.getRequestURL());
        log("CertId: " + ((info.getCertId() != null) ? info.getCertId() : ""));
        log("RequestType: " + info.getCertRequestType());
        log("Status:        " + info.getRequestStatus());
        log("Type:          " + info.getRequestType());
        log("CertURL: "
                + ((info.getCertURL() != null) ? info.getCertURL() : "") + "\n");
    }

    private void printCertificate(CertData info) {

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

    /*
     * private static void log(String string) { log(string); }
     */
}
