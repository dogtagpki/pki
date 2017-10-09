package com.netscape.beakertests;

import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.ca.CACertClient;
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
    CACertClient certClient;

    public CATestJunit() {
    }

    @Before
    public void initializeDB() throws Exception {

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
        }

        // log into token
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

        ClientConfig config = new ClientConfig();
        config.setServerURI(protocol + "://" + host + ":" + port + "/ca");
        config.setCertNickname(clientCertNickname);
        log("URI::: " + config.getServerURI().toString());
        client = new CAClient(new PKIClient(config, null));
        certClient = (CACertClient)client.getClient("cert");
    }

    @Test
    public void listCompleteCertRequests() {

        Collection<CertRequestInfo> list =
                certClient.listRequests("complete", null, null, null, null, null).getEntries();

        printRequests(list);
    }

    @Test
    public void getACert() {
        // Get a CertInfo
        int certIdToPrint = 1;
        CertId id = new CertId(certIdToPrint);
        CertData certData = certClient.getCert(id);
        printCertificate(certData);
    }

    @Test(expected = CertNotFoundException.class)
    public void getABadCert() {
        // Try an invalid Cert to print out
        // Get a CertInfo
        int certIdBadToPrint = 9999999;
        CertId certIdBad = new CertId(certIdBadToPrint);
        CertData certDataBad = certClient.getCert(certIdBad);
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
