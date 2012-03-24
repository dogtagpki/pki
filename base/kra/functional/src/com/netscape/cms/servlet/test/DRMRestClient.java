package com.netscape.cms.servlet.test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.jboss.resteasy.client.ClientExecutor;
import org.jboss.resteasy.client.ClientResponse;
import org.jboss.resteasy.client.ProxyFactory;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.request.RequestId;
import org.jboss.resteasy.client.core.executors.ApacheHttpClientExecutor;
import com.netscape.cms.servlet.admin.SystemCertificateResource;
import com.netscape.cms.servlet.cert.model.CertificateData;
import com.netscape.cms.servlet.key.KeyResource;
import com.netscape.cms.servlet.key.KeysResource;
import com.netscape.cms.servlet.key.model.KeyData;
import com.netscape.cms.servlet.key.model.KeyDataInfo;
import com.netscape.cms.servlet.key.model.KeyDataInfos;
import com.netscape.cms.servlet.request.KeyRequestResource;
import com.netscape.cms.servlet.request.KeyRequestsResource;
import com.netscape.cms.servlet.request.model.ArchivalRequestData;
import com.netscape.cms.servlet.request.model.KeyRequestInfo;
import com.netscape.cms.servlet.request.model.KeyRequestInfos;
import com.netscape.cms.servlet.request.model.RecoveryRequestData;
import com.netscape.cmsutil.util.Utils;

import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLClientCertificateSelectionCallback;
import org.mozilla.jss.ssl.SSLSocket;

public class DRMRestClient {

    // Callback to approve or deny returned SSL server certs
    // Right now, simply approve the cert.
    // ToDO: Look into taking this JSS http client code and move it into
    // its own class to be used by possible future clients.
    private class ServerCertApprovalCB implements SSLCertificateApprovalCallback {
        
        public boolean approve(org.mozilla.jss.crypto.X509Certificate servercert,
                SSLCertificateApprovalCallback.ValidityStatus status) {

            //For now lets just accept the server cert. This is a test tool, being
            // pointed at a well know kra instance.


            if (servercert != null) {
                System.out.println("Peer cert details: " +
                        "\n     subject: " + servercert.getSubjectDN().toString() +
                        "\n     issuer:  " + servercert.getIssuerDN().toString() +
                        "\n     serial:  " + servercert.getSerialNumber().toString()
                        );
            }

            SSLCertificateApprovalCallback.ValidityItem item;

            Enumeration<?> errors = status.getReasons();
            int i = 0;
            while (errors.hasMoreElements()) {
                i++;
                item = (SSLCertificateApprovalCallback.ValidityItem) errors.nextElement();
                System.out.println("item " + i +
                        " reason=" + item.getReason() +
                        " depth=" + item.getDepth());

                int reason = item.getReason();

                if (reason ==
                        SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER ||
                        reason == SSLCertificateApprovalCallback.ValidityStatus.BAD_CERT_DOMAIN) {

                    //Allow these two since we haven't necessarily installed the CA cert for trust
                    // and we are choosing "localhost" as the host for this client. 

                    return true;

                }
            }

            //For other errors return false

            return false;
        }
    }
    
    private  class JSSProtocolSocketFactory implements ProtocolSocketFactory {

        @Override
        public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
            
            SSLSocket sock = createJSSSocket(host,port, null, 0, null);
            return (Socket) sock;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress clientHost, int clientPort) throws IOException,
                UnknownHostException {
            
            SSLSocket sock = createJSSSocket(host,port, clientHost, clientPort, null);
            return (Socket) sock;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localAddress, int localPort, HttpConnectionParams params)
                throws IOException, UnknownHostException, ConnectTimeoutException {
            
           SSLSocket sock = createJSSSocket(host, port, localAddress, localPort, null);
           return (Socket) sock;
        }
    }

    private SSLSocket createJSSSocket(String host, int port, InetAddress localAddress, 
            int localPort, SSLClientCertificateSelectionCallback clientCertSelectionCallback)
            throws IOException, UnknownHostException, ConnectTimeoutException {
        
        SSLSocket sock = new SSLSocket(InetAddress.getByName(host),
                port,
                localAddress,
                localPort,
                new ServerCertApprovalCB(),
                null);
        
        if(sock != null && clientCertNickname != null) {
            sock.setClientCertNickname(clientCertNickname);
        }
        
        return  sock;
        
    }
    private KeyResource keyClient;
    private KeysResource keysClient;
    private KeyRequestsResource keyRequestsClient;
    private KeyRequestResource keyRequestClient;
    private SystemCertificateResource systemCertClient;
    
    private String clientCertNickname = null;
    
    public DRMRestClient(String baseUri, String clientCertNick) throws MalformedURLException {
        
        // For SSL we are assuming the caller has already intialized JSS and has
        // a valid CryptoManager and CryptoToken
        // optional clientCertNickname is provided for use if required.
        
        
        URL url = new URL(baseUri);
        
        String protocol = url.getProtocol();
        int port = url.getPort();
        
        clientCertNickname = null;
        if(protocol != null && protocol.equals("https")) {
            if (clientCertNick != null) {
                clientCertNickname = clientCertNick;
            } 
            
            Protocol.registerProtocol("https", 
                new Protocol(protocol, new JSSProtocolSocketFactory(), port));
        }
        
        HttpClient httpclient = new HttpClient();
        ClientExecutor executor = new ApacheHttpClientExecutor(httpclient);

        systemCertClient = ProxyFactory.create(SystemCertificateResource.class, baseUri, executor);
        keyRequestsClient = ProxyFactory.create(KeyRequestsResource.class, baseUri, executor);
        keyRequestClient = ProxyFactory.create(KeyRequestResource.class, baseUri, executor);
        keysClient = ProxyFactory.create(KeysResource.class, baseUri, executor);
        keyClient = ProxyFactory.create(KeyResource.class, baseUri, executor);
    }
    
    public String getTransportCert() {
        @SuppressWarnings("unchecked")
        ClientResponse<CertificateData> response = (ClientResponse<CertificateData>) systemCertClient.getTransportCert();
        CertificateData certData = response.getEntity();
        String transportCert = certData.getB64();
        return transportCert;
    }
    
    public Collection<KeyRequestInfo> listRequests(String requestState, String requestType) {
        KeyRequestInfos infos = keyRequestsClient.listRequests(
                requestState, requestType, null, new RequestId(0), 100, 100, 10
        );
        Collection<KeyRequestInfo> list = infos.getRequests();
        return list;
    }
    
    public KeyRequestInfo archiveSecurityData(byte[] encoded, String clientId, String dataType) {
        // create archival request
        ArchivalRequestData data = new ArchivalRequestData();
        String req1 = Utils.base64encode(encoded);
        data.setWrappedPrivateData(req1);
        data.setClientId(clientId);
        data.setDataType(dataType);

        KeyRequestInfo info = keyRequestClient.archiveKey(data);
        return info;
    }
    
    public KeyDataInfo getKeyData(String clientId, String status) {
        KeyDataInfos infos = keysClient.listKeys(clientId, status, 100, 10);
        Collection<KeyDataInfo> list = infos.getKeyInfos();
        Iterator<KeyDataInfo> iter = list.iterator();

        while (iter.hasNext()) {
            KeyDataInfo info = iter.next();
            if (info != null) {
                // return the first one
                return info;
            }
        }
        return null;
    }
    
    public KeyRequestInfo requestRecovery(KeyId keyId, byte[] rpwd, byte[] rkey, byte[] nonceData) {
        // create recovery request
        RecoveryRequestData data = new RecoveryRequestData();
        data.setKeyId(keyId);
        if (rpwd != null) {
            data.setSessionWrappedPassphrase(Utils.base64encode(rpwd));
        }
        if (rkey != null) {
            data.setTransWrappedSessionKey(Utils.base64encode(rkey));
        }

        if (nonceData != null) {
            data.setNonceData(Utils.base64encode(nonceData));
        }

        KeyRequestInfo info = keyRequestClient.recoverKey(data);
        return info;
    }
    
    public void approveRecovery(RequestId recoveryId) {
        keyRequestClient.approveRequest(recoveryId);
    }
    
    public KeyData retrieveKey(KeyId keyId, RequestId requestId, byte[] rpwd, byte[] rkey, byte[] nonceData) {
        // create recovery request
        RecoveryRequestData data = new RecoveryRequestData();
        data.setKeyId(keyId);
        data.setRequestId(requestId);
        if (rkey != null) {
            data.setTransWrappedSessionKey(Utils.base64encode(rkey));
        }
        if (rpwd != null) {
            data.setSessionWrappedPassphrase(Utils.base64encode(rpwd));
        }

        if (nonceData != null) {
            data.setNonceData(Utils.base64encode(nonceData));
        }

        KeyData key = keyClient.retrieveKey(data);
        return key;
    }
}
