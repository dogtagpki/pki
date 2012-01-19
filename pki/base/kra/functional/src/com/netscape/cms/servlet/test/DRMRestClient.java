package com.netscape.cms.servlet.test;

import java.util.Collection;
import java.util.Iterator;

import javax.ws.rs.core.Response;

import org.jboss.resteasy.client.ProxyFactory;

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

public class DRMRestClient {

    private KeyResource keyClient;
    private KeysResource keysClient;
    private KeyRequestsResource keyRequestsClient;
    private KeyRequestResource keyRequestClient;
    private SystemCertificateResource systemCertClient;
    
    public DRMRestClient(String baseUri) {
        systemCertClient = ProxyFactory.create(SystemCertificateResource.class, baseUri);
        keyRequestsClient = ProxyFactory.create(KeyRequestsResource.class, baseUri);
        keyRequestClient = ProxyFactory.create(KeyRequestResource.class, baseUri);
        keysClient = ProxyFactory.create(KeysResource.class, baseUri);
        keyClient = ProxyFactory.create(KeyResource.class, baseUri);
    }
    
    public String getTransportCert() {
        Response response = systemCertClient.getTransportCert();
        CertificateData certData = (CertificateData) response.getEntity();
        String transportCert = certData.getB64();
        return transportCert;
    }
    
    public Collection<KeyRequestInfo> listRequests(String requestState, String requestType) {
        KeyRequestInfos infos = keyRequestsClient.listRequests(requestState, requestType, null, "0", 100, 100, 10);
        Collection<KeyRequestInfo> list = infos.getRequests();
        return list;
    }
    
    public KeyRequestInfo archiveSecurityData(byte[] encoded, String clientId) {
        // create archival request
        ArchivalRequestData data = new ArchivalRequestData();
        String req1 = com.netscape.osutil.OSUtil.BtoA(encoded);
        data.setWrappedPrivateData(req1);
        data.setClientId(clientId);

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
    
    public KeyRequestInfo requestRecovery(String keyId, byte[] rpwd, byte[] rkey) {
        // create recovery request
        RecoveryRequestData data = new RecoveryRequestData();
        data.setKeyId(keyId);
        if (rpwd != null) {
            data.setSessionWrappedPassphrase(com.netscape.osutil.OSUtil.BtoA(rpwd));
        }
        if (rkey != null) {
            data.setTransWrappedSessionKey(com.netscape.osutil.OSUtil.BtoA(rkey));
        }

        KeyRequestInfo info = keyRequestClient.recoverKey(data);
        return info;
    }
    
    public void approveRecovery(String recoveryId) {
        keyRequestClient.approveRequest(recoveryId);
    }
    
    public KeyData retrieveKey(String keyId, String requestId, byte[] rpwd, byte[] rkey) { 
        // create recovery request
        RecoveryRequestData data = new RecoveryRequestData();
        data.setKeyId(keyId);
        data.setRequestId(requestId);
        if (rkey != null) {
            data.setTransWrappedSessionKey(com.netscape.osutil.OSUtil.BtoA(rkey));
        }
        if (rpwd != null) {
            data.setSessionWrappedPassphrase(com.netscape.osutil.OSUtil.BtoA(rpwd));
        }
        KeyData key = keyClient.retrieveKey(data);
        return key;
    }
     

    
}