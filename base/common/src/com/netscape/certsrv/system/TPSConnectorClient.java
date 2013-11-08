package com.netscape.certsrv.system;

import java.net.URISyntaxException;

import org.jboss.resteasy.client.ClientResponse;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.key.KeyData;

public class TPSConnectorClient extends Client {

    private TPSConnectorResource tpsConnectorClient;

    public TPSConnectorClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "tpsconnector");
        init();
    }

    public void init() throws URISyntaxException {
        tpsConnectorClient = createProxy(TPSConnectorResource.class);
    }

    public TPSConnectorCollection findConnectors(Integer start, Integer size) {
        return tpsConnectorClient.findConnectors(start, size);
    }

    public TPSConnectorData getConnector(String id) {
        return tpsConnectorClient.getConnector(id);
    }

    public TPSConnectorData getConnector(String host, String port) {
        return tpsConnectorClient.getConnector(host, port);
    }

    public TPSConnectorData createConnector(String tpsHost, String tpsPort) {
        @SuppressWarnings("unchecked")
        ClientResponse<TPSConnectorData> response = (ClientResponse<TPSConnectorData>)
                tpsConnectorClient.createConnector(tpsHost, tpsPort);
        return client.getEntity(response);
    }

    public TPSConnectorData modifyConnector(String id, TPSConnectorData data) {
        @SuppressWarnings("unchecked")
        ClientResponse<TPSConnectorData> response = (ClientResponse<TPSConnectorData>)
                tpsConnectorClient.modifyConnector(id, data);
        return client.getEntity(response);
    }

    public void deleteConnector(String id) {
        tpsConnectorClient.deleteConnector(id);
    }

    public KeyData createSharedSecret(String id) {
        return tpsConnectorClient.createSharedSecret(id);
    }

    public KeyData replaceSharedSecret(String id) {
        return tpsConnectorClient.replaceSharedSecret(id);
    };

    public void deleteSharedSecret(String id) {
        tpsConnectorClient.deleteSharedSecret(id);
    }

    public KeyData getSharedSecret(String id) {
        return tpsConnectorClient.getSharedSecret(id);
    }

    public void deleteConnector(String host, String port) {
        tpsConnectorClient.deleteConnector(host, port);
    }

}
