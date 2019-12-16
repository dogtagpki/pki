package com.netscape.certsrv.system;

import java.net.URISyntaxException;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.ResourceNotFoundException;
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

    public TPSConnectorCollection findConnectors(
            String host, String port, Integer start, Integer size) throws Exception {
        Response response = tpsConnectorClient.findConnectors(host, port, start, size);
        return client.getEntity(response, TPSConnectorCollection.class);
    }

    public TPSConnectorData getConnector(String id) throws Exception {
        Response response = tpsConnectorClient.getConnector(id);
        return client.getEntity(response, TPSConnectorData.class);
    }

    public TPSConnectorData getConnector(String host, String port) throws Exception {
        TPSConnectorCollection connectors = findConnectors(host, port, null, null);
        if (connectors.getTotal() < 1) {
            throw new ResourceNotFoundException("Connector not found: " + host + ":" + port);
        }
        return connectors.getEntries().iterator().next();
    }

    public TPSConnectorData createConnector(String tpsHost, String tpsPort) throws Exception {
        Response response = tpsConnectorClient.createConnector(tpsHost, tpsPort);
        return client.getEntity(response, TPSConnectorData.class);
    }

    public TPSConnectorData modifyConnector(String id, TPSConnectorData data) throws Exception {
        Response response = tpsConnectorClient.modifyConnector(id, data);
        return client.getEntity(response, TPSConnectorData.class);
    }

    public void deleteConnector(String id) throws Exception {
        Response response = tpsConnectorClient.deleteConnector(id);
        client.getEntity(response, Void.class);
    }

    public KeyData createSharedSecret(String id) throws Exception {
        Response response = tpsConnectorClient.createSharedSecret(id);
        return client.getEntity(response, KeyData.class);
    }

    public KeyData replaceSharedSecret(String id) throws Exception {
        Response response = tpsConnectorClient.replaceSharedSecret(id);
        return client.getEntity(response, KeyData.class);
    };

    public void deleteSharedSecret(String id) throws Exception {
        Response response = tpsConnectorClient.deleteSharedSecret(id);
        client.getEntity(response, Void.class);
    }

    public KeyData getSharedSecret(String id) throws Exception {
        Response response = tpsConnectorClient.getSharedSecret(id);
        return client.getEntity(response, KeyData.class);
    }

    public void deleteConnector(String host, String port) throws Exception {
        Response response = tpsConnectorClient.deleteConnector(host, port);
        client.getEntity(response, Void.class);
    }
}
