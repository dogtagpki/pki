package com.netscape.certsrv.system;

import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpEntity;

import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.key.KeyData;

public class TPSConnectorClient extends Client {

    public TPSConnectorClient(SubsystemClient subsystemClient) throws Exception {
        this(subsystemClient.client, subsystemClient.getName());
    }

    public TPSConnectorClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "admin/tps-connectors");
    }

    public TPSConnectorCollection findConnectors(
            String host,
            String port,
            Integer start,
            Integer size) throws Exception {

        Map<String, Object> params = new HashMap<>();
        if (host != null) params.put("host", host);
        if (port != null) params.put("port", port);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);

        return get(null, params, TPSConnectorCollection.class);
    }

    public TPSConnectorData getConnector(String id) throws Exception {
        return get(id, TPSConnectorData.class);
    }

    public TPSConnectorData getConnector(String host, String port) throws Exception {
        TPSConnectorCollection connectors = findConnectors(host, port, null, null);
        if (connectors.getEntries().isEmpty()) {
            throw new ResourceNotFoundException("Connector not found: " + host + ":" + port);
        }
        return connectors.getEntries().iterator().next();
    }

    public TPSConnectorData createConnector(String host, String port) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (host != null) params.put("host", host);
        if (port != null) params.put("port", port);
        return post(null, params, null, TPSConnectorData.class);
    }

    public TPSConnectorData modifyConnector(String id, TPSConnectorData data) throws Exception {
        HttpEntity entity = client.entity(data);
        return post(id, null, entity, TPSConnectorData.class);
    }

    public void deleteConnector(String id) throws Exception {
        delete(id, Void.class);
    }

    public void deleteConnector(String host, String port) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (host != null) params.put("host", host);
        if (port != null) params.put("port", port);
        delete(null, params, Void.class);
    }

    public KeyData createSharedSecret(String id) throws Exception {
        return post(id + "/shared-secret", null, null, KeyData.class);
    }

    public KeyData replaceSharedSecret(String id) throws Exception {
        return put(id + "/shared-secret", null, null, KeyData.class);
    };

    public void deleteSharedSecret(String id) throws Exception {
        delete(id + "/shared-secret", Void.class);
    }

    public KeyData getSharedSecret(String id) throws Exception {
        return get(id + "/shared-secret", KeyData.class);
    }
}
