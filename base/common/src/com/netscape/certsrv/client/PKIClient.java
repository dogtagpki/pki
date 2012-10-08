package com.netscape.certsrv.client;

import java.net.URISyntaxException;

import org.jboss.resteasy.client.ClientResponse;


public class PKIClient {

    PKIConnection connection;

    public PKIClient(PKIConnection connection) {
        this.connection = connection;
    }

    public PKIClient(ClientConfig config) {
        this(new PKIConnection(config));
    }

    public <T> T createProxy(Class<T> clazz) throws URISyntaxException {
        return connection.createProxy(clazz);
    }

    public <T> T getEntity(ClientResponse<T> response) {
        return connection.getEntity(response);
    }
}
