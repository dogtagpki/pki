package com.netscape.cms.servlet.test;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import org.jboss.resteasy.client.ClientResponse;
import org.jboss.resteasy.client.core.ClientErrorInterceptor;

import com.netscape.cms.servlet.base.CMSException;

public class DRMErrorInterceptor implements ClientErrorInterceptor  {

    public void handle(ClientResponse<?> response) {

        // handle HTTP code 4xx and 5xx
        int code = response.getResponseStatus().getStatusCode();
        if (code < 400) return;

        MultivaluedMap<String, String> headers = response.getHeaders();
        String contentType = headers.getFirst("Content-Type");

        // handle XML content only
        if (!contentType.startsWith(MediaType.TEXT_XML)) return;

        CMSException exception;

        try {
            // Requires RESTEasy 2.3.2
            // https://issues.jboss.org/browse/RESTEASY-652
            CMSException.Data data = response.getEntity(CMSException.Data.class);

            Class<?> clazz = Class.forName(data.className);
            exception = (CMSException) clazz.getConstructor(CMSException.Data.class).newInstance(data);

        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        throw exception;
    }

}
