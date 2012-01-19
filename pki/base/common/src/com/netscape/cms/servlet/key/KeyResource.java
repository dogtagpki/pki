package com.netscape.cms.servlet.key;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import com.netscape.cms.servlet.key.model.KeyData;
import com.netscape.cms.servlet.request.model.RecoveryRequestData;

@Path("/key")
public interface KeyResource {
   
    /**
     * Used to retrieve a key
     * @param data
     * @return
     */
    @POST
    @Path("retrieve")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public KeyData retrieveKey(RecoveryRequestData data);
    
    // retrieval - used to test integration with a browser
    @POST
    @Path("retrieve")
    @Produces(MediaType.TEXT_XML)
    public KeyData retrieveKey(MultivaluedMap<String, String> form);
}
