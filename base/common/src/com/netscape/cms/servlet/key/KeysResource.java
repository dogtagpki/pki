package com.netscape.cms.servlet.key;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import com.netscape.cms.servlet.key.model.KeyDataInfos;

@Path("/keys")
public interface KeysResource {
    public static final int DEFAULT_MAXTIME = 10;
    public static final int DEFAULT_MAXRESULTS = 100;

    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    public KeyDataInfos listKeys(@QueryParam("clientID") String clientID,
                                 @QueryParam("status") String status,
                                 @DefaultValue(""+DEFAULT_MAXRESULTS) @QueryParam("maxResults") int maxResults,
                                 @DefaultValue(""+DEFAULT_MAXTIME) @QueryParam("maxTime") int maxTime);

}
