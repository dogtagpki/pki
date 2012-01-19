package com.netscape.cms.servlet.request;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import com.netscape.cms.servlet.request.model.KeyRequestInfos;

@Path("/keyrequests")
public interface KeyRequestsResource {

    public static final String DEFAULT_START = "0";
    public static final String DEFAULT_PAGESIZE = "20";
    public static final String DEFAULT_MAXRESULTS = "100";
    public static final String DEFAULT_MAXTIME = "10";

    /**
     * Used to generate list of key requests based on the search parameters
     */
    @GET
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    public KeyRequestInfos listRequests(@QueryParam("requestState") String requestState,
                                            @QueryParam("requestType") String requestType,
                                            @QueryParam("clientID") String clientID,
                                            @DefaultValue(DEFAULT_START) @QueryParam("start") String start_s,
                                            @DefaultValue(DEFAULT_PAGESIZE) @QueryParam("pageSize") int pageSize,
                                            @DefaultValue(DEFAULT_MAXRESULTS) @QueryParam("maxResults") int maxResults,
                                            @DefaultValue(DEFAULT_MAXTIME) @QueryParam("maxTime") int maxTime);

}
