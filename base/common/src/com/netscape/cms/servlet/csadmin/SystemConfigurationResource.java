// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK --- 
package com.netscape.cms.servlet.csadmin;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import com.netscape.cms.servlet.csadmin.model.ConfigurationData;
import com.netscape.cms.servlet.csadmin.model.ConfigurationResponseData;
import com.netscape.cms.servlet.csadmin.model.DomainInfo;
import com.netscape.cms.servlet.csadmin.model.InstallToken;
import com.netscape.cms.servlet.csadmin.model.InstallTokenRequest;

/**
 * @author alee
 *
 */
@Path("/installer")
public interface SystemConfigurationResource {
    
    @POST
    @Path("configure")
    @Produces({ MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_FORM_URLENCODED})
    public ConfigurationResponseData configure(MultivaluedMap<String, String> form);
    
    @POST
    @Path("configure")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public ConfigurationResponseData configure(ConfigurationData data);
    
    @POST
    @Path("installToken")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public InstallToken getInstallToken(InstallTokenRequest data);
    
    @GET
    @Path("domainInfo")
    @Produces({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON, MediaType.TEXT_XML })
    @Consumes({ MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON })
    public DomainInfo getDomainInfo();
    
    
}
