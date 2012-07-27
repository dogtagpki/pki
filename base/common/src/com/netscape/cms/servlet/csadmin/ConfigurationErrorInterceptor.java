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

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import org.jboss.resteasy.client.ClientResponse;
import org.jboss.resteasy.client.core.ClientErrorInterceptor;

import com.netscape.cms.servlet.base.CMSException;

/**
 * @author alee
 *
 */
public class ConfigurationErrorInterceptor implements ClientErrorInterceptor {

    public void handle(ClientResponse<?> response) {

        // handle HTTP code 4xx and 5xx
        int code = response.getResponseStatus().getStatusCode();
        if (code < 400) return;

        MultivaluedMap<String, String> headers = response.getHeaders();
        String contentType = headers.getFirst("Content-Type");

        // handle XML content only
        System.out.println("Content-type: "+contentType);
        if (!contentType.startsWith(MediaType.APPLICATION_XML)) return;

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
