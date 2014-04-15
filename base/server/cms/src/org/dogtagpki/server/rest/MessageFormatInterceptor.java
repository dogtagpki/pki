//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2014 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.rest;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.List;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import org.jboss.resteasy.core.ResourceMethodInvoker;

import com.netscape.certsrv.apps.CMS;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
@Provider
public class MessageFormatInterceptor implements ContainerRequestFilter {

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        ResourceMethodInvoker methodInvoker = (ResourceMethodInvoker) requestContext
                .getProperty("org.jboss.resteasy.core.ResourceMethodInvoker");
        Method method = methodInvoker.getMethod();
        Class<?> clazz = methodInvoker.getResourceClass();

        CMS.debug("MessageFormatInterceptor: " + clazz.getSimpleName() + "." + method.getName() + "()");

        MediaType contentType = requestContext.getMediaType();
        CMS.debug("MessageFormatInterceptor: content-type: " + contentType);

        List<MediaType> acceptableFormats = requestContext.getAcceptableMediaTypes();
        CMS.debug("MessageFormatInterceptor: accept: " + acceptableFormats);

        MediaType requestFormat = null;
        if (contentType != null) {
            requestFormat = PKIService.resolveFormat(contentType);
            CMS.debug("MessageFormatInterceptor: request format: " + requestFormat);

            if (requestFormat == null) {
                throw new WebApplicationException(Response.Status.UNSUPPORTED_MEDIA_TYPE);
            }
        }

        MediaType responseFormat;
        if (acceptableFormats == null || acceptableFormats.isEmpty()) {
            // if the Accept header is missing
            if (contentType == null) {
                // and if the Content-type header is missing, use the default format
                responseFormat = PKIService.MESSAGE_FORMATS.get(0);
            } else {
                // otherwise, use the Content-type header
                responseFormat = requestFormat;
            }
        } else {
            responseFormat = PKIService.resolveFormat(acceptableFormats);
        }
        CMS.debug("MessageFormatInterceptor: response format: " + responseFormat);

        if (responseFormat == null) {
            throw new WebApplicationException(Response.Status.NOT_ACCEPTABLE);
        }
    }
}
