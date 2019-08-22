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
package com.netscape.cms.servlet.base;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.FormParam;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.EntityTag;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.base.PKIException;

/**
 * Base class for CMS RESTful resources
 *
 * @author alee
 *
 */
public class PKIService {

    // caching parameters
    public static final int DEFAULT_LONG_CACHE_LIFETIME = 1000;

    public static List<MediaType> MESSAGE_FORMATS = Arrays.asList(
            MediaType.APPLICATION_XML_TYPE,
            MediaType.APPLICATION_JSON_TYPE,
            MediaType.APPLICATION_FORM_URLENCODED_TYPE,
            MediaType.APPLICATION_OCTET_STREAM_TYPE,
            MediaType.valueOf("application/pkix-cert"),
            MediaType.valueOf("application/pkcs7-mime"),
            MediaType.valueOf("application/x-pem-file")
    );

    public final static int MIN_FILTER_LENGTH = 3;
    public final static int DEFAULT_SIZE = 20;

    @Context
    protected UriInfo uriInfo;

    @Context
    protected HttpHeaders headers;

    @Context
    protected Request request;

    @Context
    protected HttpServletRequest servletRequest;

    @Context
    protected ServletContext servletContext;

    public static Path bannerFile = Paths.get(getInstanceDir(), "conf", "banner.txt");

    public static String getInstanceDir() {
        return System.getProperty("catalina.base");  // provided by Tomcat
    }

    public static String getVersion() {
        return System.getenv("PKI_VERSION");  // defined in tomcat.conf
    }

    public static boolean isBannerEnabled() {
        return Files.exists(bannerFile);
    }

    public static String getBanner() throws IOException {
        return new String(Files.readAllBytes(bannerFile), "UTF-8").trim();
    }

    public static MediaType resolveFormat(MediaType format) {

        if (format == null) return null;

        for (MediaType supportedFormat : MESSAGE_FORMATS) {
            if (format.isCompatible(supportedFormat)) return supportedFormat;
        }

        return null;
    }

    public static MediaType resolveFormat(List<MediaType> formats) {

        if (formats == null) return null;

        for (MediaType acceptableFormat : formats) {
            MediaType supportedFormat = resolveFormat(acceptableFormat);
            if (supportedFormat != null) return supportedFormat;
        }

        return null;
    }

    public static MediaType getResponseFormat(HttpHeaders headers) {
        MediaType contentType = headers.getMediaType();
        List<MediaType> acceptableFormats = headers.getAcceptableMediaTypes();

        MediaType responseFormat;
        if (acceptableFormats == null || acceptableFormats.isEmpty()) {
            // if the Accept header is missing
            if (contentType == null) {
                // and if the Content-type header is missing, use the default format
                responseFormat = PKIService.MESSAGE_FORMATS.get(0);
            } else {
                // otherwise, use the Content-type header
                responseFormat = resolveFormat(contentType);
            }
        } else {
            responseFormat = resolveFormat(acceptableFormats);
        }

        if (responseFormat == null) {
            throw new PKIException(Response.Status.NOT_ACCEPTABLE);
        }

        return responseFormat;
    }

    public MediaType getResponseFormat() {
        return getResponseFormat(headers);
    }

    public Response createOKResponse() {
        return Response
                .ok()
                .type(getResponseFormat())
                .build();
    }

    public Response createOKResponse(Object entity) {
        return Response
                .ok(entity)
                .type(getResponseFormat())
                .build();
    }

    public Response createCreatedResponse(Object entity, URI link) {
        return Response
                .created(link)
                .entity(entity)
                .type(getResponseFormat())
                .build();
    }

    public Response createNoContentResponse() {
        return Response
                .noContent()
                .type(getResponseFormat())
                .build();
    }

    public Response sendConditionalGetResponse(int ctime, Object object, Request request) {
        CacheControl cc = new CacheControl();
        cc.setMaxAge(ctime);
        EntityTag tag = new EntityTag(Integer.toString(object.hashCode()));

        ResponseBuilder builder = request.evaluatePreconditions(tag);
        if (builder != null) {
            builder.cacheControl(cc);
            return builder.build();
        }

        builder = Response.ok(object);
        builder.cacheControl(cc);
        builder.tag(tag);
        builder.type(getResponseFormat());
        return builder.build();
    }

    public Locale getLocale(HttpHeaders headers) {

        if (headers == null) return Locale.getDefault();

        List<Locale> locales = headers.getAcceptableLanguages();
        if (locales == null || locales.isEmpty()) return Locale.getDefault();

        return locales.get(0);
    }

    /**
     * Get the values of the fields annotated with @FormParam.
     */
    public Map<String, String> getParams(Object object) {

        Map<String, String> map = new HashMap<String, String>();

        // for each fields in the object
        for (Method method : object.getClass().getMethods()) {
            FormParam element = method.getAnnotation(FormParam.class);
            if (element == null) continue;

            String name = element.value();

            try {
                // get the value from the object
                Object value = method.invoke(object);

                // put the value in the map
                map.put(name, value == null ? null : value.toString());

            } catch (Exception e) {
                // ignore inaccessible fields
                e.printStackTrace();
            }
        }

        return map;
    }
}
