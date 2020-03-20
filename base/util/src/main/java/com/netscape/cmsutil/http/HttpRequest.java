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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmsutil.http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStreamWriter;

/**
 * Basic HTTP Request. not optimized for performance.
 * Set fields or parse from input.
 * Handles text content.
 */
public class HttpRequest extends HttpMessage {
    public static final String GET = "GET";
    public static final String POST = "POST";
    public static final String HEAD = "HEAD";

    protected String mMethod = null;
    protected String mURI = null;
    protected String mHttpVers = null;

    /**
     * Instantiate a HttpResponse for write to http client.
     */
    public HttpRequest() {
        super();
    }

    /**
     * set set request method.
     */
    public void setMethod(String method)
            throws HttpProtocolException {
        if (!method.equals(GET) && !method.equals(HEAD) &&
                !method.equals(POST))
            throw new HttpProtocolException("No such method " + method);
        mMethod = method;
    }

    /**
     * set reason phrase.
     */
    public void setURI(String uri) {
        mURI = uri;
    }

    /**
     * write request to the http client
     */
    public void write(OutputStreamWriter writer)
            throws IOException {
        if (mMethod == null || mURI == null) {
            HttpProtocolException e = new HttpProtocolException(
                    "Http request method or uri not initialized");

            //e.printStackTrace();
            throw e;
        }

        mLine = mMethod + " " + mURI + " " + Http.HttpVers;
        super.write(writer);
    }

    /**
     * parse a http request from a http client
     */
    public void parse(BufferedReader reader)
            throws IOException {
        super.parse(reader);

        int method = mLine.indexOf(Http.SP);

        mMethod = mLine.substring(0, method);
        if (!mMethod.equals(GET) && !mMethod.equals(POST) &&
                !mMethod.equals(HEAD)) {
            reset();
            throw new HttpProtocolException("Bad Http request method");
        }

        int uri = mLine.lastIndexOf(Http.SP);

        mURI = mLine.substring(method + 1, uri);

        mHttpVers = mLine.substring(uri + 1);
        if (!mHttpVers.equals("")) {
            if (!mHttpVers.equals(Http.Vers1_0) &&
                    !mHttpVers.equals(Http.Vers1_1)) {
                reset();
                throw new HttpProtocolException("Bad Http version in request");
            }
        }
    }

    public void reset() {
        mMethod = null;
        mURI = null;
        mHttpVers = null;
        super.reset();
    }

    /**
     * get method
     */
    public String getMethod() {
        return mMethod;
    }

    /**
     * get reason phrase
     */
    public String getURI() {
        return mURI;
    }

    /**
     * get http version
     */
    public String getHttpVers() {
        return mHttpVers;
    }
}
