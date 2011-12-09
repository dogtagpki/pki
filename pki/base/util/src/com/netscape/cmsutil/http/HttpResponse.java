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
 * Basic HTTP Response.
 * Set fields or parse from input.
 * Handles only text content.
 */
public class HttpResponse extends HttpMessage {
    protected String mStatusCode = null;
    protected String mReasonPhrase = null;
    protected String mHttpVers = null;

    /**
     * Instantiate a HttpResponse for write to http client.
     */
    public HttpResponse() {
        super();
    }

    /**
     * set status code of response
     */
    public void setStatusCode(int code) {
        mStatusCode = String.valueOf(code);
    }

    /**
     * set reason phrase.
     */
    public void setReasonPhrase(String phrase) {
        mReasonPhrase = phrase;
    }

    /**
     * get status code
     */
    public String getStatusCode() {
        return mStatusCode;
    }

    /**
     * get reason phrase
     */
    public String getReasonPhrase() {
        return mReasonPhrase;
    }

    /**
     * write the response out to the http client
     */
    public void write(OutputStreamWriter writer)
        throws IOException {
        if (mStatusCode == null) {
            throw new HttpProtocolException("status code not set in response");
        }
        // write status-line 
        mLine = Http.HttpVers + " " + mStatusCode + " ";
        if (mReasonPhrase != null)
            mLine += mReasonPhrase;
        mLine += Http.CRLF;
        super.write(writer);
    }

    /**
     * parse a http response from a http server
     */
    public void parse(BufferedReader reader)
        throws IOException {
        mHttpVers = null;
        mStatusCode = null;
        mReasonPhrase = null;

        super.parse(reader);

        int httpvers = mLine.indexOf(' ');

        if (httpvers == -1) {
            reset();
            throw new HttpProtocolException("no Http version in response");
        }
        mHttpVers = mLine.substring(0, httpvers);
        if (!mHttpVers.equals(Http.Vers1_0) && 
            !mHttpVers.equals(Http.Vers1_1)) {
            reset();
            throw new HttpProtocolException("Bad Http version in response");
        }

        int code = mLine.indexOf(' ', httpvers + 1);

        if (code == -1) {
            reset();
            throw new HttpProtocolException("no status code in response");
        }
        mStatusCode = mLine.substring(httpvers + 1, code);
        try {
            Integer.parseInt(mStatusCode);
        } catch (NumberFormatException e) {
            reset();
            throw new HttpProtocolException("Bad status code in response");
        }

        mReasonPhrase = mLine.substring(code + 1);
    }

    public void reset() {
        mStatusCode = null;
        mHttpVers = null;
        mReasonPhrase = null;
        super.reset();
    }

    /**
     * get http version
     */
    public String getHttpVers() {
        return mHttpVers;
    }
}
