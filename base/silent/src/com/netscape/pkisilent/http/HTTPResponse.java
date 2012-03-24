package com.netscape.pkisilent.http;

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

import java.util.ArrayList;
import java.util.StringTokenizer;

import com.netscape.pkisilent.common.Utilities;

public class HTTPResponse {
    // The set of cookie values included in this response.
    ArrayList<String> cookieValueList;

    // The names of the headers included in this response.
    ArrayList<String> headerNameList;

    // The values of the headers included in this response.
    ArrayList<String> headerValueList;

    // The actual data associated with this response.
    byte[] responseData;

    // The HTML document included in the response, if appropriate.
    HTMLDocument htmlDocument;

    // The number of bytes contained in the content of the response.
    int contentLength;

    // The HTTP status code for the response.
    int statusCode;

    // The MIME type of the response.
    String contentType;

    // The protocol version string for this response.
    String protolVersion;

    // The response message for this response.
    String responseMessage;

    // Parsed Content Name/Value pair info
    ArrayList<String> contentName;
    ArrayList<String> contentValue;

    /**
     * Creates a new HTTP response with the provided status code.
     * 
     * @param statusCode The HTTP status code for this response.
     * @param protocolVersion The protocol and version for this response.
     * @param responseMessage The message associated with this response.
     */
    public HTTPResponse(int statusCode, String protocolVersion,
                      String responseMessage) {
        this.statusCode = statusCode;
        this.protolVersion = protocolVersion;
        this.responseMessage = responseMessage;

        htmlDocument = null;
        contentType = null;
        contentLength = -1;
        responseData = new byte[0];
        cookieValueList = new ArrayList<String>();
        headerNameList = new ArrayList<String>();
        headerValueList = new ArrayList<String>();
        contentName = new ArrayList<String>();
        contentValue = new ArrayList<String>();
    }

    /**
     * Retrieves the status code for this HTTP response.
     * 
     * @return The status code for this HTTP response.
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * Retrieves the protocol version for this HTTP response.
     * 
     * @return The protocol version for this HTTP response.
     */
    public String getProtocolVersion() {
        return protolVersion;
    }

    /**
     * Retrieves the response message for this HTTP response.
     * 
     * @return The response message for this HTTP response.
     */
    public String getResponseMessage() {
        return responseMessage;
    }

    /**
     * Retrieves the value of the header with the specified name. If the
     * specified header has more than one value, then only the first will be
     * retrieved.
     * 
     * @return The value of the header with the specified name, or <CODE>null</CODE> if no such header is available.
     */
    public String getHeader(String headerName) {
        String lowerName = headerName.toLowerCase();

        for (int i = 0; i < headerNameList.size(); i++) {
            if (lowerName.equals(headerNameList.get(i))) {
                return headerValueList.get(i);
            }
        }

        return null;
    }

    /**
     * Retrieves the set of values for the specified header.
     * 
     * @return The set of values for the specified header.
     */
    public String[] getHeaderValues(String headerName) {
        ArrayList<String> valueList = new ArrayList<String>();
        String lowerName = headerName.toLowerCase();

        for (int i = 0; i < headerNameList.size(); i++) {
            if (lowerName.equals(headerNameList.get(i))) {
                valueList.add(headerValueList.get(i));
            }
        }

        String[] values = new String[valueList.size()];
        valueList.toArray(values);
        return values;
    }

    /**
     * Adds a header with the given name and value to this response.
     * 
     * @param headerName The name of the header to add to this response.
     * @param headerValue The value of the header to add to this response.
     */
    public void addHeader(String headerName, String headerValue) {
        String lowerName = headerName.toLowerCase();
        headerNameList.add(lowerName);
        headerValueList.add(headerValue);

        if (lowerName.equals("content-length")) {
            try {
                contentLength = Integer.parseInt(headerValue);
            } catch (NumberFormatException nfe) {
            }
        } else if (lowerName.equals("content-type")) {
            contentType = headerValue;
        } else if (lowerName.equals("set-cookie")) {
            cookieValueList.add(headerValue);
        }
    }

    /**
     * Retrieves a two-dimensional array containing the header data for this
     * response, with each element being an array containing a name/value pair.
     * 
     * @return A two-dimensional array containing the header data for this
     *         response.
     */
    public String[][] getHeaderElements() {
        String[][] headerElements = new String[headerNameList.size()][2];
        for (int i = 0; i < headerNameList.size(); i++) {
            headerElements[i][0] = headerNameList.get(i);
            headerElements[i][1] = headerValueList.get(i);
        }

        return headerElements;
    }

    /**
     * Retrieves the raw data included in this HTTP response. If the response did
     * not include any data, an empty array will be returned.
     * 
     * @return The raw data included in this HTTP response.
     */
    public byte[] getResponseData() {
        return responseData;
    }

    public String getHTML() {
        String htmlString = new String(responseData);
        return htmlString;
    }

    public String getHTMLwithoutTags() {
        String htmlString = new String(responseData);
        HTMLDocument htmldocument = new HTMLDocument(htmlString);
        return htmldocument.getTextData();
    }

    public void parseContent() {
        // parse the responseData byte[] buffer and split content into name
        // value pair
        String htmlString = new String(responseData);
        StringTokenizer st = new StringTokenizer(htmlString, "\n");
        Utilities ut = new Utilities();

        while (st.hasMoreTokens()) {
            String line = st.nextToken();
            // format for line assumed to be name="value"; format

            int eqPos = line.indexOf('=');
            if (eqPos != -1) {
                String name = line.substring(0, eqPos);
                String tempval = line.substring(eqPos + 1).trim();
                String value = ut.cleanupQuotes(ut.removechar(tempval));

                // add to array
                this.contentName.add(name.trim());
                this.contentValue.add(value);
            }

        }

    }

    public String getContentValue(String headerName) {
        for (int i = 0; i < contentName.size(); i++) {
            if (headerName.equals(contentName.get(i))) {
                return contentValue.get(i);
            }
        }

        return null;
    }

    public ArrayList<String> getContentNames() {
        return contentName;
    }

    public ArrayList<String> getContentValues() {
        return contentValue;
    }

    /**
     * Sets the actual data associated with this response.
     * 
     * @param responseData The actual data associated with this response.
     */
    public void setResponseData(byte[] responseData) {
        if (responseData == null) {
            this.responseData = new byte[0];
        } else {
            this.responseData = responseData;
        }
    }

    /**
     * Retrieves the content length associated with this response.
     * 
     * @return The content length associated with this response, or -1 if no
     *         content length is available.
     */
    public int getContentLength() {
        return contentLength;
    }

    /**
     * Retrieves the content type associated with this response.
     * 
     * @return The content type associated with this response, or <CODE>null</CODE> if no content type is available.
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * Retrieves an array containing the values of the cookies that should be set
     * based on the information in this response.
     * 
     * @return An array containing the values of the cookies that should be set
     *         based on the information in this response.
     */
    public String[] getCookieValues() {
        String[] cookieValues = new String[cookieValueList.size()];
        cookieValueList.toArray(cookieValues);
        return cookieValues;
    }

    public String getCookieValue(String headerName) {
        for (int i = 0; i < cookieValueList.size(); i++) {
            System.out.println("cookie list: " + cookieValueList.get(i));

            String temp = cookieValueList.get(i);
            if (temp.startsWith(headerName)) {
                return cookieValueList.get(i);
            }
        }

        return null;
    }

}
