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
package com.netscape.cms.servlet.common;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Enumeration;

import javax.servlet.ServletOutputStream;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.logging.ILogger;

/**
 * File templates. This implementation will take
 * an HTML file with a special customer tag
 * &lt;CMS_TEMPLATE&gt; and replace the tag with
 * a series of javascript variable definitions
 * (depending on the servlet)
 *
 * @version $Revision$, $Date$
 */
public class CMSTemplate extends CMSFile {

    public static final String SUFFIX = ".template";

    /*==========================================================
     * variables
     *==========================================================*/

    /* public vaiables */
    public String mPreOutput;
    public String mPostOutput;
    public static final String TEMPLATE_TAG = "<CMS_TEMPLATE>";

    /* Character set for i18n */

    /* Will be set by CMSServlet.getTemplate() */
    private String mCharset = null;

    /*==========================================================
     * constructors
     *==========================================================*/

    /**
     * Constructor
     *
     * @param file template file to load
     * @param charset character set
     * @throws IOException if the there was an error opening the file
     */
    public CMSTemplate(File file, String charset) throws IOException, EBaseException {
        mCharset = charset;
        mAbsPath = file.getAbsolutePath();
        mLastModified = file.lastModified();
        try {
            init(file);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_CANT_LOAD_TEMPLATE", mAbsPath, e.toString()));
            throw new ECMSGWException(
                    CMS.getLogMessage("CMSGW_ERROR_LOADING_TEMPLATE"));
        }
        String content = mPreOutput + mPostOutput;

        mContent = content.getBytes(mCharset);
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    /* *
     * Load the form from the file and setup the
     * pre/post output buffer if it is a template
     * file. Otherwise, only post output buffer is
     * filled.
     * @param template the template file to load
     * @return true if successful
     */
    public boolean init(File template) throws EBaseException, IOException {
        /* load template */
        String content = loadFile(template);

        if (content == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_TEMPLATE_EMPTY", mAbsPath));
            throw new ECMSGWException(
                    CMS.getLogMessage("CMSGW_TEMPLATE_NO_CONTENT_1", mAbsPath));
        }

        /* if template file, find template tag substring and set
         * pre/post output string
         */
        int location = content.indexOf(TEMPLATE_TAG);

        if (location == -1) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage(
                    "CMSGW_TEMPLATE_MISSING", mAbsPath, TEMPLATE_TAG));
            throw new ECMSGWException(
                    CMS.getLogMessage("CMSGW_MISSING_TEMPLATE_TAG_2",
                            TEMPLATE_TAG, mAbsPath));
        }
        mPreOutput = content.substring(0, location);
        mPostOutput = content.substring(TEMPLATE_TAG.length() + location);

        return true;
    }

    /**
     * Write a javascript representation of 'input'
     * surrounded by SCRIPT tags to the outputstream
     *
     * @param rout the outputstream to write to
     * @param input the parameters to write
     */
    public void renderOutput(OutputStream rout, CMSTemplateParams input)
            throws IOException {
        Enumeration<String> e = null;
        Enumeration<IArgBlock> q = null;
        IArgBlock r = null;
        CMSTemplateParams data = input;

        try (HTTPOutputStreamWriter http_out = (mCharset == null ?
                new HTTPOutputStreamWriter(rout): new HTTPOutputStreamWriter(rout, mCharset))) {
            templateLine out = new templateLine();

            // Output the prolog
            out.print(mPreOutput);

            // Output the header data
            out.println("<SCRIPT LANGUAGE=\"JavaScript\">");
            out.println("var header = new Object();");
            out.println("var fixed = new Object();");
            out.println("var recordSet = new Array;");
            out.println("var result = new Object();");

            // hack
            out.println("var httpParamsCount = 0;");
            out.println("var httpHeadersCount = 0;");
            out.println("var authTokenCount = 0;");
            out.println("var serverAttrsCount = 0;");
            out.println("header.HTTP_PARAMS = new Array;");
            out.println("header.HTTP_HEADERS = new Array;");
            out.println("header.AUTH_TOKEN = new Array;");
            out.println("header.SERVER_ATTRS = new Array;");

            r = data.getHeader();
            if (r != null) {
                e = r.elements();
                while (e.hasMoreElements()) {
                    String n = e.nextElement();
                    Object v = r.getValue(n);

                    out.println("header." + n + " = " + renderValue(v) + ";");
                }
            }

            // Output the fixed data
            r = data.getFixed();
            if (r != null) {
                e = r.elements();
                while (e.hasMoreElements()) {
                    String n = e.nextElement();
                    Object v = r.getValue(n);

                    out.println("fixed." + n + " = " + renderValue(v) + ";");
                }
            }

            // Output the query data
            q = data.queryRecords();
            if (q != null && q.hasMoreElements()) {
                out.println("var recordCount = 0;");
                out.println("var record;");
                while (q.hasMoreElements()) {
                    out.println("record = new Object;");
                    out.println("record.HTTP_PARAMS = new Array;");
                    out.println("record.HTTP_HEADERS = new Array;");
                    out.println("record.AUTH_TOKEN = new Array;");
                    out.println("record.SERVER_ATTRS = new Array;");

                    // Get a query record
                    r = q.nextElement();
                    e = r.elements();
                    while (e.hasMoreElements()) {
                        String n = e.nextElement();
                        Object v = r.getValue(n);

                        out.println("record." + n + "=" + renderValue(v) + ";");
                    }
                    out.println("recordSet[recordCount++] = record;");
                }
                out.println("record.recordSet = recordSet;");
            }

            //if (headerBlock)
            out.println("result.header = header;");
            //if (fixedBlock)
            out.println("result.fixed = fixed;");
            //if (queryBlock)
            out.println("result.recordSet = recordSet;");
            out.println("</SCRIPT>");
            out.println(mPostOutput);
            http_out.print(out.toString());

        } catch (EBaseException ex) {
            throw new IOException(ex.getMessage());
        }
    }

    /**
     * Ouput the pre-amble HTML Header including
     * the pre-output buffer.
     *
     * @param out output stream specified
     * @return success or error
     */
    public boolean outputProlog(PrintWriter out) {

        //Debug.trace("FormCache:outputProlog");

        /* output pre-output buffer */
        out.print(mPreOutput);

        /* output JavaScript variables and objects */
        out.println("<SCRIPT LANGUAGE=\"JavaScript\">");
        out.println("var header = new Object();");
        out.println("var result = new Object();");

        return true;
    }

    /**
     * Output the post HTML tags and post-output
     * buffer.
     *
     * @param out output stream specified
     * @return success or error
     */
    public boolean outputEpilog(PrintWriter out) {

        out.println("</SCRIPT>");
        out.println(mPostOutput);

        return true;
    }

    /**
     * @return full path of template
     */
    public String getTemplateName() {
        return mAbsPath;
    }

    // inherit getabspath, getContent, get last access and set last access

    /*==========================================================
     * private methods
     *==========================================================*/

    /* load file into string */
    private String loadFile(File template) throws IOException {

        // Debug.trace("FormCache:loadFile");

        /* create input stream, can throw IOException */
        FileInputStream inStream = new FileInputStream(template);
        InputStreamReader inReader = new InputStreamReader(inStream, mCharset);
        ;
        BufferedReader in = new BufferedReader(inReader);
        StringBuffer buf = new StringBuffer();
        String line;

        while ((line = in.readLine()) != null) {
            buf.append(line);
            buf.append('\n');
        }
        try {
            in.close();
            inStream.close();
        } catch (IOException e) {
            log(ILogger.LL_WARN,
                    CMS.getLogMessage("CMSGW_ERR_CLOSE_TEMPL_FILE", mAbsPath, e.getMessage()));
        }
        return buf.toString();
    }

    private String renderValue(Object v) {
        String s = null;

        // Figure out the type of object
        if (v instanceof IRawJS) {
            s = v.toString();
        } else if (v instanceof String) {
            if (v.equals(""))
                s = "null";
            else
                s = "\"" + escapeJavaScriptString((String) v) + "\"";
        } else if (v instanceof Integer) {
            s = ((Integer) v).toString();
        } else if (v instanceof Boolean) {

            if (((Boolean) v).booleanValue() == true) {
                s = "true";
            } else {
                s = "false";
            }
        } else if (v instanceof BigInteger) {
            s = ((BigInteger) v).toString(10);
        } else if (v instanceof Character &&
                ((Character) v).equals(Character.valueOf((char) 0))) {
            s = "null";
        } else {
            s = "\"" + v.toString() + "\"";
        }

        return s;
    }

    /**
     * Escape the contents of src string in preparation to be enclosed in
     * double quotes as a JavaScript String Literal within an <script>
     * portion of an HTML document.
     * stevep - performance improvements - about 4 times faster than before.
     */
    public static String escapeJavaScriptString(String v) {
        int l = v.length();
        char in[] = new char[l];
        char out[] = new char[l * 4];
        int j = 0;

        v.getChars(0, l, in, 0);

        for (int i = 0; i < l; i++) {
            char c = in[i];

            if ((c > 0x23) && (c != 0x5c) && (c != 0x3c) && (c != 0x3e)) {
                out[j++] = c;
                continue;
            }

            if ((c == 0x5c) && ((i + 1) < l) && (in[i + 1] == 'n' ||
                    in[i + 1] == 'r' || in[i + 1] == 'f' || in[i + 1] == 't' ||
                    in[i + 1] == '<' || in[i + 1] == '>' ||
                    in[i + 1] == '\"' || in[i + 1] == '\'' || in[i + 1] == '\\')) {
                if (in[i + 1] == 'x' && ((i + 3) < l) && in[i + 2] == '3' &&
                        (in[i + 3] == 'c' || in[i + 3] == 'e')) {
                    out[j++] = '\\';
                    out[j++] = in[i + 1];
                    out[j++] = in[i + 2];
                    out[j++] = in[i + 3];
                    i += 3;
                } else {
                    out[j++] = '\\';
                    out[j++] = in[i + 1];
                    i++;
                }
                continue;
            }

            switch (c) {
            case '\n':
                out[j++] = '\\';
                out[j++] = 'n';
                break;

            case '\\':
                out[j++] = '\\';
                out[j++] = '\\';
                break;

            case '\"':
                out[j++] = '\\';
                out[j++] = '\"';
                break;

            case '\r':
                out[j++] = '\\';
                out[j++] = 'r';
                break;

            case '\f':
                out[j++] = '\\';
                out[j++] = 'f';
                break;

            case '\t':
                out[j++] = '\\';
                out[j++] = 't';
                break;

            case '<':
                out[j++] = '\\';
                out[j++] = 'x';
                out[j++] = '3';
                out[j++] = 'c';
                break;

            case '>':
                out[j++] = '\\';
                out[j++] = 'x';
                out[j++] = '3';
                out[j++] = 'e';
                break;

            default:
                out[j++] = c;
            }
        }
        return new String(out, 0, j);
    }

    /**
     * Like escapeJavaScriptString(String s) but also escape '[' for
     * HTML processing.
     */
    public static String escapeJavaScriptStringHTML(String v) {
        int l = v.length();
        char in[] = new char[l];
        char out[] = new char[l * 4];
        int j = 0;

        v.getChars(0, l, in, 0);

        for (int i = 0; i < l; i++) {
            char c = in[i];

            if (c > 0x5C) {
                out[j++] = c;
                continue;
            }

            if ((c == 0x5c) && ((i + 1) < l) && (in[i + 1] == 'n' ||
                    in[i + 1] == 'r' || in[i + 1] == 'f' || in[i + 1] == 't' ||
                    in[i + 1] == '<' || in[i + 1] == '>' ||
                    in[i + 1] == '\"' || in[i + 1] == '\'' || in[i + 1] == '\\')) {
                if (in[i + 1] == 'x' && ((i + 3) < l) && in[i + 2] == '3' &&
                        (in[i + 3] == 'c' || in[i + 3] == 'e')) {
                    out[j++] = '\\';
                    out[j++] = in[i + 1];
                    out[j++] = in[i + 2];
                    out[j++] = in[i + 3];
                    i += 3;
                } else {
                    out[j++] = '\\';
                    out[j++] = in[i + 1];
                    i++;
                }
                continue;
            }

            switch (c) {
            case '\n':
                out[j++] = '\\';
                out[j++] = 'n';
                break;

            case '\\':
                out[j++] = '\\';
                out[j++] = '\\';
                break;

            case '\"':
                out[j++] = '\\';
                out[j++] = '\"';
                break;

            case '\r':
                out[j++] = '\\';
                out[j++] = 'r';
                break;

            case '\f':
                out[j++] = '\\';
                out[j++] = 'f';
                break;

            case '\t':
                out[j++] = '\\';
                out[j++] = 't';
                break;

            case '<':
                out[j++] = '\\';
                out[j++] = 'x';
                out[j++] = '3';
                out[j++] = 'c';
                break;
            case '>':
                out[j++] = '\\';
                out[j++] = 'x';
                out[j++] = '3';
                out[j++] = 'e';
                break;

            default:
                out[j++] = c;
            }
        }
        return new String(out, 0, j);
    }

    /**
     * for debugging, return contents that would've been outputed.
     */
    public String getOutput(CMSTemplateParams input)
            throws IOException {
        debugOutputStream out = new debugOutputStream();

        renderOutput(out, input);
        return out.toString();
    }

    private class HTTPOutputStreamWriter extends OutputStreamWriter {
        public HTTPOutputStreamWriter(OutputStream out)
                throws UnsupportedEncodingException {
            super(out);
        }

        public HTTPOutputStreamWriter(OutputStream out, String enc)
                throws UnsupportedEncodingException {
            super(out, enc);
        }

        public void print(String s) throws IOException {
            write(s, 0, s.length());
            flush();
            return;
        }
    }

    private class templateLine {
        private StringBuffer s = new StringBuffer();

        void println(String p) {
            s.append('\n');
            s.append(p);
        }

        void print(String p) {
            s.append(p);
        }

        public String toString() {
            return s.toString();
        }

    }

    private static class debugOutputStream extends ServletOutputStream {
        private StringWriter mStringWriter = new StringWriter();

        public debugOutputStream() {
            super();
        }

        public void write(int b) throws IOException {
            mStringWriter.write(b);
        }

        public String toString() {
            return mStringWriter.toString();
        }

    }

}
