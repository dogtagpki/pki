package com.netscape.pkisilent.common;

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

/*
 * @(#)Properties.java	1.60 00/02/02
 *
 * Copyright 1995-2000 Sun Microsystems, Inc. All Rights Reserved.
 * 
 * This software is the proprietary information of Sun Microsystems, Inc.  
 * Use is subject to license terms.
 * 
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

/**
 * The <code>Properties</code> class represents a persistent set of properties.
 * The <code>Properties</code> can be saved to a stream or loaded from a stream.
 * Each key and its corresponding value in the property list is a string.
 * <p>
 * A property list can contain another property list as its "defaults"; this
 * second property list is searched if the property key is not found in the
 * original property list.
 * <p>
 * Because <code>Properties</code> inherits from <code>Hashtable</code>, the
 * <code>put</code> and <code>putAll</code> methods can be applied to a
 * <code>Properties</code> object. Their use is strongly discouraged as they
 * allow the caller to insert entries whose keys or values are not
 * <code>Strings</code>. The <code>setProperty</code> method should be used
 * instead. If the <code>store</code> or <code>save</code> method is called on a
 * "compromised" <code>Properties</code> object that contains a non-
 * <code>String</code> key or value, the call will fail.
 * <p>
 * <a name="encoding"></a> When saving properties to a stream or loading them
 * from a stream, the ISO 8859-1 character encoding is used. For characters that
 * cannot be directly represented in this encoding, <a
 * href="http://java.sun.com/docs/books/jls/html/3.doc.html#100850">Unicode
 * escapes</a> are used; however, only a single 'u' character is allowed in an
 * escape sequence. The native2ascii tool can be used to convert property files
 * to and from other character encodings.
 * 
 * @see <a href="../../../tooldocs/solaris/native2ascii.html">native2ascii tool
 *      for Solaris</a>
 * @see <a href="../../../tooldocs/win32/native2ascii.html">native2ascii tool
 *      for Windows</a>
 * 
 * @author Arthur van Hoff
 * @author Michael McCloskey
 * @version 1.60, 02/02/00
 * @since JDK1.0
 */

class CMSProperties extends Hashtable<String, String> {

    /**
     * use serialVersionUID from JDK 1.1.X for interoperability
     */
    private static final long serialVersionUID = 4112578634029874840L;

    /**
     * A property list that contains default values for any keys not found in
     * this property list.
     * 
     * @serial
     */
    protected CMSProperties defaults;

    /**
     * Creates an empty property list with no default values.
     */
    public CMSProperties() {
        this(null);
    }

    /**
     * Creates an empty property list with the specified defaults.
     * 
     * @param defaults the defaults.
     */
    public CMSProperties(CMSProperties defaults) {
        this.defaults = defaults;
    }

    /**
     * Calls the hashtable method <code>put</code>. Provided for parallelism
     * with the <tt>getProperty</tt> method. Enforces use of strings for
     * property keys and values.
     * 
     * @param key the key to be placed into this property list.
     * @param value the value corresponding to <tt>key</tt>.
     * @see #getProperty
     * @since 1.2
     */
    public synchronized Object setProperty(String key, String value) {
        return put(key, value);
    }

    private static final String keyValueSeparators = "=: \t\r\n\f";

    private static final String strictKeyValueSeparators = "=:";

    private static final String specialSaveChars = " \t\r\n\f";

    private static final String whiteSpaceChars = " \t\r\n\f";

    /**
     * Reads a property list (key and element pairs) from the input stream. The
     * stream is assumed to be using the ISO 8859-1 character encoding.
     * <p>
     * Every property occupies one line of the input stream. Each line is
     * terminated by a line terminator (<code>\n</code> or <code>\r</code> or
     * <code>\r\n</code>). Lines from the input stream are processed until end
     * of file is reached on the input stream.
     * <p>
     * A line that contains only whitespace or whose first non-whitespace
     * character is an ASCII <code>#</code> or <code>!</code> is ignored (thus,
     * <code>#</code> or <code>!</code> indicate comment lines).
     * <p>
     * Every line other than a blank line or a comment line describes one
     * property to be added to the table (except that if a line ends with \,
     * then the following line, if it exists, is treated as a continuation line,
     * as described below). The key consists of all the characters in the line
     * starting with the first non-whitespace character and up to, but not
     * including, the first ASCII <code>=</code>, <code>:</code>, or whitespace
     * character. All of the key termination characters may be included in the
     * key by preceding them with a \. Any whitespace after the key is skipped;
     * if the first non-whitespace character after the key is <code>=</code> or
     * <code>:</code>, then it is ignored and any whitespace characters after it
     * are also skipped. All remaining characters on the line become part of the
     * associated element string. Within the element string, the ASCII escape
     * sequences <code>\t</code>, <code>\n</code>, <code>\r</code>,
     * <code>\\</code>, <code>\"</code>, <code>\'</code>, <code>\ &#32;</code>
     * &#32;(a backslash and a space), and <code>&#92;u</code><i>xxxx</i> are
     * recognized and converted to single characters. Moreover, if the last
     * character on the line is <code>\</code>, then the next line is treated as
     * a continuation of the current line; the <code>\</code> and line
     * terminator are simply discarded, and any leading whitespace characters on
     * the continuation line are also discarded and are not part of the element
     * string.
     * <p>
     * As an example, each of the following four lines specifies the key
     * <code>"Truth"</code> and the associated element value
     * <code>"Beauty"</code>:
     * <p>
     * 
     * <pre>
     * Truth = Beauty
     * Truth:Beauty
     * Truth			:Beauty
     * </pre>
     * 
     * As another example, the following three lines specify a single property:
     * <p>
     * 
     * <pre>
     * fruits				apple, banana, pear, \
     *                                  cantaloupe, watermelon, \
     *                                  kiwi, mango
     * </pre>
     * 
     * The key is <code>"fruits"</code> and the associated element is:
     * <p>
     * 
     * <pre>
     * &quot;apple, banana, pear, cantaloupe, watermelon,kiwi, mango&quot;
     * </pre>
     * 
     * Note that a space appears before each <code>\</code> so that a space will
     * appear after each comma in the final result; the <code>\</code>, line
     * terminator, and leading whitespace on the continuation line are merely
     * discarded and are <i>not</i> replaced by one or more other characters.
     * <p>
     * As a third example, the line:
     * <p>
     * 
     * <pre>
     * cheeses
     * </pre>
     * 
     * specifies that the key is <code>"cheeses"</code> and the associated
     * element is the empty string.
     * <p>
     * 
     * @param inStream the input stream.
     * @exception IOException if an error occurred when reading from the input
     *                stream.
     */
    public synchronized void load(InputStream inStream) throws IOException {

        BufferedReader in = new BufferedReader(new InputStreamReader(inStream,
                "8859_1"));

        while (true) {
            // Get next line
            String line = in.readLine();

            if (line == null) {
                return;
            }

            if (line.length() > 0) {
                // Continue lines that end in slashes if they are not comments
                char firstChar = line.charAt(0);

                if ((firstChar != '#') && (firstChar != '!')) {
                    while (continueLine(line)) {
                        String nextLine = in.readLine();

                        if (nextLine == null) {
                            nextLine = new String("");
                        }
                        String loppedLine = line
                                .substring(0, line.length() - 1);
                        // Advance beyond whitespace on new line
                        int startIndex = 0;

                        for (startIndex = 0; startIndex < nextLine.length(); startIndex++) {
                            if (whiteSpaceChars.indexOf(nextLine
                                    .charAt(startIndex)) == -1) {
                                break;
                            }
                        }
                        nextLine = nextLine.substring(startIndex,
                                nextLine.length());
                        line = new String(loppedLine + nextLine);
                    }

                    // Find start of key
                    int len = line.length();
                    int keyStart;

                    for (keyStart = 0; keyStart < len; keyStart++) {
                        if (whiteSpaceChars.indexOf(line.charAt(keyStart)) == -1) {
                            break;
                        }
                    }

                    // Blank lines are ignored
                    if (keyStart == len) {
                        continue;
                    }

                    // Find separation between key and value
                    int separatorIndex;

                    for (separatorIndex = keyStart; separatorIndex < len; separatorIndex++) {
                        char currentChar = line.charAt(separatorIndex);

                        if (currentChar == '\\') {
                            separatorIndex++;
                        } else if (keyValueSeparators.indexOf(currentChar) != -1) {
                            break;
                        }
                    }

                    // Skip over whitespace after key if any
                    int valueIndex;

                    for (valueIndex = separatorIndex; valueIndex < len; valueIndex++) {
                        if (whiteSpaceChars.indexOf(line.charAt(valueIndex)) == -1) {
                            break;
                        }
                    }

                    // Skip over one non whitespace key value separators if any
                    if (valueIndex < len) {
                        if (strictKeyValueSeparators.indexOf(line
                                .charAt(valueIndex)) != -1) {
                            valueIndex++;
                        }
                    }

                    // Skip over white space after other separators if any
                    while (valueIndex < len) {
                        if (whiteSpaceChars.indexOf(line.charAt(valueIndex)) == -1) {
                            break;
                        }
                        valueIndex++;
                    }
                    String key = line.substring(keyStart, separatorIndex);
                    String value = (separatorIndex < len) ? line.substring(
                            valueIndex, len) : "";

                    // Convert then store key and value
                    key = loadConvert(key);
                    value = loadConvert(value);
                    put(key, value);
                }
            }
        }
    }

    /*
     * Returns true if the given line is a line that must be appended to the
     * next line
     */
    private boolean continueLine(String line) {
        int slashCount = 0;
        int index = line.length() - 1;

        while ((index >= 0) && (line.charAt(index--) == '\\')) {
            slashCount++;
        }
        return (slashCount % 2 == 1);
    }

    /*
     * Converts encoded &#92;uxxxx to unicode chars and changes special saved
     * chars to their original forms
     */
    private String loadConvert(String theString) {
        char aChar;
        int len = theString.length();
        StringBuffer outBuffer = new StringBuffer(len);

        for (int x = 0; x < len;) {
            aChar = theString.charAt(x++);
            if (aChar == '\\') {
                aChar = theString.charAt(x++);
                if (aChar == 'u') {
                    // Read the xxxx
                    int value = 0;

                    for (int i = 0; i < 4; i++) {
                        aChar = theString.charAt(x++);
                        switch (aChar) {
                        case '0':
                        case '1':
                        case '2':
                        case '3':
                        case '4':
                        case '5':
                        case '6':
                        case '7':
                        case '8':
                        case '9':
                            value = (value << 4) + aChar - '0';
                            break;

                        case 'a':
                        case 'b':
                        case 'c':
                        case 'd':
                        case 'e':
                        case 'f':
                            value = (value << 4) + 10 + aChar - 'a';
                            break;

                        case 'A':
                        case 'B':
                        case 'C':
                        case 'D':
                        case 'E':
                        case 'F':
                            value = (value << 4) + 10 + aChar - 'A';
                            break;

                        default:
                            throw new IllegalArgumentException(
                                    "Malformed \\uxxxx encoding.");
                        }
                    }
                    outBuffer.append((char) value);
                } else {
                    if (aChar == 't') {
                        aChar = '\t';
                    } else if (aChar == 'r') {
                        aChar = '\r';
                    } else if (aChar == 'n') {
                        aChar = '\n';
                    } else if (aChar == 'f') {
                        aChar = '\f';
                    }
                    outBuffer.append(aChar);
                }
            } else {
                outBuffer.append(aChar);
            }
        }
        return outBuffer.toString();
    }

    /*
     * Converts unicodes to encoded &#92;uxxxx and writes out any of the
     * characters in specialSaveChars with a preceding slash
     */
    private String saveConvert(String theString, boolean escapeSpace) {
        int len = theString.length();
        StringBuffer outBuffer = new StringBuffer(len * 2);

        for (int x = 0; x < len; x++) {
            char aChar = theString.charAt(x);

            switch (aChar) {
            case ' ':
                if (x == 0 || escapeSpace) {
                    outBuffer.append('\\');
                }

                outBuffer.append(' ');
                break;

            case '\\':
                outBuffer.append('\\');
                outBuffer.append('\\');
                break;

            case '\t':
                outBuffer.append('\\');
                outBuffer.append('t');
                break;

            case '\n':
                outBuffer.append('\\');
                outBuffer.append('n');
                break;

            case '\r':
                outBuffer.append('\\');
                outBuffer.append('r');
                break;

            case '\f':
                outBuffer.append('\\');
                outBuffer.append('f');
                break;

            default:
                if ((aChar < 0x0020) || (aChar > 0x007e)) {
                    outBuffer.append('\\');
                    outBuffer.append('u');
                    outBuffer.append(toHex((aChar >> 12) & 0xF));
                    outBuffer.append(toHex((aChar >> 8) & 0xF));
                    outBuffer.append(toHex((aChar >> 4) & 0xF));
                    outBuffer.append(toHex(aChar & 0xF));
                } else {
                    if (specialSaveChars.indexOf(aChar) != -1) {
                        outBuffer.append('\\');
                    }
                    outBuffer.append(aChar);
                }
            }
        }
        return outBuffer.toString();
    }

    /**
     * Calls the <code>store(OutputStream out, String header)</code> method and
     * suppresses IOExceptions that were thrown.
     * 
     * @deprecated This method does not throw an IOException if an I/O error
     *             occurs while saving the property list. As of the Java 2
     *             platform v1.2, the preferred way to save a properties list is
     *             via the <code>store(OutputStream out,
     * String header)</code> method.
     * 
     * @param out an output stream.
     * @param header a description of the property list.
     * @exception ClassCastException if this <code>Properties</code> object
     *                contains any keys or values that are not
     *                <code>Strings</code>.
     */
    public synchronized void save(OutputStream out, String header) {
        try {
            store(out, header);
        } catch (IOException e) {
        }
    }

    /**
     * Writes this property list (key and element pairs) in this
     * <code>Properties</code> table to the output stream in a format suitable
     * for loading into a <code>Properties</code> table using the
     * <code>load</code> method. The stream is written using the ISO 8859-1
     * character encoding.
     * <p>
     * Properties from the defaults table of this <code>Properties</code> table
     * (if any) are <i>not</i> written out by this method.
     * <p>
     * If the header argument is not null, then an ASCII <code>#</code>
     * character, the header string, and a line separator are first written to
     * the output stream. Thus, the <code>header</code> can serve as an
     * identifying comment.
     * <p>
     * Next, a comment line is always written, consisting of an ASCII
     * <code>#</code> character, the current date and time (as if produced by
     * the <code>toString</code> method of <code>Date</code> for the current
     * time), and a line separator as generated by the Writer.
     * <p>
     * Then every entry in this <code>Properties</code> table is written out,
     * one per line. For each entry the key string is written, then an ASCII
     * <code>=</code>, then the associated element string. Each character of the
     * element string is examined to see whether it should be rendered as an
     * escape sequence. The ASCII characters <code>\</code>, tab, newline, and
     * carriage return are written as <code>\\</code>, <code>\t</code>,
     * <code>\n</code>, and <code>\r</code>, respectively. Characters less than
     * <code>&#92;u0020</code> and characters greater than
     * <code>&#92;u007E</code> are written as <code>&#92;u</code><i>xxxx</i> for
     * the appropriate hexadecimal value <i>xxxx</i>. Leading space characters,
     * but not embedded or trailing space characters, are written with a
     * preceding <code>\</code>. The key and value characters <code>#</code>,
     * <code>!</code>, <code>=</code>, and <code>:</code> are written with a
     * preceding slash to ensure that they are properly loaded.
     * <p>
     * After the entries have been written, the output stream is flushed. The
     * output stream remains open after this method returns.
     * 
     * @param out an output stream.
     * @param header a description of the property list.
     * @exception IOException if writing this property list to the specified
     *                output stream throws an <tt>IOException</tt>.
     * @exception ClassCastException if this <code>Properties</code> object
     *                contains any keys or values that are not
     *                <code>Strings</code>.
     */
    public synchronized void store(OutputStream out, String header)
            throws IOException {
        BufferedWriter awriter;

        awriter = new BufferedWriter(new OutputStreamWriter(out, "8859_1"));
        if (header != null) {
            writeln(awriter, "#" + header);
        }
        writeln(awriter, "#" + new Date().toString());
        for (Enumeration<String> e = keys(); e.hasMoreElements();) {
            String key = e.nextElement();
            String val = get(key);

            key = saveConvert(key, true);

            /*
             * No need to escape embedded and trailing spaces for value, hence
             * pass false to flag.
             */
            val = saveConvert(val, false);
            writeln(awriter, key + "=" + val);
        }
        awriter.flush();
    }

    private static void writeln(BufferedWriter bw, String s) throws IOException {
        bw.write(s);
        bw.newLine();
    }

    /**
     * Searches for the property with the specified key in this property list.
     * If the key is not found in this property list, the default property list,
     * and its defaults, recursively, are then checked. The method returns
     * <code>null</code> if the property is not found.
     * 
     * @param key the property key.
     * @return the value in this property list with the specified key value.
     * @see #setProperty
     * @see #defaults
     */
    public String getProperty(String key) {
        String oval = super.get(key);
        String sval = (oval instanceof String) ? oval : null;

        return ((sval == null) && (defaults != null)) ? defaults
                .getProperty(key) : sval;
    }

    /**
     * Searches for the property with the specified key in this property list.
     * If the key is not found in this property list, the default property list,
     * and its defaults, recursively, are then checked. The method returns the
     * default value argument if the property is not found.
     * 
     * @param key the hashtable key.
     * @param defaultValue a default value.
     * 
     * @return the value in this property list with the specified key value.
     * @see #setProperty
     * @see #defaults
     */
    public String getProperty(String key, String defaultValue) {
        String val = getProperty(key);

        return (val == null) ? defaultValue : val;
    }

    /**
     * Returns an enumeration of all the keys in this property list, including
     * the keys in the default property list.
     * 
     * @return an enumeration of all the keys in this property list, including
     *         the keys in the default property list.
     * @see java.util.Enumeration
     * @see java.util.Properties#defaults
     */
    public Enumeration<String> propertyNames() {
        Hashtable<String, String> h = new Hashtable<String, String>();

        enumerate(h);
        return h.keys();
    }

    /**
     * Prints this property list out to the specified output stream. This method
     * is useful for debugging.
     * 
     * @param out an output stream.
     */
    public void list(PrintStream out) {
        out.println("-- listing properties --");
        Hashtable<String, String> h = new Hashtable<String, String>();

        enumerate(h);
        for (Enumeration<String> e = h.keys(); e.hasMoreElements();) {
            String key = e.nextElement();
            String val = h.get(key);

            if (val.length() > 40) {
                val = val.substring(0, 37) + "...";
            }
            out.println(key + "=" + val);
        }
    }

    /**
     * Prints this property list out to the specified output stream. This method
     * is useful for debugging.
     * 
     * @param out an output stream.
     * @since JDK1.1
     */

    /*
     * Rather than use an anonymous inner class to share common code, this
     * method is duplicated in order to ensure that a non-1.1 compiler can
     * compile this file.
     */
    public void list(PrintWriter out) {
        out.println("-- listing properties --");
        Hashtable<String, String> h = new Hashtable<String, String>();

        enumerate(h);
        for (Enumeration<String> e = h.keys(); e.hasMoreElements();) {
            String key = e.nextElement();
            String val = h.get(key);

            if (val.length() > 40) {
                val = val.substring(0, 37) + "...";
            }
            out.println(key + "=" + val);
        }
    }

    /**
     * Enumerates all key/value pairs in the specified hastable.
     * 
     * @param h the hashtable
     */
    private synchronized void enumerate(Hashtable<String, String> h) {
        if (defaults != null) {
            defaults.enumerate(h);
        }
        for (Enumeration<String> e = keys(); e.hasMoreElements();) {
            String key = e.nextElement();

            h.put(key, get(key));
        }
    }

    /**
     * Convert a nibble to a hex character
     * 
     * @param nibble the nibble to convert.
     */
    private static char toHex(int nibble) {
        return hexDigit[(nibble & 0xF)];
    }

    /** A table of hex digits */
    private static final char[] hexDigit = { '0', '1', '2', '3', '4', '5', '6',
            '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
}
