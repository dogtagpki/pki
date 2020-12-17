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
package com.netscape.cmsutil.password;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Vector;

public class PlainPasswordFile implements IPasswordStore {
    private String mPwdPath = "";
    private Properties mPwdStore;
    private String id;

    private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PlainPasswordFile.class);

    public PlainPasswordFile() {
        mPwdStore = new Properties();
    }

    /**
     * Initialization method to read passwords(key and element pairs) from a file.
     * <p>
     * Every property occupies one line of the input stream. Each line is terminated by a line terminator (
     * <code>\n</code> or <code>\r</code> or <code>\r\n</code>). Lines are processed until end of
     * file is reached.
     * <p>
     * A line that contains only whitespace or whose first non-whitespace character is an ASCII <code>#</code>
     * is ignored (thus, <code>#</code> indicates comment line).
     * <p>
     * Every line other than a blank line or a comment line describes one property to be added to the table.
     * The characters before the delimiter <code>=</code> forms the <code>key</code> and the characters after
     * the <code>=</code> is assigned as <code>value</code> to the key.
     * <p>
     * As an example, each of the following lines specify the key <code>"Truth"</code> and the associated element
     * value <code>"Beauty"</code>:
     * <p>
     *
     * <pre>
     * Truth = Beauty
     * Truth= Beauty
     * Truth                    =Beauty
     * </pre>
     *
     * <p>
     * Note that the space appearing before/after <code>=</code> is ignored. However, the space appearing in between are
     * stored.
     * <p>
     * Example:
     *
     * <pre>
     * Welcome Message  = Hello World
     * </pre>
     *
     * assigns value <code>Hello World</code> to key <code>Welcome Message</code>
     * <p>
     *
     * If the line doesn't have the delimiter <code>=</code>, the method throws an IOException
     *
     * @param pwdPath the input file path.
     * @exception IOException if an error occurred when reading from the
     *                input stream.
     */
    public void init(String pwdPath) throws IOException {

        logger.debug("PlainPasswordFile: Initializing PlainPasswordFile");

        // initialize mPwdStore
        mPwdPath = pwdPath;

        try (FileInputStream file = new FileInputStream(mPwdPath);
                InputStreamReader isr = new InputStreamReader(file);
                BufferedReader br = new BufferedReader(isr)) {

            String line;
            int index = 1;
            while ((line = br.readLine()) != null) {
                // Remove any leading or trailing spaces
                line = line.trim();

                if (line.startsWith("#") || line.isEmpty())
                    continue;

                String[] parts = line.split("=", 2);
                if (parts.length < 2) {
                    throw new IOException("Missing delimiter '=' in file " + mPwdPath + " in line " + index);
                }

                String name = parts[0].trim();
                String value = parts[1].trim();
                logger.debug("PlainPasswordFile: - " + name + ": ********");

                mPwdStore.put(name, value);
                index++;
            }
        }
    }

    public String getPassword(String tag, int iteration) {
        return mPwdStore.getProperty(tag);
    }

    // return an array of String-based tag
    public Enumeration<String> getTags() {
        Enumeration<?> e = mPwdStore.propertyNames();
        Vector<String> v = new Vector<String>();
        while (e.hasMoreElements()) {
            v.add((String) e.nextElement());
        }
        return v.elements();
    }

    public Object putPassword(String tag, String password) {
        return mPwdStore.setProperty(tag, password);
    }

    public synchronized void commit()
            throws IOException, ClassCastException, NullPointerException {
        try (FileOutputStream file = new FileOutputStream(mPwdPath);
                OutputStreamWriter osw = new OutputStreamWriter(file);
                BufferedWriter bw = new BufferedWriter(osw)) {

            for (Enumeration<?> e = mPwdStore.keys(); e.hasMoreElements();) {
                String key = ((String) e.nextElement()).trim();
                String val = ((String) mPwdStore.get(key)).trim();
                bw.write(key + "=" + val);
                bw.newLine();
            }
        }

    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public int getSize() {
        return mPwdStore.size();
    }
}
