/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.acl;

import java.io.File;
import java.io.Reader;
import java.io.Writer;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.StreamTokenizer;
import java.io.IOException;
import java.io.EOFException;
import java.util.Hashtable;
import java.util.Enumeration;

import com.netscape.management.client.util.Debug;

/**
 * FileACL extends the ACL class to manipulate file-based
 * ONE ACLs.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2, 8/18/97
 * @see ACL
 */
public class FileACL extends ACL {
    protected Hashtable auth = new Hashtable();

    protected Reader openACLReader(Object ACLref) throws IOException {
        // The FileACL subclass expects the ACLref
        // parameter to be a File object, representing
        // the location of the file.

        return (new FileReader((File) ACLref));
    }

    protected Writer openACLWriter(Object ACLref) throws IOException {
        // The FileACL subclass expects the ACLref
        // parameter to be a File object, representing
        // the location of the file.

        return (new FileWriter((File) ACLref));
    }

    /**
      * @exception Exception any Exception from the abstract implementation.
      */
    protected void parse(StreamTokenizer st) throws Exception {
        st.quoteChar(QUOTE_CHAR);

        parseHeader(st);
        parseAuthenticateBlock(st);

        try {
            while (true)
                appendRule(st);
        } catch (EOFException eofe) {
            if (!eofe.getMessage().equals("Clean EOF"))
                throw (eofe);
        }
    }

    /**
      * @exception Exception any Exception from the abstract implementation.
      */
    protected void write(Writer w) throws Exception {
        writeHeader(w);
        writeAuthenticateBlock(w);

        for (int i = 0 ; i < rules.size(); i++)
            ((Rule)(rules.elementAt(i))).writeRule(w);
    }

    /**
      * Returns a Hashtable of the name = value attributes
      * from the ACL authenticate block.
      *
      * @return Hashtable of name = value pairs.
      */
    public Hashtable getAuthAttributes() {
        return auth;
    }

    /**
      * Parses the ACL authentication block.
      *
      * @param st the StreamTokenizer for the ACL.
      */
    protected void parseAuthenticateBlock(StreamTokenizer st)
            throws IOException {
        int tokentype;
        String name = null;
        String value = null;
        boolean outside = true;

        Debug.println("FileACL.parseAuthenticationBlock: Parsing ACL Authenticate Block.");

        while ((tokentype = st.nextToken()) != StreamTokenizer.TT_EOF) {
            switch (tokentype) {
            case StreamTokenizer.TT_WORD:
                if (outside)
                    break;
                name = st.sval;
                break;

            case '{':
                if (!outside)
                    throw new IOException("Unrecognized token in ACL authentication header");
                outside = false;
                break;

            case '}':
                if (outside)
                    throw new IOException("Unrecognized token in ACL authentication header");
                outside = true;
                break;

            case '=':
            case ',':
            case '(':
            case ')':
                break;

            case ';':
                if (outside)
                    return;

                if ((name == null) || (value == null))
                    throw new IOException("Unrecognized token in ACL authentication header");

                Debug.println("FileACL.parseAuthenticationBlock:"+
                        name + " = " + value);

                auth.put(name, value);
                name = null;
                value = null;
                break;

            case QUOTE_CHAR:
                value = st.sval;
                break;

            default:
                throw new IOException("Unrecognized token in ACL authentication header");
            }
        }

        throw new EOFException("Unexpected EOF while parsing ACL authentication header");
    }

    /**
      * Writes the ACL resource string, and the ACL name
      * header.
      *
      * @param w the Writer for the destination ACL
      */
    protected void writeHeader(Writer w) throws IOException {
        w.write("version " + version + ";\n");
        w.write("acl \"" + resource + "\";\n");
    }

    /**
      * Writes the ACL authenticate block.
      *
      * @param w the Writer for the destination ACL
      */
    protected void writeAuthenticateBlock(Writer w) throws IOException {
        w.write("authenticate (user,group) {\n");

        for (Enumeration e = auth.keys(); e.hasMoreElements();) {
            String name = (String)(e.nextElement());
            String value = (String)(auth.get(name));

            w.write("\t" + name + " = \"" + value + "\";\n");
        }

        w.write("};\n");
    }

    /**
      * Returns a String representation of this ACL.
      *
      * @return a String representation of this ACL.
      */
    public String toString() {
        String s = "-----------------------------------------------" +
                '\n' + "ACL Header:     " + resource + '\n' +
                "ACL Auth Block: " + auth + '\n' + '\n';

        for (int i = 0 ; i < rules.size(); i++) {
            s += "Rule: " + i + '\n';
            s += rules.elementAt(i).toString();
            s += '\n';
        }

        s += "-----------------------------------------------" + '\n';
        return s;
    }
}
