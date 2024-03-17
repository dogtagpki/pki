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

import java.util.Hashtable;
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.io.Writer;
import java.io.StreamTokenizer;
import java.io.IOException;
import java.io.EOFException;
import java.io.StringWriter;

import com.netscape.management.client.util.Debug;

/**
 * The Rule class defines the necessary operations that
 * any ACL entry object must implement to be recognized
 * and manipulated by the ACL editor, within the context
 * of an ACL.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2, 8/18/97
 * @see ACL
 */
public class Rule extends Object {
    public static final int QUOTE_CHAR = '"';

    protected boolean allow = true;
    protected boolean absolute = false;
    protected AttributeList rights = new AttributeList();
    protected Hashtable attr = new Hashtable();
    protected String syntax = null;

    /**
     * Create a new Rule, using default values.
     *
     */
    public Rule() {
        setDefaults();
    }

    /**
      * Create a new Rule, parsing the contents from the StreamTokenizer
      * parameter.
      *
      * @param st a valid open StreamTokenizer.
      *
      */
    public Rule(StreamTokenizer st) throws IOException {
        parseRule(st);
    }

    /**
      * Set the default values for the rule.
      *
      */
    protected void setDefaults() {
        setRight("all");
        setAttribute("user", "any");
        setAttribute("dns", "any");
    }

    /**
      * Parse the rule from the source ACL via the Reader.
      *
      * @param r a valid open Reader.
      */
    protected void parseRule(StreamTokenizer st) throws IOException {
        st.quoteChar(QUOTE_CHAR);

        parseAllow(st);
        parseAbsolute(st);
        parseRights(st);
        parseBody(st);
    }

    /**
      * Write the rule to the destination ACL via the Writer.
      *
      * @param w a valid open Writer.
      */
    public void writeRule(Writer w) throws IOException {
        if (attr.size() == 0)
            return;

        writeHeader(w);
        writeContent(w);
    }

    /**
      * Get the current value of the allow/deny syntax
      * component of the rule.
      *
      * @return boolean value, true for allow, false for deny.
      */
    public boolean getAllow() {
        return allow;
    }

    /**
      * Set the current value of the allow/deny syntax
      * component of the rule.
      *
      * @param value the boolean value, true for allow, false for deny.
      */
    public void setAllow(boolean value) {
        allow = value;
    }

    /**
      * Toggle the current value of the allow/deny syntax
      * component of the rule.
      *
      */
    public void toggleAllow() {
        allow = !allow;
    }

    /**
      * Get the current value of the absolute syntax
      * component of the rule.
      *
      * @return boolean value, true for absolute, false for continue.
      */
    public boolean getAbsolute() {
        return absolute;
    }

    /**
      * Set the current value of the absolute syntax
      * component of the rule.
      *
      * @param value the boolean value, true for absolute, false for continue.
      */
    public void setAbsolute(boolean value) {
        absolute = value;
    }

    /**
      * Adds value to the list of rights.
      *
      * @param value the value to be added.
      */
    public void setRight(String value) {
        rights.setAttribute(value);
    }

    /**
      * Removes value from the list of rights.
      *
      * @param value the value to be removed.
      */
    public void unSetRight(String value) {
        rights.removeAttribute(value);
    }

    /**
      * Returns the AttributeList of rights.
      *
      * @return the AttributeList of rights.
      */
    public AttributeList getRightsList() {
        return rights;
    }

    /**
      * Adds value to the valuelist for the name attribute.
      *
      * @param name the attribute name.
      * @param value the value to be added to name's valuelist.
      */
    public void setAttribute(String name, String value) {
        AttributeList attrlist = getAttributeList(name);

        if (attrlist == null)
            setAttributeList(name, attrlist = new AttributeList());

        attrlist.setAttribute(value);
    }

    /**
      * Adds value to the valuelist for the name attribute, and sets the
      * comparator operator for the value.
      *
      * @param name the attribute name.
      * @param value the value to be added to name's valuelist.
      * @param operator the comparator for the attribute (=, !=, <, etc...).
      */
    public void setAttribute(String name, String value, String operator) {
        AttributeList attrlist = getAttributeList(name);

        if (attrlist == null)
            setAttributeList(name, attrlist = new AttributeList());

        attrlist.setAttribute(value, operator);
    }

    /**
      * Removes value from the valuelist for the name attribute.
      *
      * @param name the attribute name.
      * @param value the value to be to removed from name's valuelist.
      */
    public void unSetAttribute(String name, String value) {
        AttributeList attrlist = getAttributeList(name);

        if (attrlist == null)
            return;

        attrlist.removeAttribute(value);
        if (attrlist.size() == 0)
            removeAttributeList(name);
    }

    /**
      * Returns the AttributeList for the
      * named attribute.
      *
      * @param name the attribute name.
      * @return the AttributeList for the name attribute.
      */
    public AttributeList getAttributeList(String name) {
        return (AttributeList)(attr.get(name));
    }

    /**
      * Sets the AttributeList for the
      * named attribute.
      *
      * @param name the attribute name.
      * @param list the AttributeList value list.
      */
    public void setAttributeList(String name, AttributeList list) {
        attr.put(name, list);
    }

    /**
      * Removes the AttributeList for the
      * named attribute.
      *
      * @param name the attribute name.
      */
    public void removeAttributeList(String name) {
        attr.remove(name);
    }

    /**
      * Updates the Attributelist for the named attribute, removing if
      * necessary.
      *
      * @param name the attribute name.
      * @param list the new AttributeList value list.
      */
    public void updateAttributeList(String name, AttributeList list) {
        AttributeList olddata = getAttributeList(name);

        if (olddata != null) {
            olddata.removeAll();
            removeAttributeList(name);
        }

        if (list.size() > 0)
            setAttributeList(name, list);
    }

    /**
      * Returns a String representation of the
      * ACL rule content, created from
      * the syntax of the specified ACL rule.
      *
      * @return expression String.
      */
    public String getSyntax() {
        StringWriter sw = new StringWriter();
        try {
            writeContent(sw);
            sw.close();
        } catch (IOException ioe) { }
        return sw.toString();
    }

    /**
      * Sets the String representation of the
      * ACL rule content, overriding the contents
      * of the discrete storage objects.
      *
      * @param s the new expression String.
      */
    public void setSyntax(String s) {
        syntax = s;
    }

    /**
      * Returns true if the ACL rule content has been
      * overridden by a call to setScript().
      *
      * @return true if overridden, false otherwise.
      */
    public boolean syntaxOverrideSet() {
        return (syntax != null);
    }

    /**
      * Parses the allow/deny component of the syntax.
      *
      * @param st the StreamTokenizer for the ACL.
      *
      */
    protected void parseAllow(StreamTokenizer st) throws IOException {
        int tokentype;

        Debug.println("Rule.parseAllow: Parsing Rule Allow.");

        tokentype = st.nextToken();

        switch (tokentype) {
        case StreamTokenizer.TT_WORD:
            if (st.sval.equals("allow")) {
                Debug.println("Rule.parseAllow: allow set");
                allow = true;
                return;
            }
            if (st.sval.equals("deny")) {
                Debug.println("Rule.parseAllow: deny set");
                allow = false;
                return;
            }

        default:
            throw new IOException("Unrecognized token in ACL rule allow/deny");

        case StreamTokenizer.TT_EOF:
        case ')': // for LDAP value termination
            Debug.println("Rule.parseAllow: Clean EOF");
            throw new EOFException("Clean EOF");
        }
    }

    /**
      * Parses the absolute component of the snytax.
      *
      * @param st the StreamTokenizer for the ACL.
      */
    protected void parseAbsolute(StreamTokenizer st) throws IOException {
        int tokentype;

        Debug.println("Rule.parseAbsolute: Parsing Rule Absolute.");

        tokentype = st.nextToken();

        switch (tokentype) {
        case '(':
            Debug.println("Rule.parseAbsolute: absolute not set");
            absolute = false;
            st.pushBack();
            return;

        case StreamTokenizer.TT_WORD:
            if (st.sval.equals("absolute")) {
                Debug.println("Rule.parseAbsolute: absolute set");
                absolute = true;
                return;
            }

        default:
            throw new IOException("Unrecognized token in ACL rule absolute");

        case StreamTokenizer.TT_EOF:
            throw new EOFException("Unexpected EOF while parsing ACL rule absolute");
        }
    }

    /**
      * Parses the rights of the rule.
      *
      * @param st the StreamTokenizer for the ACL.
      */
    protected void parseRights(StreamTokenizer st) throws IOException {
        int tokentype;

        Debug.println("Rule.parseAbsolute: Parsing Rule Rights.");

        while ((tokentype = st.nextToken()) != StreamTokenizer.TT_EOF) {
            switch (tokentype) {
            case '(':
            case ',':
            case '|':
                break;

            case ')':
                if (rights.size() != 0)
                    return;
                throw new IOException("No rights specified in ACL rule");

            case StreamTokenizer.TT_WORD:
                Debug.println("right: " + st.sval);
                setRight(st.sval);
                break;

            default:
                throw new IOException("Unrecognized token in ACL rule rights");
            }
        }

        throw new EOFException("Unexpected EOF while parsing ACL rule rights");
    }

    /**
      * Parses the body of the rule.
      *
      * @param st the StreamTokenizer for the ACL.
      */
    protected void parseBody(StreamTokenizer st) throws IOException {
        int tokentype;
        String name = null;
        StringBuffer op = new StringBuffer();

        Debug.println("Rule.parseBody: Parsing Rule Body.");

        while ((tokentype = st.nextToken()) != StreamTokenizer.TT_EOF) {
            switch (tokentype) {
            case '(':
            case ')':
                break;

            case '=':
            case '!':
            case '>':
            case '<':
                op.append((char) tokentype);
                break;

            case StreamTokenizer.TT_WORD:

                if (st.sval.equalsIgnoreCase("and") ||
                        st.sval.equalsIgnoreCase("or") ||
                        st.sval.equalsIgnoreCase("not"))
                    break;

                name = st.sval;
                Debug.print("Rule.parseBody: " + name);
                break;

            case ';':
                return;

            case QUOTE_CHAR:

                StringTokenizer sgt = new StringTokenizer(st.sval, "|");
                while (sgt.hasMoreTokens())
                    setAttribute(name, sgt.nextToken(), op.toString());

                Debug.println("Rule.parseBody: " + op.toString() +
                        " " + st.sval);

                name = null;
                op = new StringBuffer();
                break;

            default:
                throw new IOException("Unrecognized token in ACL rule body");
            }
        }

        throw new EOFException("Unexpected EOF while parsing ACL rule body");
    }

    /**
      * Write the rule header to the destination ACL via the Writer
      *
      * @param w a valid open Writer.
      *
      */
    protected void writeHeader(Writer w) throws IOException {
        w.write((allow ? "allow" : "deny") +
                (absolute ? " absolute " : " "));

        w.write("(" + rights.generateList(",") + ")" + newLine());
    }

    /**
      * Write the rule content to the destination ACL via the Writer
      *
      * @param w a valid open Writer.
      *
      */
    protected void writeContent(Writer w) throws IOException {
        if (syntaxOverrideSet()) {
            w.write(syntax + newLine());
            return;
        }

        if (attr.size() == 0)
            return;

        Enumeration e = attr.keys();

        while (true) {
            String key = (String)(e.nextElement());

            w.write(indent() +
                    getAttributeList(key).generateExpression(key));

            if (!e.hasMoreElements()) {
                w.write(";" + newLine());
                return;
            }

            w.write(" or" + newLine());
        }
    }

    public String toString() {
        StringWriter sw = new StringWriter();
        try {
            writeRule(sw);
            sw.close();
        } catch (IOException ioe) { }
        return sw.toString();
    }

    protected String newLine() {
        return "\n";
    }
    protected String indent() {
        return "\t";
    }
}
