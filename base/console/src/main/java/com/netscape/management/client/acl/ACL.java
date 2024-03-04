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

import java.util.Vector;
import java.io.Reader;
import java.io.Writer;
import java.io.StringWriter;
import java.io.StreamTokenizer;
import java.io.IOException;
import java.io.EOFException;

import com.netscape.management.client.util.Debug;

/**
 * The ACL abstract class defines the necessary operations that
 * any ACL object must implement to be recognized and manipulated
 * by the ACL editor.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2, 8/18/97
 * @see Task
 */
public abstract class ACL {
    public static final int QUOTE_CHAR = '"';

    protected String resource = null;
    protected String version = null;
    protected Vector rules = new Vector();
    protected String syntax = null;

    /**
     * Retrieve the content of the specified ACL from some
     * repository, and parse it.
     *
     * @param ACLref an implementation specific reference to the
     *  ACL to be retrieved.
     */
    public void retrieveACL(Object ACLref) {
        try {
            Reader r = openACLReader(ACLref);

            if (r == null) {
                setDefaults();
                return;
            }

            StreamTokenizer st = new StreamTokenizer(r);

            parse(st);
            r.close();
        } catch (Exception e) {
            System.err.println("ACL:retrieveACL():" + e);
            setDefaults();
        }
    }

    /**
      * Used to copy the contents of acl into this.
      *
      * @param acl the source ACL, whose contents are copied into this ACL.
      */
    protected void copy(ACL acl) {
        resource = acl.resource;
        version = acl.version;
        rules = acl.rules;
        syntax = acl.syntax;
    }

    /**
      * Update the ACL contents in some repository to reflect
      * changes, if any.
      *
      * @param ACLref an implementation specific reference to the
      *  ACL to be updated.
      * @exception Exception any Exception from the abstract implementation.
      */
    public void updateACL(Object ACLref) throws Exception {
        Writer w = openACLWriter(ACLref);

        if (!syntaxOverrideSet()) {
            if (rules.size() > 0)
                write(w);
        } else
            w.write(syntax);

        w.close();
    }

    /**
      * Returns the resource string from the acl
      * header.
      *
      * @return the resource String.
      */
    public String getResourceString() {
        return resource;
    }

    /**
      * Sets the resource string for the acl
      * header.
      *
      * @param s the new resource String.
      */
    public void setResourceString(String s) {
        resource = s;
    }

    /**
      * Returns the current rule count of the ACL.
      *
      * @return current rule count.
      */
    public int getRuleCount() {
        return rules.size();
    }

    /**
      * Creates a new Rule.
      *
      * @param r a Reader for the rule.
      * @return a new Rule, parsed from the StreamTokenizer.
      * @exception Exception any Exception from the abstract implementation.
      */
    public Rule newRule(StreamTokenizer st) throws Exception {
        return new Rule(st);
    }

    /**
      * Creates a new Rule.
      *
      * @return a new Rule, with no initial contents.
      */
    public Rule newRule() {
        return new Rule();
    }

    /**
      * Append a new rule to the end of the current ACL, with default values
      * populated.
      *
      */
    public void appendRule() {
        rules.addElement(newRule());
    }

    /**
      * Append a new rule to the end of the current ACL, parsed from the Reader.
      *
      * @param st the StreamTokenizer for the ACL content.
      * @exception Exception any Exception from the abstract implementation.
      */
    public void appendRule(StreamTokenizer st) throws Exception {
        rules.addElement(newRule(st));
    }

    /**
      * Insert a new rule before the specified rule.
      *
      * @param beforeRule the rule before which the new rule is inserted.
      */
    public void insertRule(int beforeRule) {
        rules.insertElementAt(newRule(), beforeRule);
    }

    /**
      * Delete the specified rule.
      *
      * @param rule the rule number to be deleted
      */
    public void deleteRule(int rule) {
        rules.removeElementAt(rule);
    }

    /**
      * Swap the positions of the specified rules.
      *
      */
    public void swapRules(int rule1, int rule2) {
        Object r1 = rules.elementAt(rule1);
        Object r2 = rules.elementAt(rule2);

        rules.setElementAt(r1, rule2);
        rules.setElementAt(r2, rule1);
    }

    /**
       * Get the Rule object for the numbered rule.
       *
       * @param rule the rule number.
       */
    public Rule getRule(int rule) {
        return ((Rule)(rules.elementAt(rule)));
    }

    /**
      * Returns a String representation of the
      * ACL syntax.
      *
      * @return ACL syntax String.
      */
    public String getSyntax() {
        if (syntax != null)
            return syntax;

        StringWriter sw = new StringWriter();
        try {
            write(sw);
            sw.close();
        } catch (Exception e) { }
        return sw.toString();
    }

    /**
      * Sets the String representation of the
      * ACL content, overriding the contents
      * of the discrete storage objects.
      *
      * @param s the new expression String.
      */
    public void setSyntax(String s) {
        syntax = s;
    }

    /**
      * Sets the String representation of the
      * ACL content, overriding the contents
      * of the discrete storage objects.
      *
      * @param s the new expression String.
      */
    public void setSyntaxOverride(String s) {
        syntax = s;
    }

    /**
      * Returns true if the ACL content has been
      * overridden by a call to setSyntax().
      *
      * @return true if overridden, false otherwise.
      */
    public boolean syntaxOverrideSet() {
        return (syntax != null);
    }

    /**
      * Clears the overriding value of the ACL
      * content, set by a call to setSyntax().
      *
      */
    public void clearSyntaxOverride() {
        syntax = null;
    }

    /**
      * Returns a String representation of this ACL.
      *
      * @return a String representation of this ACL.
      */
    public String toString() {
        String s = "-----------------------------------------------" + '\n';

        for (int i = 0 ; i < rules.size(); i++) {
            s += "Rule: " + i + '\n';
            s += rules.elementAt(i).toString();
            s += '\n';
        }

        s += "-----------------------------------------------" + '\n';
        return s;
    }

    /**
      * Parses the ACL resource string, and the ACL name
      * header.
      *
      * @param st the StreamTokenizer for the ACL.
      */
    protected void parseHeader(StreamTokenizer st) throws IOException {
        int tokentype;

        Debug.println("ACL.parseHeader: Parsing ACL Header.");

        while ((tokentype = st.nextToken()) != StreamTokenizer.TT_EOF) {
            switch (tokentype) {
            case StreamTokenizer.TT_WORD:
                if (st.sval.equals("acl"))
                    break;
                if (st.sval.equals("version"))
                    break;
                if (st.sval.equals("allow") || st.sval.equals("deny") ||
                        st.sval.equals("authenticate")) {
                    st.pushBack();
                    if (resource != null)
                        return;
                    throw new IOException("Resource string not found in ACL header");
                }
                throw new IOException(
                        "Unrecognized token in ACL resource header (" +
                        st.sval + ")");

            case StreamTokenizer.TT_NUMBER:
                Debug.println("ACL.parseHeader: Version = " + st.nval);
                version = Double.toString(st.nval);
                break;

            case ';':
                break;

            case QUOTE_CHAR:
                Debug.println("ACL.parseHeader: Resource = " + st.sval);
                resource = st.sval;
                break;

            default:
                throw new IOException("Unrecognized token in ACL resource header");
            }
        }

        throw new EOFException("Unexpected EOF while parsing ACL resource header");
    }

    /**
      * Called by retrieveACL() to create a Reader object
      * for the ACL content. The underlying implementation of
      * this function needs to be subclassed.
      *
      * @param ACLref an implementation specific reference to the
      *  ACL to be retrieved.
      * @exception Exception any Exception from the abstract implementation.
      * @return a Reader to the ACL content, or null if content unavailable.
      */
    protected abstract Reader openACLReader(Object ACLref) throws Exception;

    /**
     * Called by updateACL() to create a Writer object
     * for the ACL destination. The underlying implementation of
     * this function needs to be subclassed.
     *
     * @param ACLref an implementation specific reference to the
     *  ACL to be updated.
     * @exception Exception any Exception from the abstract implementation.
     */
    protected abstract Writer openACLWriter(Object ACLref) throws Exception;

    /**
     * Called by retrieveACL() to parse the ACL.
     * The underlying implementation of this function needs to be subclassed.
     *
     * @param r a Reader for the ACL contents.
     * @exception Exception any Exception from the abstract implementation.
     */
    protected abstract void parse(StreamTokenizer r) throws Exception;

    /**
     * Called by updateACL() to write the ACL.
     * The underlying implementation of this function needs to be subclassed.
     *
     * @param w a Writer for the ACL contents.
     * @exception Exception any Exception from the abstract implementation.
     */
    protected abstract void write(Writer r) throws Exception;

    protected void setDefaults() {
        resource = "unknown";
        version = "3.0";
        appendRule();
    }
}
