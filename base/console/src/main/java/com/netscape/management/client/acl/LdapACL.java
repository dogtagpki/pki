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

import java.io.Reader;
import java.io.Writer;
import java.io.StringReader;
import java.io.StreamTokenizer;
import java.io.IOException;
import java.io.EOFException;
import java.util.Enumeration;

import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPAttributeSet;

import com.netscape.management.client.util.KingpinLDAPConnection;
import com.netscape.management.client.util.LDAPUtil;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.UtilConsoleGlobals;

class booleanValue {
    boolean val;

    protected booleanValue(boolean v) {
        val = v;
    }
    protected void setValue(boolean v) {
        val = v;
    }
    protected boolean getValue() {
        return val;
    }
}

/**
  * LdapACL extends the ACL class to manipulate directory server
  * resident ONE ACLs, accessed via LDAP.
  *
  * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
  * @version 0.2, 8/25/97
  * @see ACL
  */
public class LdapACL extends ACL {
    public static final int QUOTE_CHAR = '"';

    public static final String LDAPPrefix = "ldap:///";
    public static final String TargetName = "target";
    public static final String AttributeName = "targetattr";
    public static final String FilterName = "targetfilter";
    public static final String ACIAttributeName = "aci";
    public static final String SASLAttributeName = "supportedsaslmechanisms";
    public static final String SASLNameBase = "SASL ";

    protected String host;
    protected int port;
    protected boolean ssl;    
    protected String dn;
    protected String pw;

    protected LdapACLSelector valueSelector = null;

    protected boolean entryFound = false;
    protected String oldValue = null;
    protected String entryDN = null;

    protected String target = null;
    protected booleanValue targetEq = new booleanValue(true);
    protected String targetAttr = null;
    protected booleanValue targetAttrEq = new booleanValue(true);
    protected String targetFilter = null;
    protected booleanValue targetFilterEq = new booleanValue(true);

    protected void copy(ACL acl) {
        super.copy(acl);

        LdapACL lacl = (LdapACL) acl;
        host = lacl.host;
        port = lacl.port;
        ssl  = lacl.ssl;        
        dn = lacl.dn;
        pw = lacl.pw;
        valueSelector = lacl.valueSelector;
        entryFound = lacl.entryFound;
        oldValue = lacl.oldValue;
        entryDN = lacl.entryDN;
        target = lacl.target;
        targetEq = lacl.targetEq;
        targetAttr = lacl.targetAttr;
        targetAttrEq = lacl.targetAttrEq;
        targetFilter = lacl.targetFilter;
        targetFilterEq = lacl.targetFilterEq;
    }

    public LdapACL(String _host, int _port, String _dn, String _pw) {
        this(_host, _port, false, _dn, _pw, null);
    }

    public LdapACL(String _host, int _port, boolean _ssl, String _dn, String _pw) {
        this(_host, _port, _ssl, _dn, _pw, null);
    }

    public LdapACL(String _host, int _port, String _dn, String _pw,
            LdapACLSelector las) {
        this(_host, _port, false, _dn, _pw, las);
    }

    public LdapACL(String _host, int _port, boolean _ssl ,String _dn, String _pw,
            LdapACLSelector las) {
        host = _host;
        port = _port;
        ssl  = _ssl;
        dn = _dn;
        pw = _pw;

        valueSelector = las;
    }

    public LdapACL(LdapACL acl) {
        this(acl.host, acl.port, acl.ssl, acl.dn, acl.pw, acl.valueSelector);

        entryFound = acl.entryFound;
        oldValue = acl.oldValue;
        entryDN = acl.entryDN;
    }

    protected LDAPConnection newConnection() throws LDAPException {
        LDAPConnection ldc = null;
        if (ssl) {
            ldc=new KingpinLDAPConnection(
			   UtilConsoleGlobals.getLDAPSSLSocketFactory(), 
			   dn, 
			   pw);

        } else {
            ldc=new KingpinLDAPConnection(dn, pw);
        }
        ldc.connect(LDAPUtil.LDAP_VERSION, host, port, dn, pw);
        return ldc;        
    }

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
            System.err.println("LdapACL:retrieveACL():" + e);
            if (valueSelector != null)
                valueSelector.error(this, e);
            setDefaults();
        }
    }

    /**
      * Opens the LDAP connection, retrieves the aci attribute from the
      * entry, and returns a Reader to the buffered aci.
      *
      # @param ACLref the DN of the entry from which the aci is to retrieved.
      * @exception IOException from the LDAP java SDK.
      * @exception netscape.ldap.LDAPException from the LDAP java SDK.
      */
    protected Reader openACLReader(Object ACLref) throws IOException,
    LDAPException {
        // The LdapACL implementation expects the ACLref object to be the
        // dn of an entry. The ACL will be retrieved from the aci attribute of
        // this entry.

        entryDN = (String) ACLref;

        LDAPConnection ldc = newConnection();

        Debug.println("LdapACL:openACLReader():connected to " + host +
                ":" + port);

        try {
            LDAPEntry entry = ldc.read(entryDN);

            if (entry == null) {
                Debug.println("LdapACL:openACLReader():entry not found");
                if (valueSelector != null)
                    valueSelector.select(this, null);
                return null;
            }

            LDAPAttributeSet attr = entry.getAttributeSet();

            if (attr.size() == 0) {
                Debug.println("LdapACL:openACLReader():aci attribute not found");
                if (valueSelector != null)
                    valueSelector.select(this, null);
                return null;
            }

            LDAPAttribute acl = attr.getAttribute(ACIAttributeName);

            if (acl == null) {
                Debug.println("LdapACL:openACLReader():aci attribute not found");
                if (valueSelector != null)
                    valueSelector.select(this, null);
                return null;
            }

            if (acl.size() == 0) {
                Debug.println("LdapACL:openACLReader():aci attribute not found");
                if (valueSelector != null)
                    valueSelector.select(this, null);
                return null;
            }

            Enumeration e = acl.getStringValues();

            if (valueSelector != null) {
                Debug.println("LdapACL:openACLReader():calling LdapACLSelector for multi-valued aci");

                String val = valueSelector.select(this, e);

                if (val == null) {
                    Debug.println("LdapACL:openACLReader():create new acl value (no aci selected)");
                    return null;
                }

                oldValue = val;
            } else {
                Debug.println("LdapACL:openACLReader():no LdapACLSelector, using first value of multi-value aci");
                oldValue = (String)(e.nextElement()); // DT 3/15/98 If no valueSelector is passed, we use the first value.
            }

            Debug.println("LdapACL.aci: " + oldValue);

            entryFound = true;

            return new StringReader(oldValue);
        }
        finally { if (ldc != null && ldc.isConnected()) {
                try {
                    ldc.disconnect();
                } catch (Exception e) {}
            }
        } }

    protected Writer openACLWriter(Object ACLref) throws IOException {
        return new LdapWriter(this, ACLref);
    }

    protected void setDefaults() {
        super.setDefaults();

        if (entryDN != null)
            setTarget(LDAPPrefix + entryDN);
        setTargetAttributes("*");
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
      * Sets the String representation of the
      * ACL content, overriding the contents
      * of the discrete storage objects.
      *
      * @param s the new expression String.
      */
    public void setSyntax(String s) {
        try {
            LdapACL acl = new LdapACL(this);
            acl.parse(new StreamTokenizer(new StringReader(s)));
            copy(acl);
            return;
        } catch (Exception e) {
            Debug.println(
                    "LdapACL:setSyntax():invalid ACL syntax, using override:" + e);
            syntax = s;
            return;
        }
    }

    /**
      * @exception Exception any Exception from the abstract implementation.
      */
    protected void parse(StreamTokenizer st) throws Exception {
        int tokentype;

        st.quoteChar(QUOTE_CHAR);
        st.ordinaryChar('/');

        while ((tokentype = st.nextToken()) != StreamTokenizer.TT_EOF) {
            switch (tokentype) {
            case '(':
                Debug.println("Token type '('");
                break;

            case StreamTokenizer.TT_WORD:
                Debug.println("Token type TT_WORD, sval = " + st.sval);
                if (st.sval.equals(TargetName)) {
                    target = parseValue(st, targetEq);
                    Debug.println("target = " + target);
                    break;
                }
                if (st.sval.equals(AttributeName)) {
                    targetAttr = parseValue(st, targetAttrEq);
                    Debug.println("targetAttr = " + targetAttr);
                    break;
                }
                if (st.sval.equals(FilterName)) {
                    targetFilter = parseValue(st, targetFilterEq);
                    Debug.println("targetFilter = " + targetFilter);
                    break;
                }
                if (st.sval.equals("version")) {
                    parseHeader(st);
                    try {
                        while (true)
                            appendRule(st);
                    } catch (EOFException eofe) {
                        if (!eofe.getMessage().equals("Clean EOF"))
                            throw (eofe);
                    }
                    break;
                }

            default:
                throw new IOException("Unrecognized token in ACL resource header");
            }
        }
    }

    protected String parseValue(StreamTokenizer st,
            booleanValue eq) throws IOException {
        // return everything to the right of the first =, up to the closing ).

        int tokentype;

        String s = "";

        boolean first = true;

        int parens = 0; // counts open parentheses

        while ((tokentype = st.nextToken()) != StreamTokenizer.TT_EOF) {
            switch (tokentype) {
            case '(':
                parens++;
                s += (char) tokentype;
                break;

            case ')':
                if (--parens < 0)
                    return s;
                s += (char) tokentype;
                break;

            case '!':
                int next = st.nextToken();
                if (next == '=') {
                    eq.setValue(false);
                    break;
                }
                st.pushBack();
                break;

            case '=':
                if (first) {
                    first = false;
                    break;
                }

            default:
                s += (char) tokentype;
                break;

            case StreamTokenizer.TT_WORD:
            case QUOTE_CHAR:
                s += st.sval;
                break;

            case StreamTokenizer.TT_NUMBER:
                s += st.nval;
                break;
            }
        }

        throw new EOFException("Unexpected EOF while parsing ACL");
    }

    /**
      * @exception IOException an IOException from the implementation.
      */
    protected void write(Writer w) throws IOException {
        writeHeader(w);

        for (int i = 0 ; i < rules.size(); i++)
            ((Rule)(rules.elementAt(i))).writeRule(w);

        w.write(")");
    }

    protected void writeHeader(Writer w) throws IOException {
        if (target != null)
            w.write("(" + TargetName +
                    (targetEq.getValue() ? "" : "!") + "=\"" +
                    target + "\")");
        if (targetAttr != null)
            w.write("(" + AttributeName +
                    (targetAttrEq.getValue() ? "" : "!") + "=\"" +
                    targetAttr + "\")");
        if (targetFilter != null)
            w.write("(" + FilterName +
                    (targetFilterEq.getValue() ? "" : "!") + "=\"" +
                    targetFilter + "\")");

        w.write("(version 3.0; acl \"" + resource + "\"; ");
    }

    /**
      * Creates a new Rule.
      *
      * @param st a StreamTokenizer for the rule.
      * @return a new Rule, parsed from the StreamTokenizer.
      * @exception Exception any Exception from the abstract implementation.
      */
    public Rule newRule(StreamTokenizer st) throws Exception {
        return new LdapRule(st);
    }

    /**
      * Creates a new Rule.
      *
      * @return a new Rule, with no initial contents.
      */
    public Rule newRule() {
        return new LdapRule();
    }

    protected boolean wasEntryFound() {
        return entryFound;
    }
    protected String previousACLValue() {
        return oldValue;
    }

    /**
      * Returns the target value of the ACL.
      *
      * @return the String target value.
      */
    public String getTarget() {
        return target;
    }

    /**
      * Sets the target value of the ACL.
      *
      * @param the new target value String.
      */
    public void setTarget(String newTarget) {
        if (!newTarget.startsWith(LDAPPrefix))
            target = LDAPPrefix + newTarget;
        else
            target = newTarget;
    }

    /**
      * Returns the target filter value of the ACL.
      *
      * @return the String target filter value.
      */
    public String getTargetFilter() {
        return targetFilter;
    }

    /**
      * Sets the target filter value of the ACL.
      *
      * @param the new target filter value String.
      */
    public void setTargetFilter(String newTargetFilter) {
        targetFilter = newTargetFilter;
    }

    /**
      * Returns the target attributes value of the ACL.
      *
      * @return the String target attributes value.
      */
    public String getTargetAttributes() {
        return targetAttr;
    }

    /**
      * Sets the target attributes value of the ACL.
      *
      * @param the new target attributes value String.
      */
    public void setTargetAttributes(String newTargetAttributes) {
        targetAttr = newTargetAttributes;
    }

    /**
      * Returns the target value equality of the ACL.
      *
      * @return the boolean target equality value.
      */
    public boolean getTargetEq() {
        return targetEq.getValue();
    }

    /**
      * Sets the target value equality of the ACL.
      *
      * @param the new target equality value boolean.
      */
    public void setTargetEq(boolean newTargetEq) {
        targetEq.setValue(newTargetEq);
    }

    /**
      * Returns the target filter equality value of the ACL.
      *
      * @return the boolean target filter equality value.
      */
    public boolean getTargetFilterEq() {
        return targetFilterEq.getValue();
    }

    /**
      * Sets the target filter equality value of the ACL.
      *
      * @param the new target filter equality value boolean.
      */
    public void setTargetFilterEq(boolean newTargetFilterEq) {
        targetFilterEq.setValue(newTargetFilterEq);
    }

    /**
      * Returns the target attributes equality value of the ACL.
      *
      * @return the boolean target attributes equality value.
      */
    public boolean getTargetAttributesEq() {
        return targetAttrEq.getValue();
    }

    /**
      * Sets the target attributes equality value of the ACL.
      *
      * @param the new target attributes equality value boolean.
      */
    public void setTargetAttributesEq(boolean newTargetAttributesEq) {
        targetAttrEq.setValue(newTargetAttributesEq);
    }

    /**
      * Parses the name of an acl out of a string containing the entire acl.
      *
      * @param acl the acl value
      * @return the name of the acl, if found.
      */
    public static String getACLName(String acl) {
        int i, i2;

        if ((i = acl.indexOf("version")) == -1)
            return null;

        if ((i = acl.indexOf("acl", i)) == -1)
            return null;

        if ((i = acl.indexOf('"', i)) == -1)
            return null;

        if ((i2 = acl.indexOf('"', i + 1)) == -1)
            return null;

        return acl.substring(i + 1, i2);
    }

    /**
      * Deletes a specific ACI value from an ACL
      *
      * @param acival the aci to be deleted.
     * @exception LDAPException It will throw a LDAPException of the acl cannot be deleted.
      */
    public void deleteACI(String acival) throws LDAPException {
        LDAPConnection ldc = this.newConnection();

        try {
            LDAPAttribute attr = new LDAPAttribute("aci", acival);
            ldc.modify(entryDN,
                    new LDAPModification(LDAPModification.DELETE, attr));
        }
        finally { if (ldc != null && ldc.isConnected()) {
                try {
                    ldc.disconnect();
                } catch (Exception e) {}
            }
        } }

    /**
      * Validates the LDAPException error message...
      *
      * @param le the LDAPException
      */
    public static String checkLDAPError(LDAPException le) {
        // LDAPException occasionally throws null messages...

        String msg = le.getLDAPErrorMessage();

        if (msg == null) {
            msg = le.toString();
            if (msg.indexOf(":") != -1)// snip class name prefix

                msg = "LDAP Error:" + msg.substring(msg.indexOf(":") + 1);
        }

        if (msg == null)
            msg = "Unknown LDAP Error";

        return msg;
    }

    /**
      * Returns an array of valid SASL authentication plugins, from the
      * Directory from which the ACL was retrieved.
      *
      * @return a String[] of "SASL Kerberos" format auth methods.
      */
    public String[] getAuthMethodsSASL() {
        String[] vals = null;

        LDAPConnection ldc = null;

        try {
            ldc = newConnection();

            Debug.println( "LdapACL:getAuthMethodsSASL():connected to " +
                    host + ":" + port);

            LDAPEntry entry = ldc.read("");

            if (entry == null) {
                Debug.println("LdapACL:getAuthMethodsSASL():root entry not found");
                return null;
            }

            LDAPAttributeSet attr = entry.getAttributeSet();

            if (attr.size() == 0) {
                Debug.println("LdapACL:getAuthMethodsSASL():supportedsaslmechanisms attribute not found");
                return null;
            }

            LDAPAttribute sasl = attr.getAttribute(SASLAttributeName);

            if (sasl == null) {
                Debug.println("LdapACL:getAuthMethodsSASL():supportedsaslmechanisms attribute not found");
                return null;
            }

            if (sasl.size() == 0) {
                Debug.println("LdapACL:getAuthMethodsSASL():supportedsaslmechanisms has zero size");
                return null;
            }

            Enumeration e = sasl.getStringValues();

            vals = new String[sasl.size()];

            for (int i = 0 ; e.hasMoreElements(); i++)
                vals[i] = SASLNameBase + (String)(e.nextElement());

            Debug.println("LdapACL:getAuthMethodsSASL():found " +
                    sasl.size() + " SASL types");
        } catch (LDAPException le) {
            Debug.println(
                    "LdapACL:getAuthMethodsSASL():LDAPException:" + le);
            return null;
        }
        finally { if (ldc != null && ldc.isConnected()) {
                try {
                    ldc.disconnect();
                } catch (Exception e) {}
            }
        }
        return vals;
    }
}
