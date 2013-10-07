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
package com.netscape.cms.publish.mappers;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;
import netscape.ldap.LDAPv3;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.AVA;
import netscape.security.x509.RDN;
import netscape.security.x509.X500Name;
import netscape.security.x509.X500NameAttrMap;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.ILdapPlugin;

/**
 * Maps a Subject name to an entry in the LDAP server.
 * subject name to form the ldap search dn and filter.
 * Takes a optional root search dn.
 * The DN comps are used to form a LDAP entry to begin a subtree search.
 * The filter comps are used to form a search filter for the subtree.
 * If none of the DN comps matched, baseDN is used for the subtree.
 * If the baseDN is null and none of the DN comps matched, it is an error.
 * If none of the DN comps and filter comps matched, it is an error.
 * If just the filter comps is null, a base search is performed.
 *
 * @version $Revision$, $Date$
 */
public class LdapDNCompsMap
        implements ILdapPlugin, IExtendedPluginInfo {
    //protected String mLdapAttr = null;
    protected String mBaseDN = null;
    protected ObjectIdentifier[] mDnComps = null;
    protected ObjectIdentifier[] mFilterComps = null;

    private ILogger mLogger = CMS.getLogger();
    private boolean mInited = false;
    protected IConfigStore mConfig = null;

    /**
     * Constructor.
     *
     * The DN comps are used to form a LDAP entry to begin a subtree search.
     * The filter comps are used to form a search filter for the subtree.
     * If none of the DN comps matched, baseDN is used for the subtree.
     * If the baseDN is null and none of the DN comps matched, it is an error.
     * If none of the DN comps and filter comps matched, it is an error.
     * If just the filter comps is null, a base search is performed.
     *
     * @param baseDN The base DN.
     * @param dnComps Components to form the LDAP base dn for search.
     * @param filterComps Components to form the LDAP search filter.
     */
    public LdapDNCompsMap(String ldapAttr, String baseDN,
            ObjectIdentifier[] dnComps,
            ObjectIdentifier[] filterComps) {
        //mLdapAttr = ldapAttr;
        init(baseDN, dnComps, filterComps);
    }

    /**
     * constructor if initializing from config store.
     */
    public LdapDNCompsMap() {
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * for initializing from config store.
     */
    public void init(IConfigStore config)
            throws EBaseException {
        mConfig = config;
        String baseDN = mConfig.getString("baseDN");
        ObjectIdentifier[] dnComps =
                getCompsFromString(mConfig.getString("dnComps"));
        ObjectIdentifier[] filterComps =
                getCompsFromString(mConfig.getString("filterComps"));

        init(baseDN, dnComps, filterComps);
    }

    public String getImplName() {
        return "LdapDNCompsMap";
    }

    public String getDescription() {
        return "LdapDNCompsMap";
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] s = {
                "baseDN;string;Base to search from. E.g ou=Engineering,o=Fedora",
                "dnComps;string;Comma-separated list of attributes to put in the DN",
                "filterComps;string;Comma-separated list of attributes to form the filter",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ldappublish-mapper-dncompsmapper",
                IExtendedPluginInfo.HELP_TEXT +
                        ";More complex mapper. Used when there is not enough information " +
                        "in the cert request to form the complete LDAP DN. Using this " +
                        "plugin, you can specify additional LDAP filters to narrow down the " +
                        "search"
            };

        return s;
    }

    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        v.addElement("baseDN=");
        v.addElement("dnComps=");
        v.addElement("filterComps=");
        return v;
    }

    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<String>();

        try {
            if (mBaseDN == null) {
                v.addElement("baseDN=");
            } else {
                v.addElement("baseDN=" + mConfig.getString("baseDN"));
            }
            if (mDnComps == null) {
                v.addElement("dnComps=");
            } else {
                v.addElement("dnComps=" +
                        mConfig.getString("dnComps"));
            }
            if (mFilterComps == null) {
                v.addElement("filterComps=");
            } else {
                v.addElement("filterComps=" +
                        mConfig.getString("filterComps"));
            }
        } catch (Exception e) {
        }
        return v;
    }

    /**
     * common initialization routine.
     */
    protected void init(String baseDN, ObjectIdentifier[] dnComps,
            ObjectIdentifier[] filterComps) {
        if (mInited)
            return;

        mBaseDN = baseDN;
        if (dnComps != null)
            mDnComps = dnComps.clone();
        if (filterComps != null)
            mFilterComps = filterComps.clone();

        // log debug info.
        for (int i = 0; i < mDnComps.length; i++) {
            CMS.debug(
                    "LdapDNCompsMap: dnComp " + X500NameAttrMap.getDefault().getName(mDnComps[i]));
        }
        for (int i = 0; i < mFilterComps.length; i++) {
            CMS.debug("LdapDNCompsMap: filterComp " +
                    X500NameAttrMap.getDefault().getName(mFilterComps[i]));
        }
        mInited = true;
    }

    /**
     * Maps a X500 subject name to LDAP entry.
     * Uses DN components and filter components to form a DN and
     * filter for a LDAP search.
     * If the formed DN is null the baseDN will be used.
     * If the formed DN is null and baseDN is null an error is thrown.
     * If the filter is null a base search is performed.
     * If both are null an error is thrown.
     *
     * @param conn the LDAP connection.
     * @param x500name the dn to map.
     * @param obj the object
     * @exception ELdapException if any LDAP exceptions occured.
     * @return the DN of the entry.
     */
    public String map(LDAPConnection conn, X500Name x500name,
            byte[] obj)
            throws ELdapException {
        try {
            if (conn == null)
                return null;

            CMS.debug("LdapDNCompsMap: " + x500name.toString());

            String[] dnAndFilter = formDNandFilter(x500name);
            String dn = dnAndFilter[0];
            String filter = dnAndFilter[1];

            if (dn == null) {
                // #362332
                // if (filter == null) {
                //	log(ILogger.LL_FAILURE, "No dn and filter formed");
                //	throw new ELdapException(
                //		LdapResources.NO_DN_AND_FILTER_COMPS,
                //		x500name.toString());
                // }
                if (mBaseDN == null) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("PUBLISH_NO_BASE"));
                    throw new ELdapException(
                            CMS.getUserMessage("CMS_LDAP_NO_DN_COMPS_AND_BASEDN",
                                    x500name.toString()));
                }
                dn = mBaseDN;
            }
            int scope = LDAPv2.SCOPE_SUB;

            if (filter == null) {
                scope = LDAPv2.SCOPE_BASE;
                filter = "(objectclass=*)";
            }

            // search for entry
            String[] attrs;

            attrs = new String[] { LDAPv3.NO_ATTRS };

            log(ILogger.LL_INFO, "searching for " + dn + " " + filter + " " +
                    ((scope == LDAPv2.SCOPE_SUB) ? "sub" : "base"));

            LDAPSearchResults results =
                    conn.search(dn, scope, filter, attrs, false);
            LDAPEntry entry = results.next();

            if (results.hasMoreElements()) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_MORE_THAN_ONE_ENTRY", "", x500name.toString()));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_MORE_THAN_ONE_ENTRY",
                            x500name.toString()));
            }
            if (entry != null) {
                return entry.getDN();
            } else {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_ENTRY_NOT_FOUND", "", x500name.toString()));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND",
                            "null entry"));
            }
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"));
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()));
            } else {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("PUBLISH_DN_MAP_EXCEPTION", "LDAPException", e.toString()));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND", e.toString()));
            }
        }
    }

    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_LDAP, level,
                "LdapDNCompsMap: " + msg);
    }

    /**
     * form a dn and filter from component in the cert subject name
     *
     * @param subjName subject name
     */
    public String[] formDNandFilter(X500Name subjName)
            throws ELdapException {
        Vector<RDN> dnRdns = new Vector<RDN>();
        SearchFilter filter = new SearchFilter();
        X500NameAttrMap attrMap = X500NameAttrMap.getDefault();
        String dnStr = null, filterStr = null;
        ObjectIdentifier EOid = attrMap.getOid("E");
        ObjectIdentifier mailOid = attrMap.getOid("MAIL");

        try {
            // get the base DN & filter.
            for (Enumeration<RDN> n = subjName.getRDNs(); n.hasMoreElements();) {
                RDN rdn = n.nextElement();
                // NOTE assumes one AVA per RDN.
                AVA ava = rdn.getAssertion()[0];
                ObjectIdentifier oid = ava.getOid();

                for (int i = 0; i < mDnComps.length; i++) {
                    if (mDnComps[i].equals(oid)) {
                        if (oid == EOid) {
                            DerValue val = ava.getValue();
                            AVA newAVA = new AVA(mailOid, val);
                            RDN newRDN = new RDN(new AVA[] { newAVA }
                                    );

                            CMS.debug(
                                    "LdapDNCompsMap: Converted " + rdn.toLdapDNString() + " to " +
                                            newRDN.toLdapDNString() + " in DN");
                            rdn = newRDN;
                        }
                        dnRdns.addElement(rdn);
                        CMS.debug(
                                "LdapDNCompsMap: adding dn comp " + rdn.toLdapDNString());
                        break;
                    }
                }
                for (int i = 0; i < mFilterComps.length; i++) {
                    if (mFilterComps[i].equals(oid)) {
                        if (oid == EOid) {
                            DerValue val = ava.getValue();
                            AVA newAVA = new AVA(mailOid, val);

                            CMS.debug(
                                    "LdapDNCompsMap: Converted " + ava.toLdapDNString() + " to " +
                                            newAVA.toLdapDNString() + " in filter");
                            ava = newAVA;
                        }
                        filter.addElement(ava.toLdapDNString());
                        CMS.debug(
                                "LdapDNCompsMap: adding filter comp " + ava.toLdapDNString());
                        break;
                    }
                }

                // XXX should be an error when string is null?
                // return to caller to decide.
                if (dnRdns.size() != 0) {
                    dnStr = new X500Name(dnRdns).toLdapDNString();
                }
                if (filter.size() != 0) {
                    filterStr = filter.toFilterString();
                }
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("PUBLISH_FROM_SUBJ_TO_DN", e.toString()));
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_FORM_DN_COMPS_FAILED", e.toString()));
        }

        return new String[] { dnStr, filterStr };
    }

    public ObjectIdentifier[] getDnComps() {
        return mDnComps.clone();
    }

    public ObjectIdentifier[] getFilterComps() {
        return mFilterComps.clone();
    }

    /**
     * class for forming search filters for ldap searching from
     * name=value components. components are anded.
     */

    public static class SearchFilter extends Vector<Object> {
        private static final long serialVersionUID = 4210302171279891828L;

        public String toFilterString() {
            StringBuffer buf = new StringBuffer();

            if (elementCount == 0) {
                return null;
            }
            if (elementCount == 1) {
                buf.append("(" + (String) elementData[0] + ")");
                return buf.toString();
            }
            buf.append("(&");
            for (int i = 0; i < elementCount; i++) {
                buf.append("(" + (String) elementData[i] + ")");
            }
            buf.append(")");
            return buf.toString();
        }
    }

    /**
     * useful routine for parsing components given as string to
     * arrays of objectidentifiers.
     * The string is expected to be comma separated AVA attribute names.
     * For example, "uid,cn,o,ou". Attribute names are case insensitive.
     *
     * @param val the string specifying the comps
     * @exception ELdapException if any error occurs.
     */
    public static ObjectIdentifier[] getCompsFromString(String val)
            throws ELdapException {
        StringTokenizer tokens;
        ObjectIdentifier[] comps;
        String attr;
        ObjectIdentifier oid;

        if (val == null || val.length() == 0)
            return new ObjectIdentifier[0];

        tokens = new StringTokenizer(val, ", \t\n\r");
        comps = new ObjectIdentifier[tokens.countTokens()];
        if (comps.length == 0) {
            return new ObjectIdentifier[0];
        }
        int i = 0;

        while (tokens.hasMoreTokens()) {
            attr = tokens.nextToken().trim();
            // mail -> E hack to look for E in subject names.
            if (attr.equalsIgnoreCase("mail"))
                attr = "E";
            oid = X500NameAttrMap.getDefault().getOid(attr);
            if (oid != null) {
                comps[i++] = oid;
            } else {
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_UNKNOWN_ATTR_IN_DN_FILTER_COMPS", attr));
            }
        }
        return comps;
    }

}
