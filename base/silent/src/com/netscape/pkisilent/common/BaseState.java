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

/**
 * CMS Test framework .
 * This class reads and sets the values for a CMS subsytems Config file (CS.cfg)
 * Using this class you can set the server to a base state.
 */

public class BaseState {

    private String CMSConfigFile;
    private CMSConfig cmscfg = null;
    private String ldapbase, ldaphost, ldapport, ldapdn, ldapdnpw;
    private boolean ldapsecConn = false;

    // Constructor 

    public BaseState() {
    }

    /**
     * Constructor . Takes the parameter CMSConfigfilename ( with fullpath)
     * 
     * @param CMSConfigfile.
     */

    public BaseState(String cmscfilename) {
        CMSConfigFile = cmscfilename;

    }

    /**
     * Set the publishing directory information . Takes the paramters ldaphost,ldapport,ldapDN, ldapDN password, BaseDN
     * , Secure coonection (true/false)
     */
    public void setLDAPInfo(String h, String p, String dn, String pw, String base, boolean sc) {
        ldaphost = h;
        ldapport = p;
        ldapdn = dn;
        ldapdnpw = pw;
        ldapbase = base;
        ldapsecConn = sc;

    }

    /**
     * Enable SSL Client authentication for Directory enrollment and publishing
     */

    public void EnableSSLClientAuth() {
        ldapsecConn = true;
        cmscfg = new CMSConfig(CMSConfigFile);
        // Enable DirBaseEnrollment
        cmscfg.EnableDirEnrollment(ldapsecConn, ldapbase, ldaphost, ldapport);
        // Enable Publishing
        cmscfg.EnablePublishing(ldapsecConn, ldapdn, ldapdnpw, ldaphost,
                ldapport);
        cmscfg.saveCMSConfig();

    }

    /**
     * Set to CA 's base state . Enables Directory based enrollment , publishing and Portal enrollment
     */

    public void CABaseState() {
        cmscfg = new CMSConfig(CMSConfigFile);
        cmscfg.EnableAdminEnrollment();
        // Enable DirBaseEnrollment
        cmscfg.EnableDirEnrollment(ldapsecConn, ldapbase, ldaphost, ldapport);
        // Enable Publishing
        cmscfg.DisablePublishing(ldapsecConn, ldapdn, ldapdnpw, ldaphost,
                ldapport, ldapbase);
        // Enable Portalbased enrollment
        cmscfg.EnablePortalAuth(ldapsecConn, ldapdn, ldapdnpw, ldaphost,
                ldapport, ldapbase);
        cmscfg.saveCMSConfig();

    }

    /**
     * Set to RA 's base state . Enables Directory based enrollment and Portal enrollment
     */

    public void RABaseState() {
        cmscfg = new CMSConfig(CMSConfigFile);
        cmscfg.EnableAdminEnrollment();
        // Enable DirBaseEnrollment
        cmscfg.EnableDirEnrollment(ldapsecConn, ldapbase, ldaphost, ldapport);
        // Enable Portalbased enrollment
        cmscfg.EnablePortalAuth(ldapsecConn, ldapdn, ldapdnpw, ldaphost,
                ldapport, ldapbase);
        cmscfg.saveCMSConfig();

    }

    public static void main(String args[]) {
    }// end of function main

}
