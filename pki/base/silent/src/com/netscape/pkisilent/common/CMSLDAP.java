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

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;


/**
 * CMS Test framework .
 * Using this class you can add a user and user certificate to LDAP server.
 * You can also check if a certificate / CRL is published in LDAP server    
 *  USe this class to turn of SSL and turn on SSL in a LDAP server.
 */


public class CMSLDAP {

    private String HOST, DN, BASEDN, PASSWORD;
    private int PORT;

    private LDAPConnection conn = new LDAPConnection();

    public CMSLDAP() {}

    /**
     * Constructor. Takes parametes ldaphost, ldapport
     */
    public CMSLDAP(String h, String p) {
        HOST = h;
        PORT = Integer.parseInt(p);
    }

    /**
     * Cosntructor. Takes parameters ldaphost,ldapport,ldapbinddn, ldapbindnpassword.
     */
    public CMSLDAP(String h, String p, String dn, String pwd) {
        HOST = h;
        PORT = Integer.parseInt(p);
        DN = dn;
        PASSWORD = pwd;
    }

    /**
     * Connect to ldap server 
     */

    public boolean connect() {
        try {
            conn.connect(HOST, PORT, DN, PASSWORD);
            return true;
        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
            return false;
        }
    }

    /**
     * Disconnect form ldap server
     */

    public void disconnect() {

        if ((conn != null) && conn.isConnected()) {
            try {
                conn.disconnect();
            } catch (Exception e) {
                System.out.println("ERROR: " + e.toString());
            }

        }

    }

    private boolean RemoveInstance(String basedn) {
        try {
            conn.delete(basedn);
            return true;
        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
            return false;
        }

    }

    /**
     * Search for certificaterevocationList attribute. Takes basedn and filter as parameters
     */ 

    public boolean searchCRL(String basedn, String filter) throws LDAPException { 
        int searchScope = LDAPv2.SCOPE_SUB;
        String getAttrs[] = { "certificateRevocationList;binary"};
        LDAPSearchResults results = conn.search(basedn, searchScope, filter,
                getAttrs, false);

        if (results == null) {
            System.out.println("Could not search");
            return false;
        }
        while (results.hasMoreElements()) {
            LDAPEntry entry = (LDAPEntry) results.nextElement();

            System.out.println(entry.getDN());
            LDAPAttribute anAttr = entry.getAttribute(
                    "certificateRevocationList;binary");

            if (anAttr == null) {
                System.out.println("Attribute not found ");
                return false;
            } else {
                System.out.println(anAttr.getName());
                System.out.println(anAttr.getByteValueArray());
                return true;
            }
        }
        return true;
    }

    /**
     * Search for attriburte usercertificate. Takes parameters basedn and filter
     */



    public boolean searchUserCert(String basedn, String filter) throws LDAPException { 
        int searchScope = LDAPv2.SCOPE_SUB;
        String getAttrs[] = { "usercertificate;binary"};
        LDAPSearchResults results = conn.search(basedn, searchScope, filter,
                getAttrs, false);

        if (results == null) {
            System.out.println("Could not search");
            return false;
        }
        while (results.hasMoreElements()) {
            LDAPEntry entry = (LDAPEntry) results.nextElement();

            System.out.println(entry.getDN());
            LDAPAttribute anAttr = entry.getAttribute("usercertificate;binary");

            if (anAttr == null) {
                System.out.println("Attribute not found ");
                return false;
            } else {
                System.out.println(anAttr.getName());
                System.out.println(anAttr.getByteValueArray());
                return true;
            }
        }
        return true;
    }

    /**
     * Adds a user to direcrtory server . Takes parameters basedn, cn,sn,uid and passwd
     */

    public boolean userAdd(String basedn, String cn, String sn, String uid, String pwd) {
        try {
            LDAPAttributeSet attrSet = new LDAPAttributeSet();

            attrSet.add(
                    new LDAPAttribute("objectclass",
                    new String[] {
                "top", "person", "organizationalPerson",
                "inetorgperson"}));
            attrSet.add(new LDAPAttribute("cn", cn));
            attrSet.add(new LDAPAttribute("mail", uid + "@netscape.com"));
            attrSet.add(new LDAPAttribute("userpassword", pwd));
            attrSet.add(new LDAPAttribute("sn", sn));
            attrSet.add(new LDAPAttribute("givenName", cn + sn));
            String name = "uid=" + uid + "," + basedn;

            System.out.println("Basedn " + name);
            LDAPEntry entry = new LDAPEntry(name, attrSet);

            conn.add(entry);
            System.out.println("ADDED: " + name);
            return true;
        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
            return false;
        }

    }

    private X509Certificate getXCertificate(byte[] cpack) {

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream s = new ByteArrayInputStream(cpack);

            System.out.println("Building certificate :" + cpack);
            java.security.cert.X509Certificate the_cert = (
                    java.security.cert.X509Certificate) cf.generateCertificate(s);

            return the_cert;
        } catch (Exception e) {
            System.out.println("ERROR: getXCertificate " + e.toString());
            return null;
        }

    }

    private String buildDNString(String s) {

        String val = "";

        for (int i = 0; i < s.length(); i++) {
            if ((s.charAt(i) == ',') && (s.charAt(i + 1) == ' ')) {
                val += ',';
                i++;
                continue;
            } else { 
                val += s.charAt(i);
            }
        }
        return val;
    }

    /**
     * Returns the SerialNumber;issuerDN;SubjectDN string.
     * Takes certificate as parameter
     */

    public String getCertificateString(X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        String idn = ((cert.getIssuerDN()).toString()).trim();

        idn = buildDNString(idn);
        String sdn = ((cert.getSubjectDN()).toString()).trim();

        sdn = buildDNString(sdn);

        System.out.println("GetCertificateString : " + idn + ";" + sdn);

        // note that it did not represent a certificate fully
        // return cert.getVersion() + ";" + cert.getSerialNumber().toString() +
        // ";" + cert.getIssuerDN() + ";" + cert.getSubjectDN();
        return "2;" + cert.getSerialNumber().toString() + ";" + idn + ";" + sdn;

    }

    /**
     * Adds a user of objectclass cmsuser .  Takes cn,sn,uid,password,certificate as parameters.
     */
    public boolean CMSuserAdd(String cn, String sn, String uid, String pwd, byte[] certpack) {
        try {
            X509Certificate cert = getXCertificate(certpack);
 
            LDAPAttributeSet attrSet = new LDAPAttributeSet();

            attrSet.add(
                    new LDAPAttribute("objectclass",
                    new String[] {
                "top", "person", "organizationalPerson",
                "inetorgperson", "cmsuser"}));
            attrSet.add(new LDAPAttribute("cn", cn));
            attrSet.add(new LDAPAttribute("mail", uid + "@netscape.com"));
            attrSet.add(new LDAPAttribute("userpassword", pwd));
            attrSet.add(new LDAPAttribute("sn", sn));
            attrSet.add(new LDAPAttribute("givenName", cn + sn));
            attrSet.add(new LDAPAttribute("usertype", "sub"));
            attrSet.add(new LDAPAttribute("userstate", "1"));

            attrSet.add(
                    new LDAPAttribute("description", getCertificateString(cert)));
            LDAPAttribute attrCertBin = new LDAPAttribute("usercertificate");

            attrCertBin.addValue(cert.getEncoded());
            attrSet.add(attrCertBin);

            String name = "uid=" + uid + ","
                    + "ou=People,o=netscapecertificateServer";
            LDAPEntry entry = new LDAPEntry(name, attrSet);

            conn.add(entry);
            System.out.println("ADDED: " + name);
            return true;
        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
            return false;
        }

    }

    /**
     * Adds a user of objectclass cmsuser .  Takes cn,sn,uid,password,certificate as parameters.
     */

    public boolean CMSuserAdd(String cn, String sn, String uid, String pwd, X509Certificate cert) {

        try {
            LDAPAttributeSet attrSet = new LDAPAttributeSet();

            attrSet.add(
                    new LDAPAttribute("objectclass", 
                    new String[] {
                "top", "person", "organizationalPerson", 
                "inetorgperson", "cmsuser"}));
            attrSet.add(new LDAPAttribute("cn", cn));
            attrSet.add(new LDAPAttribute("mail", uid + "@netscape.com"));
            attrSet.add(new LDAPAttribute("userpassword", pwd));
            attrSet.add(new LDAPAttribute("sn", sn));
            attrSet.add(new LDAPAttribute("givenName", cn + sn));
            attrSet.add(new LDAPAttribute("usertype", "sub"));
            attrSet.add(new LDAPAttribute("userstate", "1"));

            attrSet.add(
                    new LDAPAttribute("description", getCertificateString(cert)));

            LDAPAttribute attrCertBin = new LDAPAttribute("usercertificate");

            attrCertBin.addValue(cert.getEncoded());
            attrSet.add(attrCertBin);

            String name = "uid=" + uid + ","
                    + "ou=People,o=netscapecertificateServer";
            LDAPEntry entry = new LDAPEntry(name, attrSet);

            conn.add(entry);
            System.out.println("ADDED: " + name);
        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
            return false;
        }

        return true;
    }

    /**
     * adds a cms user  to  Trusted Manager Group. Takes uid as parameter.
     */

    public boolean addCMSUserToTMGroup(String uid) {
        try {
            LDAPAttributeSet attrSet = new LDAPAttributeSet();
            LDAPAttribute um = new LDAPAttribute("uniquemember",
                    "uid=" + uid + ",ou=People,o=NetscapeCertificateServer");

            attrSet.add(um);
            LDAPModification gr = new LDAPModification(LDAPModification.ADD, um);

            String dn = "cn=Trusted Managers,ou=groups,o=netscapeCertificateServer";

            conn.modify(dn, gr);
            return true;

        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
            return false;
        }

    }

    /**
     * adds a cms user  to  Agent Group. Takes subsytem (ca/ra/ocsp/kra) and uid as parameters .
     */

    public boolean addCMSUserToAgentGroup(String subsystem, String uid) {
        try {
            String dn = null;

            if (subsystem.equals("ocsp")) {
                dn = "cn=Online Certificate Status Manager Agents,ou=groups,o=netscapeCertificateServer";
            }
            if (subsystem.equals("kra")) {
                dn = "cn=Data Recovery Manager Agents,ou=groups,o=netscapeCertificateServer";
            }
            if (subsystem.equals("ra")) {
                dn = "cn=Registration Manager Agents,ou=groups,o=netscapeCertificateServer";
            }
            if (subsystem.equals("ca")) {
                dn = "cn=Certificate Manager Agents,ou=groups,o=netscapeCertificateServer";
            }
            if (subsystem.equals("tks")) {
                dn = "cn=Token Key Service Manager Agents,ou=groups,o=netscapeCertificateServer";
            }

            LDAPAttributeSet attrSet = new LDAPAttributeSet();
            LDAPAttribute um = new LDAPAttribute("uniquemember",
                    "uid=" + uid + ",ou=People,o=NetscapeCertificateServer");

            System.out.println(
                    "uid=" + uid + ",ou=People,o=NetscapeCertificateServer");

            attrSet.add(um);
            LDAPModification gr = new LDAPModification(LDAPModification.ADD, um);

            conn.modify(dn, gr);

            return true;

        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
            return false;
        }

    }

    /**
     * Will trun of SSL in LDAP server 
     **/

    public boolean TurnOffSSL() {
        try {

            LDAPModificationSet mods = new LDAPModificationSet();
            LDAPAttribute ssl3 = new LDAPAttribute("nsssl3", "off");
            LDAPAttribute ssl3ciphers = new LDAPAttribute("nsssl3ciphers", "");
            LDAPAttribute kfile = new LDAPAttribute("nskeyfile", "alias/");
            LDAPAttribute cfile = new LDAPAttribute("nscertfile", "alias/");
            LDAPAttribute cauth = new LDAPAttribute("nssslclientauth", "allowed");

            // conn.delete("cn=RSA,cn=encryption,cn=config"); 		


            mods.add(LDAPModification.REPLACE, ssl3);
            mods.add(LDAPModification.DELETE, ssl3ciphers);
            mods.add(LDAPModification.DELETE, kfile);
            mods.add(LDAPModification.DELETE, cfile);
            mods.add(LDAPModification.DELETE, cauth);
            System.out.println("going to mod");
            // conn.modify("cn=encryption,cn=config",mods);
            System.out.println("mod en=encryption");
            int i = 4;

            while (i >= 0) {
                mods.removeElementAt(i);
                i--;
            }

            LDAPAttribute sec = new LDAPAttribute("nsslapd-security", "off");

            mods.add(LDAPModification.REPLACE, sec);
            conn.modify("cn=config", mods);
            System.out.println("mod cn=config");

            return true;

        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
            return false;
        }

    }

    /**
     * Will Turn ON SSL in LDAP server . Takes certPrefix, certificatenickanme and sslport as parameters.
     **/
 
    public boolean TurnOnSSL(String certPrefix, String certName, String sslport) {
        String dn;
        String CIPHERS = "-rsa_null_md5,+rsa_fips_3des_sha,+rsa_fips_des_sha,+rsa_3des_sha,+rsa_rc4_128_md5,+rsa_des_sha,+rsa_rc2_40_md5,+rsa_rc4_40_md5";

        try {
            boolean found = false;
            int searchScope = LDAPv2.SCOPE_SUB;
            String getAttrs[] = { "nssslactivation"};
        
            LDAPModificationSet mods = new LDAPModificationSet();
            LDAPAttribute sec = new LDAPAttribute("nsslapd-security", "on");
            LDAPAttribute sp = new LDAPAttribute("nsslapd-securePort", sslport);

            mods.add(LDAPModification.REPLACE, sec);
            mods.add(LDAPModification.REPLACE, sp);
            conn.modify("cn=config", mods);
            mods.removeElementAt(1); 
            mods.removeElementAt(0);

            LDAPAttribute ssl3 = new LDAPAttribute("nsssl3", "on");
            LDAPAttribute ssl3ciphers = new LDAPAttribute("nsssl3ciphers",
                    CIPHERS);
            LDAPAttribute kfile = new LDAPAttribute("nskeyfile",
                    "alias/" + certPrefix + "-key3.db");
            LDAPAttribute cfile = new LDAPAttribute("nscertfile",
                    "alias/" + certPrefix + "-cert7.db");
            LDAPAttribute cauth = new LDAPAttribute("nssslclientauth", "allowed");

            mods.add(LDAPModification.REPLACE, ssl3);
            mods.add(LDAPModification.REPLACE, ssl3ciphers);
            mods.add(LDAPModification.REPLACE, kfile);
            mods.add(LDAPModification.REPLACE, cfile);
            mods.add(LDAPModification.REPLACE, cauth);

            conn.modify("cn=encryption,cn=config", mods);
            int i = 4; 

            while (i >= 0) {
                mods.removeElementAt(i);
                i--;
            }

            // conn.delete("cn=RSA,cn=encryption,cn=config"); 		
            try {
                LDAPSearchResults results = conn.search(
                        "cn=RSA,cn=encryption,cn=config", searchScope, null,
                        getAttrs, false);
                LDAPAttribute cn = new LDAPAttribute("cn", "RSA");
                LDAPAttribute ssltoken = new LDAPAttribute("nsssltoken",
                        "internal (software)");
                LDAPAttribute activation = new LDAPAttribute("nssslactivation",
                        "on");
                LDAPAttribute cname = new LDAPAttribute("nssslpersonalityssl",
                        certName);

                mods.add(LDAPModification.REPLACE, cn);
                mods.add(LDAPModification.REPLACE, ssltoken);
                mods.add(LDAPModification.REPLACE, activation);
                mods.add(LDAPModification.REPLACE, cname);

                conn.modify("cn=RSA,cn=encryption,cn=config", mods);

            } catch (Exception e1) {
                LDAPAttributeSet attrSet = new LDAPAttributeSet();

                attrSet.add(
                        new LDAPAttribute("objectclass",
                        new String[] { "top", "nsEncryptionModule"}));
                attrSet.add(new LDAPAttribute("cn", "RSA"));
                attrSet.add(
                        new LDAPAttribute("nsssltoken", "internal (software)"));
                attrSet.add(new LDAPAttribute("nssslactivation", "on"));
                attrSet.add(new LDAPAttribute("nssslpersonalityssl", certName));
                LDAPEntry entry = new LDAPEntry("cn=RSA,cn=encryption,cn=config",
                        attrSet);

                conn.add(entry);
            }

            return true;

        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
            return false;
        }

    }

    public static void main(String args[]) {
        String HOST = args[0];
        // int PORT = Integer.parseInt(args[1]);
        String PORT = args[1];
        String DN = args[2];
        String PASSWORD = args[3];
        String BASEDN = args[4];

        String s = "MIICFzCCAYCgAwIBAgIBBjANBgkqhkiG9w0BAQQFADBDMRswGQYDVQQKExJhY2NlcHRhY25ldGVz\ndDEwMjQxFzAVBgNVBAsTDmFjY2VwdGFuY2V0ZXN0MQswCQYDVQQDEwJjYTAeFw0wMzA0MTEyMTUx\nMzZaFw0wNDA0MTAwOTQ2NTVaMFwxCzAJBgNVBAYTAlVTMQwwCgYDVQQKEwNTU0wxHTAbBgNVBAsT\nFHNzbHRlc3QxMDUwMDk3ODkzNzQ1MSAwHgYDVQQDExdqdXBpdGVyMi5uc2NwLmFvbHR3Lm5ldDBc\nMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDCsCTIIQ+bJMfPHi6kwa7HF+/xSTVHcpZ5zsodXsNWjPlD\noRu/5KAO8NotfwGnYmALWdYnqXCF0q0gkaJQalQTAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIFoDAR\nBglghkgBhvhCAQEEBAMCBkAwHwYDVR0jBBgwFoAUzxZkSySZT/Y3SxGMEiNyHnLUOPAwDQYJKoZI\nhvcNAQEEBQADgYEALtpqMOtZt6j5KlghDFgdg/dvf36nWiZwC1ap6+ka22shLkA/RjmOix97btzT\nQ+8LcmdkAW5iap4YbtrCu0wdN6IbIEXoQI1QGZBoKO2o02utssXANmTnRCyH/GX2KefQlp1NSRj9\nZNZ+GRT2Qk/8G5Ds9vVjm1I5+/AkzI9jS14=";

        s = "-----BEGIN CERTIFICATE-----" + "\n" + s + "\n"
                + "-----END CERTIFICATE-----\n";

        try {

            System.out.println(HOST + PORT + DN + PASSWORD + BASEDN);
            CMSLDAP caIdb = new CMSLDAP(HOST, PORT, DN, PASSWORD);

            /* FileInputStream fis = new FileInputStream("t1");
             DataInputStream dis = new DataInputStream(fis);

             byte[] bytes = new byte[dis.available()];
             dis.readFully(bytes);		

             //		bytes=s.getBytes();
             */

            if (!caIdb.connect()) {
                System.out.println("Could not connect to CA internal DB port");
            }

            if (!caIdb.searchCRL("o=mcom.com", "uid=CManager")) {
                System.out.println("CRL is not published");
            }

            // if(!caIdb.searchUserCert("o=mcom.com","uid=test"))
            // System.out.println("USer cert is not published");
         
            // if (!caIdb.CMSuserAdd("ra-trust" ,"ra-trust","ra-trust","netscape",bytes))
            // {System.out.println("Trusted MAnager user Could not be add ");}

            // if(!caIdb.addCMSUserToTMGroup("ra-trust"))
            // {System.out.println("CMS user Could not be added to Trusted manager group ");  }

            // if(!caIdb.addCMSUserToAgentGroup("ra","ra-agent"))
            // {System.out.println("CMS user Could not be added to Trusted manager group ");  }
            /* if(!caIdb.userAdd(BASEDN,"raeetest1","raeetest1","raeetest1","netscape"))
             {System.out.println("CMS user Could not be added to Trusted manager group ");  }
             */

        } catch (Exception e) {
            System.out.println("ERROR: " + e.toString());
        }

    }
}

