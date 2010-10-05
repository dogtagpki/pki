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

import java.util.*;
import java.net.*;
import java.io.*;

import com.netscape.cmsutil.ocsp.*;
import com.netscape.cmsutil.ocsp.Request;

import org.mozilla.jss.*;
import org.mozilla.jss.pkcs12.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.util.*;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CertDatabaseException;
import sun.misc.*;
import java.lang.Exception;

import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.pkcs11.PK11Token;

import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509Key;
import netscape.security.x509.X500Name;

import com.netscape.cmsutil.ocsp.*;
import com.netscape.cmsutil.ocsp.Request;

import com.netscape.osutil.*;


public class ConfigureCA {

    public static Hashtable mUsedPort = new Hashtable();

    // define global variables

    public static HTTPClient hc = null;
	
    public static String login_uri = "/ca/admin/console/config/login";
    public static String wizard_uri = "/ca/admin/console/config/wizard";
    public static String admin_uri = "/ca/admin/ca/getBySerial";
    public static String pkcs12_uri = "/ca/admin/console/config/savepkcs12";
    public static String sd_login_uri = "/ca/admin/ca/securityDomainLogin";
    public static String sd_get_cookie_uri = "/ca/admin/ca/getCookie";

    public static String cs_hostname = null;
    public static String cs_port = null;
    public static String client_certdb_dir = null;
    public static String client_certdb_pwd = null;

    public static String sd_hostname = null;
    public static String sd_ssl_port = null;
    public static String sd_agent_port = null;
    public static String sd_admin_port = null;
    public static String sd_admin_name = null;
    public static String sd_admin_password = null;

    // Login Panel 
    public static String pin = null;

    public static String domain_name = null;

    public static String admin_user = null;
    public static String admin_email = null;
    public static String admin_password = null;
    public static String admin_serial_number = null;
    public static String agent_name = null;

    public static String ldap_host = null;
    public static String ldap_port = null;
    public static String bind_dn = null;
    public static String bind_password = null;
    public static String base_dn = null;
    public static String db_name = null;

    public static String key_size = null;
    public static String key_type = null;
    public static String key_algorithm = null;
    public static String token_name = null;
    public static String token_pwd = null;

    public static String agent_key_size = null;
    public static String agent_key_type = null;
    public static String agent_cert_subject = null;

    public static String save_p12 = null;
    public static String backup_pwd = null;
    public static String backup_fname = null;

    public static String ca_cert_name = null;
    public static String ca_cert_req = null;
    public static String ca_cert_pp = null;
    public static String ca_cert_cert = null;

    public static String ocsp_cert_name = null;
    public static String ocsp_cert_req = null;
    public static String ocsp_cert_pp = null;
    public static String ocsp_cert_cert = null;

    public static String server_cert_name = null;
    public static String server_cert_req = null;
    public static String server_cert_pp = null;
    public static String server_cert_cert = null;

    public static String ca_subsystem_cert_name = null;
    public static String ca_subsystem_cert_req = null;
    public static String ca_subsystem_cert_pp = null;
    public static String ca_subsystem_cert_cert = null;

    public static String ca_audit_signing_cert_name = null;
    public static String ca_audit_signing_cert_req = null;
    public static String ca_audit_signing_cert_pp = null;
    public static String ca_audit_signing_cert_cert = null;

    // names 
    public static String ca_sign_cert_subject_name = null;
    public static String ca_subsystem_cert_subject_name = null;
    public static String ca_ocsp_cert_subject_name = null;
    public static String ca_server_cert_subject_name = null;
    public static String ca_audit_signing_cert_subject_name = null;

    public static String subsystem_name = null;

    public static String external_ca= null;
    public static String ext_ca_cert_file = null;
    public static String ext_ca_cert_chain_file = null;
    public static String ext_csr_file = null;
    public static String signing_cc = null;

    public static boolean clone = false;
    public static String clone_uri = null;
    public static String clone_p12_passwd = null;
    public static String clone_p12_file = null;

    //for correct selection of CA to be cloned
    public static String urls;


    public ConfigureCA() {// do nothing :)
    }

    public void sleep_time() {
        try {
            System.out.println("Sleeping for 5 secs..");
            Thread.sleep(5000);
        } catch (Exception e) {
            System.out.println("ERROR: sleep problem");
        }

    }

    public boolean LoginPanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();

            String query_string = "pin=" + pin + "&xml=true"; 
	
            hr = hc.sslConnect(cs_hostname, cs_port, login_uri, query_string);
            System.out.println("xml returned: " + hr.getHTML());

            // parse xml here - nothing to parse

            // get cookie
            String temp = hr.getCookieValue("JSESSIONID");

            if (temp != null) {
                int index = temp.indexOf(";");

                hc.j_session_id = temp.substring(0, index);
                st = true;
            }

            hr = null;
            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri,
                "p=0&op=next&xml=true");

            // parse xml here

            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();

            return st;
        } catch (Exception e) {
            System.out.println("Exception in LoginPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean TokenChoicePanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();

            String query_string = null;

            // Software Token
            if (token_name.equalsIgnoreCase("internal")) {
                query_string = "p=1" + "&op=next" + "&xml=true" + "&choice="
                    + URLEncoder.encode("Internal Key Storage Token") + ""; 
                hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
                // parse xml
                bais = new ByteArrayInputStream(hr.getHTML().getBytes());
                px.parse(bais);
                px.prettyprintxml();
            } // HSM
            else {
                // login to hsm first
                query_string = "p=2" + "&op=next" + "&xml=true" + "&uTokName="
                    + URLEncoder.encode(token_name) + "&__uPasswd="
                    + URLEncoder.encode(token_pwd) + ""; 
                hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
                // parse xml
                bais = new ByteArrayInputStream(hr.getHTML().getBytes());
                px.parse(bais);
                px.prettyprintxml();
		
                // choice with token name now
                query_string = "p=1" + "&op=next" + "&xml=true" + "&choice="
                    + URLEncoder.encode(token_name) + ""; 
                hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
                // parse xml
                bais = new ByteArrayInputStream(hr.getHTML().getBytes());
                px.parse(bais);
                px.prettyprintxml();
            }
            return true;
        } catch (Exception e) {
            System.out.println("Exception in TokenChoicePanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean DomainPanel() {
        try {
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();

            String domain_url = "https://" + cs_hostname + ":" + cs_port;
            String query_string = null;

            if (! clone) {
                query_string = "sdomainURL=" + URLEncoder.encode(domain_url)
                    + "&sdomainName=" + URLEncoder.encode(domain_name)
                    + "&choice=newdomain" + "&p=3" + "&op=next" + "&xml=true";
            } else {
                domain_url = "https://" + sd_hostname + ":" + sd_admin_port ;
                query_string = "sdomainURL=" + URLEncoder.encode(domain_url)
                    + "&sdomainName="
                    + "&choice=existingdomain" + "&p=3" + "&op=next" + "&xml=true";
            }

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();

            String temp_sdomain = px.getvalue("sdomainName");

            System.out.println("sdomainname=" + temp_sdomain);

            return true;
        } catch (Exception e) {
            System.out.println("Exception in DomainPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean DisplayCertChainPanel() {
        try {
            HTTPResponse hr = null;
            String query_string = "p=4" + "&op=next" + "&xml=true";
            hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);
            return true;
        } catch (Exception e) {
            System.out.println("Exception in DisplayCertChainPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean SecurityDomainLoginPanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();
            String subca_url = "https://" + cs_hostname + ":" + cs_port +
                "/ca/admin/console/config/wizard" + "?p=5&subsystem=CA" ;

            String query_string = "url=" + URLEncoder.encode(subca_url);

            hr = hc.sslConnect(sd_hostname,sd_admin_port,sd_login_uri,query_string);

            String query_string_1 = "uid=" + sd_admin_name + "&pwd=" + sd_admin_password +
                                    "&url=" + URLEncoder.encode(subca_url) ;

            hr = hc.sslConnect(sd_hostname,sd_admin_port,sd_get_cookie_uri,
                                                query_string_1);

            // get session id from security domain
                
            String subca_session_id = hr.getContentValue("header.session_id");
            String subca_url_1 = hr.getContentValue("header.url");
                
            System.out.println("SUBCA_SESSION_ID=" + subca_session_id );
            System.out.println("SUBCA_URL=" + subca_url_1 );

            // use session id to connect back to subCA

            String query_string_2 = "p=5" + "&subsystem=CA" +
                "&session_id=" + subca_session_id + "&xml=true" ;
        
            hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri, query_string_2);
            urls = hr.getHTML();
            int indx = urls.indexOf(clone_uri);
            if (indx < 0) {
                throw new Exception("Invalid clone_uri");
            }
            urls = urls.substring(urls.lastIndexOf("<option" , indx), indx);
            urls = urls.split("\"")[1];

            System.out.println("urls =" + urls);
                                                                                                                                                                                                                 return true;
        } catch (Exception e) {
            System.out.println("Exception in SecurityDomainLoginPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean CreateCAPanel() {
        try { 
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();
            String query_string = null;

            if (!clone) {
                query_string = "p=5" + "&op=next" + "&xml=true"
                    + "&choice=newsubsystem" + "&subsystemName="
                    + URLEncoder.encode(subsystem_name);
            } else {
                query_string = "p=5" + "&op=next" + "&xml=true"
                    + "&choice=clonesubsystem" + "&subsystemName="
                    + URLEncoder.encode(subsystem_name)
                    + "&urls=" + urls + "";
            }

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();

            if (clone) {

                hr = null;
                query_string = "p=6" + "&op=next" + "&xml=true"; 
                hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

                // parse xml
                bais = new ByteArrayInputStream(hr.getHTML().getBytes());
                px.parse(bais);
                px.prettyprintxml();
            }

            return true;
        } catch (Exception e) {
            System.out.println("Exception in CreateCAPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean RestoreKeyCertPanel() {
        try {
            ByteArrayInputStream bais = null;
            HTTPResponse hr = null;
            ParseXML px = new ParseXML();

            String query_string = "p=7" + "&op=next" + "&xml=true" 
                + "&__password=" + URLEncoder.encode(clone_p12_passwd)
                + "&path=" + URLEncoder.encode(clone_p12_file) + "";

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
 
            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();
            return true;
        } catch (Exception e) {
            System.out.println("Exception in RestoreKeyCertPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }
            

    public boolean HierarchyPanel() {
        try { 
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();

            String query_string = "p=8" + "&op=next" + "&xml=true" ;
            if (external_ca.equalsIgnoreCase("true")) 
                query_string += "&choice=join";
            else
                query_string += "&choice=root";  

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();

            /*
             hr = null;
             hr = hc.sslConnect(cs_hostname,cs_port,
             wizard_uri,"p=7&op=next&xml=true");

             // parse xml to return result
             bais = new ByteArrayInputStream(hr.getHTML().getBytes());
             px.parse(bais);
             px.prettyprintxml();
             */

            return true;
        } catch (Exception e) {
            System.out.println("Exception in HierarchyPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }

    }

    public boolean LdapConnectionPanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();

            String query_string = "p=9" + "&op=next" + "&xml=true" + "&host="
                + URLEncoder.encode(ldap_host) + "&port="
                + URLEncoder.encode(ldap_port) + "&binddn="
                + URLEncoder.encode(bind_dn) + "&__bindpwd="
                + URLEncoder.encode(bind_password) + "&basedn="
                + URLEncoder.encode(base_dn) + "&database="
                + URLEncoder.encode(db_name) + "&display="
                + URLEncoder.encode("$displayStr") + ""; 

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();

            return true;
        } catch (Exception e) {
            System.out.println("Exception in LdapConnectionPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean KeyPanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();
            ArrayList al = null;
            String query_string = null;
            if (clone) {
                query_string = "p=10" + "&op=next" + "&xml=true" 
                    + "&sslserver_custom_size=" + key_size
                    + "&sslserver_choice=custom"
                    + "&sslserver_keytype=" + key_type 
                    + "&sslserver_keyalgorithm=" + key_algorithm
                    + "&keyalgorithm=" + key_algorithm
                    + "&choice=default" + "&keytype=" + key_type 
                    + "&custom_size=" + key_size + "";
            } else {
                query_string = "p=10" + "&op=next" + "&xml=true"
                    + "&subsystem_custom_size=" + key_size
                    + "&subsystem_keytype=" + key_type
                    + "&subsystem_choice=custom"
                    + "&subsystem_keyalgorithm=" + key_algorithm
                    + "&sslserver_custom_size=" + key_size
                    + "&sslserver_keytype=" + key_type
                    + "&sslserver_choice=custom"
                    + "&sslserver_keyalgorithm=" + key_algorithm 
                    + "&signing_custom_size=" + key_size
                    + "&signing_keytype=" + key_type
                    + "&signing_choice=custom"
                    + "&signing_keyalgorithm=" + key_algorithm
                    + "&ocsp_signing_custom_size=" + key_size
                    + "&ocsp_signing_keytype=" + key_type 
                    + "&ocsp_signing_choice=custom" 
                    + "&ocsp_signing_keyalgorithm=" + key_algorithm
                    + "&audit_signing_custom_size=" + key_size
                    + "&audit_signing_keytype=" + key_type
                    + "&audit_signing_choice=custom" 
                    + "&audit_signing_keyalgorithm=" + key_algorithm
                    + "&custom_size=" + key_size
                    + "&keytype=" + key_type 
                    + "&choice=custom"
                    + "&keyalgorithm=" + key_algorithm + "";
            }

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();
		
            al = px.constructvaluelist("CertReqPair", "DN");
            // get ca cert subject name
            if (al != null) {
                for (int i = 0; i < al.size(); i++) {
                    String temp = (String) al.get(i);

                    if (temp.indexOf("Certificate Authority") > 0) {
                        ca_cert_name = temp;
                    } else if (temp.indexOf("OCSP Signing Certificate") > 0) {
                        ocsp_cert_name = temp;
                    } else if (temp.indexOf("Subsystem Certificate") > 0) {
                        ca_subsystem_cert_name = temp;
                    } else if (temp.indexOf("Audit Signing Certificate") > 0) {
                        ca_audit_signing_cert_name = temp;
                    } else {
                        server_cert_name = temp;
                    }
                }
            }
		
            System.out.println("default: ca_cert_name=" + ca_cert_name);
            System.out.println("default: ocsp_cert_name=" + ocsp_cert_name);
            System.out.println(
                "default: ca_subsystem_cert_name=" + ca_subsystem_cert_name);
            System.out.println(
                "default: ca_audit_signing_cert_name=" + ca_audit_signing_cert_name);
            System.out.println("default: server_cert_name=" + server_cert_name);
            return true;
        } catch (Exception e) {
            System.out.println("Exception in KeyPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean CertSubjectPanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();
            ArrayList req_list = null;
            ArrayList cert_list = null;
            ArrayList dn_list = null;
            String query_string = null;

            // use subject names provided as input

            if (!clone) {
                query_string = "p=11" + "&op=next" + "&xml=true" + "&subsystem="
                    + URLEncoder.encode(ca_subsystem_cert_subject_name)
                    + "&ocsp_signing="
                    + URLEncoder.encode(ca_ocsp_cert_subject_name) + "&signing="
                    + URLEncoder.encode(ca_sign_cert_subject_name) + "&sslserver="
                    + URLEncoder.encode(ca_server_cert_subject_name) + "&audit_signing=" 
                    + URLEncoder.encode(ca_audit_signing_cert_subject_name) + "&urls=0"
                    + "";
            } else {
                query_string = "p=11" + "&op=next" + "&xml=true" + "&sslserver="
                    + URLEncoder.encode(ca_server_cert_subject_name) + "&urls=0"
                    + "";
            } 

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();
		
            req_list = px.constructvaluelist("CertReqPair", "Request");
            cert_list = px.constructvaluelist("CertReqPair", "Certificate");
            dn_list = px.constructvaluelist("CertReqPair", "Nickname");

            System.out.println("req_list_size=" + req_list.size());
            System.out.println("cert_list_size=" + cert_list.size());
            System.out.println("dn_list_size=" + dn_list.size());

            if (external_ca.equalsIgnoreCase("true")) {
                if ((req_list != null) && (dn_list != null)) {
                    for (int i = 0; i < dn_list.size(); i++) {
                        String temp = (String) dn_list.get(i);
                        if (temp.indexOf("caSigningCert") >= 0) {
                            ca_cert_req = (String) req_list.get(i);
                        }
                    }
                }

                if (ext_ca_cert_file == null) {
                    try { 
                        FileOutputStream fos = new FileOutputStream(ext_csr_file);
                        PrintStream p = new PrintStream( fos );
                        p.println(ca_cert_req);
                        p.close();
                        return true;
                    } catch (Exception e) {
                        System.out.println("CertSubjectPanel: Unable to write CSR for external CA to "+ ext_csr_file);
                        System.out.println(e.toString());
		        return false;
                    } 
                }
                else {
                    try { 
                        ca_cert_cert = "";
                        FileInputStream fis = new FileInputStream(ext_ca_cert_file);
                        DataInputStream in = new DataInputStream(fis);
                        while (in.available() !=0) {
                            ca_cert_cert += in.readLine();
                        }
                        in.close();
               
                        signing_cc = "";
                        fis = new FileInputStream(ext_ca_cert_chain_file);
                        in = new DataInputStream(fis);
                        while (in.available() !=0) {
                            signing_cc += in.readLine();
                        }
                        in.close();
                        return true;
                    }
                    catch (Exception e) {
                        System.out.println("CertSubjectPanel: Unable to read in external approved CA cert or certificate chain.");
                        System.out.println(e.toString());
                        return false;
                    }
                }
            }

            if (req_list != null && cert_list != null && dn_list != null) {
                for (int i = 0; i < dn_list.size(); i++) {
                    String temp = (String) dn_list.get(i);
					
                    if (temp.indexOf("caSigningCert") >= 0) {
                        ca_cert_req = (String) req_list.get(i);
                        ca_cert_cert = (String) cert_list.get(i);
                    } else if (temp.indexOf("ocspSigningCert") >= 0) {
                        ocsp_cert_req = (String) req_list.get(i);
                        ocsp_cert_cert = (String) cert_list.get(i);
                    } else if (temp.indexOf("subsystemCert") >= 0) {
                        ca_subsystem_cert_req = (String) req_list.get(i);
                        ca_subsystem_cert_cert = (String) cert_list.get(i);
                    } else if (temp.indexOf("auditSigningCert") >=0) {
                        ca_audit_signing_cert_req = (String) req_list.get(i);
                        ca_audit_signing_cert_cert = (String) cert_list.get(i);
                    } else {
                        server_cert_req = (String) req_list.get(i);
                        server_cert_cert = (String) cert_list.get(i);
                    }
                }
            }
	
            // print out subject names	
            System.out.println("ca_cert_name=" + ca_sign_cert_subject_name);
            System.out.println("ocsp_cert_name=" + ca_ocsp_cert_subject_name);
            System.out.println(
                "ca_subsystem_cert_name=" + ca_subsystem_cert_subject_name);
            System.out.println("server_cert_name=" + ca_server_cert_subject_name);
            System.out.println("audit_signing_cert_name=" + ca_audit_signing_cert_subject_name);

            // print out requests
            System.out.println("ca_cert_req=" + ca_cert_req);
            System.out.println("ocsp_cert_req=" + ocsp_cert_req);
            System.out.println("ca_subsystem_cert_req=" + ca_subsystem_cert_req);
            System.out.println("server_cert_req=" + server_cert_req);
            System.out.println("ca_audit_siging_cert_req=" + ca_audit_signing_cert_req);

            // print out certs
            System.out.println("ca_cert_cert=" + ca_cert_cert);
            System.out.println("ocsp_cert_cert=" + ocsp_cert_cert);
            System.out.println("ca_subsystem_cert_cert=" + ca_subsystem_cert_cert);
            System.out.println("server_cert_cert=" + server_cert_cert);
            System.out.println("ca_audit_signing_cert_cert=" + ca_audit_signing_cert_cert);

            return true;
        } catch (Exception e) {
            System.out.println("Exception in CertSubjectPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }

    }

    public boolean CertificatePanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();
            ArrayList req_list = null;
            ArrayList cert_list = null;
            ArrayList dn_list = null;
            ArrayList pp_list = null;

            String query_string = "p=12" + "&op=next" + "&xml=true" + "&subsystem="
                + URLEncoder.encode(ca_subsystem_cert_cert) + "&subsystem_cc="
                + "&ocsp_signing=" + URLEncoder.encode(ocsp_cert_cert)
                + "&ocsp_signing_cc=" + "&signing="
                + URLEncoder.encode(ca_cert_cert) + "&signing_cc="
                + "&audit_signing=" + URLEncoder.encode(ca_audit_signing_cert_cert) 
                + "&audit_signing_cc="
                + "&sslserver=" + URLEncoder.encode(server_cert_cert)
                + "&sslserver_cc=" + ""; 

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();
		
            return true;
        } catch (Exception e) {
            System.out.println("Exception in CertificatePanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }

    }

    public boolean CertificatePanelExternal() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();
            ArrayList req_list = null;
            ArrayList cert_list = null;
            ArrayList dn_list = null;
            ArrayList pp_list = null;
            String genString = "...certificate be generated internally...";

            String query_string = "p=12" + "&op=apply" + "&xml=true" + "&subsystem="
                + URLEncoder.encode(genString) + "&subsystem_cc="
                + "&ocsp_signing=" + URLEncoder.encode(genString)
                + "&ocsp_signing_cc=" + "&signing="
                + URLEncoder.encode(ca_cert_cert) + "&signing_cc=" 
                + URLEncoder.encode(signing_cc)
                + "&audit_signing=" + URLEncoder.encode(genString) 
                + "&audit_signing_cc=" 
                + "&sslserver=" + URLEncoder.encode(genString)
                + "&sslserver_cc=" + ""; 

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);


            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();

            req_list = px.constructvaluelist("CertReqPair", "Request");
            cert_list = px.constructvaluelist("CertReqPair", "Certificate");
            dn_list = px.constructvaluelist("CertReqPair", "Nickname");

            System.out.println("req_list_size=" + req_list.size());
            System.out.println("cert_list_size=" + cert_list.size());
            System.out.println("dn_list_size=" + dn_list.size());

            if (req_list != null && cert_list != null && dn_list != null) {
                for (int i = 0; i < dn_list.size(); i++) {
                    String temp = (String) dn_list.get(i);

                    if (temp.indexOf("caSigningCert") >= 0) {
                        ca_cert_req = (String) req_list.get(i);
                        ca_cert_cert = (String) cert_list.get(i);
                    } else if (temp.indexOf("ocspSigningCert") >= 0) {
                        ocsp_cert_req = (String) req_list.get(i);
                        ocsp_cert_cert = (String) cert_list.get(i);
                    } else if (temp.indexOf("subsystemCert") >= 0) {
                        ca_subsystem_cert_req = (String) req_list.get(i);
                        ca_subsystem_cert_cert = (String) cert_list.get(i);
                    } else if (temp.indexOf("auditSigningCert") >= 0) {
                        ca_audit_signing_cert_req = (String) req_list.get(i);
                        ca_audit_signing_cert_cert = (String) cert_list.get(i);
                    } else {
                        server_cert_req = (String) req_list.get(i);
                        server_cert_cert = (String) cert_list.get(i);
                    }
                }
            }

            // print out subject name
            System.out.println("ca_cert_name=" + ca_sign_cert_subject_name);
            System.out.println("ocsp_cert_name=" + ca_ocsp_cert_subject_name);
            System.out.println(
                "ca_subsystem_cert_name=" + ca_subsystem_cert_subject_name);
            System.out.println("server_cert_name=" + ca_server_cert_subject_name);
            System.out.println(
                "ca_audit_signing_cert_name=" + ca_audit_signing_cert_subject_name);

            // print out requests
            System.out.println("ca_cert_req=" + ca_cert_req);
            System.out.println("ocsp_cert_req=" + ocsp_cert_req);
            System.out.println("ca_subsystem_cert_req=" + ca_subsystem_cert_req);
            System.out.println("server_cert_req=" + server_cert_req);
            System.out.println("ca_audit_signing_cert_req=" + ca_audit_signing_cert_req);

            // print out certs
            System.out.println("ca_cert_cert=" + ca_cert_cert);
            System.out.println("ocsp_cert_cert=" + ocsp_cert_cert);
            System.out.println("ca_subsystem_cert_cert=" + ca_subsystem_cert_cert);
            System.out.println("server_cert_cert=" + server_cert_cert);
            System.out.println("ca_audit_signing_cert_cert=" + ca_audit_signing_cert_cert);

            return true;
        } catch (Exception e) {
            System.out.println("Exception in CertificatePanelExternal(): " + e.toString());
            e.printStackTrace();
            return false;
        }

    }

    public boolean BackupPanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();

            if (save_p12.equalsIgnoreCase("true")) {
                String query_string = "p=13" + "&op=next" + "&xml=true"
                    + "&choice=backupkey" + "&__pwd=" + backup_pwd
                    + "&__pwdagain=" + backup_pwd + ""; 

                hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

                // parse xml
                bais = new ByteArrayInputStream(hr.getHTML().getBytes());
                px.parse(bais);
                px.prettyprintxml();

                query_string = ""; 

                hr = hc.sslConnect(cs_hostname, cs_port, pkcs12_uri, query_string);

                // dump hr.getResponseData() to file

                try {
                    FileOutputStream fos = new FileOutputStream(backup_fname);

                    fos.write(hr.getResponseData());
                    fos.close();

                    // set file to permissions 600
                    String rtParams[] = { "chmod","600", backup_fname};
                    Process proc = Runtime.getRuntime().exec(rtParams);

                    BufferedReader br = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
                    String line = null;
                    while ( (line = br.readLine()) != null)
                        System.out.println("Error: "  + line);
                    int exitVal = proc.waitFor();

                    // verify p12 file
                    // Decode the P12 file
                    FileInputStream fis = new FileInputStream(backup_fname);
                    PFX.Template pfxt = new PFX.Template();
                    PFX pfx = (PFX) pfxt.decode(new BufferedInputStream(fis, 2048));

                    System.out.println("Decoded PFX");

                    // now peruse it for interesting info
                    System.out.println("Version: " + pfx.getVersion());
                    AuthenticatedSafes authSafes = pfx.getAuthSafes();
                    SEQUENCE asSeq = authSafes.getSequence();

                    System.out.println(
                        "AuthSafes has " + asSeq.size() + " SafeContents");

                    fis.close();
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            }

            return true;
        } catch (Exception e) {
            System.out.println("Exception in BackupPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean BackupContinuePanel() {
        try {
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri,
                "p=14&op=next&xml=true");

            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();

	    return true;
        } catch (Exception e) {
            System.out.println("Exception in BackupContinuePanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean ImportCACertPanel() {
        try {
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri,
                "p=15&op=next&xml=true");

            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();

	    return true;
        } catch (Exception e) {
            System.out.println("Exception in ImportCACertPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean AdminCertReqPanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();
            String admin_cert_request = null;

            ComCrypto cCrypt = new ComCrypto(client_certdb_dir, client_certdb_pwd,
                agent_cert_subject, agent_key_size, agent_key_type);

            cCrypt.setDebug(true);
            cCrypt.setGenerateRequest(true);
            cCrypt.setTransportCert(null);
            cCrypt.setDualKey(false);
            cCrypt.loginDB();

            String crmf_request = cCrypt.generateCRMFrequest();

            if (crmf_request == null) {
                System.out.println("ERROR: AdminCertReqPanel() cert req gen failed");
                return false;
            }

            admin_cert_request = crmf_request;

            String query_string = "p=16" + "&op=next" + "&xml=true"
                + "&cert_request_type=" + "crmf" + "&uid=" + admin_user
                + "&name=" + admin_user + "&__pwd=" + admin_password
                + "&__admin_password_again=" + admin_password + "&profileId="
                + "caAdminCert" + "&email=" + URLEncoder.encode(admin_email)
                + "&cert_request=" + URLEncoder.encode(admin_cert_request)
                + "&subject=" + URLEncoder.encode(agent_cert_subject)
				+ "&clone=new"
                + "&import=true" + "&securitydomain="
                + URLEncoder.encode(domain_name) + ""; 

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();
		
            admin_serial_number = px.getvalue("serialNumber");

            return true;
        } catch (Exception e) {
            System.out.println("Exception in AdminCertReqPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }

    }

    public boolean AdminCertImportPanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();
            String cert_to_import = null;

            String query_string = "&serialNumber=" + admin_serial_number
                + "&importCert=true" + "";

            hr = hc.sslConnect(cs_hostname, cs_port, admin_uri, query_string);
		
            try {
                // get response data
                // cert_to_import = OSUtil.BtoA(hr.getResponseData());
                // Convert a byte array to base64 string
                cert_to_import = new sun.misc.BASE64Encoder().encode(
                    hr.getResponseData());

                // Convert base64 string to a byte array
                // buf = new sun.misc.BASE64Decoder().decodeBuffer(s);

                System.out.println("Cert to Import =" + cert_to_import);
            } catch (Exception e) {
                System.out.println("ERROR: failed to retrieve cert");
            }

            System.out.println("Cert to Import =" + cert_to_import);
            ComCrypto cCrypt = new ComCrypto(client_certdb_dir, client_certdb_pwd,
                null, null, null);

            cCrypt.setDebug(true);
            cCrypt.setGenerateRequest(true);
            cCrypt.loginDB();

            String start = "-----BEGIN CERTIFICATE-----\r\n";
            String end = "\r\n-----END CERTIFICATE-----";

            st = cCrypt.importCert(start + cert_to_import + end, agent_name);
            if (!st) {
                System.out.println(
                    "ERROR: AdminCertImportPanel() during cert import");
                return false;
            }

            System.out.println("SUCCESS: imported admin user cert");
            return true;
        } catch (Exception e) {
            System.out.println("Exception in AdminCertImportPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean UpdateDomainPanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();

            String query_string = "p=17" + "&op=next" + "&xml=true" + "&caHost="
                + URLEncoder.encode("/") + "&caPort=" + URLEncoder.encode("/")
                + ""; 

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();
		
            String caHost = px.getvalue("host");
            String caPort = px.getvalue("port");
            String systemType = px.getvalue("systemType");

            System.out.println("caHost=" + caHost);
            System.out.println("caPort=" + caPort);
            System.out.println("systemType=" + systemType);
		
            /*
             query_string = "p=18" + "&op=next" + "&xml=true" +
             "&caHost=" + URLEncoder.encode(caHost) +
             "&caPort=" + URLEncoder.encode(caPort) +
             "&systemType=" + URLEncoder.encode(systemType) +
             ""; 

             hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

             // parse xml
             bais = new ByteArrayInputStream(hr.getHTML().getBytes());
             px.parse(bais);
             px.prettyprintxml();
             */

            return true;
        } catch (Exception e) {
            System.out.println("Exception in UpdateDomainPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }

    }

    public boolean ConfigureCAInstance() {
        // 0. login to cert db
        ComCrypto cCrypt = new ComCrypto(client_certdb_dir, client_certdb_pwd,
                null, null, null);

        cCrypt.setDebug(true);
        cCrypt.setGenerateRequest(true);
        cCrypt.loginDB();

        // instantiate http client
        // enable ecc if need be

        if (key_type.equalsIgnoreCase("ecc")) {
            boolean st = true;

            hc = new HTTPClient(st);
        } else {
            hc = new HTTPClient();
        }

        // 1. Login panel
        boolean log_st = LoginPanel();

        if (!log_st) {
            System.out.println("ERROR: ConfigureCA: LoginPanel() failure");
            return false;
        }

        sleep_time();
        // 2. Token Choice Panel
        boolean disp_token = TokenChoicePanel();

        if (!disp_token) {
            System.out.println("ERROR: ConfigureCA: TokenChoicePanel() failure");
            return false;
        }
        sleep_time();

        // 3. domain panel
        boolean dom_st = DomainPanel();

        if (!dom_st) {
            System.out.println("ERROR: ConfigureCA: DomainPanel() failure");
            return false;
        }

        sleep_time();
        // 4. display cert chain panel and security domain login
        if (clone) {
            boolean disp_st = DisplayCertChainPanel();
            if(!disp_st) {
                System.out.println("ERROR: ConfigureCA: DisplayCertChainPanel() failure");
                return false;
            }

            boolean sd_st = SecurityDomainLoginPanel();
            if(! sd_st)
            {
                System.out.println("ERROR: ConfigureSubCA: SecurityDomainLoginPanel() failure");
                return false;
            }

        }

        sleep_time();
        // 5. display create CA panel
        boolean disp_cert = CreateCAPanel();

        if (!disp_cert) {
            System.out.println("ERROR: ConfigureCA: CreateCAPanel() failure");
            return false;
        }

        sleep_time();
        // 6. display restore key cert panel
        if (clone) {
            boolean restore_st = RestoreKeyCertPanel();
            if (!restore_st) {
                System.out.println("ERROR: ConfigureCA: RestoreKeyCertPanel() failure");
                return false;
            }
        }

        // 6. Admin user panel
        // boolean disp_ad = AdminUserPanel();
        // if(!disp_ad)
        // {
        // System.out.println("ERROR: ConfigureCA: AdminUserPanel() failure");
        // return false;
        // }

        sleep_time();
        // 7. hierarchy panel
        if (! clone) {
            boolean disp_h = HierarchyPanel();

            if (!disp_h) {
                System.out.println("ERROR: ConfigureCA: HierarchyPanel() failure");
                return false;
            }
        }

        // Agent Auth panel
        // boolean disp_ag = AgentAuthPanel();
        // if(!disp_ag)
        // {
        // System.out.println("ERROR: ConfigureCA: AgentAuthPanel() failure");
        // return false;
        // }

        sleep_time();
        // 8. ldap connection panel
        boolean disp_ldap = LdapConnectionPanel();

        if (!disp_ldap) {
            System.out.println(
                    "ERROR: ConfigureCA: LdapConnectionPanel() failure");
            return false;
        }

        sleep_time();
        sleep_time();
        // 9. Key Panel
        boolean disp_key = KeyPanel();

        if (!disp_key) {
            System.out.println("ERROR: ConfigureCA: KeyPanel() failure");
            return false;
        }

        sleep_time();
        // 10. Cert Subject Panel
        boolean disp_csubj = CertSubjectPanel();

        if (!disp_csubj) {
            System.out.println("ERROR: ConfigureCA: CertSubjectPanel() failure");
            return false;
        }

        sleep_time();
        // 11. Certificate Panel
        boolean disp_cp;

        if (external_ca.equalsIgnoreCase("true")) {
            if (ext_ca_cert_file != null) {
                // second pass - cacert file defined
                disp_cp = CertificatePanelExternal();

                if (!disp_cp) {
                    System.out.println("ERROR: ConfigureCA: CertificatePanelExternal() failure");
                    return false;
                }
            }
            else {
               // first pass - cacert file not defined
               System.out.println("A Certificate Request has been generated and stored in " + ext_csr_file);
               System.out.println("Please submit this CSR to your external CA and obtain the CA Cert and CA Cert Chain");
               return true;
            }
        }

        disp_cp = CertificatePanel();

        if (!disp_cp) {
            System.out.println("ERROR: ConfigureCA: CertificatePanel() failure");
            return false;
        }

        // 12. Certificate PP Panel
        // boolean disp_pp = CertPPPanel();
        // if(!disp_pp)
        // {
        // System.out.println("ERROR: ConfigureCA: CertificatePPPanel() failure");
        // return false;
        // }

        sleep_time();
        // 13. Backup Panel
        boolean disp_back = BackupPanel();

        if (!disp_back) {
            System.out.println("ERROR: ConfigureCA: BackupPanel() failure");
            return false;
        }

        sleep_time();
        // 14. Backup Continue Panel
        boolean disp_back_cont = BackupContinuePanel();

        if (!disp_back_cont) {
            System.out.println("ERROR: ConfigureCA: BackupContinuePanel() failure");
            return false;
        }

        sleep_time();

        // 15. Import CA Cert panel
        boolean disp_import_cacert = ImportCACertPanel();

        if (!disp_import_cacert) {
            System.out.println("ERROR: ConfigureCA: ImportCACertPanel() failure");
            return false;
        }
     
        if (clone) { 
            // no other panels required for clone
            return true;
        }

        sleep_time();

        // 16. Admin Cert Req Panel
        boolean disp_adm = AdminCertReqPanel();

        if (!disp_adm) {
            System.out.println("ERROR: ConfigureCA: AdminCertReqPanel() failure");
            return false;
        }

        sleep_time();
        // 14. Admin Cert import Panel
        boolean disp_im = AdminCertImportPanel();

        if (!disp_im) {
            System.out.println(
                    "ERROR: ConfigureCA: AdminCertImportPanel() failure");
            return false;
        }

        sleep_time();
        // 15. Update Domain Panel
        boolean disp_ud = UpdateDomainPanel();

        if (!disp_ud) {
            System.out.println("ERROR: ConfigureCA: UpdateDomainPanel() failure");
            return false;
        }

        return true;
    }

    public static void main(String args[]) {
        ConfigureCA ca = new ConfigureCA();

        // set variables
        StringHolder x_cs_hostname = new StringHolder();
        StringHolder x_cs_port = new StringHolder();
        StringHolder x_client_certdb_dir = new StringHolder();
        StringHolder x_client_certdb_pwd = new StringHolder();
        StringHolder x_preop_pin = new StringHolder();

        StringHolder x_domain_name = new StringHolder();

        StringHolder x_admin_user = new StringHolder();
        StringHolder x_admin_email = new StringHolder();
        StringHolder x_admin_password = new StringHolder();

        // ldap 

        StringHolder x_ldap_host = new StringHolder();
        StringHolder x_ldap_port = new StringHolder();
        StringHolder x_bind_dn = new StringHolder();
        StringHolder x_bind_password = new StringHolder();
        StringHolder x_base_dn = new StringHolder();
        StringHolder x_db_name = new StringHolder();

        // key size
        StringHolder x_key_size = new StringHolder();
        StringHolder x_key_type = new StringHolder();
        StringHolder x_key_algorithm = new StringHolder();
        StringHolder x_token_name = new StringHolder();
        StringHolder x_token_pwd = new StringHolder();

        StringHolder x_agent_name = new StringHolder();
        StringHolder x_save_p12 = new StringHolder();
        StringHolder x_backup_pwd = new StringHolder();
        StringHolder x_backup_fname = new StringHolder();

        // separate key size for agent cert

        StringHolder x_agent_key_size = new StringHolder();
        StringHolder x_agent_key_type = new StringHolder();
        StringHolder x_agent_cert_subject = new StringHolder();

        // ca cert subject name params
        StringHolder x_ca_sign_cert_subject_name = new StringHolder();
        StringHolder x_ca_subsystem_cert_subject_name = new StringHolder();
        StringHolder x_ca_ocsp_cert_subject_name = new StringHolder();
        StringHolder x_ca_server_cert_subject_name = new StringHolder();
        StringHolder x_ca_audit_signing_cert_subject_name = new StringHolder();

        // subsystemName
        StringHolder x_subsystem_name = new StringHolder();

        // external CA cert
        StringHolder x_external_ca = new StringHolder();
        StringHolder x_ext_ca_cert_file = new StringHolder();         
        StringHolder x_ext_ca_cert_chain_file = new StringHolder();         
        StringHolder x_ext_csr_file = new StringHolder();         

        //clone parameters
        StringHolder x_clone = new StringHolder();
        StringHolder x_clone_uri = new StringHolder();
        StringHolder x_clone_p12_file = new StringHolder();
        StringHolder x_clone_p12_passwd = new StringHolder();

        //security domain
        StringHolder x_sd_hostname = new StringHolder();
        StringHolder x_sd_ssl_port = new StringHolder();
        StringHolder x_sd_agent_port = new StringHolder();
        StringHolder x_sd_admin_port = new StringHolder();
        StringHolder x_sd_admin_name = new StringHolder();
        StringHolder x_sd_admin_password = new StringHolder();


        // parse the args
        ArgParser parser = new ArgParser("ConfigureCA");

        parser.addOption("-cs_hostname %s #CS Hostname", x_cs_hostname); 
        parser.addOption("-cs_port %s #CS SSL Admin port", x_cs_port); 
        parser.addOption("-client_certdb_dir %s #Client CertDB dir",
                x_client_certdb_dir); 
        parser.addOption("-client_certdb_pwd %s #client certdb password",
                x_client_certdb_pwd); 
        parser.addOption("-preop_pin %s #pre op pin", x_preop_pin); 
        parser.addOption("-domain_name %s #domain name", x_domain_name); 
        parser.addOption("-admin_user %s #Admin User Name", x_admin_user); 
        parser.addOption("-admin_email %s #Admin email", x_admin_email); 
        parser.addOption("-admin_password %s #Admin password", x_admin_password); 
        parser.addOption("-agent_name %s #Agent Cert Nickname", x_agent_name); 
        parser.addOption("-agent_key_size %s #Agent Cert Key size",
                x_agent_key_size); 
        parser.addOption("-agent_key_type %s #Agent Cert Key type [rsa]",
                x_agent_key_type); 
        parser.addOption("-agent_cert_subject %s #Agent Certificate Subject",
                x_agent_cert_subject); 

        parser.addOption("-ldap_host %s #ldap host", x_ldap_host); 
        parser.addOption("-ldap_port %s #ldap port", x_ldap_port); 
        parser.addOption("-bind_dn %s #ldap bind dn", x_bind_dn); 
        parser.addOption("-bind_password %s #ldap bind password",
                x_bind_password); 
        parser.addOption("-base_dn %s #base dn", x_base_dn); 
        parser.addOption("-db_name %s #db name", x_db_name); 

        parser.addOption("-key_size %s #Key Size", x_key_size); 
        parser.addOption("-key_type %s #Key type [RSA,ECC]", x_key_type); 
        parser.addOption("-key_algorithm %s #Key algorithm", x_key_algorithm);
        parser.addOption("-token_name %s #HSM/Software Token name", x_token_name); 
        parser.addOption("-token_pwd %s #HSM/Software Token password (optional - only required for HSM)",
                x_token_pwd); 

        parser.addOption("-save_p12 %s #Enable/Disable p12 Export[true,false]",
                x_save_p12); 
        parser.addOption("-backup_pwd %s #Backup Password for p12 (optional, only required if -save_p12 = true)", x_backup_pwd); 
        parser.addOption("-backup_fname %s #Backup File for p12, (optional, default is /root/tmp-ca.p12)", x_backup_fname);

        parser.addOption("-ca_sign_cert_subject_name %s #CA cert subject name",
                x_ca_sign_cert_subject_name);
        parser.addOption(
                "-ca_subsystem_cert_subject_name %s #CA subsystem cert subject name",
                x_ca_subsystem_cert_subject_name); 
        parser.addOption(
                "-ca_ocsp_cert_subject_name %s #CA ocsp cert subject name",
                x_ca_ocsp_cert_subject_name); 
        parser.addOption(
                "-ca_server_cert_subject_name %s #CA server cert subject name",
                x_ca_server_cert_subject_name); 
        parser.addOption(
                "-ca_audit_signing_cert_subject_name %s #CA audit signing cert subject name",
                x_ca_audit_signing_cert_subject_name); 

        parser.addOption("-subsystem_name %s #CA subsystem name",
                x_subsystem_name); 
        
        parser.addOption("-external %s #Subordinate to external CA [true,false] (optional, default false)",
                x_external_ca); 
        parser.addOption("-ext_ca_cert_file %s #File with CA cert from external CA (optional)",
                x_ext_ca_cert_file); 
        parser.addOption("-ext_ca_cert_chain_file %s #File with CA cert from external CA (optional)",
                x_ext_ca_cert_chain_file);
        parser.addOption("-ext_csr_file %s #File to save the CSR for submission to an external CA (optional)",
                x_ext_csr_file);

        parser.addOption("-clone %s #Clone of another CA [true, false] (optional, default false)", x_clone);
        parser.addOption("-clone_uri %s #URL of Master CA to clone. It must have the form https://<hostname>:<EE port> (optional, required if -clone=true)", x_clone_uri);
        parser.addOption("-clone_p12_file %s #File containing pk12 keys of Master CA (optional, required if -clone=true)", x_clone_p12_file);
        parser.addOption("-clone_p12_password %s #Password for pk12 file (optional, required if -clone=true)", x_clone_p12_passwd);

        parser.addOption ("-sd_hostname %s #Security Domain Hostname (optional, required if -clone=true)", x_sd_hostname);
        parser.addOption ("-sd_ssl_port %s #Security Domain SSL EE port (optional, required if -clone=true)", x_sd_ssl_port);
        parser.addOption ("-sd_agent_port %s #Security Domain SSL Agent port (optional, required if -clone=true)", x_sd_agent_port);
        parser.addOption ("-sd_admin_port %s #Security Domain SSL Admin port (optional, required if -clone=true)", x_sd_admin_port);
        parser.addOption ("-sd_admin_name %s #Security Domain admin name (optional, required if -clone=true)",
            x_sd_admin_name);
        parser.addOption ("-sd_admin_password %s #Security Domain admin password (optional, required if -clone=true)",
            x_sd_admin_password);


        // and then match the arguments
        String[] unmatched = null;

        unmatched = parser.matchAllArgs(args, 0, parser.EXIT_ON_UNMATCHED);

        if (unmatched != null) {
            System.out.println("ERROR: Argument Mismatch");
            System.exit(-1);
        }

        parser.checkRequiredArgs();

        // set variables
        cs_hostname = x_cs_hostname.value;
        cs_port = x_cs_port.value;
        client_certdb_dir = x_client_certdb_dir.value;
        client_certdb_pwd = x_client_certdb_pwd.value;
        pin = x_preop_pin.value;
        domain_name = x_domain_name.value;
        admin_user = x_admin_user.value;
        admin_email = x_admin_email.value;
        admin_password = x_admin_password.value;
        agent_name = x_agent_name.value;

        ldap_host = x_ldap_host.value;
        ldap_port = x_ldap_port.value;
        bind_dn = x_bind_dn.value;
        bind_password = x_bind_password.value;
        base_dn = x_base_dn.value;
        db_name = x_db_name.value;

        key_size = x_key_size.value;
        key_type = x_key_type.value;
        if ((x_key_algorithm.value == null) || (x_key_algorithm.equals(""))) {
            key_algorithm = "SHA256withRSA";
        } else {
            key_algorithm = x_key_algorithm.value;
        }
        token_name = x_token_name.value;
        token_pwd = x_token_pwd.value;
        save_p12 = x_save_p12.value;
        backup_pwd = x_backup_pwd.value;
        if ((x_backup_fname.value == null) || (x_backup_fname.equals(""))) {
            backup_fname = "/root/tmp-ca.p12";
        } else {
            backup_fname = x_backup_fname.value;
        }

        agent_key_size = x_agent_key_size.value;
        agent_key_type = x_agent_key_type.value;
        agent_cert_subject = x_agent_cert_subject.value;

        ca_sign_cert_subject_name = x_ca_sign_cert_subject_name.value;
        ca_subsystem_cert_subject_name = x_ca_subsystem_cert_subject_name.value;
        ca_ocsp_cert_subject_name = x_ca_ocsp_cert_subject_name.value;
        ca_server_cert_subject_name = x_ca_server_cert_subject_name.value;
        ca_audit_signing_cert_subject_name = x_ca_audit_signing_cert_subject_name.value;
		
        subsystem_name = x_subsystem_name.value;
        
        external_ca = x_external_ca.value;
        if (external_ca == null) { 
            external_ca = "false";
        }
        ext_ca_cert_file = x_ext_ca_cert_file.value;
        ext_ca_cert_chain_file = x_ext_ca_cert_chain_file.value;
        ext_csr_file = x_ext_csr_file.value;
        if ((ext_csr_file == null) || (ext_csr_file.equals(""))) {
            ext_csr_file = "/tmp/ext_ca.csr";
        }

        if ((x_clone.value != null) && (x_clone.value.equalsIgnoreCase("true"))) {
            clone = true;
        } else {
            clone = false;
        }
        clone_uri = x_clone_uri.value;
        clone_p12_file = x_clone_p12_file.value;
        clone_p12_passwd = x_clone_p12_passwd.value;

        sd_hostname = x_sd_hostname.value;
        sd_ssl_port = x_sd_ssl_port.value;
        sd_agent_port = x_sd_agent_port.value;
        sd_admin_port = x_sd_admin_port.value;
        sd_admin_name = x_sd_admin_name.value;
        sd_admin_password = x_sd_admin_password.value;

        boolean st = ca.ConfigureCAInstance();
	
        if (!st) {
            System.out.println("ERROR: unable to create CA");
            System.exit(-1);
        }
	
        System.out.println("Certificate System - CA Instance Configured.");
        System.exit(0);
		
    }

}


;
