package com.netscape.pkisilent;

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

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URLEncoder;
import java.util.ArrayList;

import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.PFX;

import com.netscape.osutil.OSUtil;
import com.netscape.pkisilent.argparser.ArgParser;
import com.netscape.pkisilent.argparser.StringHolder;
import com.netscape.pkisilent.common.ComCrypto;
import com.netscape.pkisilent.common.ParseXML;
import com.netscape.pkisilent.http.HTTPClient;
import com.netscape.pkisilent.http.HTTPResponse;

public class ConfigureCA {

    // global constants
    public static final String DEFAULT_KEY_TYPE = "RSA";
    public static final String DEFAULT_KEY_SIZE = "2048";
    public static final String DEFAULT_KEY_CURVENAME = "nistp256";
    public static final String DEFAULT_KEY_ALGORITHM_RSA = "SHA256withRSA";
    public static final String DEFAULT_KEY_ALGORITHM_ECC = "SHA256withEC";
    public static final String SUCCESS = "success";
    public static final String FAILURE = "failure";

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
    public static String secure_conn = null;
    public static String clone_start_tls = null;
    public static String remove_data = null;

    public static String key_type = null;
    public static String key_size = null;
    public static String key_curvename = null;
    public static String key_algorithm = null;
    public static String signing_algorithm = null;

    public static String signing_key_type = null;
    public static String signing_key_size = null;
    public static String signing_key_curvename = null;
    public static String signing_signingalgorithm = null;

    public static String ocsp_signing_key_type = null;
    public static String ocsp_signing_key_size = null;
    public static String ocsp_signing_key_curvename = null;
    public static String ocsp_signing_signingalgorithm = null;

    public static String subsystem_key_type = null;
    public static String subsystem_key_size = null;
    public static String subsystem_key_curvename = null;

    public static String audit_signing_key_type = null;
    public static String audit_signing_key_size = null;
    public static String audit_signing_key_curvename = null;

    public static String sslserver_key_type = null;
    public static String sslserver_key_size = null;
    public static String sslserver_key_curvename = null;

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

    public static String external_ca = null;
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

    public String getStatus(HTTPResponse hr, String name) {
        ByteArrayInputStream bais = null;
        String status = null;
        try {
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            ParseXML px = new ParseXML();
            px.parse(bais);
            px.prettyprintxml();
            status = px.getvalue(name);
        } catch (Exception e) {
            System.out.println("Exception in getStatus(): " + e.toString());
        }
        return status;
    }

    public boolean checkStatus(HTTPResponse hr, String name,
                               String expected, String location) {
        return checkStatus(hr, name, new String[] { expected }, location);
    }

    public boolean checkStatus(HTTPResponse hr, String name,
                               String[] expected, String location) {
        String status = getStatus(hr, name);
        if (status == null) {
            System.out.println("Error in " + location + ": " + name +
                               " value is null");
            return false;
        }
        for (int i = 0; i < expected.length; i++) {
            if (status.equals(expected[i])) {
                return true;
            }
        }
        System.out.println("Error in " + location + ": " + name +
                           " returns " + status);
        return false;
    }

    public boolean LoginPanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;

            String query_string = "pin=" + pin + "&xml=true";
            hr = hc.sslConnect(cs_hostname, cs_port, login_uri, query_string);
            System.out.println("xml returned: " + hr.getHTML());

            // parse xml here - nothing to parse

            // get cookie
            String temp = hr.getCookieValue("JSESSIONID");
            if (temp != null) {
                int index = temp.indexOf(";");

                HTTPClient.j_session_id = temp.substring(0, index);
                st = true;
            }

            hr = null;
            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri,
                    "p=0&op=next&xml=true");
            if (!checkStatus(hr, "status", "display", "LoginPanel()")) {
                return false;
            }

            return st;
        } catch (Exception e) {
            System.out.println("Exception in LoginPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean TokenChoicePanel() {
        try {
            HTTPResponse hr = null;
            String query_string = null;

            // Software Token
            if (token_name.equalsIgnoreCase("internal")) {
                query_string = "p=1" + "&op=next" + "&xml=true" + "&choice="
                        + URLEncoder.encode("Internal Key Storage Token") + "";
                hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
                if (!checkStatus(hr, "updateStatus", SUCCESS, "TokenChoicePanel()")) {
                    return false;
                }
            } // HSM
            else {
                // login to hsm first
                query_string = "p=2" + "&op=next" + "&xml=true" + "&uTokName="
                        + URLEncoder.encode(token_name) + "&__uPasswd="
                        + URLEncoder.encode(token_pwd) + "";
                hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
                if (!checkStatus(hr, "updateStatus", SUCCESS, "TokenChoicePanel()")) {
                    return false;
                }

                // choice with token name now
                query_string = "p=1" + "&op=next" + "&xml=true" + "&choice="
                        + URLEncoder.encode(token_name) + "";
                hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
                if (!checkStatus(hr, "updateStatus", SUCCESS, "TokenChoicePanel()")) {
                    return false;
                }
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
            String domain_url = "https://" + cs_hostname + ":" + cs_port;
            String query_string = null;

            if (!clone) {
                query_string = "sdomainURL=" + URLEncoder.encode(domain_url)
                        + "&sdomainName=" + URLEncoder.encode(domain_name)
                        + "&choice=newdomain" + "&p=3" + "&op=next" + "&xml=true";
            } else {
                domain_url = "https://" + sd_hostname + ":" + sd_admin_port;
                query_string = "sdomainURL=" + URLEncoder.encode(domain_url)
                        + "&sdomainName="
                        + "&choice=existingdomain" + "&p=3" + "&op=next" + "&xml=true";
            }

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
            if (!checkStatus(hr, "updateStatus", SUCCESS, "DomainPanel()")) {
                return false;
            }

            return true;
        } catch (Exception e) {
            System.out.println("Exception in DomainPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean DisplayCertChainPanel() {
        try {
            String query_string = "p=4" + "&op=next" + "&xml=true";
            hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
            return true;
        } catch (Exception e) {
            System.out.println("Exception in DisplayCertChainPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean SecurityDomainLoginPanel() {
        try {
            HTTPResponse hr = null;

            String subca_url = "https://" + cs_hostname + ":" + cs_port +
                    "/ca/admin/console/config/wizard" + "?p=5&subsystem=CA";

            String query_string = "url=" + URLEncoder.encode(subca_url);

            hr = hc.sslConnect(sd_hostname, sd_admin_port, sd_login_uri, query_string);

            String query_string_1 = "uid=" + sd_admin_name + "&pwd=" + URLEncoder.encode(sd_admin_password) +
                                    "&url=" + URLEncoder.encode(subca_url);

            hr = hc.sslConnect(sd_hostname, sd_admin_port, sd_get_cookie_uri,
                                                query_string_1);

            // get session id from security domain

            String subca_session_id = hr.getContentValue("header.session_id");
            String subca_url_1 = hr.getContentValue("header.url");

            System.out.println("SUBCA_SESSION_ID=" + subca_session_id);
            System.out.println("SUBCA_URL=" + subca_url_1);

            // use session id to connect back to subCA

            String query_string_2 = "p=5" + "&subsystem=CA" +
                    "&session_id=" + subca_session_id + "&xml=true";

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string_2);
            urls = hr.getHTML();
            int indx = urls.indexOf(clone_uri);
            if (indx < 0) {
                throw new Exception("Invalid clone_uri");
            }
            urls = urls.substring(urls.lastIndexOf("<option", indx), indx);
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
            HTTPResponse hr = null;
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
            if (!checkStatus(hr, "updateStatus", SUCCESS, "CreateCAPanel()")) {
                return false;
            }

            if (clone) {

                hr = null;
                query_string = "p=6" + "&op=next" + "&xml=true";
                hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
                if (!checkStatus(hr, "updateStatus", SUCCESS, "CreateCAPanel(2)")) {
                    return false;
                }
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
            HTTPResponse hr = null;

            String query_string = "p=7" + "&op=next" + "&xml=true"
                    + "&__password=" + URLEncoder.encode(clone_p12_passwd)
                    + "&path=" + URLEncoder.encode(clone_p12_file) + "";

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
            if (!checkStatus(hr, "updateStatus", SUCCESS, "RestoreKeyCertPanel()")) {
                return false;
            }
            return true;
        } catch (Exception e) {
            System.out.println("Exception in RestoreKeyCertPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean HierarchyPanel() {
        try {
            HTTPResponse hr = null;

            String query_string = "p=8" + "&op=next" + "&xml=true";
            if (external_ca.equalsIgnoreCase("true"))
                query_string += "&choice=join";
            else
                query_string += "&choice=root";

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
            if (!checkStatus(hr, "updateStatus", SUCCESS, "HierarchyPanel()")) {
                return false;
            }

            return true;
        } catch (Exception e) {
            System.out.println("Exception in HierarchyPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }

    }

    public boolean LdapConnectionPanel() {
        try {
            HTTPResponse hr = null;

            String query_string = "p=9" + "&op=next" + "&xml=true" + "&host="
                    + URLEncoder.encode(ldap_host) + "&port="
                    + URLEncoder.encode(ldap_port) + "&binddn="
                    + URLEncoder.encode(bind_dn) + "&__bindpwd="
                    + URLEncoder.encode(bind_password) + "&basedn="
                    + URLEncoder.encode(base_dn) + "&database="
                    + URLEncoder.encode(db_name) + "&display="
                    + URLEncoder.encode("$displayStr")
                    + (secure_conn.equals("true") ? "&secureConn=on" : "")
                    + (clone_start_tls.equals("true") ? "&cloneStartTLS=on" : "")
                    + (remove_data.equals("true") ? "&removeData=true" : "");

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
            if (!checkStatus(hr, "updateStatus", SUCCESS, "LdapConnectionPanel()")) {
                return false;
            }

            return true;
        } catch (Exception e) {
            System.out.println("Exception in LdapConnectionPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean KeyPanel() {
        try {
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();
            ArrayList<String> al = null;
            String query_string = null;
            if (clone) {
                query_string = "p=10" + "&op=next" + "&xml=true"
                        + "&sslserver_custom_size=" + sslserver_key_size
                        + "&sslserver_custom_curvename=" + sslserver_key_curvename
                        + "&sslserver_choice=custom"
                        + "&sslserver_keytype=" + sslserver_key_type
                        + "&choice=custom" + "&keytype=" + key_type
                        + "&custom_size=" + key_size;
            } else {
                query_string = "p=10" + "&op=next" + "&xml=true"
                        + "&subsystem_custom_size=" + subsystem_key_size
                        + "&subsystem_custom_curvename=" + subsystem_key_curvename
                        + "&subsystem_keytype=" + subsystem_key_type
                        + "&subsystem_choice=custom"
                        + "&sslserver_custom_size=" + sslserver_key_size
                        + "&sslserver_custom_curvename=" + sslserver_key_curvename
                        + "&sslserver_keytype=" + sslserver_key_type
                        + "&sslserver_choice=custom"
                        + "&signing_custom_size=" + signing_key_size
                        + "&signing_custom_curvename=" + signing_key_curvename
                        + "&signing_keytype=" + signing_key_type
                        + "&signing_choice=custom"
                        + "&signing_keyalgorithm=" + key_algorithm
                        + "&signing_signingalgorithm=" + signing_signingalgorithm
                        + "&ocsp_signing_custom_size=" + ocsp_signing_key_size
                        + "&ocsp_signing_custom_curvename=" + ocsp_signing_key_curvename
                        + "&ocsp_signing_keytype=" + ocsp_signing_key_type
                        + "&ocsp_signing_choice=custom"
                        + "&ocsp_signing_signingalgorithm=" + ocsp_signing_signingalgorithm
                        + "&audit_signing_custom_size=" + audit_signing_key_size
                        + "&audit_signing_custom_curvename=" + audit_signing_key_curvename
                        + "&audit_signing_keytype=" + audit_signing_key_type
                        + "&audit_signing_choice=custom"
                        + "&custom_size=" + key_size
                        + "&custom_curvename=" + key_curvename
                        + "&keytype=" + key_type
                        + "&choice=custom"
                        + "&signingalgorithm=" + signing_algorithm
                        + "&keyalgorithm=" + key_algorithm;
            }

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
            if (!checkStatus(hr, "updateStatus", SUCCESS, "KeyPanel()")) {
                return false;
            }

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);

            al = px.constructValueList("CertReqPair", "DN");
            // get ca cert subject name
            if (al != null) {
                for (int i = 0; i < al.size(); i++) {
                    String temp = al.get(i);

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
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();
            ArrayList<String> req_list = null;
            ArrayList<String> cert_list = null;
            ArrayList<String> dn_list = null;
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
            if (!checkStatus(hr, "updateStatus", SUCCESS, "CertSubjectPanel()")) {
                return false;
            }

            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);

            req_list = px.constructValueList("CertReqPair", "Request");
            cert_list = px.constructValueList("CertReqPair", "Certificate");
            dn_list = px.constructValueList("CertReqPair", "Nickname");

            System.out.println("req_list_size=" + req_list.size());
            System.out.println("cert_list_size=" + cert_list.size());
            System.out.println("dn_list_size=" + dn_list.size());

            if (external_ca.equalsIgnoreCase("true")) {
                if ((req_list != null) && (dn_list != null)) {
                    for (int i = 0; i < dn_list.size(); i++) {
                        String temp = dn_list.get(i);
                        if (temp.indexOf("caSigningCert") >= 0) {
                            ca_cert_req = req_list.get(i);
                        }
                    }
                }

                if (ext_ca_cert_file == null) {
                    try {
                        FileOutputStream fos = new FileOutputStream(ext_csr_file);
                        PrintStream p = new PrintStream(fos);
                        p.println(ca_cert_req);
                        p.close();
                        return true;
                    } catch (Exception e) {
                        System.out.println("CertSubjectPanel: Unable to write CSR for external CA to " + ext_csr_file);
                        System.out.println(e.toString());
                        return false;
                    }
                } else {
                    try {
                        ca_cert_cert = "";
                        FileInputStream fis = new FileInputStream(ext_ca_cert_file);
                        DataInputStream in = new DataInputStream(fis);
                        while (in.available() != 0) {
                            ca_cert_cert += in.readLine();
                        }
                        in.close();

                        signing_cc = "";
                        fis = new FileInputStream(ext_ca_cert_chain_file);
                        in = new DataInputStream(fis);
                        while (in.available() != 0) {
                            signing_cc += in.readLine();
                        }
                        in.close();
                        return true;
                    } catch (Exception e) {
                        System.out.println(
                               "CertSubjectPanel: Unable to read in external approved CA cert or certificate chain.");
                        System.out.println(e.toString());
                        return false;
                    }
                }
            }

            if (req_list != null && cert_list != null && dn_list != null) {
                for (int i = 0; i < dn_list.size(); i++) {
                    String temp = dn_list.get(i);

                    if (temp.indexOf("caSigningCert") >= 0) {
                        ca_cert_req = req_list.get(i);
                        ca_cert_cert = cert_list.get(i);
                    } else if (temp.indexOf("ocspSigningCert") >= 0) {
                        ocsp_cert_req = req_list.get(i);
                        ocsp_cert_cert = cert_list.get(i);
                    } else if (temp.indexOf("subsystemCert") >= 0) {
                        ca_subsystem_cert_req = req_list.get(i);
                        ca_subsystem_cert_cert = cert_list.get(i);
                    } else if (temp.indexOf("auditSigningCert") >= 0) {
                        ca_audit_signing_cert_req = req_list.get(i);
                        ca_audit_signing_cert_cert = cert_list.get(i);
                    } else {
                        server_cert_req = req_list.get(i);
                        server_cert_cert = cert_list.get(i);
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
            HTTPResponse hr = null;

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
            if (!checkStatus(hr, "updateStatus", SUCCESS, "CertificatePanel()")) {
                return false;
            }

            return true;
        } catch (Exception e) {
            System.out.println("Exception in CertificatePanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }

    }

    public boolean CertificatePanelExternal() {
        try {
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();
            ArrayList<String> req_list = null;
            ArrayList<String> cert_list = null;
            ArrayList<String> dn_list = null;
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
            if (!checkStatus(hr, "updateStatus", SUCCESS, "CertificatePanelExternal()")) {
                return false;
            }

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);

            req_list = px.constructValueList("CertReqPair", "Request");
            cert_list = px.constructValueList("CertReqPair", "Certificate");
            dn_list = px.constructValueList("CertReqPair", "Nickname");

            System.out.println("req_list_size=" + req_list.size());
            System.out.println("cert_list_size=" + cert_list.size());
            System.out.println("dn_list_size=" + dn_list.size());

            if (req_list != null && cert_list != null && dn_list != null) {
                for (int i = 0; i < dn_list.size(); i++) {
                    String temp = dn_list.get(i);

                    if (temp.indexOf("caSigningCert") >= 0) {
                        ca_cert_req = req_list.get(i);
                        ca_cert_cert = cert_list.get(i);
                    } else if (temp.indexOf("ocspSigningCert") >= 0) {
                        ocsp_cert_req = req_list.get(i);
                        ocsp_cert_cert = cert_list.get(i);
                    } else if (temp.indexOf("subsystemCert") >= 0) {
                        ca_subsystem_cert_req = req_list.get(i);
                        ca_subsystem_cert_cert = cert_list.get(i);
                    } else if (temp.indexOf("auditSigningCert") >= 0) {
                        ca_audit_signing_cert_req = req_list.get(i);
                        ca_audit_signing_cert_cert = cert_list.get(i);
                    } else {
                        server_cert_req = req_list.get(i);
                        server_cert_cert = cert_list.get(i);
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
            HTTPResponse hr = null;

            if (save_p12.equalsIgnoreCase("true")) {
                String query_string = "p=13" + "&op=next" + "&xml=true"
                        + "&choice=backupkey" + "&__pwd=" + URLEncoder.encode(backup_pwd)
                        + "&__pwdagain=" + URLEncoder.encode(backup_pwd);

                hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
                if (!checkStatus(hr, "updateStatus", SUCCESS, "BackupPanel()")) {
                    return false;
                }

                query_string = "";

                hr = hc.sslConnect(cs_hostname, cs_port, pkcs12_uri, query_string);

                // dump hr.getResponseData() to file

                try {
                    FileOutputStream fos = new FileOutputStream(backup_fname);

                    fos.write(hr.getResponseData());
                    fos.close();

                    // set file to permissions 600
                    String rtParams[] = { "chmod", "600", backup_fname };
                    Process proc = Runtime.getRuntime().exec(rtParams);

                    BufferedReader br = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
                    String line = null;
                    while ((line = br.readLine()) != null)
                        System.out.println("Error: " + line);
                    proc.waitFor();

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

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri,
                    "p=14&op=next&xml=true");
            if (!checkStatus(hr, "updateStatus", SUCCESS, "BackupContinuePanel()")) {
                return false;
            }

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

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri,
                    "p=15&op=next&xml=true");
            if (!checkStatus(hr, "updateStatus", SUCCESS, "ImportCACertPanel()")) {
                return false;
            }

            return true;
        } catch (Exception e) {
            System.out.println("Exception in ImportCACertPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean AdminCertReqPanel() {
        try {
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
                    + "&name=" + admin_user + "&__pwd=" + URLEncoder.encode(admin_password)
                    + "&__admin_password_again=" + URLEncoder.encode(admin_password) + "&profileId="
                    + "caAdminCert" + "&email=" + URLEncoder.encode(admin_email)
                    + "&cert_request=" + URLEncoder.encode(admin_cert_request)
                    + "&subject=" + URLEncoder.encode(agent_cert_subject)
                    + "&clone=new"
                    + "&import=true" + "&securitydomain="
                    + URLEncoder.encode(domain_name) + "";

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
            if (!checkStatus(hr, "updateStatus", SUCCESS, "AdminCertReqPanel()")) {
                return false;
            }

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);

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
            String cert_to_import = null;

            String query_string = "&serialNumber=" + admin_serial_number
                    + "&importCert=true" + "";

            hr = hc.sslConnect(cs_hostname, cs_port, admin_uri, query_string);

            try {
                // get response data
                // Convert a byte array to base64 string
                // cert_to_import = new sun.misc.BASE64Encoder().encode(
                //     hr.getResponseData());
                cert_to_import = OSUtil.BtoA(hr.getResponseData());

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
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();

            String query_string = "p=17" + "&op=next" + "&xml=true" + "&caHost="
                    + URLEncoder.encode("/") + "&caPort=" + URLEncoder.encode("/")
                    + "";

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
            if (!checkStatus(hr, "updateStatus", SUCCESS, "UpdateDomainPanel()")) {
                return false;
            }

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);

            String caHost = px.getvalue("host");
            String caPort = px.getvalue("port");
            String systemType = px.getvalue("systemType");

            System.out.println("caHost=" + caHost);
            System.out.println("caPort=" + caPort);
            System.out.println("systemType=" + systemType);

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
            hc = new HTTPClient(true);
        } else {
            hc = new HTTPClient(false);
        }

        // 1. Login panel
        boolean log_st = LoginPanel();

        if (!log_st) {
            System.out.println("ERROR: ConfigureCA: LoginPanel() failure");
            return false;
        }

        // 2. Token Choice Panel
        boolean disp_token = TokenChoicePanel();

        if (!disp_token) {
            System.out.println("ERROR: ConfigureCA: TokenChoicePanel() failure");
            return false;
        }

        // 3. domain panel
        boolean dom_st = DomainPanel();

        if (!dom_st) {
            System.out.println("ERROR: ConfigureCA: DomainPanel() failure");
            return false;
        }

        // 4. display cert chain panel and security domain login
        if (clone) {
            boolean disp_st = DisplayCertChainPanel();
            if (!disp_st) {
                System.out.println("ERROR: ConfigureCA: DisplayCertChainPanel() failure");
                return false;
            }

            boolean sd_st = SecurityDomainLoginPanel();
            if (!sd_st) {
                System.out.println("ERROR: ConfigureSubCA: SecurityDomainLoginPanel() failure");
                return false;
            }

        }

        // 5. display create CA panel
        boolean disp_cert = CreateCAPanel();

        if (!disp_cert) {
            System.out.println("ERROR: ConfigureCA: CreateCAPanel() failure");
            return false;
        }

        // 6. display restore key cert panel
        if (clone) {
            boolean restore_st = RestoreKeyCertPanel();
            if (!restore_st) {
                System.out.println("ERROR: ConfigureCA: RestoreKeyCertPanel() failure");
                return false;
            }
        }

        // 7. hierarchy panel
        if (!clone) {
            boolean disp_h = HierarchyPanel();

            if (!disp_h) {
                System.out.println("ERROR: ConfigureCA: HierarchyPanel() failure");
                return false;
            }
        }

        // 8. ldap connection panel
        boolean disp_ldap = LdapConnectionPanel();

        if (!disp_ldap) {
            System.out.println(
                    "ERROR: ConfigureCA: LdapConnectionPanel() failure");
            return false;
        }

        // 9. Key Panel
        boolean disp_key = KeyPanel();

        if (!disp_key) {
            System.out.println("ERROR: ConfigureCA: KeyPanel() failure");
            return false;
        }

        // 10. Cert Subject Panel
        boolean disp_csubj = CertSubjectPanel();

        if (!disp_csubj) {
            System.out.println("ERROR: ConfigureCA: CertSubjectPanel() failure");
            return false;
        }

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
            } else {
                // first pass - cacert file not defined
                System.out.println("A Certificate Request has been generated and stored in " + ext_csr_file);
                System.out.println(
                       "Please submit this CSR to your external CA and obtain the CA Cert and CA Cert Chain");
                return true;
            }
        }

        disp_cp = CertificatePanel();

        if (!disp_cp) {
            System.out.println("ERROR: ConfigureCA: CertificatePanel() failure");
            return false;
        }

        // 13. Backup Panel
        boolean disp_back = BackupPanel();

        if (!disp_back) {
            System.out.println("ERROR: ConfigureCA: BackupPanel() failure");
            return false;
        }

        // 14. Backup Continue Panel
        boolean disp_back_cont = BackupContinuePanel();

        if (!disp_back_cont) {
            System.out.println("ERROR: ConfigureCA: BackupContinuePanel() failure");
            return false;
        }

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

        // 16. Admin Cert Req Panel
        boolean disp_adm = AdminCertReqPanel();

        if (!disp_adm) {
            System.out.println("ERROR: ConfigureCA: AdminCertReqPanel() failure");
            return false;
        }

        // 14. Admin Cert import Panel
        boolean disp_im = AdminCertImportPanel();

        if (!disp_im) {
            System.out.println(
                    "ERROR: ConfigureCA: AdminCertImportPanel() failure");
            return false;
        }

        // 15. Update Domain Panel
        boolean disp_ud = UpdateDomainPanel();

        if (!disp_ud) {
            System.out.println("ERROR: ConfigureCA: UpdateDomainPanel() failure");
            return false;
        }

        return true;
    }

    private static String set_default(String val, String def) {
        if ((val == null) || (val.equals(""))) {
            return def;
        } else {
            return val;
        }
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
        StringHolder x_secure_conn = new StringHolder();
        StringHolder x_clone_start_tls = new StringHolder();
        StringHolder x_remove_data = new StringHolder();

        // key properties (defaults)
        StringHolder x_key_size = new StringHolder();
        StringHolder x_key_type = new StringHolder();
        StringHolder x_key_curvename = new StringHolder();
        StringHolder x_key_algorithm = new StringHolder();
        StringHolder x_signing_algorithm = new StringHolder();

        // key properties (custom - signing)
        StringHolder x_signing_key_size = new StringHolder();
        StringHolder x_signing_key_type = new StringHolder();
        StringHolder x_signing_key_curvename = new StringHolder();
        StringHolder x_signing_signingalgorithm = new StringHolder();

        // key properties (custom - ocsp_signing)
        StringHolder x_ocsp_signing_key_size = new StringHolder();
        StringHolder x_ocsp_signing_key_type = new StringHolder();
        StringHolder x_ocsp_signing_key_curvename = new StringHolder();
        StringHolder x_ocsp_signing_signingalgorithm = new StringHolder();

        // key properties (custom - audit_signing)
        StringHolder x_audit_signing_key_size = new StringHolder();
        StringHolder x_audit_signing_key_type = new StringHolder();
        StringHolder x_audit_signing_key_curvename = new StringHolder();

        // key properties (custom - subsystem)
        StringHolder x_subsystem_key_size = new StringHolder();
        StringHolder x_subsystem_key_type = new StringHolder();
        StringHolder x_subsystem_key_curvename = new StringHolder();

        // key properties (custom - sslserver)
        StringHolder x_sslserver_key_size = new StringHolder();
        StringHolder x_sslserver_key_type = new StringHolder();
        StringHolder x_sslserver_key_curvename = new StringHolder();

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
        parser.addOption("-secure_conn %s #use ldaps port (optional, default is false)", x_secure_conn);
        parser.addOption("-remove_data %s #remove existing data under base_dn (optional, default is false) ",
                x_remove_data);
        parser.addOption(
                "-clone_start_tls %s #use startTLS for cloning replication agreement (optional, default is false)",
                x_clone_start_tls);

        // key and algorithm options (default)
        parser.addOption("-key_type %s #Key type [RSA,ECC] (optional, default is RSA)", x_key_type);
        parser.addOption("-key_size %s #Key Size (optional, for RSA default is 2048)", x_key_size);
        parser.addOption("-key_curvename %s #Key Curve Name (optional, for ECC default is nistp256)", x_key_curvename);
        parser.addOption(
                "-key_algorithm %s #Key algorithm of the CA certificate (optional, default is SHA256withRSA for RSA and SHA256withEC for ECC)",
                x_key_algorithm);
        parser.addOption("-signing_algorithm %s #Signing algorithm (optional, default is key_algorithm)",
                x_signing_algorithm);

        // key and algorithm options for signing certificate (overrides default)
        parser.addOption("-signing_key_type %s #Key type [RSA,ECC] (optional, default is key_type)", x_signing_key_type);
        parser.addOption("-signing_key_size %s #Key Size (optional, for RSA default is key_size)", x_signing_key_size);
        parser.addOption("-signing_key_curvename %s #Key Curve Name (optional, for ECC default is key_curvename)",
                x_signing_key_curvename);
        parser.addOption(
                "-signing_signingalgorithm %s #Algorithm used be CA cert to sign objects (optional, default is signing_algorithm)",
                x_signing_signingalgorithm);

        // key and algorithm options for ocsp_signing certificate (overrides default)
        parser.addOption("-ocsp_signing_key_type %s #Key type [RSA,ECC] (optional, default is key_type)",
                x_ocsp_signing_key_type);
        parser.addOption("-ocsp_signing_key_size %s #Key Size (optional, for RSA default is key_size)",
                x_ocsp_signing_key_size);
        parser.addOption("-ocsp_signing_key_curvename %s #Key Curve Name (optional, for ECC default is key_curvename)",
                x_ocsp_signing_key_curvename);
        parser.addOption(
                "-ocsp_signing_signingalgorithm %s #Algorithm used by the OCSP signing cert to sign objects (optional, default is signing_algorithm)",
                x_ocsp_signing_signingalgorithm);

        // key and algorithm options for audit_signing certificate (overrides default)
        parser.addOption("-audit_signing_key_type %s #Key type [RSA,ECC] (optional, default is key_type)",
                x_audit_signing_key_type);
        parser.addOption("-audit_signing_key_size %s #Key Size (optional, for RSA default is key_size)",
                x_audit_signing_key_size);
        parser.addOption(
                "-audit_signing_key_curvename %s #Key Curve Name (optional, for ECC default is key_curvename)",
                x_audit_signing_key_curvename);

        // key and algorithm options for subsystem certificate (overrides default)
        parser.addOption("-subsystem_key_type %s #Key type [RSA,ECC] (optional, default is key_type)",
                x_subsystem_key_type);
        parser.addOption("-subsystem_key_size %s #Key Size (optional, for RSA default is key_size)",
                x_subsystem_key_size);
        parser.addOption("-subsystem_key_curvename %s #Key Curve Name (optional, for ECC default is key_curvename)",
                x_subsystem_key_curvename);

        // key and algorithm options for sslserver certificate (overrides default)
        parser.addOption("-sslserver_key_type %s #Key type [RSA,ECC] (optional, default is key_type)",
                x_sslserver_key_type);
        parser.addOption("-sslserver_key_size %s #Key Size (optional, for RSA default is key_size)",
                x_sslserver_key_size);
        parser.addOption("-sslserver_key_curvename %s #Key Curve Name (optional, for ECC default is key_curvename)",
                x_sslserver_key_curvename);

        parser.addOption("-token_name %s #HSM/Software Token name", x_token_name);
        parser.addOption("-token_pwd %s #HSM/Software Token password (optional - only required for HSM)",
                x_token_pwd);

        parser.addOption("-save_p12 %s #Enable/Disable p12 Export[true,false]",
                x_save_p12);
        parser.addOption("-backup_pwd %s #Backup Password for p12 (optional, only required if -save_p12 = true)",
                x_backup_pwd);
        parser.addOption("-backup_fname %s #Backup File for p12, (optional, default is /root/tmp-ca.p12)",
                x_backup_fname);

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
        parser.addOption(
                "-clone_uri %s #URL of Master CA to clone. It must have the form https://<hostname>:<EE port> (optional, required if -clone=true)",
                x_clone_uri);
        parser.addOption(
                "-clone_p12_file %s #File containing pk12 keys of Master CA (optional, required if -clone=true)",
                x_clone_p12_file);
        parser.addOption("-clone_p12_password %s #Password for pk12 file (optional, required if -clone=true)",
                x_clone_p12_passwd);

        parser.addOption("-sd_hostname %s #Security Domain Hostname (optional, required if -clone=true)", x_sd_hostname);
        parser.addOption("-sd_ssl_port %s #Security Domain SSL EE port (optional, required if -clone=true)",
                x_sd_ssl_port);
        parser.addOption("-sd_agent_port %s #Security Domain SSL Agent port (optional, required if -clone=true)",
                x_sd_agent_port);
        parser.addOption("-sd_admin_port %s #Security Domain SSL Admin port (optional, required if -clone=true)",
                x_sd_admin_port);
        parser.addOption("-sd_admin_name %s #Security Domain admin name (optional, required if -clone=true)",
                x_sd_admin_name);
        parser.addOption("-sd_admin_password %s #Security Domain admin password (optional, required if -clone=true)",
                x_sd_admin_password);

        // and then match the arguments
        String[] unmatched = null;

        unmatched = parser.matchAllArgs(args, 0, ArgParser.EXIT_ON_UNMATCHED);

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
        secure_conn = set_default(x_secure_conn.value, "false");
        remove_data = set_default(x_remove_data.value, "false");
        clone_start_tls = set_default(x_clone_start_tls.value, "false");

        key_type = set_default(x_key_type.value, DEFAULT_KEY_TYPE);
        signing_key_type = set_default(x_signing_key_type.value, key_type);
        ocsp_signing_key_type = set_default(x_ocsp_signing_key_type.value, key_type);
        audit_signing_key_type = set_default(x_audit_signing_key_type.value, key_type);
        subsystem_key_type = set_default(x_subsystem_key_type.value, key_type);
        sslserver_key_type = set_default(x_sslserver_key_type.value, key_type);

        key_size = set_default(x_key_size.value, DEFAULT_KEY_SIZE);
        signing_key_size = set_default(x_signing_key_size.value, key_size);
        ocsp_signing_key_size = set_default(x_ocsp_signing_key_size.value, key_size);
        audit_signing_key_size = set_default(x_audit_signing_key_size.value, key_size);
        subsystem_key_size = set_default(x_subsystem_key_size.value, key_size);
        sslserver_key_size = set_default(x_sslserver_key_size.value, key_size);

        key_curvename = set_default(x_key_curvename.value, DEFAULT_KEY_CURVENAME);
        signing_key_curvename = set_default(x_signing_key_curvename.value, key_curvename);
        ocsp_signing_key_curvename = set_default(x_ocsp_signing_key_curvename.value, key_curvename);
        audit_signing_key_curvename = set_default(x_audit_signing_key_curvename.value, key_curvename);
        subsystem_key_curvename = set_default(x_subsystem_key_curvename.value, key_curvename);
        sslserver_key_curvename = set_default(x_sslserver_key_curvename.value, key_curvename);

        if (signing_key_type.equalsIgnoreCase("RSA")) {
            key_algorithm = set_default(x_key_algorithm.value, DEFAULT_KEY_ALGORITHM_RSA);
        } else {
            key_algorithm = set_default(x_key_algorithm.value, DEFAULT_KEY_ALGORITHM_ECC);
        }

        signing_algorithm = set_default(x_signing_algorithm.value, key_algorithm);
        signing_signingalgorithm = set_default(x_signing_signingalgorithm.value, signing_algorithm);
        ocsp_signing_signingalgorithm = set_default(x_ocsp_signing_signingalgorithm.value, signing_algorithm);

        token_name = x_token_name.value;
        token_pwd = x_token_pwd.value;
        save_p12 = x_save_p12.value;
        backup_pwd = x_backup_pwd.value;
        backup_fname = set_default(x_backup_fname.value, "/root/tmp-ca.p12");

        agent_key_size = x_agent_key_size.value;
        agent_key_type = x_agent_key_type.value;
        agent_cert_subject = x_agent_cert_subject.value;

        ca_sign_cert_subject_name = x_ca_sign_cert_subject_name.value;
        ca_subsystem_cert_subject_name = x_ca_subsystem_cert_subject_name.value;
        ca_ocsp_cert_subject_name = x_ca_ocsp_cert_subject_name.value;
        ca_server_cert_subject_name = x_ca_server_cert_subject_name.value;
        ca_audit_signing_cert_subject_name = x_ca_audit_signing_cert_subject_name.value;

        subsystem_name = x_subsystem_name.value;

        external_ca = set_default(x_external_ca.value, "false");
        ext_ca_cert_file = x_ext_ca_cert_file.value;
        ext_ca_cert_chain_file = x_ext_ca_cert_chain_file.value;
        ext_csr_file = set_default(x_ext_csr_file.value, "/tmp/ext_ca.csr");

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

};
