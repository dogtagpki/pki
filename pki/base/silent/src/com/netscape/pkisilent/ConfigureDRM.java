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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
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

public class ConfigureDRM {

    // global constants
    public static final String DEFAULT_KEY_TYPE = "RSA";
    public static final String DEFAULT_KEY_SIZE = "2048";
    public static final String DEFAULT_KEY_CURVENAME = "nistp256";
    public static final String DEFAULT_KEY_ALGORITHM_RSA = "SHA256withRSA";
    public static final String DEFAULT_KEY_ALGORITHM_ECC = "SHA256withEC";

    // define global variables

    public static HTTPClient hc = null;

    public static String login_uri = "/kra/admin/console/config/login";
    public static String wizard_uri = "/kra/admin/console/config/wizard";
    public static String admin_uri = "/ca/admin/ca/getBySerial";

    public static String sd_login_uri = "/ca/admin/ca/securityDomainLogin";
    public static String sd_get_cookie_uri = "/ca/admin/ca/getCookie";
    public static String pkcs12_uri = "/kra/admin/console/config/savepkcs12";

    public static String cs_hostname = null;
    public static String cs_port = null;

    public static String sd_hostname = null;
    public static String sd_ssl_port = null;
    public static String sd_agent_port = null;
    public static String sd_admin_port = null;
    public static String sd_admin_name = null;
    public static String sd_admin_password = null;

    public static String ca_hostname = null;
    public static String ca_port = null;
    public static String ca_ssl_port = null;

    public static String client_certdb_dir = null;
    public static String client_certdb_pwd = null;

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
    public static String signing_algorithm = null;

    public static String transport_key_type = null;
    public static String transport_key_size = null;
    public static String transport_key_curvename = null;
    public static String transport_signingalgorithm = null;

    public static String storage_key_type = null;
    public static String storage_key_size = null;
    public static String storage_key_curvename = null;

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

    public static String drm_transport_cert_name = null;
    public static String drm_transport_cert_req = null;
    public static String drm_transport_cert_pp = null;
    public static String drm_transport_cert_cert = null;

    public static String drm_storage_cert_name = null;
    public static String drm_storage_cert_req = null;
    public static String drm_storage_cert_pp = null;
    public static String drm_storage_cert_cert = null;

    public static String server_cert_name = null;
    public static String server_cert_req = null;
    public static String server_cert_pp = null;
    public static String server_cert_cert = null;

    public static String drm_subsystem_cert_name = null;
    public static String drm_subsystem_cert_req = null;
    public static String drm_subsystem_cert_pp = null;
    public static String drm_subsystem_cert_cert = null;

    public static String drm_audit_signing_cert_name = null;
    public static String drm_audit_signing_cert_req = null;
    public static String drm_audit_signing_cert_pp = null;
    public static String drm_audit_signing_cert_cert = null;

    public static String backup_pwd = null;
    public static String backup_fname = null;

    // cert subject names 
    public static String drm_transport_cert_subject_name = null;
    public static String drm_subsystem_cert_subject_name = null;
    public static String drm_storage_cert_subject_name = null;
    public static String drm_server_cert_subject_name = null;
    public static String drm_audit_signing_cert_subject_name = null;

    public static String subsystem_name = null;

    // cloning
    public static boolean clone = false;
    public static String clone_uri = null;
    public static String clone_p12_passwd = null;
    public static String clone_p12_file = null;

    //for correct selection of CA to be cloned
    public static String urls;

    public ConfigureDRM() {
        // do nothing :)
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
            HTTPClient.j_session_id = temp.substring(0, index);
            st = true;
        }

        hr = null;
        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, "p=0&op=next&xml=true");

        // parse xml here
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        return st;
    }

    public boolean TokenChoicePanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        String query_string = null;

        // Software Token
        if (token_name.equalsIgnoreCase("internal")) {
            query_string = "p=1" + "&op=next" + "&xml=true" +
                           "&choice=" +
                           URLEncoder.encode("Internal Key Storage Token");
            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();
        } else {
            // login to hsm first
            query_string = "p=2" + "&op=next" + "&xml=true" +
                            "&uTokName=" +
                            URLEncoder.encode(token_name) +
                            "&__uPasswd=" +
                            URLEncoder.encode(token_pwd);
            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();

            // choice with token name now
            query_string = "p=1" + "&op=next" + "&xml=true" +
                           "&choice=" +
                           URLEncoder.encode(token_name);
            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();
        }

        return true;
    }

    public boolean DomainPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        String domain_url = "https://" + sd_hostname + ":" + sd_admin_port;

        String query_string = "sdomainURL=" +
                            URLEncoder.encode(domain_url) +
                            "&choice=existingdomain" +
                            "&p=3" +
                            "&op=next" +
                            "&xml=true";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        return true;

    }

    public boolean DisplayChainPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();
        String query_string = null;

        query_string = "p=4" + "&op=next" + "&xml=true";
        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        return true;

    }

    public boolean SecurityDomainLoginPanel() {
        try {
            boolean st = false;
            HTTPResponse hr = null;
            ByteArrayInputStream bais = null;
            ParseXML px = new ParseXML();

            String kra_url = "https://" + cs_hostname + ":" + cs_port +
                            "/kra/admin/console/config/wizard" +
                            "?p=5&subsystem=KRA";

            String query_string = "url=" + URLEncoder.encode(kra_url);

            hr = hc.sslConnect(sd_hostname, sd_admin_port, sd_login_uri, query_string);

            String query_string_1 = "uid=" + sd_admin_name +
                                "&pwd=" + URLEncoder.encode(sd_admin_password) +
                                "&url=" + URLEncoder.encode(kra_url);

            hr = hc.sslConnect(sd_hostname, sd_admin_port, sd_get_cookie_uri,
                        query_string_1);

            // get session id from security domain

            String kra_session_id = hr.getContentValue("header.session_id");
            String kra_url_1 = hr.getContentValue("header.url");

            System.out.println("KRA_SESSION_ID=" + kra_session_id);
            System.out.println("KRA_URL=" + kra_url_1);

            // use session id to connect back to KRA

            String query_string_2 = "p=5" +
                                "&subsystem=KRA" +
                                "&session_id=" + kra_session_id +
                                "&xml=true";

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri,
                        query_string_2);

            if (clone) {
                // parse urls
                urls = hr.getHTML();
                int indx = urls.indexOf(clone_uri);
                if (indx < 0) {
                    throw new Exception("Invalid clone_uri");
                }
                urls = urls.substring(urls.lastIndexOf("<option", indx), indx);
                urls = urls.split("\"")[1];

                System.out.println("urls =" + urls);
            }

            return true;
        } catch (Exception e) {
            System.out.println("Exception in SecurityDomainLoginPanel(): " + e.toString());
            e.printStackTrace();
            return false;
        }
    }

    public boolean SubsystemPanel() {
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
                    + "&urls=" + urls;
        }

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        return true;
    }

    public boolean RestoreKeyCertPanel() {
        try {
            ByteArrayInputStream bais = null;
            HTTPResponse hr = null;
            ParseXML px = new ParseXML();

            String query_string = "p=6" + "&op=next" + "&xml=true"
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

    public boolean LdapConnectionPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        String query_string = "p=7" + "&op=next" + "&xml=true" +
                              "&host=" + URLEncoder.encode(ldap_host) +
                              "&port=" + URLEncoder.encode(ldap_port) +
                              "&binddn=" + URLEncoder.encode(bind_dn) +
                              "&__bindpwd=" + URLEncoder.encode(bind_password) +
                              "&basedn=" + URLEncoder.encode(base_dn) +
                              "&database=" + URLEncoder.encode(db_name) +
                              "&display=" + URLEncoder.encode("$displayStr") +
                              (secure_conn.equals("true") ? "&secureConn=on" : "") +
                              (clone_start_tls.equals("true") ? "&cloneStartTLS=on" : "") +
                              (remove_data.equals("true") ? "&removeData=true" : "");

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        return true;
    }

    public boolean KeyPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();
        ArrayList<String> al = null;

        String query_string = null;

        if (!clone) {
            query_string = "p=8" + "&op=next" + "&xml=true" +
                    "&transport_custom_size=" + transport_key_size +
                    "&storage_custom_size=" + storage_key_size +
                    "&subsystem_custom_size=" + subsystem_key_size +
                    "&sslserver_custom_size=" + sslserver_key_size +
                    "&audit_signing_custom_size=" + key_size +
                    "&custom_size=" + key_size +
                    "&transport_custom_curvename=" + transport_key_curvename +
                    "&storage_custom_curvename=" + storage_key_curvename +
                    "&subsystem_custom_curvename=" + subsystem_key_curvename +
                    "&sslserver_custom_curvename=" + sslserver_key_curvename +
                    "&audit_signing_custom_curvename=" + audit_signing_key_curvename +
                    "&custom_curvename=" + key_curvename +
                    "&transport_keytype=" + transport_key_type +
                    "&storage_keytype=" + storage_key_type +
                    "&subsystem_keytype=" + subsystem_key_type +
                    "&sslserver_keytype=" + sslserver_key_type +
                    "&audit_signing_keytype=" + audit_signing_key_type +
                    "&keytype=" + key_type +
                    "&transport_choice=custom" +
                    "&storage_choice=custom" +
                    "&subsystem_choice=custom" +
                    "&sslserver_choice=custom" +
                    "&choice=custom" +
                    "&audit_signing_choice=custom" +
                    "&signingalgorithm=" + signing_algorithm +
                    "&transport_signingalgorithm=" + transport_signingalgorithm;

        } else {
            query_string = "p=8" + "&op=next" + "&xml=true" +
                    "&sslserver_custom_size=" + sslserver_key_size +
                    "&sslserver_keytype=" + sslserver_key_type +
                    "&sslserver_choice=custom" +
                    "&custom_size=" + key_size +
                    "&keytype=" + key_type +
                    "&choice=custom";
        }

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        al = px.constructValueList("CertReqPair", "DN");
        // get ca cert subject name
        if (al != null) {
            for (int i = 0; i < al.size(); i++) {
                String temp = al.get(i);
                if (temp.indexOf("DRM Transport") > 0) {
                    drm_transport_cert_name = temp;
                } else if (temp.indexOf("DRM Storage") > 0) {
                    drm_storage_cert_name = temp;
                } else if (temp.indexOf("DRM Subsystem") > 0) {
                    drm_subsystem_cert_name = temp;
                } else if (temp.indexOf("DRM Audit Signing Certificate") > 0) {
                    drm_audit_signing_cert_name = temp;
                } else {
                    server_cert_name = temp;
                }
            }
        }

        System.out.println("default: drm_transport_cert_name=" +
                drm_transport_cert_name);
        System.out.println("default: drm_storage_cert_name=" +
                drm_storage_cert_name);
        System.out.println("default: drm_subsystem_cert_name=" +
                drm_subsystem_cert_name);
        System.out.println("default: drm_audit_signing_cert_name=" +
                drm_audit_signing_cert_name);

        System.out.println("default: server_cert_name=" +
                server_cert_name);
        return true;
    }

    public boolean CertSubjectPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();
        ArrayList<String> req_list = null;
        ArrayList<String> cert_list = null;
        ArrayList<String> dn_list = null;
        String query_string = null;

        String domain_url = "https://" + ca_hostname + ":" + ca_ssl_port;

        if (!clone) {
            query_string = "p=9" + "&op=next" + "&xml=true" +
                    "&subsystem=" +
                    URLEncoder.encode(drm_subsystem_cert_subject_name) +
                    "&transport=" +
                    URLEncoder.encode(drm_transport_cert_subject_name) +
                    "&storage=" +
                    URLEncoder.encode(drm_storage_cert_subject_name) +
                    "&sslserver=" +
                    URLEncoder.encode(drm_server_cert_subject_name) +
                    "&audit_signing=" +
                    URLEncoder.encode(drm_audit_signing_cert_subject_name) +
                    "&urls=" +
                    URLEncoder.encode(domain_url);
        } else {
            query_string = "p=9" + "&op=next" + "&xml=true" +
                    "&sslserver=" +
                    URLEncoder.encode(drm_server_cert_subject_name) +
                    "&urls=" +
                    URLEncoder.encode(domain_url);
        }

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        req_list = px.constructValueList("CertReqPair", "Request");
        cert_list = px.constructValueList("CertReqPair", "Certificate");
        dn_list = px.constructValueList("CertReqPair", "Nickname");

        if (req_list != null && cert_list != null && dn_list != null) {
            for (int i = 0; i < dn_list.size(); i++) {
                String temp = dn_list.get(i);

                if (temp.indexOf("transportCert") >= 0) {
                    drm_transport_cert_req = req_list.get(i);
                    drm_transport_cert_cert = cert_list.get(i);
                } else if (temp.indexOf("storageCert") >= 0) {
                    drm_storage_cert_req = req_list.get(i);
                    drm_storage_cert_cert = cert_list.get(i);
                } else if (temp.indexOf("subsystemCert") >= 0) {
                    drm_subsystem_cert_req = req_list.get(i);
                    drm_subsystem_cert_cert = cert_list.get(i);
                } else if (temp.indexOf("auditSigningCert") >= 0) {
                    drm_audit_signing_cert_req = req_list.get(i);
                    drm_audit_signing_cert_cert = cert_list.get(i);
                } else {
                    server_cert_req = req_list.get(i);
                    server_cert_cert = cert_list.get(i);
                }
            }
        }

        return true;
    }

    public boolean CertificatePanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();
        ArrayList<String> req_list = null;
        ArrayList<String> cert_list = null;
        ArrayList<String> dn_list = null;
        ArrayList<String> pp_list = null;

        String query_string = "p=10" + "&op=next" + "&xml=true" +
                            "&subsystem=" +
                            URLEncoder.encode(drm_subsystem_cert_cert) +
                            "&subsystem_cc=" +
                            "&transport=" +
                            URLEncoder.encode(drm_transport_cert_cert) +
                            "&transport_cc=" +
                            "&storage=" +
                            URLEncoder.encode(drm_storage_cert_cert) +
                            "&storage_cc=" +
                            "&sslserver=" +
                            URLEncoder.encode(server_cert_cert) +
                            "&sslserver_cc=" +
                            "&audit_signing=" +
                            URLEncoder.encode(drm_audit_signing_cert_cert) +
                            "&audit_signing_cc=";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        return true;
    }

    public boolean BackupPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        String query_string = "p=11" + "&op=next" + "&xml=true" +
                            "&choice=backupkey" +
                            "&__pwd=" + URLEncoder.encode(backup_pwd) +
                            "&__pwdagain=" + URLEncoder.encode(backup_pwd);

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        return true;
    }

    public boolean SavePKCS12Panel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        String query_string = "";

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
            System.out.println("AuthSafes has " +
                    asSeq.size() + " SafeContents");

            fis.close();

            if (clone) {
                query_string = "p=12" + "&op=next" + "&xml=true";
                hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

                // parse xml
                bais = new ByteArrayInputStream(hr.getHTML().getBytes());
                px.parse(bais);
                px.prettyprintxml();
            }
        } catch (Exception e) {
            System.out.println("ERROR: Exception=" + e.getMessage());
            return false;
        }

        return true;
    }

    public boolean AdminCertReqPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();
        String admin_cert_request = null;

        ComCrypto cCrypt = new ComCrypto(client_certdb_dir,
                                        client_certdb_pwd,
                                        agent_cert_subject,
                                        agent_key_size,
                                        agent_key_type);
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

        String query_string = "p=13" + "&op=next" + "&xml=true" +
                            "&cert_request_type=" + "crmf" +
                            "&uid=" + admin_user +
                            "&name=" + admin_user +
                            "&__pwd=" + URLEncoder.encode(admin_password) +
                            "&__admin_password_again=" + URLEncoder.encode(admin_password) +
                            "&profileId=" + "caAdminCert" +
                            "&email=" +
                            URLEncoder.encode(admin_email) +
                            "&cert_request=" +
                            URLEncoder.encode(admin_cert_request) +
                            "&subject=" +
                            URLEncoder.encode(agent_cert_subject) +
                            "&clone=new" +
                            "&import=true" +
                            "&securitydomain=" +
                            URLEncoder.encode(domain_name);

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        admin_serial_number = px.getvalue("serialNumber");

        return true;
    }

    public boolean AdminCertImportPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        String query_string = "serialNumber=" + admin_serial_number +
                            "&importCert=" + "true";

        hr = hc.sslConnect(sd_hostname, sd_admin_port, admin_uri, query_string);

        // get response data
        // String cert_to_import = 
        //     new sun.misc.BASE64Encoder().encode(hr.getResponseData());
        String cert_to_import =
                OSUtil.BtoA(hr.getResponseData());
        System.out.println("Imported Cert=" + cert_to_import);

        ComCrypto cCrypt = new ComCrypto(client_certdb_dir,
                                        client_certdb_pwd,
                                        null,
                                        null,
                                        null);
        cCrypt.setDebug(true);
        cCrypt.setGenerateRequest(true);
        cCrypt.loginDB();

        String start = "-----BEGIN CERTIFICATE-----\r\n";
        String end = "\r\n-----END CERTIFICATE-----";

        st = cCrypt.importCert(start + cert_to_import + end, agent_name);
        if (!st) {
            System.out.println("ERROR: AdminCertImportPanel() during cert import");
            return false;
        }

        System.out.println("SUCCESS: imported admin user cert");
        return true;
    }

    public boolean UpdateDomainPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        String query_string = "p=14" + "&op=next" + "&xml=true" +
                            "&caHost=" + URLEncoder.encode(sd_hostname) +
                            "&caPort=" + URLEncoder.encode(sd_agent_port);

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        return true;
    }

    public boolean ConfigureDRMInstance() {
        // 0. login to cert db
        ComCrypto cCrypt = new ComCrypto(client_certdb_dir,
                                        client_certdb_pwd,
                                        null,
                                        null,
                                        null);
        cCrypt.setDebug(true);
        cCrypt.setGenerateRequest(true);
        cCrypt.loginDB();

        // instantiate http client
        hc = new HTTPClient();

        // 1. Login panel
        boolean log_st = LoginPanel();
        if (!log_st) {
            System.out.println("ERROR: ConfigureDRM: LoginPanel() failure");
            return false;
        }

        sleep_time();
        // 2. Token Choice Panel
        boolean disp_token = TokenChoicePanel();
        if (!disp_token) {
            System.out.println("ERROR: ConfigureDRM: TokenChoicePanel() failure");
            return false;
        }

        sleep_time();
        // 3. domain panel
        boolean dom_st = DomainPanel();
        if (!dom_st) {
            System.out.println("ERROR: ConfigureDRM: DomainPanel() failure");
            return false;
        }

        sleep_time();
        // 4. display cert chain panel
        boolean disp_st = DisplayChainPanel();
        if (!disp_st) {
            System.out.println("ERROR: ConfigureDRM: DisplayChainPanel() failure");
            return false;
        }

        sleep_time();
        // security domain login panel
        boolean disp_sd = SecurityDomainLoginPanel();
        if (!disp_sd) {
            System.out.println("ERROR: ConfigureDRM: SecurityDomainLoginPanel() failure");
            return false;
        }

        sleep_time();
        // subsystem panel
        boolean disp_ss = SubsystemPanel();
        if (!disp_ss) {
            System.out.println("ERROR: ConfigureDRM: SubsystemPanel() failure");
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

        sleep_time();
        // 7. ldap connection panel
        boolean disp_ldap = LdapConnectionPanel();
        if (!disp_ldap) {
            System.out.println("ERROR: ConfigureDRM: LdapConnectionPanel() failure");
            return false;
        }

        sleep_time();
        sleep_time();
        // 9. Key Panel
        boolean disp_key = KeyPanel();
        if (!disp_key) {
            System.out.println("ERROR: ConfigureDRM: KeyPanel() failure");
            return false;
        }

        sleep_time();
        // 10. Cert Subject Panel
        boolean disp_csubj = CertSubjectPanel();
        if (!disp_csubj) {
            System.out.println("ERROR: ConfigureDRM: CertSubjectPanel() failure");
            return false;
        }

        sleep_time();
        // 11. Certificate Panel
        boolean disp_cp = CertificatePanel();
        if (!disp_cp) {
            System.out.println("ERROR: ConfigureDRM: CertificatePanel() failure");
            return false;
        }

        sleep_time();
        // backup panel
        boolean disp_back = BackupPanel();
        if (!disp_back) {
            System.out.println("ERROR: ConfigureDRM: BackupPanel() failure");
            return false;
        }

        sleep_time();
        // save panel
        boolean disp_save = SavePKCS12Panel();
        if (!disp_save) {
            System.out.println("ERROR: ConfigureDRM: SavePKCS12Panel() failure");
            return false;
        }

        if (clone) {
            // no other panels required for clone
            return true;
        }

        sleep_time();
        // 13. Admin Cert Req Panel
        boolean disp_adm = AdminCertReqPanel();
        if (!disp_adm) {
            System.out.println("ERROR: ConfigureDRM: AdminCertReqPanel() failure");
            return false;
        }

        sleep_time();
        // 14. Admin Cert import Panel
        boolean disp_im = AdminCertImportPanel();
        if (!disp_im) {
            System.out.println("ERROR: ConfigureDRM: AdminCertImportPanel() failure");
            return false;
        }

        sleep_time();
        // 15. Update Domain Panel
        boolean disp_ud = UpdateDomainPanel();
        if (!disp_ud) {
            System.out.println("ERROR: ConfigureDRM: UpdateDomainPanel() failure");
            return false;
        }

        sleep_time();
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
        ConfigureDRM ca = new ConfigureDRM();

        // set variables
        StringHolder x_cs_hostname = new StringHolder();
        StringHolder x_cs_port = new StringHolder();

        StringHolder x_sd_hostname = new StringHolder();
        StringHolder x_sd_ssl_port = new StringHolder();
        StringHolder x_sd_agent_port = new StringHolder();
        StringHolder x_sd_admin_port = new StringHolder();
        StringHolder x_sd_admin_name = new StringHolder();
        StringHolder x_sd_admin_password = new StringHolder();

        StringHolder x_ca_hostname = new StringHolder();
        StringHolder x_ca_port = new StringHolder();
        StringHolder x_ca_ssl_port = new StringHolder();

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
        StringHolder x_signing_algorithm = new StringHolder();

        // key properties (custom - transport)
        StringHolder x_transport_key_size = new StringHolder();
        StringHolder x_transport_key_type = new StringHolder();
        StringHolder x_transport_key_curvename = new StringHolder();
        StringHolder x_transport_signingalgorithm = new StringHolder();

        // key properties (custom - storage)
        StringHolder x_storage_key_size = new StringHolder();
        StringHolder x_storage_key_type = new StringHolder();
        StringHolder x_storage_key_curvename = new StringHolder();

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

        StringHolder x_agent_key_size = new StringHolder();
        StringHolder x_agent_key_type = new StringHolder();
        StringHolder x_agent_cert_subject = new StringHolder();

        StringHolder x_agent_name = new StringHolder();
        StringHolder x_backup_pwd = new StringHolder();
        StringHolder x_backup_fname = new StringHolder();

        // drm cert subject name params
        StringHolder x_drm_subsystem_cert_subject_name = new StringHolder();
        StringHolder x_drm_server_cert_subject_name = new StringHolder();
        StringHolder x_drm_transport_cert_subject_name = new StringHolder();
        StringHolder x_drm_storage_cert_subject_name = new StringHolder();
        StringHolder x_drm_audit_signing_cert_subject_name = new StringHolder();

        // subsystemName
        StringHolder x_subsystem_name = new StringHolder();

        //clone parameters
        StringHolder x_clone = new StringHolder();
        StringHolder x_clone_uri = new StringHolder();
        StringHolder x_clone_p12_file = new StringHolder();
        StringHolder x_clone_p12_passwd = new StringHolder();

        // parse the args
        ArgParser parser = new ArgParser("ConfigureDRM");

        parser.addOption("-cs_hostname %s #CS Hostname",
                            x_cs_hostname);
        parser.addOption("-cs_port %s #CS SSL Admin port",
                            x_cs_port);

        parser.addOption("-sd_hostname %s #Security Domain Hostname",
                            x_sd_hostname);
        parser.addOption("-sd_ssl_port %s #Security Domain SSL EE port",
                            x_sd_ssl_port);
        parser.addOption("-sd_agent_port %s #Security Domain SSL Agent port",
                            x_sd_agent_port);
        parser.addOption("-sd_admin_port %s #Security Domain SSL Admin port",
                            x_sd_admin_port);
        parser.addOption("-sd_admin_name %s #Security Domain username",
                            x_sd_admin_name);
        parser.addOption("-sd_admin_password %s #Security Domain password",
                            x_sd_admin_password);

        parser.addOption("-ca_hostname %s #CA Hostname",
                            x_ca_hostname);
        parser.addOption("-ca_port %s #CA non-SSL EE port",
                            x_ca_port);
        parser.addOption("-ca_ssl_port %s #CA SSL EE port",
                            x_ca_ssl_port);

        parser.addOption("-client_certdb_dir %s #Client CertDB dir",
                            x_client_certdb_dir);
        parser.addOption("-client_certdb_pwd %s #client certdb password",
                            x_client_certdb_pwd);
        parser.addOption("-preop_pin %s #pre op pin",
                            x_preop_pin);
        parser.addOption("-domain_name %s #domain name",
                            x_domain_name);
        parser.addOption("-admin_user %s #Admin User Name",
                            x_admin_user);
        parser.addOption("-admin_email %s #Admin email",
                            x_admin_email);
        parser.addOption("-admin_password %s #Admin password",
                            x_admin_password);
        parser.addOption("-agent_name %s #Agent Cert Nickname",
                            x_agent_name);

        parser.addOption("-ldap_host %s #ldap host",
                            x_ldap_host);
        parser.addOption("-ldap_port %s #ldap port",
                            x_ldap_port);
        parser.addOption("-bind_dn %s #ldap bind dn",
                            x_bind_dn);
        parser.addOption("-bind_password %s #ldap bind password",
                            x_bind_password);
        parser.addOption("-base_dn %s #base dn",
                            x_base_dn);
        parser.addOption("-db_name %s #db name",
                            x_db_name);
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
                "-signing_algorithm %s #Signing algorithm (optional, default is SHA256withRSA for RSA and SHA256withEC for ECC)",
                x_signing_algorithm);

        // key and algorithm options for transport certificate (overrides default)
        parser.addOption("-transport_key_type %s #Key type [RSA,ECC] (optional, default is key_type)",
                x_transport_key_type);
        parser.addOption("-transport_key_size %s #Key Size (optional, for RSA default is key_size)",
                x_transport_key_size);
        parser.addOption("-transport_key_curvename %s #Key Curve Name (optional, for ECC default is key_curvename)",
                x_transport_key_curvename);
        parser.addOption(
                "-transport_signingalgorithm %s #Algorithm used by the transport cert to sign objects (optional, default is signing_algorithm)",
                x_transport_signingalgorithm);

        // key and algorithm options for storage certificate (overrides default)
        parser.addOption("-storage_key_type %s #Key type [RSA,ECC] (optional, default is key_type)", x_storage_key_type);
        parser.addOption("-storage_key_size %s #Key Size (optional, for RSA default is key_size)", x_storage_key_size);
        parser.addOption("-storage_key_curvename %s #Key Curve Name (optional, for ECC default is key_curvename)",
                x_storage_key_curvename);

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

        parser.addOption("-token_name %s #HSM/Software Token name",
                            x_token_name);
        parser.addOption("-token_pwd %s #HSM/Software Token password (optional, required for HSM)",
                            x_token_pwd);

        parser.addOption("-agent_key_size %s #Agent Cert Key Size",
                            x_agent_key_size);
        parser.addOption("-agent_key_type %s #Agent Cert Key type [rsa]",
                            x_agent_key_type);
        parser.addOption("-agent_cert_subject %s #Agent Cert Subject ",
                            x_agent_cert_subject);

        parser.addOption("-backup_pwd %s #PKCS12 password",
                            x_backup_pwd);

        parser.addOption("-backup_fname %s #Backup File for p12, (optional, default /root/tmp-kra.p12)",
                            x_backup_fname);

        parser.addOption(
                "-drm_transport_cert_subject_name %s #DRM transport cert subject name",
                            x_drm_transport_cert_subject_name);
        parser.addOption(
                "-drm_subsystem_cert_subject_name %s #DRM subsystem cert subject name",
                            x_drm_subsystem_cert_subject_name);
        parser.addOption(
                "-drm_storage_cert_subject_name %s #DRM storage cert subject name",
                            x_drm_storage_cert_subject_name);
        parser.addOption(
                "-drm_server_cert_subject_name %s #DRM server cert subject name",
                            x_drm_server_cert_subject_name);

        parser.addOption(
                "-subsystem_name %s #CA subsystem name",
                            x_subsystem_name);

        parser.addOption(
                "-drm_audit_signing_cert_subject_name %s #DRM audit signing cert subject name",
                            x_drm_audit_signing_cert_subject_name);

        parser.addOption("-clone %s #Clone of another KRA [true, false] (optional, default false)", x_clone);
        parser.addOption(
                "-clone_uri %s #URL of Master KRA to clone. It must have the form https://<hostname>:<EE port> (optional, required if -clone=true)",
                x_clone_uri);
        parser.addOption(
                "-clone_p12_file %s #File containing pk12 keys of Master KRA (optional, required if -clone=true)",
                x_clone_p12_file);
        parser.addOption("-clone_p12_password %s #Password for pk12 file (optional, required if -clone=true)",
                x_clone_p12_passwd);

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

        sd_hostname = x_sd_hostname.value;
        sd_ssl_port = x_sd_ssl_port.value;
        sd_agent_port = x_sd_agent_port.value;
        sd_admin_port = x_sd_admin_port.value;
        sd_admin_name = x_sd_admin_name.value;
        sd_admin_password = x_sd_admin_password.value;

        ca_hostname = x_ca_hostname.value;
        ca_port = x_ca_port.value;
        ca_ssl_port = x_ca_ssl_port.value;

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
        transport_key_type = set_default(x_transport_key_type.value, key_type);
        storage_key_type = set_default(x_storage_key_type.value, key_type);
        audit_signing_key_type = set_default(x_audit_signing_key_type.value, key_type);
        subsystem_key_type = set_default(x_subsystem_key_type.value, key_type);
        sslserver_key_type = set_default(x_sslserver_key_type.value, key_type);

        key_size = set_default(x_key_size.value, DEFAULT_KEY_SIZE);
        transport_key_size = set_default(x_transport_key_size.value, key_size);
        storage_key_size = set_default(x_storage_key_size.value, key_size);
        audit_signing_key_size = set_default(x_audit_signing_key_size.value, key_size);
        subsystem_key_size = set_default(x_subsystem_key_size.value, key_size);
        sslserver_key_size = set_default(x_sslserver_key_size.value, key_size);

        key_curvename = set_default(x_key_curvename.value, DEFAULT_KEY_CURVENAME);
        transport_key_curvename = set_default(x_transport_key_curvename.value, key_curvename);
        storage_key_curvename = set_default(x_storage_key_curvename.value, key_curvename);
        audit_signing_key_curvename = set_default(x_audit_signing_key_curvename.value, key_curvename);
        subsystem_key_curvename = set_default(x_subsystem_key_curvename.value, key_curvename);
        sslserver_key_curvename = set_default(x_sslserver_key_curvename.value, key_curvename);

        if (transport_key_type.equalsIgnoreCase("RSA")) {
            signing_algorithm = set_default(x_signing_algorithm.value, DEFAULT_KEY_ALGORITHM_RSA);
        } else {
            signing_algorithm = set_default(x_signing_algorithm.value, DEFAULT_KEY_ALGORITHM_ECC);
        }

        transport_signingalgorithm = set_default(x_transport_signingalgorithm.value, signing_algorithm);

        token_name = x_token_name.value;
        token_pwd = x_token_pwd.value;

        agent_key_size = x_agent_key_size.value;
        agent_key_type = x_agent_key_type.value;
        agent_cert_subject = x_agent_cert_subject.value;

        backup_pwd = x_backup_pwd.value;
        backup_fname = set_default(x_backup_fname.value, "/root/tmp-kra.p12");

        drm_transport_cert_subject_name =
                x_drm_transport_cert_subject_name.value;
        drm_subsystem_cert_subject_name =
                x_drm_subsystem_cert_subject_name.value;
        drm_storage_cert_subject_name = x_drm_storage_cert_subject_name.value;
        drm_server_cert_subject_name = x_drm_server_cert_subject_name.value;
        drm_audit_signing_cert_subject_name = x_drm_audit_signing_cert_subject_name.value;

        subsystem_name = x_subsystem_name.value;

        if ((x_clone.value != null) && (x_clone.value.equalsIgnoreCase("true"))) {
            clone = true;
        } else {
            clone = false;
        }
        clone_uri = x_clone_uri.value;
        clone_p12_file = x_clone_p12_file.value;
        clone_p12_passwd = x_clone_p12_passwd.value;

        boolean st = ca.ConfigureDRMInstance();

        if (!st) {
            System.out.println("ERROR: unable to create DRM");
            System.exit(-1);
        }

        System.out.println("Certificate System - DRM Instance Configured");
        System.exit(0);
    }

};
