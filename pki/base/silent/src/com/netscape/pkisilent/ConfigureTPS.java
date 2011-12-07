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

import java.io.ByteArrayInputStream;
import java.net.URLEncoder;
import java.util.ArrayList;

import com.netscape.osutil.OSUtil;
import com.netscape.pkisilent.argparser.ArgParser;
import com.netscape.pkisilent.argparser.StringHolder;
import com.netscape.pkisilent.common.ComCrypto;
import com.netscape.pkisilent.common.ParseXML;
import com.netscape.pkisilent.http.HTTPClient;
import com.netscape.pkisilent.http.HTTPResponse;

public class ConfigureTPS {
    // define global variables

    public static HTTPClient hc = null;

    public static String login_uri = "/tps/admin/console/config/login";
    public static String wizard_uri = "/tps/admin/console/config/wizard";
    public static String admin_uri = "/ca/admin/ca/getBySerial";

    public static String sd_login_uri = "/ca/admin/ca/securityDomainLogin";
    public static String sd_get_cookie_uri = "/ca/admin/ca/getCookie";
    public static String sd_update_domain_uri = "/ca/agent/ca/updateDomainXML";
    public static String pkcs12_uri = "/tps/admin/console/config/savepkcs12";

    public static String cs_hostname = null;
    public static String cs_port = null;
    public static String cs_clientauth_port = null;

    public static String sd_hostname = null;
    public static String sd_ssl_port = null;
    public static String sd_agent_port = null;
    public static String sd_admin_port = null;
    public static String sd_admin_name = null;
    public static String sd_admin_password = null;

    public static String ca_hostname = null;
    public static String ca_port = null;
    public static String ca_ssl_port = null;
    public static String ca_admin_port = null;

    public static String drm_hostname = null;
    public static String drm_ssl_port = null;

    public static String tks_hostname = null;
    public static String tks_ssl_port = null;

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

    public static String ldap_auth_host = null;
    public static String ldap_auth_port = null;
    public static String ldap_auth_base_dn = null;

    public static String ldap_host = null;
    public static String ldap_port = null;
    public static String bind_dn = null;
    public static String bind_password = null;
    public static String base_dn = null;
    public static String db_name = null;

    public static String key_size = null;
    public static String key_type = null;
    public static String token_name = null;
    public static String token_pwd = null;

    public static String agent_key_size = null;
    public static String agent_key_type = null;
    public static String agent_cert_subject = null;

    public static String tps_transport_cert_name = null;
    public static String tps_transport_cert_req = null;
    public static String tps_transport_cert_pp = null;
    public static String tps_transport_cert_cert = null;

    public static String tps_storage_cert_name = null;
    public static String tps_storage_cert_req = null;
    public static String tps_storage_cert_pp = null;
    public static String tps_storage_cert_cert = null;

    public static String server_cert_name = null;
    public static String server_cert_req = null;
    public static String server_cert_pp = null;
    public static String server_cert_cert = null;

    public static String tps_subsystem_cert_name = null;
    public static String tps_subsystem_cert_req = null;
    public static String tps_subsystem_cert_pp = null;
    public static String tps_subsystem_cert_cert = null;

    public static String tps_audit_signing_cert_name = null;
    public static String tps_audit_signing_cert_req = null;
    public static String tps_audit_signing_cert_pp = null;
    public static String tps_audit_signing_cert_cert = null;

    public static String ss_keygen = null;

    // names
    public static String tps_server_cert_subject_name = null;
    public static String tps_server_cert_nickname = null;
    public static String tps_subsystem_cert_subject_name = null;
    public static String tps_subsystem_cert_nickname = null;
    public static String tps_audit_signing_cert_subject_name = null;
    public static String tps_audit_signing_cert_nickname = null;
    public static String subsystem_name = null;

    // Security Domain Login Panel
    public static String tps_session_id = null;

    // Admin Certificate Request Panel
    public static String requestor_name = null;

    public ConfigureTPS() {
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

        // no cookie for tps
        // get cookie
        String temp = hr.getCookieValue("pin");

        if (temp != null) {
            int index = temp.indexOf(";");
            HTTPClient.j_session_id = temp.substring(0, index);
            st = true;
        }

        hr = null;
        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri,
                "p=0&op=next&xml=true");

        // parse xml here

        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        st = true;
        return st;
    }

    public boolean DomainPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        String domain_url = "https://" + sd_hostname + ":" + sd_admin_port;

        String query_string = "p=3" + "&choice=existingdomain" + "&sdomainURL="
                + URLEncoder.encode(domain_url) + "&op=next" + "&xml=true";

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
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        String tps_url = "https://" + cs_hostname + ":" + cs_port
                + "/tps/admin/console/config/wizard" + "?p=3&subsystem=TPS";

        String query_string = "url=" + URLEncoder.encode(tps_url) + "";

        hr = hc.sslConnect(sd_hostname, sd_admin_port, sd_login_uri,
                query_string);

        String query_string_1 = "uid=" + sd_admin_name + "&pwd="
                + URLEncoder.encode(sd_admin_password) + "&url="
                + URLEncoder.encode(tps_url) + "";

        hr = hc.sslConnect(sd_hostname, sd_admin_port, sd_get_cookie_uri,
                query_string_1);

        // get session id from security domain
        sleep_time();

        tps_session_id = hr.getContentValue("header.session_id");
        String tps_url_1 = hr.getContentValue("header.url");

        System.out.println("TPS_SESSION_ID=" + tps_session_id);
        System.out.println("TPS_URL=" + tps_url_1);

        // use session id to connect back to TPS

        String query_string_2 = "p=5" + "&subsystem=TPS" + "&session_id="
                + tps_session_id + "&xml=true";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string_2);

        // parse xml - no parsing

        return true;

    }

    public boolean SubsystemPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        sleep_time();
        String query_string = "p=5" + "&choice=newsubsystem"
                + "&subsystemName=" + URLEncoder.encode(subsystem_name)
                + "&op=next" + "&xml=true";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        sleep_time();
        String ca_url = "https://" + ca_hostname + ":" + ca_ssl_port;

        // CA choice panel
        query_string = "p=6" + "&urls=0" + "&op=next" + "&xml=true";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        sleep_time();
        // TKS choice panel
        String tks_url = "https://" + tks_hostname + ":" + tks_ssl_port;
        query_string = "p=7" + "&urls=0" + "&op=next" + "&xml=true";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        // DRM / server side keygen panel

        sleep_time();
        if (ss_keygen.equalsIgnoreCase("true")) {
            ss_keygen = "keygen";
        }

        String drm_url = "https://" + drm_hostname + ":" + drm_ssl_port;

        query_string = "p=8" + "&choice=" + ss_keygen + "&urls=0" + "&op=next"
                + "&xml=true";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        return true;
    }

    public boolean LdapAuthConnectionPanel() {
        // auth db
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        String query_string = "p=9" + "&host="
                + URLEncoder.encode(ldap_auth_host) + "&port="
                + URLEncoder.encode(ldap_auth_port) + "&basedn="
                + URLEncoder.encode(ldap_auth_base_dn) + "&op=next"
                + "&xml=true";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        return true;
    }

    public boolean LdapConnectionPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        String query_string = "p=10" + "&host=" + URLEncoder.encode(ldap_host)
                + "&port=" + URLEncoder.encode(ldap_port) + "&binddn="
                + URLEncoder.encode(bind_dn) + "&__bindpwd="
                + URLEncoder.encode(bind_password) + "&basedn="
                + URLEncoder.encode(base_dn) + "&database="
                + URLEncoder.encode(db_name) + "&display="
                + URLEncoder.encode("") + "&op=next" + "&xml=true";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        return true;
    }

    public boolean TokenChoicePanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();

        // //////////////////////////////////////////////////////
        String query_string = null;

        // Software Token
        if (token_name.equalsIgnoreCase("internal")) {
            query_string = "p=1" + "&choice="
                    + URLEncoder.encode("NSS Certificate DB") + "&op=next"
                    + "&xml=true";

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();
        }
        // HSM
        else {
            // login to hsm first
            query_string = "p=2" + "&uTokName=" + URLEncoder.encode(token_name)
                    + "&__uPasswd=" + URLEncoder.encode(token_pwd) + "&op=next"
                    + "&xml=true";

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();

            // choice with token name now
            query_string = "p=1" + "&choice=" + URLEncoder.encode(token_name)
                    + "&op=next" + "&xml=true";

            hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);
            // parse xml
            bais = new ByteArrayInputStream(hr.getHTML().getBytes());
            px.parse(bais);
            px.prettyprintxml();

        }

        return true;
    }

    public boolean KeyPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();
        ArrayList<String> friendly_list = null;
        ArrayList<String> dn_list = null;

        String query_string = "p=11" + "&keytype=" + key_type
                + "&choice=default" + "&custom_size=" + key_size
                + "&sslserver_keytype=" + key_type + "&sslserver_choice=custom"
                + "&sslserver_custom_size=" + key_size + "&subsystem_keytype="
                + key_type + "&subsystem_choice=custom"
                + "&subsystem_custom_size=" + key_size
                + "&audit_signing_keytype=" + key_type
                + "&audit_signing_choice=default"
                + "&audit_signing_custom_size=" + key_size + "&op=next"
                + "&xml=true";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

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
        ArrayList<String> friendly_list = null;

        String ca_url = "https://" + ca_hostname + ":" + ca_ssl_port;

        String query_string = "p=12" + "&sslserver="
                + URLEncoder.encode(tps_server_cert_subject_name)
                + "&sslserver_nick="
                + URLEncoder.encode(tps_server_cert_nickname) + "&subsystem="
                + URLEncoder.encode(tps_subsystem_cert_subject_name)
                + "&subsystem_nick="
                + URLEncoder.encode(tps_subsystem_cert_nickname)
                + "&audit_signing="
                + URLEncoder.encode(tps_audit_signing_cert_subject_name)
                + "&audit_signing_nick="
                + URLEncoder.encode(tps_audit_signing_cert_nickname)
                + "&urls=0" + "&op=next" + "&xml=true";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        // parse the certs if needed

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

        String query_string = "p=13" + "&sslserver=" + "&sslserver_cc="
                + "&subsystem=" + "&subsystem_cc=" + "&audit_signing="
                + "&audit_signing_cc=" + "&op=next" + "&xml=true";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        return true;
    }

    public boolean AdminCertReqPanel() {
        boolean st = false;
        HTTPResponse hr = null;
        ByteArrayInputStream bais = null;
        ParseXML px = new ParseXML();
        String admin_cert_request = null;

        requestor_name = "TPS-" + cs_hostname + "-" + cs_clientauth_port;

        ComCrypto cCrypt = new ComCrypto(client_certdb_dir, client_certdb_pwd,
                agent_cert_subject, agent_key_size, agent_key_type);
        cCrypt.setDebug(true);
        cCrypt.setGenerateRequest(true);
        cCrypt.setTransportCert(null);
        cCrypt.setDualKey(false);
        cCrypt.loginDB();

        String crmf_request = cCrypt.generateCRMFrequest();

        if (crmf_request == null) {
            System.out
                    .println("ERROR: AdminCertReqPanel() cert req gen failed");
            return false;
        }

        admin_cert_request = crmf_request;

        String query_string = "p=14" + "&uid=" + admin_user + "&name="
                + URLEncoder.encode("TPS Administrator") + "&email="
                + URLEncoder.encode(admin_email) + "&__pwd="
                + URLEncoder.encode(admin_password)
                + "&__admin_password_again="
                + URLEncoder.encode(admin_password) + "&cert_request="
                + URLEncoder.encode(admin_cert_request) + "&display=0"
                + "&profileId=" + "caAdminCert" + "&cert_request_type="
                + "crmf" + "&import=true" + "&uid=" + admin_user + "&clone=0"
                + "&securitydomain=" + URLEncoder.encode(domain_name)
                + "&subject=" + URLEncoder.encode(agent_cert_subject)
                + "&requestor_name=" + URLEncoder.encode(requestor_name)
                + "&sessionID=" + tps_session_id + "&auth_hostname="
                + ca_hostname + "&auth_port=" + ca_ssl_port + "&op=next"
                + "&xml=true";

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
        String cert_to_import = null;

        String query_string = "serialNumber=" + admin_serial_number
                + "&importCert=" + "true" + "";

        // NOTE: CA, DRM, OCSP, and TKS use the Security Domain Admin Port;
        // whereas RA and TPS use the CA Admin Port associated with
        // the 'CA choice panel' as invoked from the SubsystemPanel()
        // which MAY or MAY NOT be the same CA as the CA specified
        // by the Security Domain.
        hr = hc.sslConnect(ca_hostname, ca_admin_port, admin_uri, query_string);

        try {
            // cert_to_import =
            // new sun.misc.BASE64Encoder().encode(hr.getResponseData());
            cert_to_import = OSUtil.BtoA(hr.getResponseData());

        } catch (Exception e) {
            System.out.println("ERROR: failed to retrieve cert");
        }

        System.out.println("Imported Cert=" + cert_to_import);

        ComCrypto cCrypt = new ComCrypto(client_certdb_dir, client_certdb_pwd,
                null, null, null);
        cCrypt.setDebug(true);
        cCrypt.setGenerateRequest(true);
        cCrypt.loginDB();

        String start = "-----BEGIN CERTIFICATE-----\r\n";
        String end = "\r\n-----END CERTIFICATE-----";

        st = cCrypt.importCert(start + cert_to_import + end, agent_name);
        if (!st) {
            System.out
                    .println("ERROR: AdminCertImportPanel() during cert import");
            return false;
        }

        System.out.println("SUCCESS: imported admin user cert");

        String query_string_1 = "p=15" + "&serialNumber=" + admin_serial_number
                + "&caHost=" + URLEncoder.encode(ca_hostname) + "&caPort="
                + ca_admin_port + "&op=next" + "&xml=true";

        hr = hc.sslConnect(cs_hostname, cs_port, wizard_uri, query_string_1);

        // parse xml
        bais = new ByteArrayInputStream(hr.getHTML().getBytes());
        px.parse(bais);
        px.prettyprintxml();

        return true;
    }

    public boolean ConfigureTPSInstance() {
        // 0. login to cert db
        ComCrypto cCrypt = new ComCrypto(client_certdb_dir, client_certdb_pwd,
                null, null, null);
        cCrypt.setDebug(true);
        cCrypt.setGenerateRequest(true);
        cCrypt.loginDB();

        // instantiate http client
        hc = new HTTPClient();

        sleep_time();
        // 1. Login panel
        boolean log_st = LoginPanel();
        if (!log_st) {
            System.out.println("ERROR: JSESSIONID not found.");
            System.out.println("ERROR: ConfigureTPS: LoginPanel() failure");
            return false;
        }

        sleep_time();
        // 2. Token Choice Panel
        boolean disp_token = TokenChoicePanel();
        if (!disp_token) {
            System.out
                    .println("ERROR: ConfigureTPS: TokenChoicePanel() failure");
            return false;
        }

        sleep_time();
        // 3. domain panel
        boolean dom_st = DomainPanel();
        if (!dom_st) {
            System.out.println("ERROR: ConfigureTPS: DomainPanel() failure");
            return false;
        }

        sleep_time();
        // 4. display cert chain panel
        boolean disp_st = DisplayChainPanel();
        if (!disp_st) {
            System.out
                    .println("ERROR: ConfigureTPS: DisplayChainPanel() failure");
            return false;
        }

        sleep_time();
        // 5. security domain login panel
        boolean disp_sd = SecurityDomainLoginPanel();
        if (!disp_sd) {
            System.out
                    .println("ERROR: ConfigureTPS: SecurityDomainLoginPanel() failure");
            return false;
        }

        sleep_time();
        // 6. subsystem panel
        boolean disp_ss = SubsystemPanel();
        if (!disp_ss) {
            System.out.println("ERROR: ConfigureTPS: SubsystemPanel() failure");
            return false;
        }

        sleep_time();
        // 7. ldap auth connection panel
        boolean disp_ldap_auth = LdapAuthConnectionPanel();
        if (!disp_ldap_auth) {
            System.out
                    .println("ERROR: ConfigureTPS: LdapAuthConnectionPanel() failure");
            return false;
        }

        sleep_time();
        // 8. ldap connection panel
        boolean disp_ldap = LdapConnectionPanel();
        if (!disp_ldap) {
            System.out
                    .println("ERROR: ConfigureTPS: LdapConnectionPanel() failure");
            return false;
        }

        sleep_time();
        // 11. Key Panel
        boolean disp_key = KeyPanel();
        if (!disp_key) {
            System.out.println("ERROR: ConfigureTPS: KeyPanel() failure");
            return false;
        }

        sleep_time();
        // 12. Cert Subject Panel
        boolean disp_csubj = CertSubjectPanel();
        if (!disp_csubj) {
            System.out
                    .println("ERROR: ConfigureTPS: CertSubjectPanel() failure");
            return false;
        }

        sleep_time();
        // 13. Certificate Panel
        boolean disp_cp = CertificatePanel();
        if (!disp_cp) {
            System.out
                    .println("ERROR: ConfigureTPS: CertificatePanel() failure");
            return false;
        }

        sleep_time();
        // 14. Admin Cert Req Panel
        boolean disp_adm = AdminCertReqPanel();
        if (!disp_adm) {
            System.out
                    .println("ERROR: ConfigureTPS: AdminCertReqPanel() failure");
            return false;
        }

        sleep_time();
        // 15. Admin Cert import Panel
        boolean disp_im = AdminCertImportPanel();
        if (!disp_im) {
            System.out
                    .println("ERROR: ConfigureTPS: AdminCertImportPanel() failure");
            return false;
        }

        return true;
    }

    public static void main(String args[]) {
        ConfigureTPS ca = new ConfigureTPS();

        // set variables
        StringHolder x_cs_hostname = new StringHolder();
        StringHolder x_cs_port = new StringHolder();
        StringHolder x_cs_clientauth_port = new StringHolder();

        StringHolder x_sd_hostname = new StringHolder();
        StringHolder x_sd_ssl_port = new StringHolder();
        StringHolder x_sd_agent_port = new StringHolder();
        StringHolder x_sd_admin_port = new StringHolder();
        StringHolder x_sd_admin_name = new StringHolder();
        StringHolder x_sd_admin_password = new StringHolder();

        StringHolder x_ca_hostname = new StringHolder();
        StringHolder x_ca_port = new StringHolder();
        StringHolder x_ca_ssl_port = new StringHolder();
        StringHolder x_ca_admin_port = new StringHolder();

        StringHolder x_drm_hostname = new StringHolder();
        StringHolder x_drm_ssl_port = new StringHolder();

        StringHolder x_tks_hostname = new StringHolder();
        StringHolder x_tks_ssl_port = new StringHolder();

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

        StringHolder x_ldap_auth_host = new StringHolder();
        StringHolder x_ldap_auth_port = new StringHolder();
        StringHolder x_ldap_auth_base_dn = new StringHolder();

        // key size
        StringHolder x_token_name = new StringHolder();
        StringHolder x_token_pwd = new StringHolder();
        StringHolder x_key_size = new StringHolder();
        StringHolder x_key_type = new StringHolder();

        StringHolder x_agent_key_size = new StringHolder();
        StringHolder x_agent_key_type = new StringHolder();
        StringHolder x_agent_cert_subject = new StringHolder();

        StringHolder x_agent_name = new StringHolder();

        StringHolder x_ss_keygen = new StringHolder();

        // tps cert subject name params
        StringHolder x_tps_server_cert_subject_name = new StringHolder();
        StringHolder x_tps_server_cert_nickname = new StringHolder();
        StringHolder x_tps_subsystem_cert_subject_name = new StringHolder();
        StringHolder x_tps_subsystem_cert_nickname = new StringHolder();
        StringHolder x_tps_audit_signing_cert_subject_name = new StringHolder();
        StringHolder x_tps_audit_signing_cert_nickname = new StringHolder();

        // subsystemName
        StringHolder x_subsystem_name = new StringHolder();

        // parse the args
        ArgParser parser = new ArgParser("ConfigureTPS");

        parser.addOption("-cs_hostname %s #CS Hostname", x_cs_hostname);
        parser.addOption("-cs_port %s #CS SSL port", x_cs_port);
        parser.addOption("-cs_clientauth_port %s #CS SSL port",
                x_cs_clientauth_port);

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

        parser.addOption("-ca_hostname %s #CA Hostname", x_ca_hostname);
        parser.addOption("-ca_port %s #CA non-SSL port", x_ca_port);
        parser.addOption("-ca_ssl_port %s #CA SSL port", x_ca_ssl_port);
        parser.addOption("-ca_admin_port %s #CA SSL Admin port",
                x_ca_admin_port);

        parser.addOption("-drm_hostname %s #DRM Hostname", x_drm_hostname);
        parser.addOption("-drm_ssl_port %s #DRM SSL port", x_drm_ssl_port);
        parser.addOption(
                "-ss_keygen %s #Enable Server Side Keygen [true,false]",
                x_ss_keygen);

        parser.addOption("-tks_hostname %s #TKS Hostname", x_tks_hostname);
        parser.addOption("-tks_ssl_port %s #TKS SSL port", x_tks_ssl_port);

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

        parser.addOption("-ldap_host %s #ldap host", x_ldap_host);
        parser.addOption("-ldap_port %s #ldap port", x_ldap_port);
        parser.addOption("-bind_dn %s #ldap bind dn", x_bind_dn);
        parser.addOption("-bind_password %s #ldap bind password",
                x_bind_password);
        parser.addOption("-base_dn %s #base dn", x_base_dn);
        parser.addOption("-db_name %s #db name", x_db_name);

        parser.addOption("-token_name %s #HSM/Software Token name",
                x_token_name);
        parser.addOption(
                "-token_pwd %s #HSM/Software Token password (optional, required for HSM)",
                x_token_pwd);
        parser.addOption("-key_size %s #Key Size", x_key_size);
        parser.addOption("-key_type %s #Key type [rsa,ecc]", x_key_type);

        parser.addOption("-agent_key_size %s #Agent Cert Key Size",
                x_agent_key_size);
        parser.addOption("-agent_key_type %s #Agent cert Key type [rsa]",
                x_agent_key_type);
        parser.addOption("-agent_cert_subject %s #Agent cert Subject",
                x_agent_cert_subject);

        parser.addOption("-ldap_auth_host %s #ldap auth host", x_ldap_auth_host);
        parser.addOption("-ldap_auth_port %s #ldap auth port", x_ldap_auth_port);
        parser.addOption("-ldap_auth_base_dn %s #ldap auth base dn",
                x_ldap_auth_base_dn);

        parser.addOption(
                "-tps_server_cert_subject_name %s #TPS server cert subject name",
                x_tps_server_cert_subject_name);
        parser.addOption(
                "-tps_server_cert_nickname %s #TPS server cert nickname",
                x_tps_server_cert_nickname);
        parser.addOption(
                "-tps_subsystem_cert_subject_name %s #TPS subsystem cert subject name",
                x_tps_subsystem_cert_subject_name);
        parser.addOption(
                "-tps_subsystem_cert_nickname %s #TPS subsystem cert nickname",
                x_tps_subsystem_cert_nickname);
        parser.addOption(
                "-tps_audit_signing_cert_subject_name %s #TPS audit signing cert subject name",
                x_tps_audit_signing_cert_subject_name);
        parser.addOption(
                "-tps_audit_signing_cert_nickname %s #TPS audit signing cert nickname",
                x_tps_audit_signing_cert_nickname);

        parser.addOption("-subsystem_name %s #CA subsystem name",
                x_subsystem_name);

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
        cs_clientauth_port = x_cs_clientauth_port.value;

        sd_hostname = x_sd_hostname.value;
        sd_ssl_port = x_sd_ssl_port.value;
        sd_agent_port = x_sd_agent_port.value;
        sd_admin_port = x_sd_admin_port.value;
        sd_admin_name = x_sd_admin_name.value;
        sd_admin_password = x_sd_admin_password.value;

        ca_hostname = x_ca_hostname.value;
        ca_port = x_ca_port.value;
        ca_ssl_port = x_ca_ssl_port.value;
        ca_admin_port = x_ca_admin_port.value;

        tks_hostname = x_tks_hostname.value;
        tks_ssl_port = x_tks_ssl_port.value;

        drm_hostname = x_drm_hostname.value;
        drm_ssl_port = x_drm_ssl_port.value;

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

        ldap_auth_host = x_ldap_auth_host.value;
        ldap_auth_port = x_ldap_auth_port.value;
        ldap_auth_base_dn = x_ldap_auth_base_dn.value;

        key_size = x_key_size.value;
        key_type = x_key_type.value;
        token_name = x_token_name.value;
        token_pwd = x_token_pwd.value;

        agent_key_size = x_agent_key_size.value;
        agent_key_type = x_agent_key_type.value;
        agent_cert_subject = x_agent_cert_subject.value;

        ss_keygen = x_ss_keygen.value;

        tps_server_cert_subject_name = x_tps_server_cert_subject_name.value;
        tps_server_cert_nickname = x_tps_server_cert_nickname.value;
        tps_subsystem_cert_subject_name = x_tps_subsystem_cert_subject_name.value;
        tps_subsystem_cert_nickname = x_tps_subsystem_cert_nickname.value;
        tps_audit_signing_cert_subject_name = x_tps_audit_signing_cert_subject_name.value;
        tps_audit_signing_cert_nickname = x_tps_audit_signing_cert_nickname.value;

        subsystem_name = x_subsystem_name.value;

        boolean st = ca.ConfigureTPSInstance();

        if (!st) {
            System.out.println("ERROR: unable to create TPS");
            System.exit(-1);
        }

        System.out.println("Certificate System - TPS Instance Configured");
        System.exit(0);

    }

};
