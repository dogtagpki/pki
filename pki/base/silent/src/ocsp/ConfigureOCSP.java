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

import com.netscape.osutil.*;

public class ConfigureOCSP
{

	public static Hashtable mUsedPort = new Hashtable();

	// define global variables

	public static HTTPClient hc = null;
	
	public static String login_uri = "/ocsp/admin/console/config/login";
	public static String wizard_uri = "/ocsp/admin/console/config/wizard";
	public static String ee_uri = "/ca/ee/ca/getBySerial";

	public static String sd_login_uri = "/ca/ee/ca/securityDomainLogin";
	public static String sd_get_cookie_uri = "/ca/ee/ca/getCookie";
	public static String pkcs12_uri = "/ocsp/admin/console/config/savepkcs12";

	public static String cs_hostname = null;
	public static String cs_port = null;

	public static String sd_hostname = null;
	public static String sd_ssl_port = null;
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

	public static String key_size = null;
	public static String key_type = null;
	public static String token_name = null;
	public static String token_pwd = null;

	public static String agent_key_size = null;
	public static String agent_key_type = null;
	public static String agent_cert_subject = null;

	public static String ocsp_signing_cert_name = null;
	public static String ocsp_signing_cert_req = null;
	public static String ocsp_signing_cert_pp = null;
	public static String ocsp_signing_cert_cert = null;

	public static String server_cert_name = null;
	public static String server_cert_req = null;
	public static String server_cert_pp = null;
	public static String server_cert_cert = null;

	public static String ocsp_subsystem_cert_name = null;
	public static String ocsp_subsystem_cert_req = null;
	public static String ocsp_subsystem_cert_pp = null;
	public static String ocsp_subsystem_cert_cert = null;

        public static String ocsp_audit_signing_cert_name = null;
        public static String ocsp_audit_signing_cert_req = null;
        public static String ocsp_audit_signing_cert_pp = null;
        public static String ocsp_audit_signing_cert_cert = null;


	public static String backup_pwd = null;

	// cert subject names 
	public static String ocsp_sign_cert_subject_name = null;
	public static String ocsp_subsystem_cert_subject_name = null;
	public static String ocsp_server_cert_subject_name = null;
        public static String ocsp_audit_signing_cert_subject_name = null;

	public static String subsystem_name = null;
	public ConfigureOCSP ()
	{
		// do nothing :)
	}

	public void sleep_time()
	{
		try
		{
			System.out.println("Sleeping for 5 secs..");
			Thread.sleep(5000);
		}
		catch(Exception e)
		{
			System.out.println("ERROR: sleep problem");
		}

	}

	public boolean LoginPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();

		String query_string = "pin=" + pin + "&xml=true"; 
	
		hr = hc.sslConnect(cs_hostname,cs_port,login_uri,query_string);
		System.out.println("xml returned: " + hr.getHTML());

		// parse xml here - nothing to parse

		// get cookie
		String temp = hr.getCookieValue("JSESSIONID");

		if(temp!=null)
		{
			int index = temp.indexOf(";");
			hc.j_session_id = temp.substring(0,index);
			st = true;
		}

		hr = null;
		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,
						"p=0&op=next&xml=true");

		// parse xml here

		bais = new ByteArrayInputStream(
							hr.getHTML().getBytes());
		px.parse(bais);
		px.prettyprintxml();

		return st;
	}

	public boolean DomainPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();


		String domain_url = "https://" + sd_hostname + ":" + sd_ssl_port ;

		String query_string = "sdomainURL=" +
							URLEncoder.encode(domain_url) +
							"&choice=existingdomain"+ 
							"&p=1" +
							"&op=next" +
							"&xml=true"; 

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
		px.parse(bais);
		px.prettyprintxml();

		return true;

	}

	public boolean DisplayChainPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();
		String query_string = null;

		query_string = "p=2" + "&op=next" + "&xml=true"; 
		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);
		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
		px.parse(bais);
		px.prettyprintxml();

		return true;

	}

	public boolean SecurityDomainLoginPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();


		String ocsp_url = "https://" + cs_hostname + ":" + cs_port +
							"/ocsp/admin/console/config/wizard" +
							"?p=3&subsystem=OCSP" ;

		String query_string = "url=" + URLEncoder.encode(ocsp_url); 

		hr = hc.sslConnect(sd_hostname,sd_ssl_port,sd_login_uri,query_string);

		String query_string_1 = "uid=" + sd_admin_name +
								"&pwd=" + sd_admin_password +
								"&url=" + URLEncoder.encode(ocsp_url) ;

		hr = hc.sslConnect(sd_hostname,sd_ssl_port,sd_get_cookie_uri,
						query_string_1);

		// get session id from security domain

		String ocsp_session_id = hr.getContentValue("header.session_id");
		String ocsp_url_1 = hr.getContentValue("header.url");

		System.out.println("OCSP_SESSION_ID=" + ocsp_session_id );
		System.out.println("OCSP_URL=" + ocsp_url_1 );

		// use session id to connect back to OCSP

		String query_string_2 = "p=3" +
								"&subsystem=OCSP" +
								"&session_id=" + ocsp_session_id +
								"&xml=true" ;

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,
						query_string_2);

		// parse xml
		// bais = new ByteArrayInputStream(hr.getHTML().getBytes());
		// px.parse(bais);
		// px.prettyprintxml();

		return true;

	}
	
	public boolean SubsystemPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();

		String query_string = "p=3" + "&op=next" + "&xml=true" + 
						"&subsystemName=" +
						URLEncoder.encode(subsystem_name) + 
						"&choice=newsubsystem" ; 

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);
		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
		px.parse(bais);
		px.prettyprintxml();

		return true;
	}

	public boolean LdapConnectionPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();


		String query_string = "p=5" + "&op=next" + "&xml=true" +
								"&host=" + URLEncoder.encode(ldap_host) + 
								"&port=" + URLEncoder.encode(ldap_port) +
								"&binddn=" + URLEncoder.encode(bind_dn) +
							"&__bindpwd=" + URLEncoder.encode(bind_password) +
								"&basedn=" + URLEncoder.encode(base_dn) +
								"&database=" + URLEncoder.encode(db_name) +
								"&display=" + URLEncoder.encode("displayStr") +
								""; 

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
		px.parse(bais);
		px.prettyprintxml();

		return true;
	}

	public boolean TokenChoicePanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();

		String query_string = null;

		// Software Token
		if(token_name.equalsIgnoreCase("internal"))
		{
			query_string = "p=6" + "&op=next" + "&xml=true" +
							"&choice=" + 
					URLEncoder.encode("Internal Key Storage Token") +
								""; 
			hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);
			// parse xml
			bais = new ByteArrayInputStream(hr.getHTML().getBytes());
			px.parse(bais);
			px.prettyprintxml();
		}
		// HSM
		else
		{
			// login to hsm first
			query_string = "p=7" + "&op=next" + "&xml=true" +
							"&uTokName=" + 
							URLEncoder.encode(token_name) +
							"&__uPasswd=" + 
							URLEncoder.encode(token_pwd) +
							""; 
			hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);
			// parse xml
			bais = new ByteArrayInputStream(hr.getHTML().getBytes());
			px.parse(bais);
			px.prettyprintxml();
		
			// choice with token name now
			query_string = "p=6" + "&op=next" + "&xml=true" +
							"&choice=" + 
							URLEncoder.encode(token_name) +
							""; 
			hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);
			// parse xml
			bais = new ByteArrayInputStream(hr.getHTML().getBytes());
			px.parse(bais);
			px.prettyprintxml();

		}


		return true;
	}

	public boolean KeyPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();
		ArrayList al = null;


		String query_string = "p=8" + "&op=next" + "&xml=true" +
							"&signing_custom_size=" + key_size +
							"&subsystem_custom_size=" + key_size +
							"&sslserver_custom_size=" + key_size +
                                                        "&audit_signing_custom_size=" + key_size +
							"&custom_size=" + key_size +
							"&signing_keytype=" + key_type + 
							"&subsystem_keytype=" + key_type + 
							"&sslserver_keytype=" + key_type +
                                                        "&audit_signing_keytype=" + key_type + 
							"&keytype=" + key_type + 
							"&signing_choice=default"+
							"&subsystem_choice=default"+
							"&sslserver_choice=default"+
                                                        "&audit_signing_choice=default" +
							"&choice=default"+
							""; 


		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
		px.parse(bais);
		px.prettyprintxml();
		
		al = px.constructvaluelist("CertReqPair","DN");
		// get ca cert subject name
		if(al != null)
		{
			for (int i=0; i < al.size(); i++)
			{
				String temp = (String) al.get(i);
				if(temp.indexOf("OCSP Signing") > 0 )
				{
					ocsp_signing_cert_name = temp;
				}
				else if(temp.indexOf("OCSP Subsystem") > 0 )
				{
					ocsp_subsystem_cert_name = temp;
				}
                                else if (temp.indexOf("Audit Signing Certificate") > 0) {
                                        ocsp_audit_signing_cert_name = temp;
                                }
				else 
				{
					server_cert_name = temp;
				}
			}
		}
		
	System.out.println("default: ocsp_signing_cert_name=" + ocsp_signing_cert_name);
	System.out.println("default: ocsp_subsystem_cert_name=" + ocsp_subsystem_cert_name);
	System.out.println("default: server_cert_name=" + server_cert_name);
        System.out.println("default: oscp_audit_signing_cert_name=" + ocsp_audit_signing_cert_name);

		return true;
	}

	public boolean CertSubjectPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();
		ArrayList req_list = null;
		ArrayList cert_list = null;
		ArrayList dn_list = null;

		String domain_url = "https://" + ca_hostname + ":" + ca_ssl_port ;

		String query_string = "p=9" + "&op=next" + "&xml=true" +
				"&subsystem=" + 
				URLEncoder.encode(ocsp_subsystem_cert_subject_name) +
				"&signing=" + 
				URLEncoder.encode(ocsp_sign_cert_subject_name) + 
				"&sslserver=" + 
				URLEncoder.encode(ocsp_server_cert_subject_name) + 
                                "&audit_signing=" +
                                URLEncoder.encode(ocsp_audit_signing_cert_name) +
				"&urls=" + 
				URLEncoder.encode(domain_url) + 
				""; 

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
		px.parse(bais);
		px.prettyprintxml();
		
		req_list = px.constructvaluelist("CertReqPair","Request");
		cert_list = px.constructvaluelist("CertReqPair","Certificate");
		dn_list = px.constructvaluelist("CertReqPair","Nickname");

		if(req_list != null && cert_list != null && dn_list != null)
		{
			for (int i=0; i < dn_list.size(); i++)
			{
				String temp = (String) dn_list.get(i);

				if(temp.indexOf("ocspSigningCert") >= 0 )
				{
					ocsp_signing_cert_req = (String) req_list.get(i);
					ocsp_signing_cert_cert = (String) cert_list.get(i);
				}
				else if(temp.indexOf("subsystemCert") >= 0 )
				{
					ocsp_subsystem_cert_req = (String) req_list.get(i);
					ocsp_subsystem_cert_cert = (String) cert_list.get(i);
				}
                                else if (temp.indexOf("auditSigningCert") >=0) {
                                        ocsp_audit_signing_cert_req = (String) req_list.get(i);
                                        ocsp_audit_signing_cert_cert = (String) cert_list.get(i);
                                }
				else 
				{
					server_cert_req = (String) req_list.get(i);
					server_cert_cert = (String) cert_list.get(i);
				}
			}
		}
		
		return true;
	}

	public boolean CertificatePanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();
		ArrayList req_list = null;
		ArrayList cert_list = null;
		ArrayList dn_list = null;
		ArrayList pp_list = null;


		String query_string = "p=10" + "&op=next" + "&xml=true" +
							"&subsystem=" + 
							URLEncoder.encode(ocsp_subsystem_cert_cert) +
							"&subsystem_cc=" + 
							"&signing=" + 
							URLEncoder.encode(ocsp_signing_cert_cert) + 
							"&signing_cc=" + 
							"&sslserver=" + 
							URLEncoder.encode(server_cert_cert) + 
							"&sslserver_cc=" + 
                                                        "&audit_signing=" + 
                                                        URLEncoder.encode(ocsp_audit_signing_cert_cert) +
                                                        "&audit_signing_cc=" +
							""; 

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
	
		System.out.println("html returned=" + hr.getHTML());

		px.parse(bais);
		px.prettyprintxml();
		
		return true;
	}

	public boolean BackupPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();


		String query_string = "p=11" + "&op=next" + "&xml=true" +
							"&choice=backupkey" + 
							"&__pwd=" + backup_pwd +
							"&__pwdagain=" + backup_pwd +
							""; 

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
		px.parse(bais);
		px.prettyprintxml();
		
		return true;
	}

	public boolean SavePKCS12Panel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();


		String query_string = ""; 

		hr = hc.sslConnect(cs_hostname,cs_port,pkcs12_uri,query_string);

		// dump hr.getResponseData() to file

		try
		{
			FileOutputStream fos = new FileOutputStream("/tmp/tmp-ocsp.p12");
			fos.write(hr.getResponseData());
			fos.close();

			
		// verify p12 file
		
		// Decode the P12 file
		FileInputStream fis = new FileInputStream("/tmp/tmp-ocsp.p12");
		PFX.Template pfxt = new PFX.Template();
		PFX pfx = (PFX) pfxt.decode(new BufferedInputStream(fis, 2048));
		System.out.println("Decoded PFX");

		// now peruse it for interesting info
		System.out.println("Version: "+pfx.getVersion());
		AuthenticatedSafes authSafes = pfx.getAuthSafes();
		SEQUENCE asSeq = authSafes.getSequence();
		System.out.println("AuthSafes has "+
			asSeq.size()+" SafeContents");

		fis.close();
		}
		catch(Exception e)
		{
			System.out.println("ERROR: Exception=" + e.getMessage());
			return false;
		}

		return true;
	}

	public boolean AdminCertReqPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();
		String admin_cert_request = null;


		String cert_subject = "CN=ocsp-" + admin_user;

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

		if(crmf_request == null)
		{
		System.out.println("ERROR: AdminCertReqPanel() cert req gen failed");
			return false;
		}

		admin_cert_request = crmf_request;

		String query_string = "p=13" + "&op=next" + "&xml=true" +
							"&cert_request_type=" + "crmf" +
							"&uid=" + admin_user +
							"&name=" + admin_user +
							"&__pwd=" + admin_password +
							"&__admin_password_again=" + admin_password +
							"&profileId=" + "caAdminCert" +
							"&email=" + 
							URLEncoder.encode(admin_email) +
							"&cert_request=" + 
							URLEncoder.encode(admin_cert_request) +
							"&subject=" + agent_cert_subject +
							"&clone=new" +
							"&import=true" +
							"&securitydomain=" + domain_name +
							""; 

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
		px.parse(bais);
		px.prettyprintxml();
		
		admin_serial_number  = px.getvalue("serialNumber");

		return true;
	}

	public boolean AdminCertImportPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();

		String query_string = "serialNumber=" + admin_serial_number +
							"&importCert=" + "true" +
							""; 

		hr = hc.sslConnect(ca_hostname,ca_ssl_port,ee_uri,query_string);
		
		// get response data
		String cert_to_import = 
				new sun.misc.BASE64Encoder().encode(hr.getResponseData());
		System.out.println("Imported Cert=" + cert_to_import);

		ComCrypto cCrypt = new ComCrypto(client_certdb_dir,
										client_certdb_pwd,
										null,
										null,
										null);
		cCrypt.setDebug(true);
		cCrypt.setGenerateRequest(true);
		cCrypt.loginDB();

		String start = "-----BEGIN CERTIFICATE-----\r\n" ;
		String end = "\r\n-----END CERTIFICATE-----" ;

		st = cCrypt.importCert(start+cert_to_import+end,agent_name);
		if(!st)
		{
		System.out.println("ERROR: AdminCertImportPanel() during cert import");
			return false;
		}

		System.out.println("SUCCESS: imported admin user cert");
		return true;
	}

	public boolean UpdateDomainPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();

		String query_string = "p=14" + "&op=next" + "&xml=true" +
							"&caHost=" + URLEncoder.encode(ca_hostname) +
							"&caPort=" + URLEncoder.encode(ca_port) +
							""; 

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
		px.parse(bais);
		px.prettyprintxml();
		
		return true;
	}


	public boolean ConfigureOCSPInstance()
	{
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
		if(!log_st)
		{
			System.out.println("ERROR: ConfigureOCSP: LoginPanel() failure");
			return false;
		}

		sleep_time();
		// 2. domain panel
		boolean dom_st = DomainPanel();
		if(!dom_st)
		{
			System.out.println("ERROR: ConfigureOCSP: DomainPanel() failure");
			return false;
		}

		sleep_time();
		// 3. display cert chain panel
		boolean disp_st = DisplayChainPanel();
		if(!disp_st)
		{
		System.out.println("ERROR: ConfigureOCSP: DisplayChainPanel() failure");
			return false;
		}

		sleep_time();
		// security domain login panel
		boolean disp_sd = SecurityDomainLoginPanel();
		if(!disp_sd)
		{
		System.out.println("ERROR: ConfigureOCSP: SecurityDomainLoginPanel() failure");
			return false;
		}

		sleep_time();
		// subsystem panel
		boolean disp_ss = SubsystemPanel();
		if(!disp_ss)
		{
		System.out.println("ERROR: ConfigureOCSP: SubsystemPanel() failure");
			return false;
		}
		
		sleep_time();
		// 7. ldap connection panel
		boolean disp_ldap = LdapConnectionPanel();
		if(!disp_ldap)
		{
		System.out.println("ERROR: ConfigureOCSP: LdapConnectionPanel() failure");
			return false;
		}

		sleep_time();
		sleep_time();
		// 8. Token Choice Panel
		boolean disp_token = TokenChoicePanel();
		if(!disp_token)
		{
		System.out.println("ERROR: ConfigureOCSP: TokenChoicePanel() failure");
			return false;
		}

		sleep_time();
		// 9. Key Panel
		boolean disp_key = KeyPanel();
		if(!disp_key)
		{
		System.out.println("ERROR: ConfigureOCSP: KeyPanel() failure");
			return false;
		}

		sleep_time();
		// 10. Cert Subject Panel
		boolean disp_csubj = CertSubjectPanel();
		if(!disp_csubj)
		{
		System.out.println("ERROR: ConfigureOCSP: CertSubjectPanel() failure");
			return false;
		}

		sleep_time();
		// 11. Certificate Panel
		boolean disp_cp = CertificatePanel();
		if(!disp_cp)
		{
		System.out.println("ERROR: ConfigureOCSP: CertificatePanel() failure");
			return false;
		}

		sleep_time();
		// backup panel
		boolean disp_back = BackupPanel();
		if(!disp_back)
		{
		System.out.println("ERROR: ConfigureOCSP: BackupPanel() failure");
			return false;
		}

		sleep_time();
		// save panel
		boolean disp_save = SavePKCS12Panel();
		if(!disp_save)
		{
		System.out.println("ERROR: ConfigureOCSP: SavePKCS12Panel() failure");
			return false;
		}

		sleep_time();
		// 13. Admin Cert Req Panel
		boolean disp_adm = AdminCertReqPanel();
		if(!disp_adm)
		{
		System.out.println("ERROR: ConfigureOCSP: AdminCertReqPanel() failure");
			return false;
		}

		sleep_time();
		// 14. Admin Cert import Panel
		boolean disp_im = AdminCertImportPanel();
		if(!disp_im)
		{
	System.out.println("ERROR: ConfigureOCSP: AdminCertImportPanel() failure");
			return false;
		}

		sleep_time();
		// 15. Update Domain Panel
		boolean disp_ud = UpdateDomainPanel();
		if(!disp_ud)
		{
	System.out.println("ERROR: ConfigureOCSP: UpdateDomainPanel() failure");
			return false;
		}

		sleep_time();
		return true;
	}

	public static void main(String args[])
	{
		ConfigureOCSP ca = new ConfigureOCSP();

		// set variables
		StringHolder x_cs_hostname = new StringHolder();
		StringHolder x_cs_port = new StringHolder();

		StringHolder x_sd_hostname = new StringHolder();
		StringHolder x_sd_ssl_port = new StringHolder();
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

		// key size
		StringHolder x_key_size = new StringHolder();
		StringHolder x_key_type = new StringHolder();
		StringHolder x_token_name = new StringHolder();
		StringHolder x_token_pwd = new StringHolder();

		StringHolder x_agent_key_size = new StringHolder();
		StringHolder x_agent_key_type = new StringHolder();
		StringHolder x_agent_cert_subject = new StringHolder();

		StringHolder x_agent_name = new StringHolder();
		StringHolder x_backup_pwd = new StringHolder();

		// ca cert subject name params
		StringHolder x_ocsp_sign_cert_subject_name = new StringHolder();
		StringHolder x_ocsp_subsystem_cert_subject_name = new StringHolder();
		StringHolder x_ocsp_server_cert_subject_name = new StringHolder();
                StringHolder x_ocsp_audit_signing_cert_subject_name = new StringHolder();

		// subsystemName
		StringHolder x_subsystem_name = new StringHolder();

		// parse the args
		ArgParser parser = new ArgParser("ConfigureOCSP");

		parser.addOption ("-cs_hostname %s #CS Hostname",
							x_cs_hostname); 
		parser.addOption ("-cs_port %s #CS SSL port",
							x_cs_port); 

		parser.addOption ("-sd_hostname %s #Security Domain Hostname",
							x_sd_hostname); 
		parser.addOption ("-sd_ssl_port %s #Security Domain SSL port",
							x_sd_ssl_port); 
		parser.addOption ("-sd_admin_name %s #Security Domain Admin Name",
							x_sd_admin_name); 
		parser.addOption ("-sd_admin_password %s #Security Domain Admin password",
							x_sd_admin_password); 

		parser.addOption ("-ca_hostname %s #CA Hostname",
							x_ca_hostname); 
		parser.addOption ("-ca_port %s #CA non SSL port",
							x_ca_port); 
		parser.addOption ("-ca_ssl_port %s #CA SSL port",
							x_ca_ssl_port); 

		parser.addOption ("-client_certdb_dir %s #Client CertDB dir",
							x_client_certdb_dir); 
		parser.addOption ("-client_certdb_pwd %s #client certdb password",
							x_client_certdb_pwd); 
		parser.addOption ("-preop_pin %s #pre op pin",
							x_preop_pin); 
		parser.addOption ("-domain_name %s #domain name",
							x_domain_name); 
		parser.addOption ("-admin_user %s #Admin User Name",
							x_admin_user); 
		parser.addOption ("-admin_email %s #Admin email",
							x_admin_email); 
		parser.addOption ("-admin_password %s #Admin password",
							x_admin_password); 
		parser.addOption ("-agent_name %s #Agent Cert Nickname",
							x_agent_name); 

		parser.addOption ("-ldap_host %s #ldap host",
							x_ldap_host); 
		parser.addOption ("-ldap_port %s #ldap port",
							x_ldap_port); 
		parser.addOption ("-bind_dn %s #ldap bind dn",
							x_bind_dn); 
		parser.addOption ("-bind_password %s #ldap bind password",
							x_bind_password); 
		parser.addOption ("-base_dn %s #base dn",
							x_base_dn); 
		parser.addOption ("-db_name %s #db name",
							x_db_name); 

		parser.addOption ("-key_size %s #Key Size",
							x_key_size); 
		parser.addOption ("-key_type %s #Key type [RSA,ECC]",
							x_key_type); 
		parser.addOption ("-token_name %s #HSM/Software Token name",
							x_token_name); 
		parser.addOption ("-token_pwd %s #HSM/Software Token password",
							x_token_pwd); 

		parser.addOption ("-agent_key_size %s #Agent Cert Key Size",
							x_agent_key_size); 
		parser.addOption ("-agent_key_type %s #Agent Cert Key type [rsa]",
							x_agent_key_type); 
		parser.addOption ("-agent_cert_subject %s #Agent Cert Subject",
							x_agent_cert_subject); 

		parser.addOption ("-backup_pwd %s #PKCS12 password",
							x_backup_pwd); 

		parser.addOption (
		"-ocsp_sign_cert_subject_name %s #OCSP cert subject name",
							x_ocsp_sign_cert_subject_name);
		parser.addOption (
		"-ocsp_subsystem_cert_subject_name %s #OCSP subsystem cert subject name",
							x_ocsp_subsystem_cert_subject_name); 
		parser.addOption (
		"-ocsp_server_cert_subject_name %s #OCSP server cert subject name",
							x_ocsp_server_cert_subject_name); 

		parser.addOption (
		"-subsystem_name %s #OCSP subsystem name",
							x_subsystem_name); 

                parser.addOption(
                "-ocsp_audit_signing_cert_subject_name %s #OCSP audit signing cert subject name",
                                                        x_ocsp_audit_signing_cert_subject_name);

		// and then match the arguments
		String [] unmatched = null;
		unmatched = parser.matchAllArgs (args,0,parser.EXIT_ON_UNMATCHED);

		if(unmatched!=null)
		{
			System.out.println("ERROR: Argument Mismatch");
			System.exit(-1);
		}

		// set variables
		cs_hostname = x_cs_hostname.value;
		cs_port = x_cs_port.value;

		sd_hostname = x_sd_hostname.value;
		sd_ssl_port = x_sd_ssl_port.value;
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

		key_size = x_key_size.value;
		key_type = x_key_type.value;
		token_name = x_token_name.value;
		token_pwd = x_token_pwd.value;

		agent_key_size = x_agent_key_size.value;
		agent_key_type = x_agent_key_type.value;
		agent_cert_subject = x_agent_cert_subject.value;

		backup_pwd = x_backup_pwd.value;
		
		ocsp_sign_cert_subject_name = x_ocsp_sign_cert_subject_name.value ;
		ocsp_subsystem_cert_subject_name = 
			x_ocsp_subsystem_cert_subject_name.value;
		ocsp_server_cert_subject_name = x_ocsp_server_cert_subject_name.value ;
                ocsp_audit_signing_cert_subject_name = x_ocsp_audit_signing_cert_subject_name.value;
		
		subsystem_name = x_subsystem_name.value ;


		boolean st = ca.ConfigureOCSPInstance();
	
		if (!st)
		{
			System.out.println("ERROR: unable to create OCSP");
			System.exit(-1);
		}
	
		System.out.println("Certficate System - OCSP Instance Configured");
		System.exit(0);
		
	}

};
