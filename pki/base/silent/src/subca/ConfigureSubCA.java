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

public class ConfigureSubCA
{

	public static Hashtable mUsedPort = new Hashtable();

	// define global variables

	public static HTTPClient hc = null;
	
	public static String login_uri = "/ca/admin/console/config/login";
	public static String wizard_uri = "/ca/admin/console/config/wizard";
	public static String domain_uri = "/ca/ee/ca/domain";
	public static String ee_uri = "/ca/ee/ca/getBySerial";
	public static String sd_login_uri = "/ca/ee/ca/securityDomainLogin";
	public static String sd_get_cookie_uri = "/ca/ee/ca/getCookie";
	public static String pkcs12_uri = "/ca/admin/console/config/savepkcs12";

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

	public static String backup_pwd = null;

	public static String subsystem_name = null;

	// names 
	public static String subca_sign_cert_subject_name = null;
	public static String subca_subsystem_cert_subject_name = null;
	public static String subca_ocsp_cert_subject_name = null;
	public static String subca_server_cert_subject_name = null;
        public static String subca_audit_signing_cert_subject_name = null;

	public ConfigureSubCA ()
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
							"&sdomainName="+
							"&choice=existingdomain"+ 
							"&p=1" +
							"&op=next" +
							"&xml=true"; 

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
		px.parse(bais);
		px.prettyprintxml();

		String query_string_1 = "p=2" +
							"&op=next" +
							"&xml=true"; 

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string_1);

		return true;

	}

	public boolean SecurityDomainLoginPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();


		String subca_url = "https://" + cs_hostname + ":" + cs_port +
							"/ca/admin/console/config/wizard" +
							"?p=3&subsystem=CA" ;

		String query_string = "url=" + URLEncoder.encode(subca_url); 

		hr = hc.sslConnect(sd_hostname,sd_ssl_port,sd_login_uri,query_string);

		String query_string_1 = "uid=" + sd_admin_name +
								"&pwd=" + sd_admin_password +
								"&url=" + URLEncoder.encode(subca_url) ;

		hr = hc.sslConnect(sd_hostname,sd_ssl_port,sd_get_cookie_uri,
						query_string_1);

		// get session id from security domain

		String subca_session_id = hr.getContentValue("header.session_id");
		String subca_url_1 = hr.getContentValue("header.url");

		System.out.println("SUBCA_SESSION_ID=" + subca_session_id );
		System.out.println("SUBCA_URL=" + subca_url_1 );

		// use session id to connect back to subCA

		String query_string_2 = "p=3" +
								"&subsystem=CA" +
								"&session_id=" + subca_session_id +
								"&xml=true" ;

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,
						query_string_2);

		return true;

	}

	public boolean DisplayChainPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();

		String query_string;

		hr = null;
		query_string = "p=3" + "&op=next" + "&xml=true" +
						"&choice=newsubsystem" +
						"&subsystemName=" +
						URLEncoder.encode(subsystem_name) +
						"&urls=0" ; 
		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);
		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
		px.parse(bais);
		px.prettyprintxml();

		return true;
	}

	public boolean HierarchyPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();


		String query_string = "p=6" + "&op=next" + "&xml=true" +
								"&choice=join" ; 

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


		String query_string = "p=7" + "&op=next" + "&xml=true" +
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

		///////////////////////////////////////////////////////
		String query_string = null;

		// Software Token
		if(token_name.equalsIgnoreCase("internal"))
		{
			query_string = "p=8" + "&op=next" + "&xml=true" +
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
			query_string = "p=9" + "&op=next" + "&xml=true" +
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
			query_string = "p=8" + "&op=next" + "&xml=true" +
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


		String query_string = "p=10" + "&op=next" + "&xml=true" +
							"&subsystem_custom_size=" + key_size +
							"&sslserver_custom_size=" + key_size +
							"&signing_keytype=" + key_type + 
							"&keytype=" + key_type + 
							"&choice=default"+
							"&op=next"+
							"&custom_size=" + key_size +
							"&ocsp_signing_keytype=" + key_type + 
							"&subsystem_keytype=" + key_type + 
							"&ocsp_signing_custom_size=" + key_size +
							"&signing_custom_size=" + key_size +
							"&ocsp_signing_choice=default"+
							"&signing_choice=default"+
							"&subsystem_choice=default"+
							"&sslserver_keytype=" + key_type + 
							"&sslserver_choice=default"+
                                                        "&audit_signing_choice=default" + 
                                                        "&audit_signing_keytype=" + key_type +
                                                        "&audit_signing_custom_size=" + key_size + 
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
				if(temp.indexOf("Certificate Authority") > 0 )
				{
					ca_cert_name = temp;
				}
				else if(temp.indexOf("OCSP Signing Certificate") > 0 )
				{
					ocsp_cert_name = temp;
				}
				else if(temp.indexOf("Subsystem Certificate") > 0 )
				{
					ca_subsystem_cert_name = temp;
                                } 
                                else if (temp.indexOf("Audit Signing Certificate") > 0) 
                                {
                                        ca_audit_signing_cert_name = temp;
                                }
				else 
				{
					server_cert_name = temp;
				}
			}
		}
		
		System.out.println("default: ca_cert_name=" + ca_cert_name);
		System.out.println("default: ocsp_cert_name=" + ocsp_cert_name);
		System.out.println("default: ca_subsystem_cert_name=" + 
						ca_subsystem_cert_name);
		System.out.println("default: server_cert_name=" + server_cert_name);
                System.out.println("default: ca_audit_signing_cert_name=" + 
                    ca_audit_signing_cert_name);
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


		String query_string = "p=11" + "&op=next" + "&xml=true" +
			"&subsystem=" + 
			URLEncoder.encode(subca_subsystem_cert_subject_name) +
			"&ocsp_signing=" + 
			URLEncoder.encode(subca_ocsp_cert_subject_name) +
			"&signing=" + 
			URLEncoder.encode(subca_sign_cert_subject_name) + 
			"&sslserver=" + 
			URLEncoder.encode(subca_server_cert_subject_name) + 
                        "&audit_signing=" +
                        URLEncoder.encode(subca_audit_signing_cert_subject_name) + 
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

		System.out.println("req_list_size=" + req_list.size());
		System.out.println("cert_list_size=" + cert_list.size());
		System.out.println("dn_list_size=" + dn_list.size());

		if(req_list != null && cert_list != null && dn_list != null)
		{
			for (int i=0; i < dn_list.size(); i++)
			{
				String temp = (String) dn_list.get(i);

				if(temp.indexOf("caSigningCert") >= 0 )
				{
					ca_cert_req = (String) req_list.get(i);
					ca_cert_cert = (String) cert_list.get(i);
				}
				else if(temp.indexOf("ocspSigningCert") >= 0 )
				{
					ocsp_cert_req = (String) req_list.get(i);
					ocsp_cert_cert = (String) cert_list.get(i);
				}
				else if(temp.indexOf("subsystemCert") >= 0 )
				{
					ca_subsystem_cert_req = (String) req_list.get(i);
					ca_subsystem_cert_cert = (String) cert_list.get(i);
				}
                                else if (temp.indexOf("auditSigningCert") >=0) {
                                    ca_audit_signing_cert_req = (String) req_list.get(i);
                                    ca_audit_signing_cert_cert = (String) cert_list.get(i);
                                }
				else 
				{
					server_cert_req = (String) req_list.get(i);
					server_cert_cert = (String) cert_list.get(i);
				}
			}
		}
		
		System.out.println("ca_cert_name=" + subca_sign_cert_subject_name);
		System.out.println("ocsp_cert_name=" + subca_ocsp_cert_subject_name);
		System.out.println("ca_subsystem_cert_name=" + 
						subca_subsystem_cert_subject_name);
		System.out.println("server_cert_name=" + 
						subca_server_cert_subject_name);
                System.out.println("audit_signing_cert_name=" + subca_audit_signing_cert_subject_name);

		System.out.println("ca_cert_req=" + ca_cert_req);
		System.out.println("ocsp_cert_req=" + ocsp_cert_req);
		System.out.println("ca_subsystem_cert_req=" + ca_subsystem_cert_req);
		System.out.println("server_cert_req=" + server_cert_req);
                System.out.println("ca_audit_siging_cert_req=" + ca_audit_signing_cert_req);

		System.out.println("ca_cert_cert=" + ca_cert_cert);
		System.out.println("ocsp_cert_cert=" + ocsp_cert_cert);
		System.out.println("ca_subsystem_cert_cert=" + ca_subsystem_cert_cert);
		System.out.println("server_cert_cert=" + server_cert_cert);
                System.out.println("ca_audit_signing_cert_cert=" + ca_audit_signing_cert_cert);

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


		String query_string = "p=12" + "&op=next" + "&xml=true" +
							"&subsystem=" + 
							URLEncoder.encode(ca_subsystem_cert_cert) +
							"&subsystem_cc=" + 
							"&ocsp_signing=" + 
							URLEncoder.encode(ocsp_cert_cert) +
							"&ocsp_signing_cc=" + 
							"&signing=" + 
							URLEncoder.encode(ca_cert_cert) + 
							"&signing_cc=" + 
							"&sslserver=" + 
							URLEncoder.encode(server_cert_cert) + 
							"&sslserver_cc=" + 
                                                        "&audit_signing=" + 
                                                        URLEncoder.encode(ca_audit_signing_cert_cert) +
                                                        "&audit_signing_cc=" +
							""; 

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

		// parse xml
		bais = new ByteArrayInputStream(hr.getHTML().getBytes());
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


		String query_string = "p=13" + "&op=next" + "&xml=true" +
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
			FileOutputStream fos = new FileOutputStream("/tmp/tmp-subca.p12");
			fos.write(hr.getResponseData());
			fos.close();

			
		// verify p12 file
		
		// Decode the P12 file
		FileInputStream fis = new FileInputStream("/tmp/tmp-subca.p12");
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


		String cert_subject = "CN=" + "subca-" + admin_user;

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

		String query_string = "p=16" + "&op=next" + "&xml=true" +
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

		hr = hc.sslConnect(cs_hostname,cs_port,ee_uri,query_string);
		
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

		System.out.println("SUCCESS: imported admin user cert:" + agent_name);
		return true;
	}

	public boolean UpdateDomainPanel()
	{
		boolean st = false;
		HTTPResponse hr = null;
		ByteArrayInputStream bais = null;
		ParseXML px = new ParseXML();

		String query_string = "p=17" + "&op=next" + "&xml=true" +
							"&caHost=" + URLEncoder.encode("/") +
							"&caPort=" + URLEncoder.encode("/") +
							""; 

		hr = hc.sslConnect(cs_hostname,cs_port,wizard_uri,query_string);

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
		
		return true;
	}

	public boolean ConfigureCAInstance()
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

		sleep_time();
		// 1. Login panel
		boolean log_st = LoginPanel();
		if(!log_st)
		{
			System.out.println("ERROR: ConfigureCA: LoginPanel() failure");
			return false;
		}

		sleep_time();
		// 2. domain panel
		boolean dom_st = DomainPanel();
		if(!dom_st)
		{
			System.out.println("ERROR: ConfigureCA: DomainPanel() failure");
			return false;
		}

		sleep_time();
		// 2a. domain panel
		boolean sd_st = SecurityDomainLoginPanel();
		if(!sd_st)
		{
			System.out.println("ERROR: ConfigureSubCA: SecurityDomainLoginPanel() failure");
			return false;
		}

		sleep_time();
		// 3. display cert chain panel
		boolean disp_st = DisplayChainPanel();
		if(!disp_st)
		{
		System.out.println("ERROR: ConfigureCA: DisplayChainPanel() failure");
			return false;
		}

		sleep_time();
		// 5. hierarchy panel
		boolean disp_h = HierarchyPanel();
		if(!disp_h)
		{
		System.out.println("ERROR: ConfigureCA: HierarchyPanel() failure");
			return false;
		}

		sleep_time();
		// 7. ldap connection panel
		boolean disp_ldap = LdapConnectionPanel();
		if(!disp_ldap)
		{
		System.out.println("ERROR: ConfigureCA: LdapConnectionPanel() failure");
			return false;
		}

		sleep_time();
		// 8. Token Choice Panel
		boolean disp_token = TokenChoicePanel();
		if(!disp_token)
		{
		System.out.println("ERROR: ConfigureCA: TokenChoicePanel() failure");
			return false;
		}

		sleep_time();
		// 9. Key Panel
		boolean disp_key = KeyPanel();
		if(!disp_key)
		{
		System.out.println("ERROR: ConfigureCA: KeyPanel() failure");
			return false;
		}

		sleep_time();
		// 10. Cert Subject Panel
		boolean disp_csubj = CertSubjectPanel();
		if(!disp_csubj)
		{
		System.out.println("ERROR: ConfigureCA: CertSubjectPanel() failure");
			return false;
		}

		sleep_time();
		// 11. Certificate Panel
		boolean disp_cp = CertificatePanel();
		if(!disp_cp)
		{
		System.out.println("ERROR: ConfigureCA: CertificatePanel() failure");
			return false;
		}

		sleep_time();
		boolean disp_back = BackupPanel();
		if(!disp_back)
		{
		System.out.println("ERROR: ConfigureCA: BackupPanel() failure");
			return false;
		}

		sleep_time();
		boolean disp_save = SavePKCS12Panel();
		if(!disp_save)
		{
		System.out.println("ERROR: ConfigureCA: SavePKCS12Panel() failure");
			return false;
		}

		sleep_time();
		// 13. Admin Cert Req Panel
		boolean disp_adm = AdminCertReqPanel();
		if(!disp_adm)
		{
		System.out.println("ERROR: ConfigureCA: AdminCertReqPanel() failure");
			return false;
		}

		sleep_time();
		// 14. Admin Cert import Panel
		boolean disp_im = AdminCertImportPanel();
		if(!disp_im)
		{
	System.out.println("ERROR: ConfigureCA: AdminCertImportPanel() failure");
			return false;
		}

		sleep_time();
		// 15. Update Domain Panel
		boolean disp_ud = UpdateDomainPanel();
		if(!disp_ud)
		{
	System.out.println("ERROR: ConfigureCA: UpdateDomainPanel() failure");
			return false;
		}


		return true;
	}

	public static void main(String args[])
	{
		ConfigureSubCA ca = new ConfigureSubCA();

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

		// subsystem name
		StringHolder x_subsystem_name = new StringHolder();

		// subject names
		StringHolder x_subca_sign_cert_subject_name = new StringHolder();
		StringHolder x_subca_subsystem_cert_subject_name = new StringHolder();
		StringHolder x_subca_ocsp_cert_subject_name = new StringHolder();
		StringHolder x_subca_server_cert_subject_name = new StringHolder();
                StringHolder x_subca_audit_signing_cert_subject_name = new StringHolder();

		// parse the args
		ArgParser parser = new ArgParser("ConfigureSubCA");

		parser.addOption ("-cs_hostname %s #CS Hostname",
							x_cs_hostname); 
		parser.addOption ("-cs_port %s #CS SSL port",
							x_cs_port); 

		parser.addOption ("-sd_hostname %s #Security Domain Hostname",
							x_sd_hostname); 
		parser.addOption ("-sd_ssl_port %s #Security Domain SSL port",
							x_sd_ssl_port); 
		parser.addOption ("-sd_admin_name %s #Security Domain admin name",
							x_sd_admin_name); 
		parser.addOption ("-sd_admin_password %s #Security Domain admin password",
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

		parser.addOption ("-backup_pwd %s #PKCS12 backup password",
							x_backup_pwd); 

		parser.addOption ("-subsystem_name %s #Subsystem name",
							x_subsystem_name); 

		parser.addOption (
		"-subca_sign_cert_subject_name %s #subCA cert subject name",
							x_subca_sign_cert_subject_name);
		parser.addOption (
		"-subca_subsystem_cert_subject_name %s #subCA subsystem cert subject name",
							x_subca_subsystem_cert_subject_name); 
		parser.addOption (
		"-subca_ocsp_cert_subject_name %s #subCA ocsp cert subject name",
							x_subca_ocsp_cert_subject_name); 
		parser.addOption (
		"-subca_server_cert_subject_name %s #subCA server cert subject name",
							x_subca_server_cert_subject_name); 
                parser.addOption(
                "-subca_audit_signing_cert_subject_name %s #CA audit signing cert subject name",
                x_subca_audit_signing_cert_subject_name);

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
		subsystem_name = x_subsystem_name.value;
		
		subca_sign_cert_subject_name = x_subca_sign_cert_subject_name.value ;
		subca_subsystem_cert_subject_name = 
				x_subca_subsystem_cert_subject_name.value;
		subca_ocsp_cert_subject_name = x_subca_ocsp_cert_subject_name.value ;
		subca_server_cert_subject_name = x_subca_server_cert_subject_name.value ;
                subca_audit_signing_cert_subject_name = x_subca_audit_signing_cert_subject_name.value;

		boolean st = ca.ConfigureCAInstance();
	
		if (!st)
		{
			System.out.println("ERROR: unable to create CA");
			System.exit(-1);
		}
	
		System.out.println("Certficate System - CA Instance Configured.");
		System.exit(0);
		
	}

};
