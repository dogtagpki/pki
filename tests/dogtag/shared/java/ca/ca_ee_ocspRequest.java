import java.io.*;
import java.util.*;
import java.text.*;
import java.net.*;
import java.security.*;

import org.mozilla.jss.*;
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
import com.netscape.cmsutil.http.*;
//import com.netscape.osutil.*;

public class ca_ee_ocspRequest
{

	private static String url = "/ca/ocsp" ;
	private static String client_certdb_dir = null;
	private static String client_certdb_pwd = null;
	private static String ca_cert_nickname = null;
	private static String serial_number = null;
	private static String ca_hostname = null;
	private static String ca_ee_port = null;
	private static String debug = null;
	private String query = null;

	private byte[] responseData;
	private byte[] request_data;

	private static HTTPResponse hr = null;

	public ca_ee_ocspRequest()
	{
		// Do nothing
 	}

	public boolean buildquery()
	{
		boolean st = true;
                OCSPRequest  ocsp_req = null;
                ByteArrayOutputStream os = null;

                X509Certificate cert = null;
                // prepare ocsp request
                try
                {
                        CryptoManager manager = CryptoManager.getInstance();
                        cert = manager.findCertByNickname(ca_cert_nickname);
                        MessageDigest md = MessageDigest.getInstance("SHA");

                        // calculate issuer key hash
                        X509CertImpl x509Cert = new X509CertImpl(cert.getEncoded());
                        X509Key x509key = (X509Key)x509Cert.getPublicKey();
                        byte issuerKeyHash[] = md.digest(x509key.getKey());

                        // calculate name hash
                        X500Name name = (X500Name)x509Cert.getSubjectDN();
                        byte issuerNameHash[] = md.digest(name.getEncoded());

                        // constructing the OCSP request
                        CertID certid = new CertID(
                                                                new AlgorithmIdentifier(
                                                        new OBJECT_IDENTIFIER("1.3.14.3.2.26"), new NULL()),
                                                                new OCTET_STRING(issuerNameHash),
                                                                new OCTET_STRING(issuerKeyHash),
                                                                new INTEGER(serial_number));

                        Request request = new Request(certid, null);
                        SEQUENCE requestList = new SEQUENCE();
                        requestList.addElement(request);
                        TBSRequest tbsRequest = new TBSRequest(null,null,requestList,null);
                        ocsp_req = new OCSPRequest(tbsRequest, null);
                }
                catch ( Exception e )
                {
                        System.out.println("ERROR: unable to generate ocsp request");
                        e.printStackTrace();
                        st = false;
                }

                // Print the generated request
                try
                {
                        os = new ByteArrayOutputStream();
                        ocsp_req.encode(os);
                }
		catch (Exception e)
                {
                        System.out.println("ERROR: unable to generate ocsp request");
                        e.printStackTrace();
                        st = false;
                }

                request_data = os.toByteArray();
                System.out.println("OCSP_REQUEST= \n" +
                                new sun.misc.BASE64Encoder().encode(request_data));
                return st; 

	}

	public boolean Send()
	{
		HTTPClient hc = new HTTPClient();

		hr = hc.nonsslConnect(ca_hostname,ca_ee_port,url,request_data);

		System.out.println("RETURN_CODE=" + hr.getStatusCode());
				
		responseData = hr.getResponseData();

		if(hr.getStatusCode() == 200)
			return true;
		else
			return false;

	}

	

	public boolean checkcertstatus()
	{

		// 1. login to cert db
		ComCrypto cCrypt = new ComCrypto(client_certdb_dir,
										client_certdb_pwd,
										null,
										null,
										null);
		cCrypt.setDebug(true);
		cCrypt.setGenerateRequest(true);
		cCrypt.loginDB();


		// 2. build query

		if(!buildquery())
		{
			System.out.println("ERROR: unable to build query string");
			return false;
		}
		
		// 3. submit and parse response
		if(!Send())
		{
			System.out.println("ERROR: failed to send request");
			return false;
		}

		if(Verify())
		{
			System.out.println("SUCCESS");
		}
		else
		{
			System.out.println("ERROR");
			return false;
		}

		return true;

	}

	public boolean Verify()
	{
		boolean st = false;

		if(debug.equals("true"))
		System.out.println("OCSP_RESPONSE= \n" +
			(responseData));
		try
		{
 			// parse OCSPResponse
 			OCSPResponse.Template ocsp_template = new OCSPResponse.Template();
			OCSPResponse resp = (OCSPResponse)
				ocsp_template.decode(new ByteArrayInputStream(responseData));

			OCSPResponseStatus status = resp.getResponseStatus();
			ResponseBytes bytes = resp.getResponseBytes();
			BasicOCSPResponse basic = (BasicOCSPResponse)
						BasicOCSPResponse.getTemplate().decode(
				new ByteArrayInputStream(bytes.getResponse().toByteArray()));
			ResponseData rd = basic.getResponseData();

			System.out.println("response count = " + rd.getResponseCount());
			for (int i = 0; i < rd.getResponseCount(); i++)
			{
				SingleResponse rd1 = rd.getResponseAt(i);
				CertStatus status1 = rd1.getCertStatus();

				if (status1 instanceof GoodInfo)
				{
					System.out.println("CertStatus=Good \nSerialNumber=" +
										rd1.getCertID().getSerialNumber());
				}
				if (status1 instanceof UnknownInfo)
				{
					System.out.println("CertStatus=Unknown \nSerialNumber=" +
										rd1.getCertID().getSerialNumber());
				}
				if (status1 instanceof RevokedInfo)
				{
					System.out.println("CertStatus=Revoked \nSerialNumber=" +
										rd1.getCertID().getSerialNumber());
				}
			}


			st = true;
		}
		catch(Exception e)
		{
			System.out.println("ERROR: unable to verify OCSP response");
			e.printStackTrace();
			st = false;
		}
		return st;
	}

	public static void main(String args[])
	{
		ca_ee_ocspRequest prof = new ca_ee_ocspRequest();
		StringHolder x_client_certdb_dir = new StringHolder();
		StringHolder x_client_certdb_pwd = new StringHolder();
		StringHolder x_ca_cert_nickname = new StringHolder();
		StringHolder x_serial_number = new StringHolder();
		StringHolder x_ca_hostname = new StringHolder();
		StringHolder x_ca_ee_port = new StringHolder();

		StringHolder x_debug = new StringHolder();

		// parse the args
		ArgParser parser = new ArgParser("ca_ee_ocspRequest");
		parser.addOption ("-ca_hostname %s #CA Hostname",
							x_ca_hostname); 
		parser.addOption ("-ca_ee_port %s #CA EE Port",
							x_ca_ee_port);
		parser.addOption ("-client_certdb_dir %s #CertDB dir",
							x_client_certdb_dir); 
		parser.addOption ("-client_certdb_pwd %s #CertDB password",
							x_client_certdb_pwd);
		parser.addOption ("-ca_cert_nickname %s #CA Cert Nickname",
							x_ca_cert_nickname); 
		parser.addOption ("-serial_number %s #Cert Serial Number in decimal",
							x_serial_number); 
		parser.addOption ("-debug %s #enables display of debugging info",
							x_debug);

		// and then match the arguments
		String [] unmatched = null;
		unmatched = parser.matchAllArgs (args,0,parser.EXIT_ON_UNMATCHED);

		if(unmatched!=null)
		{
			System.out.println("ERROR: Argument Mismatch");
			System.exit(-1);
		}

		// set variables
		ca_hostname = x_ca_hostname.value;
		ca_ee_port = x_ca_ee_port.value;
		client_certdb_dir = x_client_certdb_dir.value;
		client_certdb_pwd = x_client_certdb_pwd.value;
		ca_cert_nickname = x_ca_cert_nickname.value;
		serial_number = x_serial_number.value;
		debug = x_debug.value;

		boolean st = prof.checkcertstatus();

		if(st)
			System.exit(0);
		else
			System.exit(-1);
	}

}; // end class
