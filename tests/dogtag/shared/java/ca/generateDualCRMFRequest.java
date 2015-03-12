import java.util.*;
import java.net.*;
import java.io.*;
import org.mozilla.jss.ssl.*;

public class generateDualCRMFRequest
{

	private static String request_type = null;
	private static String request_subject = null;
	private static String request_keysize = null;
	private static String request_keytype = null;
	private static String client_certdb_dir = null;
	private static String client_certdb_pwd = null;
	private static String output_file = null;
	public static String transport_cert_file=null;
	private static String transport_cert=null;

	private static String debug = null;

	private String cert_request = null;
	private String crmf_request = null;

	public generateDualCRMFRequest()
	{
		// Do nothing
	}

	public boolean Generate_CRMF()
	{
		System.out.println("Generating Cert Request with KeySize: " + request_keysize);
		System.out.println("Generating Cert Request with KeyType: " + request_keytype);
	
		if(transport_cert_file != null && !transport_cert_file.equalsIgnoreCase("null"))
		{
			Utilities ut = new Utilities();
			transport_cert = ut.getcertfromfile(transport_cert_file);
		}
		ComCrypto cCrypt = new ComCrypto(client_certdb_dir,client_certdb_pwd,request_subject,request_keysize,request_keytype);
		cCrypt.setDebug(true);
		cCrypt.setGenerateRequest(true);
		cCrypt.loginDB();
		if(transport_cert != null)
		{
			cCrypt.setDualKey(true);
			System.out.println("Generating Dual crmf requests");
			cCrypt.setTransportCert(transport_cert);
			crmf_request = cCrypt.generateCRMFrequest();
		}
		else
		{
			cCrypt.setDualKey(false);
			System.out.println("Generating Single crmf requess");
			cCrypt.setTransportCert(null);
			crmf_request  = cCrypt.generateCRMFrequest();
		}
		if(crmf_request == null)
		{
			System.out.println("Request could not be generated ");
			return false;
		}

		cert_request = crmf_request;
		return true;

	}

	public boolean generate()
	{

		// 1. Check Request Type and Generate Request

		System.out.println("Generating CRMF Request.");
		Generate_CRMF();
	

		// 2. Submit it

		if(cert_request == null)
		{
			System.out.println("ERROR: failed to generate request");
			return false;
		}
		PrintStream ps = null;
		try {
		ps = new PrintStream(new FileOutputStream(output_file));
		ps.println(cert_request);
		ps.flush();
		ps.close();
		} catch (Exception E){
		System.err.println ("Error in writing to file");
		}
		System.out.println("CRMF Request=" + cert_request);

		return true;

	}



	public static void main(String args[])
	{
		generateDualCRMFRequest prof = new generateDualCRMFRequest();
		// parse args
		StringHolder x_request_keysize = new StringHolder();
		StringHolder x_request_keytype = new StringHolder();
		StringHolder x_request_subject = new StringHolder();
		StringHolder x_client_certdb_dir = new StringHolder();
		StringHolder x_client_certdb_pwd = new StringHolder();
		StringHolder x_req_out_file = new StringHolder();
		StringHolder x_debug = new StringHolder();
		StringHolder x_transport_cert_file = new StringHolder();

		// parse the args
		ArgParser parser = new ArgParser("generateDualCRMFRequest");

		parser.addOption ("-client_certdb_dir %s #CertDB dir", x_client_certdb_dir); 
		parser.addOption ("-client_certdb_pwd %s #CertDB password", x_client_certdb_pwd); 
		parser.addOption ("-debug %s #enables display of debugging info", x_debug);
		parser.addOption ("-request_subject %s #Request Subject", x_request_subject);
		parser.addOption ("-request_keysize %s #Key size for the cert req", x_request_keysize);
		parser.addOption ("-request_keytype %s #Key Type for the cert req", x_request_keytype);
		parser.addOption ("-output_file %s #Ouput file for cert req", x_req_out_file);
		parser.addOption ("-transport_cert_file %s #file containing base64 transport cert", x_transport_cert_file);

		// and then match the arguments
		String [] unmatched = null;
		unmatched = parser.matchAllArgs (args,0,parser.EXIT_ON_UNMATCHED);

		if(unmatched!=null)
		{
			System.out.println("ERROR: Argument Mismatch");
			System.exit(-1);
		}

		// set variables
		client_certdb_dir = x_client_certdb_dir.value;
		client_certdb_pwd = x_client_certdb_pwd.value;
		request_subject = x_request_subject.value;
		request_keysize = x_request_keysize.value;
		request_keytype = x_request_keytype.value;
		output_file = x_req_out_file.value;
		debug = x_debug.value;
		transport_cert_file = x_transport_cert_file.value;

		boolean st = prof.generate();

		if (!st)
		{
			System.out.println("ERROR: unable to generate the crmf request");
			System.exit(-1);
		}
		System.out.println("SUCCESS");
		System.exit(0);
	
	}

};
