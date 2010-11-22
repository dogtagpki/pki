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

import java.io.*;
import java.net.*;
import java.nio.*;
import java.util.*;
import java.net.URLEncoder;

import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;


import org.mozilla.jss.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.util.*;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.pkcs11.PK11Token;


public class HTTPClient implements SSLCertificateApprovalCallback
{

	public static final int BUFFER_SIZE = 4096;
	public boolean debugMode = true;

	public static String basic_auth_header_value = null;

	public static String cs_hostname = null;
	public static String cs_port = null;
	public static String ssl = null;
	public static String client_certdb_dir = null;
	public static String client_certdb_pwd = null;
	public static String client_cert_nickname = null;
	public static String uri = null;
	public static String query = null;
	public static String request_type = null;
	public static String user_id = null;
	public static String user_password = null;
	public static String auth_type = null;
	public static String debug = null;

	public static boolean parse_xml = false;

	public static X509Certificate server_cert = null;

	// cookie variable for CS install UI
	public static String j_session_id = null;
	public static boolean ecc_support = false;

	


	public HTTPClient()
	{
		// constructor
		// turn off ecc by default
		ecc_support = true;
	}

	
	public HTTPClient(boolean ecc)
	{
		ecc_support = ecc;
	}

	public boolean setCipherPref(SSLSocket socket)
	{

		if(ecc_support)
		{
	    	int ecc_Ciphers[] = {
			// ECC Ciphers - See JSSSocketFactory.java for more info
	    	0xC001, 0xC002, 0xC003, 0xC004, 0xC005, 0xC006, 0xC007,
		    0xC008, 0xC009, 0xC00A, 0xC00B, 0xC00C, 0xC00E, 0xC00F,
		    0xC010, 0xC011, 0xC012, 0xC013, 0xC014, 0 };

			try
			{
				for (int i=0; i < ecc_Ciphers.length; i++)
				{
						if(ecc_Ciphers[i] > 0)
							socket.setCipherPreference(
								ecc_Ciphers[i],true);
				}
			}
			catch(Exception e)
			{
				System.out.println("ERROR: unable to set Cipher List");
				System.out.println("ERROR: Exception  = " + e.getMessage());
			}

		}
		return true;
	}

	public boolean disableSSL2(SSLSocket socket)
	{
		try
		{
			socket.enableSSL3Default(true);
			socket.enableSSL3(true);
			socket.enableSSL2(false);
			socket.enableSSL2Default(false);
            socket.enableV2CompatibleHello(false);
		}
		catch(Exception e)
		{
			System.out.println("ERROR: Exception  = " + e.getMessage());
		}
		return true;
	}

	public X509Certificate getServerCert()
	{
		return server_cert;
	}

	public void set_parse_xml(boolean b)
	{
		parse_xml = b;
	}

	public boolean approve(X509Certificate cert, 
		SSLCertificateApprovalCallback.ValidityStatus status)
	{

		// when this method is called by SSLSocket we get the server cert 
		// we can capture this for future use.
		server_cert = cert;
		return true;
	}

	public boolean testsslConnect(String hostname, String portnumber)
	{
		boolean st = true;

		try
		{

			System.out.println("#############################################");
			System.out.println("Attempting to connect to: " + hostname + ":" +
							portnumber);

			Integer x = new Integer(portnumber);
			int port = x.intValue();


			SSLClientCertificateSelectionCallback certSelectionCallback = 
								new TestClientCertificateSelectionCallback();

			Socket js = new Socket(InetAddress.getByName(hostname), port);
			SSLSocket socket = new SSLSocket(js, hostname, this, 
						certSelectionCallback );
			setCipherPref(socket);
			disableSSL2(socket);
			socket.forceHandshake();
			System.out.println("Connected.");
			socket.setUseClientMode(true);

			// test connection to obtain server cert. close it.
			socket.close();

	
		}

		catch(Exception e)
		{
			System.err.println("Exception: Unable to Send Request:" +e);
			e.printStackTrace();
			st = false;
		}

		if(!st)
			return false;
		else
			return true;
	}

	// performs ssl connect to given host/port requiring client auth
	// posts the given query data
	// returns HTTPResponse
	public HTTPResponse sslConnectClientAuth(String hostname, String portnumber,
								String client_cert,String url,String query)
	{

		boolean st = true;
		HTTPResponse hr = null;

		try
		{

			System.out.println("#############################################");
			System.out.println("Attempting to connect to: " + hostname + ":" +
							portnumber);

			Integer x = new Integer(portnumber);
			int port = x.intValue();


			SSLCertificateApprovalCallback approvalCallback = 
								new TestCertApprovalCallback();
			CertSelection certSelectionCallback = 
			 					new CertSelection();

			// Client Cert for Auth is set here
			certSelectionCallback.setClientCert(client_cert);

			Socket js = new Socket(InetAddress.getByName(hostname), port);
			SSLSocket socket = new SSLSocket(js, hostname, approvalCallback, 
						certSelectionCallback );
			disableSSL2(socket);
			setCipherPref(socket);
			socket.forceHandshake();
			System.out.println("Connected.");
			socket.setUseClientMode(true);

			System.out.println("Posting Query = " +
								"https://" + hostname +
								":" + portnumber +
								"/" + url +
								"?" + query);

			OutputStream rawos = socket.getOutputStream();
			BufferedOutputStream os = new BufferedOutputStream(rawos);
			PrintStream ps = new PrintStream(os);

			ps.println("POST " + url + " HTTP/1.0");
			ps.println("Connection: Keep-Alive");
			ps.println("Content-type: application/x-www-form-urlencoded");
			ps.println("Content-length: " +query.length());
			ps.println("");
			ps.print(query);
			ps.flush();
			os.flush();

			try
			{
				hr = readResponse(socket.getInputStream());
				hr.parseContent();

			}
			catch (Exception e)
			{
				System.out.println("Exception");
				e.printStackTrace();
				st = false;
			}

			socket.close();
			os.close();
			rawos.close();
			ps.close();

			os=null;
			rawos=null;
			ps=null;
	
		}

		catch(Exception e)
		{
			System.err.println("Exception: Unable to Send Request:" +e);
			e.printStackTrace();
			st = false;
		}

		if(!st)
			return null;
		else
			return hr;
	}

	// performs ssl connect to given host/port
	// posts the given query data
	// returns HTTPResponse
	public HTTPResponse sslConnect(String hostname, String portnumber,
								String url, String query)
	{

		boolean st = true;
		HTTPResponse hr = null;

		try
		{

			System.out.println("#############################################");
			System.out.println("Attempting to connect to: " + hostname + ":" +
							portnumber);

			Integer x = new Integer(portnumber);
			int port = x.intValue();


			SSLCertificateApprovalCallback approvalCallback = 
								new TestCertApprovalCallback();
			SSLClientCertificateSelectionCallback certSelectionCallback = 
								new TestClientCertificateSelectionCallback();

			Socket js = new Socket(InetAddress.getByName(hostname), port);
			SSLSocket socket = new SSLSocket(js, hostname, approvalCallback, 
						certSelectionCallback );
			setCipherPref(socket);
			disableSSL2(socket);
			socket.forceHandshake();
			System.out.println("Connected.");
			socket.setUseClientMode(true);

			System.out.println("Posting Query = " +
								"https://" + hostname +
								":" + portnumber +
								"/" + url +
								"?" + query);

			OutputStream rawos = socket.getOutputStream();
			BufferedOutputStream os = new BufferedOutputStream(rawos);
			PrintStream ps = new PrintStream(os);


			ps.println("POST " + url + " HTTP/1.0");

			// check to see if we have a cookie to send
			if(j_session_id != null )
				ps.println("Cookie: " + j_session_id);

			ps.println("Content-type: application/x-www-form-urlencoded");
			ps.println("Content-length: " +query.length());
			ps.println("Connection: Keep-Alive");

			// special header posting if available
			if(basic_auth_header_value != null)
			{
				System.out.println("basic_auth = " + basic_auth_header_value );
				ps.println("Authorization: Basic " + basic_auth_header_value );
			}

			ps.println("");
			ps.println(query);
			ps.println("\r");
			ps.flush();
			os.flush();

			try
			{
				hr = readResponse(socket.getInputStream());
				hr.parseContent();

			}
			catch (Exception e)
			{
				System.out.println("Exception");
				e.printStackTrace();
				st = false;
			}

			socket.close();
			os.close();
			rawos.close();
			ps.close();

			os=null;
			rawos=null;
			ps=null;
	
		}

		catch(Exception e)
		{
			System.err.println("Exception: Unable to Send Request:" +e);
			e.printStackTrace();
			st = false;
		}

		if(!st)
			return null;
		else
			return hr;
	}

	// performs non ssl connect to given host/port
	// posts the given query data
	// returns HTTPResponse
	public HTTPResponse nonsslConnect(String hostname, String portnumber,
								String url, String query)
	{

		boolean st = true;
		HTTPResponse hr = null;

		try
		{

			System.out.println("#############################################");
			System.out.println("Attempting to connect to: " + hostname + ":" +
							portnumber);

			Integer x = new Integer(portnumber);
			int port = x.intValue();

			Socket socket = new Socket(hostname, port);

			System.out.println("Posting Query = " +
								"http://" + hostname +
								":" + portnumber +
								"/" + url +
								"?" + query);

			OutputStream rawos = socket.getOutputStream();
			BufferedOutputStream os = new BufferedOutputStream(rawos);
			PrintStream ps = new PrintStream(os);

			System.out.println("Connected.");

			ps.println("POST " + url + " HTTP/1.0");

			// check to see if we have a cookie to send
			if(j_session_id != null )
				ps.println("Cookie: " + j_session_id);

			ps.println("Content-type: application/x-www-form-urlencoded");
			ps.println("Content-length: " +query.length());
			ps.println("Connection: Keep-Alive");

			// special header posting if available
			if(basic_auth_header_value != null)
			{
				System.out.println("basic_auth = " + basic_auth_header_value );
				ps.println("Authorization: Basic " + basic_auth_header_value );
			}

			ps.println("");
			ps.println(query);
			ps.println("\r");
			ps.flush();
			os.flush();

			try
			{
				hr = readResponse(socket.getInputStream());
				hr.parseContent();

			}
			catch (Exception e)
			{
				System.out.println("Exception");
				e.printStackTrace();
				st = false;
			}

			socket.close();
			os.close();
			rawos.close();
			ps.close();

			os=null;
			rawos=null;
			ps=null;
	
		}

		catch(Exception e)
		{
			System.err.println("Exception: Unable to Send Request:" +e);
			e.printStackTrace();
			st = false;
		}

		if(!st)
			return null;
		else
			return hr;
	}

	public HTTPResponse readResponse(InputStream inputStream)
		throws Exception
	{
		// read response from http input stream and return HTTPResponse
    byte[] buffer  = new byte[BUFFER_SIZE];
    HTTPResponse    response = null;
    int statusCode = 0;

    // Read an initial chunk of the response from the server.
    int bytesRead = inputStream.read(buffer);
    if (bytesRead < 0)
    {
      throw new IOException("Unexpected end of input stream from server");
    }

    // Hopefully, this initial chunk will contain the entire header, so look for
    // it.  Technically, HTTP is supposed to use CRLF as the end-of-line
    // character, so look for that first, but also check for LF by itself just
    // in case.
    int headerEndPos = -1;
    int dataStartPos = -1;
    for (int i=0; i < (bytesRead-3); i++)
    {
      if ((buffer[i] == '\r') && (buffer[i+1] == '\n') &&
          (buffer[i+2] == '\r') && (buffer[i+3] == '\n'))
      {
        headerEndPos = i;
        dataStartPos = i+4;
        break;
      }
    }

    if (headerEndPos < 0)
    {
      for (int i=0; i < (bytesRead-1); i++)
      {
        if ((buffer[i] == '\n') && (buffer[i+1] == '\n'))
        {
          headerEndPos = i;
          dataStartPos = i+2;
          break;
        }
      }
    }


    // In the event that we didn't get the entire header in the first pass, keep
    // reading until we do have enough.
    if (headerEndPos < 0)
    {
      byte[] buffer2 = new byte[BUFFER_SIZE];
      while (headerEndPos < 0)
      {
        int startPos      = bytesRead;
        int moreBytesRead = inputStream.read(buffer2);
        if (moreBytesRead < 0)
        {
          throw new IOException("Unexpected end of input stream from server " +
                                "when reading more data from response");
        }

        byte[] newBuffer = new byte[bytesRead + moreBytesRead];
        System.arraycopy(buffer, 0, newBuffer, 0, bytesRead);
        System.arraycopy(buffer2, 0, newBuffer, bytesRead, moreBytesRead);
        buffer = newBuffer;
        bytesRead += moreBytesRead;

        for (int i=startPos; i < (bytesRead-3); i++)
        {
          if ((buffer[i] == '\r') && (buffer[i+1] == '\n') &&
              (buffer[i+2] == '\r') && (buffer[i+3] == '\n'))
          {
            headerEndPos = i;
            dataStartPos = i+4;
            break;
          }
        }

        if (headerEndPos < 0)
        {
          for (int i=startPos; i < (bytesRead-1); i++)
          {
            if ((buffer[i] == '\n') && (buffer[i+1] == '\n'))
            {
              headerEndPos = i;
              dataStartPos = i+2;
              break;
            }
          }
        }
      }
    }


    // At this point, we should have the entire header, so read and analyze it.
    String          headerStr = new String(buffer, 0, headerEndPos);
    StringTokenizer tokenizer = new StringTokenizer(headerStr, "\r\n");
    if (tokenizer.hasMoreTokens())
    {
      String statusLine = tokenizer.nextToken();
      if (debugMode)
      {
        System.out.println("RESPONSE STATUS:  " + statusLine);
      }

      int spacePos   = statusLine.indexOf(' ');
      if (spacePos < 0)
      {
        System.out.println("ERROR: Unable to parse response header -- could " +
                                "not find protocol/version delimiter");
		return null;
		
      }

      String protocolVersion = statusLine.substring(0, spacePos);
      int    spacePos2       = statusLine.indexOf(' ', spacePos+1);
      if (spacePos2 < 0)
      {
        System.out.println("ERROR: Unable to parse response header -- could " +
                                "not find response code delimiter");
		return null;
      }

      try
      {
        statusCode = Integer.parseInt(statusLine.substring(spacePos+1,
                                                           spacePos2));
      }
      catch (NumberFormatException nfe)
      {
        System.out.println("Unable to parse response header -- could " +
                                "not interpret status code as an integer");
		return null;
      }

      String responseMessage = statusLine.substring(spacePos2+1);
      response = new HTTPResponse(statusCode, protocolVersion,
                                  responseMessage);

      while (tokenizer.hasMoreTokens())
      {
        String headerLine = tokenizer.nextToken();
        if (debugMode)
        {
          System.out.println("RESPONSE HEADER:  " + headerLine);
        }

        int colonPos = headerLine.indexOf(':');
        if (colonPos < 0)
        {
          if (headerLine.toLowerCase().startsWith("http/"))
          {
            // This is a direct violation of RFC 2616, but certain HTTP servers
            // seem to immediately follow a 100 continue with a 200 ok without
            // the required CRLF in between.
            System.out.println("ERROR: Found illegal status line '" + headerLine +
                                "'in the middle of a response -- attempting " +
                                "to deal with it as the start of a new " +
                                "response.");
            statusLine = headerLine;
            spacePos   = statusLine.indexOf(' ');
            if (spacePos < 0)
            {
              System.out.println("ERROR: Unable to parse response header -- " +
                                      "could not find protocol/version " +
                                      "delimiter");
				return null;
            }

            protocolVersion = statusLine.substring(0, spacePos);
            spacePos2       = statusLine.indexOf(' ', spacePos+1);
            if (spacePos2 < 0)
            {
              System.out.println("ERROR: Unable to parse response header -- " +
                                      "could not find response code delimiter");
				return null;
            }

            try
            {
              statusCode = Integer.parseInt(statusLine.substring(spacePos+1,
                                                                 spacePos2));
            }
            catch (NumberFormatException nfe)
            {
              System.out.println("ERROR: Unable to parse response header -- " +
                                      "could not interpret status code as an " +
                                      "integer");
				return null;
            }

            responseMessage = statusLine.substring(spacePos2+1);
            response = new HTTPResponse(statusCode, protocolVersion,
                                        responseMessage);
            continue;
          }
          else
          {
            System.out.println("ERROR: Unable to parse response header -- no " +
                                    "colon found on header line \"" +
                                    headerLine + "\"");
          }
        }

        String headerName  = headerLine.substring(0, colonPos);
        String headerValue = headerLine.substring(colonPos+1).trim();
        response.addHeader(headerName, headerValue);
      }
    }
    else
    {
      // This should never happen -- an empty response
      System.out.println("Unable to parse response header -- empty " +
                              "header");
    }


    // If the status code was 100 (continue), then it was an intermediate header
    // and we need to keep reading until we get the real response header.
    while (response.getStatusCode() == 100)
    {
      if (dataStartPos < bytesRead)
      {
        byte[] newBuffer = new byte[bytesRead - dataStartPos];
        System.arraycopy(buffer, dataStartPos, newBuffer, 0, newBuffer.length);
        buffer = newBuffer;
        bytesRead = buffer.length;

        headerEndPos = -1;
        for (int i=0; i < (bytesRead-3); i++)
        {
          if ((buffer[i] == '\r') && (buffer[i+1] == '\n') &&
              (buffer[i+2] == '\r') && (buffer[i+3] == '\n'))
          {
            headerEndPos = i;
            dataStartPos = i+4;
            break;
          }
        }

        if (headerEndPos < 0)
        {
          for (int i=0; i < (bytesRead-1); i++)
          {
            if ((buffer[i] == '\n') && (buffer[i+1] == '\n'))
            {
              headerEndPos = i;
              dataStartPos = i+2;
              break;
            }
          }
        }
      }
      else
      {
        buffer       = new byte[0];
        bytesRead    = 0;
        headerEndPos = -1;
      }


      byte[] buffer2 = new byte[BUFFER_SIZE];
      while (headerEndPos < 0)
      {
        int startPos      = bytesRead;
        int moreBytesRead = inputStream.read(buffer2);

        if (moreBytesRead < 0)
        {
          throw new IOException("Unexpected end of input stream from server " +
                                "when reading more data from response");
        }

        byte[] newBuffer = new byte[bytesRead + moreBytesRead];
        System.arraycopy(buffer, 0, newBuffer, 0, bytesRead);
        System.arraycopy(buffer2, 0, newBuffer, bytesRead, moreBytesRead);
        buffer = newBuffer;
        bytesRead += moreBytesRead;

        for (int i=startPos; i < (bytesRead-3); i++)
        {
          if ((buffer[i] == '\r') && (buffer[i+1] == '\n') &&
              (buffer[i+2] == '\r') && (buffer[i+3] == '\n'))
          {
            headerEndPos = i;
            dataStartPos = i+4;
            break;
          }
        }

        if (headerEndPos < 0)
        {
          for (int i=startPos; i < (bytesRead-1); i++)
          {
            if ((buffer[i] == '\n') && (buffer[i+1] == '\n'))
            {
              headerEndPos = i;
              dataStartPos = i+2;
              break;
            }
          }
        }
      }


      // We should now have the next header, so examine it.
      headerStr = new String(buffer, 0, headerEndPos);
      tokenizer = new StringTokenizer(headerStr, "\r\n");
      if (tokenizer.hasMoreTokens())
      {
        String statusLine = tokenizer.nextToken();
        if (debugMode)
        {
          System.out.println("RESPONSE STATUS:  " + statusLine);
        }

        int spacePos   = statusLine.indexOf(' ');
        if (spacePos < 0)
        {
          System.out.println("Unable to parse response header -- could " +
                                  "not find protocol/version delimiter");
        }

        String protocolVersion = statusLine.substring(0, spacePos);
        int    spacePos2       = statusLine.indexOf(' ', spacePos+1);
        if (spacePos2 < 0)
        {
          System.out.println("Unable to parse response header -- could " +
                                  "not find response code delimiter");
        }

        try
        {
          statusCode = Integer.parseInt(statusLine.substring(spacePos+1,
                                                             spacePos2));
        }
        catch (NumberFormatException nfe)
        {
          System.out.println("Unable to parse response header -- could " +
                                  "not interpret status code as an integer");
        }

        String responseMessage = statusLine.substring(spacePos2+1);
        response = new HTTPResponse(statusCode, protocolVersion,
                                    responseMessage);

        while (tokenizer.hasMoreTokens())
        {
          String headerLine = tokenizer.nextToken();
          if (debugMode)
          {
            System.out.println("RESPONSE HEADER:  " + headerLine);
          }

          int colonPos = headerLine.indexOf(':');
          if (colonPos < 0)
          {
            System.out.println("Unable to parse response header -- no " +
                                    "colon found on header line \"" +
                                    headerLine + "\"");
          }

          String headerName  = headerLine.substring(0, colonPos);
          String headerValue = headerLine.substring(colonPos+1).trim();
          response.addHeader(headerName, headerValue);
        }
      }
      else
      {
        // This should never happen -- an empty response
        System.out.println("Unable to parse response header -- empty " +
                                "header");
      }
    }


    // Now that we have parsed the header, use it to determine how much data
    // there is.  If we're lucky, the server will have told us using the
    // "Content-Length" header.
    int contentLength = response.getContentLength();


    if (contentLength >= 0)
    {
      readContentDataUsingLength(response, inputStream, contentLength, buffer,
                                 dataStartPos, bytesRead);
    }
    else
    {
        // It's not chunked encoding, so our last hope is that the connection
        // will be closed when all the data has been sent.
        String connectionStr = response.getHeader("connection");
        if ((connectionStr != null) &&
            (! connectionStr.equalsIgnoreCase("close")))
        {
          System.out.println("ERROR:Unable to determine how to find when the " +
                                  "end of the data has been reached (no " +
                                  "content length, not chunked encoding, " +
                                  "connection string is \"" + connectionStr +
                                  "\" rather than \"close\")");
        }
        else
        {
          readContentDataUsingConnectionClose(response, inputStream, buffer,
                                              dataStartPos, bytesRead);
        }
    }
    // Finally, return the response to the caller.
    return response;
	}

  /**
   * Reads the actual data of the response based on the content length provided
   * by the server in the response header.
   *
   * @param  response       The response with which the data is associated.
   * @param  inputStream    The input stream from which to read the response.
   * @param  contentLength  The number of bytes that the server said are in the
   *                        response.
   * @param  dataRead       The data that we have already read.  This includes
   *                        the header data, but may also include some or all of
   *                        the content data as well.
   * @param  dataStartPos   The position in the provided array at which the
   *                        content data starts.
   * @param  dataBytesRead  The total number of valid bytes in the provided
   *                        array that should be considered part of the
   *                        response (the number of header bytes is included in
   *                        this count).
   *
   * @throws  IOException  If a problem occurs while reading data from the
   *                       server.
   */
  private void readContentDataUsingLength(HTTPResponse response,
                                          InputStream inputStream,
                                          int contentLength, byte[] dataRead,
                                          int dataStartPos, int dataBytesRead)
          throws IOException
  {
    if (contentLength <= 0)
    {
      response.setResponseData(new byte[0]);
      return;
    }


    byte[] contentBytes = new byte[contentLength];
    int    startPos     = 0;
    if (dataBytesRead > dataStartPos)
    {
      // We've already got some data to include in the header, so copy that into
      // the content array.  Make sure the server didn't do something stupid
      // like return more data than it told us was in the response.
      int bytesToCopy = Math.min(contentBytes.length,
                                 (dataBytesRead - dataStartPos));
      System.arraycopy(dataRead, dataStartPos, contentBytes, 0, bytesToCopy);
      startPos = bytesToCopy;
    }

    byte[] buffer = new byte[BUFFER_SIZE];
    while (startPos < contentBytes.length)
    {
      int bytesRead = inputStream.read(buffer);
      if (bytesRead < 0)
      {
        throw new IOException("Unexpected end of input stream reached when " +
                              "reading data from the server");
      }

      System.arraycopy(buffer, 0, contentBytes, startPos, bytesRead);
      startPos += bytesRead;
    }


    response.setResponseData(contentBytes);
  }

  /**
   * Reads the actual data of the response using chunked encoding, which is a
   * way for the server to provide the data in several chunks rather than all at
   * once.
   *
   * @param  response       The response with which the data is associated.
   * @param  inputStream    The input stream from which to read the response.
   * @param  dataRead       The data that we have already read.  This includes
   *                        the header data, but may also include some or all of
   *                        the content data as well.
   * @param  dataStartPos   The position in the provided array at which the
   *                        content data starts.
   * @param  dataBytesRead  The total number of valid bytes in the provided
   *                        array that should be considered part of the
   *                        response (the number of header bytes is included in
   *                        this count).
   *
   * @throws  IOException  If a problem occurs while reading data from the
   *                       server.
   */
  private void readContentDataUsingConnectionClose(HTTPResponse response,
                                                   InputStream inputStream,
                                                   byte[] dataRead,
                                                   int dataStartPos,
                                                   int dataBytesRead)
          throws IOException
  {
    // Create an array list that we will use to hold the chunks of information
    // read from the server.
    ArrayList bufferList = new ArrayList();


    // Create a variable to hold the total number of bytes in the data.
    int totalBytes = 0;


    // See if we have unread data in the array already provided.
    int existingBytes = dataBytesRead - dataStartPos;
    if (existingBytes > 0)
    {
      ByteBuffer byteBuffer = ByteBuffer.allocate(existingBytes);
      byteBuffer.put(dataRead, dataStartPos, existingBytes);
      bufferList.add(byteBuffer);
      totalBytes += existingBytes;
    }


    // Keep reading until we hit the end of the input stream.
    byte[] buffer = new byte[BUFFER_SIZE];
    while (true)
    {
      try
      {
        int bytesRead = inputStream.read(buffer);
        if (bytesRead < 0)
        {
          // We've hit the end of the stream and therefore the end of the
          // document.
          break;
        }
        else if (bytesRead > 0)
        {
          ByteBuffer byteBuffer = ByteBuffer.allocate(bytesRead);
          byteBuffer.put(buffer, 0, bytesRead);
          bufferList.add(byteBuffer);
          totalBytes += bytesRead;
        }
      }
      catch (IOException ioe)
      {
        // In this case we'll assume that the end of the stream has been
        // reached.  It's possible that there was some other error, but we can't
        // do anything about it so try to process what we've got so far.
		System.out.println("ERROR: unable to read until end of stream");
		System.out.println("ERROR: "+ ioe.getMessage());
        break;
      }
    }


    // Assemble the contents of all the buffers into a big array and store that
    // array in the response.
    int startPos = 0;
    byte[] contentData = new byte[totalBytes];
    for (int i=0; i < bufferList.size(); i++)
    {
      ByteBuffer byteBuffer = (ByteBuffer) bufferList.get(i);
      byteBuffer.flip();
      byteBuffer.get(contentData, startPos, byteBuffer.limit());
      startPos += byteBuffer.limit();
    }
    response.setResponseData(contentData);
  }

	// performs ssl connect to given host/port
	// posts the given query data - format - a byte array
	// returns HTTPResponse

	public HTTPResponse sslConnect(String hostname, String portnumber,
								String url, byte[] data)
	{

		boolean st = true;
		HTTPResponse hr = null;

		try
		{

			System.out.println("#############################################");
			System.out.println("Attempting to connect to: " + hostname + ":" +
							portnumber);

			Integer x = new Integer(portnumber);
			int port = x.intValue();


			SSLCertificateApprovalCallback approvalCallback = 
								new TestCertApprovalCallback();
			SSLClientCertificateSelectionCallback certSelectionCallback = 
								new TestClientCertificateSelectionCallback();

			Socket js = new Socket(InetAddress.getByName(hostname), port);
			SSLSocket socket = new SSLSocket(js, hostname, approvalCallback, 
						certSelectionCallback );
			setCipherPref(socket);
			disableSSL2(socket);
			socket.forceHandshake();
			System.out.println("Connected.");
			socket.setUseClientMode(true);

			DataOutputStream dos = 
					new DataOutputStream(socket.getOutputStream()); 
			dos.writeBytes("POST /ocsp HTTP/1.0\r\n");
			dos.writeBytes("Content-length: " + data.length + "\r\n");
			dos.writeBytes("\r\n");
			dos.write(data);
			dos.writeBytes("\r\n");
			dos.flush();

			try
			{
				hr = readResponse(socket.getInputStream());
				hr.parseContent();
			}
			catch (Exception e)
			{
				System.out.println("Exception");
				e.printStackTrace();
				st = false;
			}

			socket.close();
			dos.close();

		}

		catch(Exception e)
		{
			System.err.println("Exception: Unable to Send Request:" +e);
			e.printStackTrace();
			st = false;
		}

		if(!st)
			return null;
		else
			return hr;
	}

	// performs non ssl connect to given host/port
	// posts the given query data
	// returns HTTPResponse
	public HTTPResponse nonsslConnect(String hostname, String portnumber,
								String url, byte[] data)
	{

		boolean st = true;
		HTTPResponse hr = null;

		try
		{

			System.out.println("#############################################");
			System.out.println("Attempting to connect to: " + hostname + ":" +
							portnumber);

			Integer x = new Integer(portnumber);
			int port = x.intValue();

			Socket socket = new Socket(hostname, port);

			System.out.println("Posting Query = " +
								"http://" + hostname +
								":" + portnumber +
								"/" + url );

			System.out.println("Connected.");

			DataOutputStream dos = 
					new DataOutputStream(socket.getOutputStream()); 
			dos.writeBytes("POST " + url +  " HTTP/1.0\r\n");
			dos.writeBytes("Content-length: " + data.length + "\r\n");
			dos.writeBytes("\r\n");
			dos.write(data);
			dos.writeBytes("\r\n");
			dos.flush();

			try
			{
				hr = readResponse(socket.getInputStream());
				hr.parseContent();
			}
			catch (Exception e)
			{
				System.out.println("Exception");
				e.printStackTrace();
				st = false;
			}

			socket.close();
			dos.close();

		}

		catch(Exception e)
		{
			System.err.println("Exception: Unable to Send Request:" +e);
			e.printStackTrace();
			st = false;
		}

		if(!st)
			return null;
		else
			return hr;
	}

	public static boolean init_nss()
	{
		try
		{

			ComCrypto cCrypt = new ComCrypto(client_certdb_dir,
										client_certdb_pwd,
										null,
										null,
										null);
			cCrypt.setDebug(true);
			cCrypt.setGenerateRequest(false);
			cCrypt.loginDB();
		}
		catch(Exception e)
		{
			System.out.println("ERROR: unable to login to : " +
							client_certdb_dir );
			return false;
		}

		return true;
	}

	public static void main(String args[])
	{
		HTTPClient hc = new HTTPClient();
		HTTPResponse hr = null;
		byte[] responseData = null;

		// parse args
		StringHolder x_hostname = new StringHolder();
		StringHolder x_port = new StringHolder();
		StringHolder x_ssl = new StringHolder();
		StringHolder x_client_certdb_dir = new StringHolder();
		StringHolder x_client_certdb_pwd = new StringHolder();
		StringHolder x_client_cert_nickname = new StringHolder();
		StringHolder x_uri = new StringHolder();
		StringHolder x_query = new StringHolder();
		StringHolder x_request_type = new StringHolder();
		StringHolder x_auth_type = new StringHolder();
		StringHolder x_user_id = new StringHolder();
		StringHolder x_user_password = new StringHolder();
		StringHolder x_debug = new StringHolder();
		StringHolder x_decode = new StringHolder();

		// parse the args
		ArgParser parser = new ArgParser("HTTPClient");

		parser.addOption ("-hostname %s #Hostname",
							x_hostname); 
		parser.addOption ("-port %s #port number",
							x_port); 
		parser.addOption ("-ssl %s #HTTP or HTTPS[true or false]",
							x_ssl); 
		parser.addOption ("-client_certdb_dir %s #CertDB dir",
							x_client_certdb_dir); 
		parser.addOption ("-client_certdb_pwd %s #CertDB password",
							x_client_certdb_pwd); 
		parser.addOption ("-client_cert_nickname %s #client cert nickname",
							x_client_cert_nickname); 
		parser.addOption ("-uri %s #URI",
							x_uri); 
		parser.addOption ("-query %s #URL encoded query string[note: url encode value part only for CS operations]",
							x_query); 
		parser.addOption ("-request_type %s #Request Type [ post ]",
							x_request_type); 
		parser.addOption ("-user_id %s #user id for authorization",
							x_user_id); 
		parser.addOption ("-user_password %s #password for authorization",
							x_user_password); 
		parser.addOption ("-auth_type %s #type of authorization [ BASIC ]",
							x_auth_type); 
		parser.addOption ("-debug %s #enables display of debugging info",
							x_debug);
		parser.addOption ("-decode %s #URL Decode the resulting output" ,
							x_decode);

		// and then match the arguments
		String [] unmatched = null;
		unmatched = parser.matchAllArgs (args,0,parser.EXIT_ON_UNMATCHED);

		if(unmatched!=null)
		{
			System.out.println("ERROR: Argument Mismatch");
			System.exit(-1);
		}

		// set variables
		cs_hostname = x_hostname.value;
		cs_port = x_port.value;
		ssl = x_ssl.value;
		client_certdb_dir = x_client_certdb_dir.value;
		client_certdb_pwd = x_client_certdb_pwd.value;
		client_cert_nickname = x_client_cert_nickname.value;
		uri = x_uri.value;
		query = x_query.value;
		request_type = x_request_type.value;
		user_id = x_user_id.value;
		user_password = x_user_password.value;
		auth_type = x_auth_type.value;
		debug = x_debug.value;

		String decode = x_decode.value;

		// init_nss if needed
		boolean st = init_nss();
		if(!st)
			System.exit(-1);

		// set basic auth if needed
		if(auth_type != null && auth_type.equalsIgnoreCase("BASIC"))
		{
        	BASE64Encoder encoder = new BASE64Encoder();

			String temp = encoder.encodeBuffer((user_id + 
						":" + user_password).getBytes());

			// note: temp already contains \r and \n. 
			// remove \r and \n from the base64 encoded string. 
			// causes problems when sending http post requests
			// using PrintStream.println()

			temp = temp.replaceAll("\\r" , "");
			temp = temp.replaceAll("\\n" , "");

	        basic_auth_header_value = temp;
		}

		// route to proper function

		if(ssl != null && ssl.equalsIgnoreCase("true"))
		{
			if(client_cert_nickname != null && 
				!client_cert_nickname.equalsIgnoreCase("null"))
			{
				// ssl client auth call

				hr = hc.sslConnectClientAuth(cs_hostname,cs_port,
										client_cert_nickname,
										uri,query);
			}

			else
			{
				// ssl client call
				hr = hc.sslConnect(cs_hostname,cs_port,uri,query);
			}
		}
		else if(ssl!=null && ssl.equalsIgnoreCase("false"))
		{
			// non ssl connect
			hr = hc.nonsslConnect(cs_hostname,cs_port,uri,query);
		}
		else
		{
			System.out.println("ERROR: ssl parameter is null");
			System.exit(-1);
		}
		

		// collect and print response
		
		responseData = hr.getResponseData();

		if(hr.getStatusCode() == 200)
			System.out.println("Response from Host:" + cs_hostname + " OK");
		else
		{
			System.out.println("ERROR: unable to get response from host:" +
								cs_hostname);
			System.exit(-1);
		}

		String responseValue = null;
		if(decode.equalsIgnoreCase("true"))
			responseValue = URLDecoder.decode(hr.getHTML());
		else
			responseValue = hr.getHTML();
			

		System.out.println("###############################");
		System.out.println("RESULT=" + responseValue);
		System.out.println("###############################");

	}

};
