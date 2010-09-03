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
package com.netscape.cms.servlet.cert.scep;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.ldap.*;
import java.security.*;
import java.security.MessageDigest;

import netscape.security.x509.*;
import netscape.security.pkcs.*;
import netscape.security.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.publish.*;
import com.netscape.certsrv.apps.*;
import com.netscape.cms.servlet.profile.*;
import org.mozilla.jss.pkcs7.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.pkix.cert.Certificate;
import com.netscape.cmsutil.scep.CRSPKIMessage;

/**
 * This servlet deals with PKCS#10-based certificate requests from
 * CRS, now called SCEP, and defined at:
 *    http://search.ietf.org/internet-drafts/draft-nourse-scep-02.txt
 * 
 * The router is hardcoded to look for the http://host:80/cgi-bin/pkiclient.exe
 *
 * The HTTP parameters are 'operation' and 'message'
 * operation can be either 'GetCACert' or 'PKIOperation'
 *
 * @version $Revision$, $Date$
 */
public class CRSEnrollment extends HttpServlet
{
  protected IProfileSubsystem     mProfileSubsystem = null;
  protected String                mProfileId = null;
  protected ICertAuthority        mAuthority;
  protected IConfigStore          mConfig = null;
  protected IAuthSubsystem        mAuthSubsystem;
  protected String                mAppendDN=null;
  protected String                mEntryObjectclass=null;
  protected boolean               mCreateEntry=false;
  protected boolean               mFlattenDN=false;

  private   String                mAuthManagerName;
  private   String                mSubstoreName;
  private   boolean               mEnabled = false;
  private   String                mHashAlgorithm = "SHA1";
  private   String                mmEncryptionAlgorithm = "DES3";
  private   String                mEncryptionAlgorithm = "DES3";
  protected ILogger mLogger =      CMS.getLogger();
  private ICertificateAuthority ca;
		/* for hashing challenge password */
  protected MessageDigest mSHADigest = null;
    
  private static final String PROP_SUBSTORENAME   = "substorename";
  private static final String PROP_AUTHORITY   = "authority";
  private static final String PROP_CRS        = "crs";
  private static final String PROP_CRSCA      = "casubsystem";
  private static final String PROP_CRSAUTHMGR = "authName";
  private static final String PROP_APPENDDN   = "appendDN";
  private static final String PROP_CREATEENTRY= "createEntry";
  private static final String PROP_FLATTENDN  = "flattenDN";
  private static final String PROP_ENTRYOC    = "entryObjectclass";
    
  // URL parameters
  private static final String URL_OPERATION   = "operation";
  private static final String URL_MESSAGE     = "message";

  // possible values for 'operation'
  private static final String OP_GETCACERT    = "GetCACert";
  private static final String OP_PKIOPERATION = "PKIOperation";

  public static final String AUTH_PASSWORD    = "pwd";

  public static final String AUTH_CREDS       = "AuthCreds";
  public static final String AUTH_TOKEN       = "AuthToken";
  public static final String AUTH_FAILED      = "AuthFailed";
 
  public static final String SANE_DNSNAME     = "DNSName";
  public static final String SANE_IPADDRESS   = "IPAddress";

  public static final String CERTINFO         = "CertInfo";
  public static final String SUBJECTNAME      = "SubjectName";


  public static ObjectIdentifier OID_UNSTRUCTUREDNAME    = null;
  public static ObjectIdentifier OID_UNSTRUCTUREDADDRESS = null;
  public static ObjectIdentifier OID_SERIALNUMBER        = null;

  public CRSEnrollment(){}

  public static Hashtable toHashtable(HttpServletRequest req) {
       Hashtable httpReqHash = new Hashtable();
       Enumeration names = req.getParameterNames();
       while (names.hasMoreElements()) {
               String name = (String)names.nextElement();
               httpReqHash.put(name, req.getParameter(name));
       }
       return httpReqHash;
   }

  public void init(ServletConfig sc) {
      // Find the CertificateAuthority we should use for CRS.
	  String crsCA = sc.getInitParameter(PROP_AUTHORITY);
	  if (crsCA == null)
		  crsCA = "ca";
	  mAuthority = (ICertAuthority) CMS.getSubsystem(crsCA);
	  ca = (ICertificateAuthority)mAuthority;

	  if (mAuthority == null) {
          log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_CANT_FIND_AUTHORITY",crsCA));
	  }

      try {
          if (mAuthority instanceof ISubsystem) {
              IConfigStore authorityConfig = ((ISubsystem)mAuthority).getConfigStore();
              IConfigStore scepConfig = authorityConfig.getSubStore("scep");
              mEnabled = scepConfig.getBoolean("enable", false);
              mHashAlgorithm = scepConfig.getString("hashAlgorithm", "SHA1");
              mEncryptionAlgorithm = scepConfig.getString("encryptionAlgorithm", "DES3");
          }
      } catch (EBaseException e) {
      } 
      mmEncryptionAlgorithm = mEncryptionAlgorithm;
      CMS.debug("CRSEnrollment: init: SCEP support is "+((mEnabled)?"enabled":"disabled")+".");

      try {
	      mProfileSubsystem = (IProfileSubsystem)CMS.getSubsystem("profile");
          mProfileId  = sc.getInitParameter("profileId");
          CMS.debug("CRSEnrollment: init: mProfileId="+mProfileId);

	      mAuthSubsystem   = (IAuthSubsystem)CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
          mAuthManagerName  = sc.getInitParameter(PROP_CRSAUTHMGR);
          mAppendDN         = sc.getInitParameter(PROP_APPENDDN);
		  String tmp = sc.getInitParameter(PROP_CREATEENTRY);
		  if (tmp != null && tmp.trim().equalsIgnoreCase("true"))
			  mCreateEntry = true;
		  else
			  mCreateEntry = false;
		  tmp = sc.getInitParameter(PROP_FLATTENDN);
		  if (tmp != null && tmp.trim().equalsIgnoreCase("true"))
			  mFlattenDN = true;
		  else
			  mFlattenDN = false;
          mEntryObjectclass = sc.getInitParameter(PROP_ENTRYOC);
		  if (mEntryObjectclass == null)
			  mEntryObjectclass = "cep";
          mSubstoreName = sc.getInitParameter(PROP_SUBSTORENAME);
		  if (mSubstoreName == null)
			  mSubstoreName = "default";
      } catch (Exception e) {
      } 

      OID_UNSTRUCTUREDNAME    = X500NameAttrMap.getDefault().getOid("UNSTRUCTUREDNAME");
      OID_UNSTRUCTUREDADDRESS = X500NameAttrMap.getDefault().getOid("UNSTRUCTUREDADDRESS");
      OID_SERIALNUMBER        = X500NameAttrMap.getDefault().getOid("SERIALNUMBER");


	try {
      mSHADigest = MessageDigest.getInstance("SHA1");
    }
    catch (NoSuchAlgorithmException e) {
      }

  }


  /**
   *
   * Service a CRS Request. It all starts here. This is where the message from the
   * router is processed
   *
   * @param httpReq     The HttpServletRequest.
   * @param httpResp    The HttpServletResponse.
   *
   */
  public void service(HttpServletRequest httpReq,
                      HttpServletResponse httpResp)
    throws ServletException
    {
		boolean running_state = CMS.isInRunningState();
		if (!running_state)
			throw new ServletException(
				"CMS server is not ready to serve.");

        String operation = null;
        String message   = null;
        mEncryptionAlgorithm = mmEncryptionAlgorithm;
        
      
        // Parse the URL from the HTTP Request. Split it up into
        // a structure which enables us to read the form elements
        IArgBlock input = CMS.createArgBlock(toHashtable(httpReq));
        
        try {            
            // Read in two form parameters - the router sets these
            operation = (String)input.get(URL_OPERATION);
            CMS.debug("operation=" + operation);
            message   = (String)input.get(URL_MESSAGE);
            CMS.debug("message=" + message);
            
            if (!mEnabled) {
                CMS.debug("CRSEnrollment: SCEP support is disabled.");
                throw new ServletException("SCEP support is disabled.");
            }
            if (operation == null) {
                // 'operation' is mandatory.
                throw new ServletException("Bad request: operation missing from URL");
            }
            
            /** 
             *  the router can make two kinds of requests
             *  1) simple request for CA cert
             *  2) encoded, signed, enveloped request for anything else (PKIOperation)
             */
            
            if (operation.equals(OP_GETCACERT)) {
                handleGetCACert(httpReq, httpResp);  
            }
            else if (operation.equals(OP_PKIOPERATION)) {
                String decodeMode   = (String)input.get("decode");
                if (decodeMode == null || decodeMode.equals("false")) {
                  handlePKIOperation(httpReq, httpResp, message);
                } else {
                  decodePKIMessage(httpReq, httpResp, message);
                }
            }
            else {
                CMS.debug("Invalid operation " + operation);
                throw new ServletException("unknown operation requested: "+operation);
            }
                    
        }
        catch (Exception e)
            {
                CMS.debug("Service exception " + e);
                log(ILogger.LL_FAILURE,e.getMessage());
            }
        
    }

    /**
     *  Log a message to the system log
     */


    private void log(int level, String msg) {
        
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    level, "CEP Enrollment: "+msg);
    }

    public IAuthToken authenticate(AuthCredentials credentials, IProfileAuthenticator authenticator,
        HttpServletRequest request)  throws EBaseException {

        // build credential
        Enumeration authNames = authenticator.getValueNames();

        if (authNames != null) {
            while (authNames.hasMoreElements()) {
                String authName = (String) authNames.nextElement();

                credentials.set(authName, request.getParameter(authName));
            }
        }

        credentials.set("clientHost", request.getRemoteHost());
        IAuthToken authToken = authenticator.authenticate(credentials);
        if (authToken == null) {
          return null;
        }
        SessionContext sc = SessionContext.getContext();
        if (sc != null) {
          sc.put(SessionContext.AUTH_MANAGER_ID, authenticator.getName());
          String userid = authToken.getInString(IAuthToken.USER_ID);
          if (userid != null) {
            sc.put(SessionContext.USER_ID, userid);
          }
        }

        return authToken;
    }

  /**
   *  Return the CA certificate back to the requestor.
   *  This needs to be changed so that if the CA has a certificate chain,
   *  the whole thing should get packaged as a PKIMessage (degnerate PKCS7 - no
   *  signerInfo)
   */
    
  public void handleGetCACert(HttpServletRequest httpReq,
                              HttpServletResponse httpResp) 
    throws ServletException {
      java.security.cert.X509Certificate[]  chain = null;

      CertificateChain certChain = mAuthority.getCACertChain();
        
      try {
          if (certChain == null) {
              throw new ServletException("Internal Error: cannot get CA Cert");
          }

          chain = certChain.getChain();
        
          byte[] bytes = null;
		  
          int i = 0;
          String message   = (String)httpReq.getParameter(URL_MESSAGE);
          CMS.debug("handleGetCACert message=" + message);
          if (message != null) {
            try {
              int j = Integer.parseInt(message);
              if (j < chain.length) {
                i = j;
              }
            } catch (NumberFormatException e1) {
            }
          }
          CMS.debug("handleGetCACert selected chain=" + i);

          bytes = chain[i].getEncoded();

          httpResp.setContentType("application/x-x509-ca-cert");


// The following code may be used one day to encode
// the RA/CA cert chain for RA mode, but it will need some
// work.

  /******
              SET certs  = new SET();
              for (int i=0; i<chain.length; i++) {
                  ANY cert   = new ANY(chain[i].getEncoded());
                  certs.addElement(cert);
              }

              SignedData crsd  = new SignedData(
                      new SET(),         // empty set of digestAlgorithmID's
                      new ContentInfo(
                      new OBJECT_IDENTIFIER(new long[] {1,2,840,113549,1,7,1}),
                                             null), //empty content
                      certs,
                      null,     // no CRL's
                      new SET() // empty SignerInfos
                      );

              ContentInfo wrap = new ContentInfo(ContentInfo.SIGNED_DATA, crsd);

              ByteArrayOutputStream baos = new ByteArrayOutputStream();
              wrap.encode(baos);

              bytes = baos.toByteArray();

              httpResp.setContentType("application/x-x509-ca-ra-cert");
  *****/ 

          httpResp.setContentLength(bytes.length);
          httpResp.getOutputStream().write(bytes);
          httpResp.getOutputStream().flush();

          CMS.debug("Output certificate chain:");
          CMS.debug(bytes);
      }
      catch (Exception e) {
          CMS.debug("handleGetCACert exception " + e);
          log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERROR_SENDING_DER_ENCODE_CERT",e.getMessage()));
          throw new ServletException("Failed sending DER encoded version of CA cert to client");
      }

  }
    
  public String getPasswordFromP10(PKCS10 p10) 
  {
     PKCS10Attributes p10atts = p10.getAttributes();
     Enumeration e = p10atts.getElements();
              
     try {
       while (e.hasMoreElements()) {
         PKCS10Attribute p10a = (PKCS10Attribute)e.nextElement();
         CertAttrSet attr = p10a.getAttributeValue();

         if (attr.getName().equals(ChallengePassword.NAME)) {
           if (attr.get(ChallengePassword.PASSWORD) != null) {
             return (String)attr.get(ChallengePassword.PASSWORD);
           }
         }
       }
     } catch(Exception e1) {
       // do nothing
     }
     return null;
  }

  /**
   *  If the 'operation' is 'PKIOperation', the 'message' part of the URL is a
   *  PKIMessage structure. We decode it to see what type message it is.
   */

  /**
   * Decodes the PKI message and return information to RA.
   */
  public void decodePKIMessage(HttpServletRequest httpReq,
                                 HttpServletResponse httpResp,
                                 String msg)
    throws ServletException {

      CryptoContext cx=null;

      CRSPKIMessage req=null;
        
      byte[] decodedPKIMessage;
      byte[] response=null;
      String responseData = "";
        
      decodedPKIMessage = com.netscape.osutil.OSUtil.AtoB(msg);
            
      try {
          ByteArrayInputStream is = new ByteArrayInputStream(decodedPKIMessage);

          // We make two CRSPKIMessages. One of them, is the request, so we initialize
          // it from the DER given to us from the router.
          // The second is the response, and we'll fill this in as we go.

          if (decodedPKIMessage.length < 50) {
		  	throw new ServletException("CRS request is too small to be a real request ("+
				decodedPKIMessage.length+" bytes)");
			}
		  try {
          	req     = new CRSPKIMessage();
          	String ea = req.decodeCRSPKIMessage(is);
          	if (ea != null) {
          	    mEncryptionAlgorithm = ea;
          	}
		  }
		  catch (Exception e) {
            CMS.debug(e);
		  	throw new ServletException("Could not decode the request.");
		  }
                
          // Create a new crypto context for doing all the crypto operations
          cx = new CryptoContext(mEncryptionAlgorithm);

          // Verify Signature on message (throws exception if sig bad)
          verifyRequest(req,cx);
          unwrapPKCS10(req,cx);

          IProfile profile = mProfileSubsystem.getProfile(mProfileId);
          if (profile == null) {
              CMS.debug("Profile '" + mProfileId + "' not found.");
              throw new ServletException("Profile '" + mProfileId + "' not found.");
          } else {
              CMS.debug("Found profile '" + mProfileId + "'.");
          }

          IProfileAuthenticator authenticator = null;
          try {
              CMS.debug("Retrieving authenticator");
              authenticator = profile.getAuthenticator();
              if (authenticator == null) {
                  CMS.debug("Authenticator not found.");
                  throw new ServletException("Authenticator not found.");
              } else {
                  CMS.debug("Got authenticator=" + authenticator.getClass().getName());
              }
          } catch (EProfileException e) {
              throw new ServletException("Authenticator not found.");
          }
          AuthCredentials credentials = new AuthCredentials();
          IAuthToken authToken = null;
          // for ssl authentication; pass in servlet for retrieving
          // ssl client certificates
          SessionContext context = SessionContext.getContext();

          // insert profile context so that input parameter can be retrieved
          context.put("sslClientCertProvider", new SSLClientCertProvider(httpReq));

          try {
              authToken = authenticate(credentials, authenticator, httpReq);
          } catch (Exception e) {
              CMS.debug("Authentication failure: "+ e.getMessage());
              throw new ServletException("Authentication failure: "+ e.getMessage());
          }
          if (authToken == null) {
              CMS.debug("Authentication failure.");
              throw new ServletException("Authentication failure.");
          }

          // Deal with Transaction ID
          String transactionID = req.getTransactionID();
          responseData = responseData + 
              "<TransactionID>" + transactionID + "</TransactionID>";

          // End-User or RA's IP address
          responseData = responseData + 
              "<RemoteAddr>" + httpReq.getRemoteAddr() + "</RemoteAddr>";

          responseData = responseData + 
              "<RemoteHost>" + httpReq.getRemoteHost() + "</RemoteHost>";
                
          // Deal with Nonces
          byte[] sn = req.getSenderNonce();
                
          // Deal with message type
          String mt = req.getMessageType();
          responseData = responseData + 
              "<MessageType>" + mt + "</MessageType>";

          PKCS10 p10 = (PKCS10)req.getP10();
          X500Name p10subject      = p10.getSubjectName();
          responseData = responseData + 
              "<SubjectName>" + p10subject.toString() + "</SubjectName>";

          String pkcs10Attr = "";
              PKCS10Attributes p10atts = p10.getAttributes();
              Enumeration e = p10atts.getElements();
              
              while (e.hasMoreElements()) {
                  PKCS10Attribute p10a = (PKCS10Attribute)e.nextElement();
                  CertAttrSet attr = p10a.getAttributeValue();


                  if (attr.getName().equals(ChallengePassword.NAME)) {
					  if (attr.get(ChallengePassword.PASSWORD) != null) {
                                pkcs10Attr = pkcs10Attr + 
                                         "<ChallengePassword><Password>" + (String)attr.get(ChallengePassword.PASSWORD) + "</Password></ChallengePassword>";
                      }
                  
                  }
                  String extensionsStr = "";
                  if (attr.getName().equals(ExtensionsRequested.NAME)) {

					Enumeration exts = ((ExtensionsRequested)attr).getExtensions().elements();
					while (exts.hasMoreElements()) {
						Extension ext = (Extension) exts.nextElement();

						if (ext.getExtensionId().equals(
							OIDMap.getOID(SubjectAlternativeNameExtension.IDENT)) ) {
							DerOutputStream dos = new DerOutputStream();
							SubjectAlternativeNameExtension sane = new SubjectAlternativeNameExtension(
									Boolean.valueOf(false),  // noncritical
									ext.getExtensionValue());

								
							Vector v = 
                              (Vector) sane.get(SubjectAlternativeNameExtension. SUBJECT_NAME);

							Enumeration gne = v.elements();

                            StringBuffer subjAltNameStr = new StringBuffer();
							while (gne.hasMoreElements()) {
								GeneralNameInterface gni = (GeneralNameInterface) gne.nextElement();
								if (gni instanceof GeneralName) {
									GeneralName genName = (GeneralName) gni;

									String gn = genName.toString();
									int colon = gn.indexOf(':');
									String gnType = gn.substring(0,colon).trim();
									String gnValue = gn.substring(colon+1).trim();

                                    subjAltNameStr.append("<");
                                    subjAltNameStr.append(gnType);
                                    subjAltNameStr.append(">");
                                    subjAltNameStr.append(gnValue);
                                    subjAltNameStr.append("</");
                                    subjAltNameStr.append(gnType);
                                    subjAltNameStr.append(">");
								}
							} // while
                            extensionsStr = "<SubjAltName>" +
                                 subjAltNameStr.toString() + "</SubjAltName>";
						} // if
					} // while
                    pkcs10Attr = pkcs10Attr + 
                                         "<Extensions>" + extensionsStr + "</Extensions>";
				} // if extensions
              } // while
          responseData = responseData + 
              "<PKCS10>" + pkcs10Attr + "</PKCS10>";

      } catch (ServletException e) {
          throw new ServletException(e.getMessage().toString());
      } catch (CRSInvalidSignatureException e) {
          CMS.debug("handlePKIMessage exception " + e);
          CMS.debug(e);
      } catch (Exception e) {
          CMS.debug("handlePKIMessage exception " + e);
          CMS.debug(e);
          throw new ServletException("Failed to process message in CEP servlet: "+ e.getMessage());
      }

      // We have now processed the request, and need to make the response message
      
      try {   

          responseData = "<XMLResponse>" + responseData + "</XMLResponse>";
          // Get the response coding
          response = responseData.getBytes();
            
          // Encode the httpResp into B64
          httpResp.setContentType("application/xml");
          httpResp.setContentLength(response.length);
          httpResp.getOutputStream().write(response);
          httpResp.getOutputStream().flush();

          int i1 = responseData.indexOf("<Password>");
          if (i1 > -1) {
              i1 += 10; // 10 is a length of "<Password>"
              int i2 = responseData.indexOf("</Password>", i1);
              if (i2 > -1) {
                  responseData = responseData.substring(0, i1) + "********" +
                                 responseData.substring(i2, responseData.length());
              }
          }

          CMS.debug("Output (decoding) PKIOperation response:");
          CMS.debug(responseData);
      }
      catch (Exception e) {
          throw new ServletException("Failed to create response for CEP message"+e.getMessage());
      }

  }
    
  
  /**
   *   finds a request with this transaction ID.
   *   If could not find any request - return null
   *   If could only find 'rejected' or 'cancelled' requests, return null
   *   If found 'pending' or 'completed' request - return that request
   */
    
    
  public void handlePKIOperation(HttpServletRequest httpReq,
                                 HttpServletResponse httpResp,
                                 String msg)
    throws ServletException {


      CryptoContext cx=null;

      CRSPKIMessage req=null;
      CRSPKIMessage crsResp=null;
        
      byte[] decodedPKIMessage;
      byte[] response=null;
      X509CertImpl cert = null;
        
      decodedPKIMessage = com.netscape.osutil.OSUtil.AtoB(msg);
            
      try {
          ByteArrayInputStream is = new ByteArrayInputStream(decodedPKIMessage);

          // We make two CRSPKIMessages. One of them, is the request, so we initialize
          // it from the DER given to us from the router.
          // The second is the response, and we'll fill this in as we go.

          if (decodedPKIMessage.length < 50) {
		  	throw new ServletException("CRS request is too small to be a real request ("+
				decodedPKIMessage.length+" bytes)");
			}
		  try {
          	req     = new CRSPKIMessage();
          	String ea = req.decodeCRSPKIMessage(is);
          	if (ea != null) {
          	    mEncryptionAlgorithm = ea;
          	}
          	crsResp = new CRSPKIMessage();
		  }
		  catch (Exception e) {
            CMS.debug(e);
		  	throw new ServletException("Could not decode the request.");
		  }
		  crsResp.setMessageType(crsResp.mType_CertRep);
                
          // Create a new crypto context for doing all the crypto operations
          cx = new CryptoContext(mEncryptionAlgorithm);

          // Verify Signature on message (throws exception if sig bad)
          verifyRequest(req,cx);
                
          // Deal with Transaction ID
          String transactionID = req.getTransactionID();
          if (transactionID == null) {
              throw new ServletException("Error: malformed PKIMessage - missing transactionID");
          }
          else {
              crsResp.setTransactionID(transactionID);
          }
                
          // Deal with Nonces
          byte[] sn = req.getSenderNonce();
          if (sn == null) {
              throw new ServletException("Error: malformed PKIMessage - missing sendernonce");
          }
          else {
              crsResp.setRecipientNonce(sn);
              crsResp.setSenderNonce(new byte[] {0});
          }
                
          // Deal with message type
          String mt = req.getMessageType();
          if (mt == null) {
              throw new ServletException("Error: malformed PKIMessage - missing messageType");
          }

          // now run appropriate code, depending on message type
          if (mt.equals(req.mType_PKCSReq)) {
              CMS.debug("Processing PKCSReq");
              try {
                // Check if there is an existing request. If this returns non-null,
				// then the request is 'active' (either pending or completed) in 
				// which case, we compare the hash of the new request to the hash of the
                // one in the queue - if they are the same, I return the state of the 
                // original request - as if it was 'getCertInitial' message.
                // If the hashes are different, then the user attempted to enroll
                // for a new request with the same txid, which is not allowed - 
                // so we return 'failure'.

				IRequest cmsRequest= findRequestByTransactionID(req.getTransactionID(),true);

                // If there was no request (with a cert) with this transaction ID, 
                // process it as a new request

                cert = handlePKCSReq(httpReq, cmsRequest,req,crsResp,cx);
                
              }
              catch (CRSFailureException e) {
                  throw new ServletException("Couldn't handle CEP request (PKCSReq) - "+e.getMessage());
              }
          }
          else if (mt.equals(req.mType_GetCertInitial)) {
              CMS.debug("Processing GetCertInitial");
              cert = handleGetCertInitial(req,crsResp);
          } else {
              CMS.debug("Invalid request type " + mt);
          }
      }
      catch (CRSInvalidSignatureException e) {
          CMS.debug("handlePKIMessage exception " + e);
          CMS.debug(e);
          crsResp.setFailInfo(crsResp.mFailInfo_badMessageCheck);
      }
      catch (Exception e) {
          CMS.debug("handlePKIMessage exception " + e);
          CMS.debug(e);
          throw new ServletException("Failed to process message in CEP servlet: "+ e.getMessage());
      }

      // We have now processed the request, and need to make the response message
      
      try {   
          // make the response
          processCertRep(cx, cert,crsResp, req);

          // Get the response coding
          response = crsResp.getResponse();
            
          // Encode the crsResp into B64
          httpResp.setContentType("application/x-pki-message");
          httpResp.setContentLength(response.length);
          httpResp.getOutputStream().write(response);
          httpResp.getOutputStream().flush();

          CMS.debug("Output PKIOperation response:");
          CMS.debug(CMS.BtoA(response));
      }
      catch (Exception e) {
          throw new ServletException("Failed to create response for CEP message"+e.getMessage());
      }

  }
    
  
  /**
   *   finds a request with this transaction ID.
   *   If could not find any request - return null
   *   If could only find 'rejected' or 'cancelled' requests, return null
   *   If found 'pending' or 'completed' request - return that request
   */
    
  public IRequest findRequestByTransactionID(String txid, boolean ignoreRejected)
    throws EBaseException {

      /* Check if certificate request has been completed */
        
      IRequestQueue rq  = ca.getRequestQueue();
      IRequest foundRequest = null;

      Enumeration rids    = rq.findRequestsBySourceId(txid);
	  if (rids == null) { return null; }

      int count=0;
      while (rids.hasMoreElements()) {
			RequestId rid = (RequestId) rids.nextElement();
			if (rid == null) {
				continue;
			}
			
      		IRequest request = rq.findRequest(rid);
			if (request == null) {
				continue;
			}
			if ( !ignoreRejected || 
				request.getRequestStatus().equals(RequestStatus.PENDING) ||
			    request.getRequestStatus().equals(RequestStatus.COMPLETE)) {
				if (foundRequest != null) {
				}
			foundRequest = request;
			}
		}
	 return foundRequest;
  }
    
  /** 
   *  Called if the router is requesting us to send it its certificate
   *  Examine request queue for a request matching the transaction ID.
   *  Ignore any rejected or cancelled requests.
   *
   *  If a request is found in the pending state, the response should be
   *  'pending'
   *
   *  If a request is found in the completed state, the response should be
   *  to return the certificate
   *
   *  If no request is found, the response should be to return null
   *
   */

  public X509CertImpl handleGetCertInitial(CRSPKIMessage req,CRSPKIMessage resp) 
  {
      IRequest foundRequest=null;

      resp.setRecipientNonce(req.getSenderNonce());
      resp.setSenderNonce(null);

	  try {
	  	foundRequest = findRequestByTransactionID(req.getTransactionID(),false);
	  } catch (EBaseException e) {
      }

	  if (foundRequest == null) {
	  	resp.setFailInfo(resp.mFailInfo_badCertId);
	  	resp.setPKIStatus(resp.mStatus_FAILURE);
		return null;
	  }

      return makeResponseFromRequest(req,resp,foundRequest);
  }


  public void verifyRequest(CRSPKIMessage req, CryptoContext cx)     
    throws  CRSInvalidSignatureException {

      // Get Signed Data
      
      byte[] reqAAbytes = req.getAA();
      byte[] reqAAsig = req.getAADigest();
        
  }


  /**
   *  Create an entry for this user in the publishing directory
   *
   */

   private boolean createEntry(String dn)
   {
      boolean result = false;

      IPublisherProcessor ldapPub = mAuthority.getPublisherProcessor();
      if (ldapPub == null || !ldapPub.enabled()) {
          log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERROR_CREATE_ENTRY_FROM_CEP")); 

          return result;
      }

      ILdapConnFactory connFactory = ((IPublisherProcessor)ldapPub).getLdapConnModule().getLdapConnFactory();
      if (connFactory == null) {
          return result;
      }

      LDAPConnection connection=null;
      try {
         connection = connFactory.getConn();
         String[] objectclasses = { "top", mEntryObjectclass };
         LDAPAttribute ocAttrs = new LDAPAttribute("objectclass",objectclasses);

         LDAPAttributeSet attrSet = new LDAPAttributeSet();
         attrSet.add(ocAttrs);

         LDAPEntry newEntry = new LDAPEntry(dn, attrSet);
         connection.add(newEntry);
         result=true;
      }
      catch (Exception e) {
          log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_FAIL_CREAT_ENTRY_EXISTS",dn));
      }
      finally {
          try {
             connFactory.returnConn(connection);
          }
          catch (Exception f) {}
      }
      return result;
    }



  /**
   *  Here we decrypt the PKCS10 message from the client
   *
   */
    
  public void unwrapPKCS10(CRSPKIMessage req, CryptoContext cx)
    throws   ServletException, 
             CryptoManager.NotInitializedException,
			 CryptoContext.CryptoContextException,
             CRSFailureException {
        
      byte[] decryptedP10bytes = null;
      SymmetricKey sk;
      SymmetricKey skinternal;
      SymmetricKey.Type skt;
      KeyWrapper kw;
      Cipher cip;
      EncryptionAlgorithm ea;
      boolean errorInRequest = false;

      // Unwrap the session key with the Cert server key
	try {
      kw = cx.getKeyWrapper();

      kw.initUnwrap(cx.getPrivateKey(),null);

      skt = SymmetricKey.Type.DES;
      ea = EncryptionAlgorithm.DES_CBC;
      if (mEncryptionAlgorithm != null && mEncryptionAlgorithm.equals("DES3")) {
          skt = SymmetricKey.Type.DES3;
          ea = EncryptionAlgorithm.DES3_CBC;
      }

      sk = kw.unwrapSymmetric(req.getWrappedKey(),
                              skt,
                              SymmetricKey.Usage.DECRYPT,
                              0);  // keylength is ignored
          
     skinternal = cx.getDESKeyGenerator().clone(sk);
          
     cip = skinternal.getOwningToken().getCipherContext(ea);
          
     cip.initDecrypt(skinternal,(new IVParameterSpec(req.getIV())));
        
     decryptedP10bytes = cip.doFinal(req.getEncryptedPkcs10());
     CMS.debug("decryptedP10bytes:");
     CMS.debug(decryptedP10bytes);
          
     req.setP10(new PKCS10(decryptedP10bytes));
     } catch (Exception e) {
        CMS.debug("failed to unwrap PKCS10 " + e);
		throw new CRSFailureException("Could not unwrap PKCS10 blob: "+e.getMessage());
     }
          
  }



private void getDetailFromRequest(CRSPKIMessage req, CRSPKIMessage crsResp)
  throws CRSFailureException {

      IRequest issueReq = null;
      X509CertImpl issuedCert=null;
      Vector extensionsRequested = null;
      SubjectAlternativeNameExtension sane = null;
      CertAttrSet requested_ext = null;

      try {
             PKCS10 p10 = (PKCS10)req.getP10();

             if (p10 == null) {
			     crsResp.setFailInfo(crsResp.mFailInfo_badMessageCheck);
		  	     crsResp.setPKIStatus(crsResp.mStatus_FAILURE);
			     throw new CRSFailureException("Failed to decode pkcs10 from CEP request");
		      }
                
              AuthCredentials authCreds = new AuthCredentials();

              String challengePassword = null;
              // Here, we make a new CertInfo - it's a new start for a certificate
                    
              X509CertInfo certInfo = CMS.getDefaultX509CertInfo();
                
              // get some stuff out of the request
              X509Key key              = p10.getSubjectPublicKeyInfo();
              X500Name p10subject      = p10.getSubjectName();

              X500Name subject=null;

              // The following code will copy all the attributes
			  // into the AuthCredentials so they can be used for
			  // authentication
			  //
			  // Optionally, you can re-map the subject name from:
              //   one RDN, with many AVA's    to
              //   many RDN's with one AVA in each.

              Enumeration rdne     = p10subject.getRDNs();
              Vector      rdnv = new Vector();

			  Hashtable sanehash = new Hashtable();

              X500NameAttrMap xnap = X500NameAttrMap.getDefault();
              while (rdne.hasMoreElements()) {
                  RDN rdn = (RDN) rdne.nextElement();
                  int i=0;
                  AVA[] oldavas = rdn.getAssertion();
                  for (i=0; i<rdn.getAssertionLength(); i++) {
                      AVA[] newavas = new AVA[1];
                      newavas[0]    = oldavas[i];
					  
				      authCreds.set(xnap.getName(oldavas[i].getOid()),
					        oldavas[i].getValue().getAsString());
					  
					  if (oldavas[i].getOid().equals(OID_UNSTRUCTUREDNAME)) {
						
						  sanehash.put(SANE_DNSNAME,oldavas[i].getValue().getAsString());
					  }	
					  if (oldavas[i].getOid().equals(OID_UNSTRUCTUREDADDRESS)) {
						  sanehash.put(SANE_IPADDRESS,oldavas[i].getValue().getAsString());
					  }	

                      RDN newrdn    = new RDN(newavas);
					  if (mFlattenDN) {
                          rdnv.addElement(newrdn);
                      }
                  }
              }

              if (mFlattenDN) subject  = new X500Name(rdnv);
              else subject = p10subject;

                
				// create default key usage extension
              KeyUsageExtension kue = new KeyUsageExtension();
              kue.set(KeyUsageExtension.DIGITAL_SIGNATURE, Boolean.valueOf(true));
              kue.set(KeyUsageExtension.KEY_ENCIPHERMENT, Boolean.valueOf(true));


              PKCS10Attributes p10atts = p10.getAttributes();
              Enumeration e = p10atts.getElements();
              
              while (e.hasMoreElements()) {
                  PKCS10Attribute p10a = (PKCS10Attribute)e.nextElement();
                  CertAttrSet attr = p10a.getAttributeValue();


                  if (attr.getName().equals(ChallengePassword.NAME)) {
					  if (attr.get(ChallengePassword.PASSWORD) != null) {
		              		req.put(AUTH_PASSWORD,
									(String)attr.get(ChallengePassword.PASSWORD));
		              		req.put(ChallengePassword.NAME,
                           		hashPassword(
									(String)attr.get(ChallengePassword.PASSWORD)));
							}
                      }
                  
                  if (attr.getName().equals(ExtensionsRequested.NAME)) {

					Enumeration exts = ((ExtensionsRequested)attr).getExtensions().elements();
					while (exts.hasMoreElements()) {
						Extension ext = (Extension) exts.nextElement();

						if (ext.getExtensionId().equals(
							OIDMap.getOID(KeyUsageExtension.IDENT)) ) {
							
							kue = new KeyUsageExtension(
									new Boolean(false), // noncritical
									ext.getExtensionValue());
						}

						if (ext.getExtensionId().equals(
							OIDMap.getOID(SubjectAlternativeNameExtension.IDENT)) ) {
							DerOutputStream dos = new DerOutputStream();
							sane = new SubjectAlternativeNameExtension(
									new Boolean(false),  // noncritical
									ext.getExtensionValue());

								
							Vector v = 
                              (Vector) sane.get(SubjectAlternativeNameExtension. SUBJECT_NAME);

							Enumeration gne = v.elements();

							while (gne.hasMoreElements()) {
								GeneralNameInterface gni = (GeneralNameInterface) gne.nextElement();
								if (gni instanceof GeneralName) {
									GeneralName genName = (GeneralName) gni;

									String gn = genName.toString();
									int colon = gn.indexOf(':');
									String gnType = gn.substring(0,colon).trim();
									String gnValue = gn.substring(colon+1).trim();

				      				authCreds.set(gnType,gnValue);
								}
							}
						}
					}
                  }
              }

			  if (authCreds != null) req.put(AUTH_CREDS,authCreds);

			try {
			  if (sane == null)  sane = makeDefaultSubjectAltName(sanehash);
			} catch (Exception sane_e) {
				log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ENROLL_FAIL_NO_SUBJ_ALT_NAME",
						sane_e.getMessage()));
			}
				
                    

		  try {
              if (mAppendDN != null && ! mAppendDN.equals("")) {

				  X500Name newSubject = new X500Name(subject.toString());
                  subject = new X500Name( subject.toString().concat(","+mAppendDN));
              }

		  } catch (Exception sne) {
	     	log(ILogger.LL_INFO, "Unable to use appendDN parameter: "+mAppendDN+". Error is "+sne.getMessage()+" Using unmodified subjectname");
		  }

			  if (subject != null) req.put(SUBJECTNAME, subject);

              if (key == null || subject == null) {
                  // log 
                  //throw new ERegistrationException(RegistrationResources.ERROR_MALFORMED_P10);
              }



              certInfo.set(X509CertInfo.VERSION,
                           new CertificateVersion(CertificateVersion.V3));
                    
              certInfo.set(X509CertInfo.SUBJECT,
                           new CertificateSubjectName(subject));
                    
              certInfo.set(X509CertInfo.KEY,
                           new CertificateX509Key(key));
              
              CertificateExtensions ext = new CertificateExtensions();

              if (kue != null) {
                  ext.set(KeyUsageExtension.NAME, kue);
              }

              // add subjectAltName extension, if present
              if (sane != null) {
                  ext.set(SubjectAlternativeNameExtension.NAME, sane);
              }

              certInfo.set(X509CertInfo.EXTENSIONS,ext);

			  req.put(CERTINFO, certInfo);
      } catch (Exception e) {
	     crsResp.setFailInfo(crsResp.mFailInfo_badMessageCheck);
	     crsResp.setPKIStatus(crsResp.mStatus_FAILURE);
	     return ;
	  }   // NEED TO FIX
  }
                  

  private SubjectAlternativeNameExtension makeDefaultSubjectAltName(Hashtable ht) {

    // if no subjectaltname extension was requested, we try to make it up
    // from some of the elements of the subject name

	int itemCount = ht.size();
	GeneralNameInterface[] gn = new GeneralNameInterface[ht.size()];

	itemCount = 0;
	Enumeration en = ht.keys();
    while (en.hasMoreElements()) {
		String key = (String) en.nextElement();
		if (key.equals(SANE_DNSNAME)) {
			gn[itemCount++] = new DNSName((String)ht.get(key));
		}
		if (key.equals(SANE_IPADDRESS)) {
			gn[itemCount++] = new IPAddressName((String)ht.get(key));
        }
    }

	try {
		return new SubjectAlternativeNameExtension( new GeneralNames(gn) );
	} catch (Exception e) {
		log(ILogger.LL_INFO, CMS.getLogMessage("CMSGW_ENROLL_FAIL_NO_SUBJ_ALT_NAME",
			e.getMessage()));	  
		return null;
	}
  }
              


  // Perform authentication

  /*
   * if the authentication is set up for CEP, and the user provides
   * some credential, an attempt is made to authenticate the user
   * If this fails, this method will return true
   * If it is sucessful, this method will return true and
   * an authtoken will be in the request
   *
   * If authentication is not configured, this method will
   * return false. The request will be processed in the usual
   * way, but no authtoken will be in the request.
   *
   * In other word, this method returns true if the request
   * should be aborted, false otherwise.
   */

  private boolean authenticateUser(CRSPKIMessage req) {
		  boolean authenticationFailed = true;

		  if (mAuthManagerName == null) {
			return false;
		  }

		  String password = (String)req.get(AUTH_PASSWORD);

          AuthCredentials authCreds = (AuthCredentials)req.get(AUTH_CREDS);

		  if (authCreds == null) {
			  authCreds = new AuthCredentials();
		  }

		  // authtoken starts as null
          AuthToken token = null;

          	  if (password != null && !password.equals(""))  {
				try {
               		authCreds.set(AUTH_PASSWORD,password);
				} catch (Exception e) {}
			  }
			  

                try {
                 token = (AuthToken)mAuthSubsystem.authenticate(authCreds,mAuthManagerName);
                   authCreds.delete(AUTH_PASSWORD);
				// if we got here, the authenticate call must not have thrown
				// an exception
                   authenticationFailed = false;
              	}
              	catch (EInvalidCredentials ex) {
                   // Invalid credentials - we must reject the request
                   authenticationFailed = true;
              	}
              	catch (EMissingCredential mc) {
                   // Misssing credential - we'll log, and process manually
                   authenticationFailed = false;
              	}
              	catch (EBaseException ex) {
                  // If there's some other error, we'll reject
                  // So, we just continue on, - AUTH_TOKEN will not be set.
              	}

	 	 if (token != null) {
	     	req.put(AUTH_TOKEN,token);
		 }

         return authenticationFailed;
   }

  private boolean areFingerprintsEqual(IRequest req, Hashtable fingerprints)
  {
	
	Hashtable old_fprints = req.getExtDataInHashtable(IRequest.FINGERPRINTS);
	if (old_fprints == null) { return false; }

    byte[] old_md5 = CMS.AtoB((String) old_fprints.get("MD5"));
	byte[] new_md5 = (byte[]) fingerprints.get("MD5");

	if (old_md5.length != new_md5.length) return false;
	
	for (int i=0;i<old_md5.length; i++) {
		if (old_md5[i] != new_md5[i]) return false;
	}
	return true;
  }

  public X509CertImpl handlePKCSReq(HttpServletRequest httpReq,
                                 IRequest cmsRequest, CRSPKIMessage req, 
									CRSPKIMessage crsResp, CryptoContext cx)
    throws   ServletException, 
             CryptoManager.NotInitializedException,
             CRSFailureException {

	try {
       unwrapPKCS10(req,cx);
	   Hashtable fingerprints = makeFingerPrints(req);

       if (cmsRequest != null) {
			if (areFingerprintsEqual(cmsRequest, fingerprints)) {
               CMS.debug("created response from request");
				return makeResponseFromRequest(req,crsResp,cmsRequest);
			}
			else {
                CMS.debug("duplicated transaction id");
		  		log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ENROLL_FAIL_DUP_TRANS_ID"));	  
		  		crsResp.setFailInfo(crsResp.mFailInfo_badRequest);
		  		crsResp.setPKIStatus(crsResp.mStatus_FAILURE);
		  		return null;
			}
		}

	   getDetailFromRequest(req,crsResp);
	   boolean authFailed = authenticateUser(req);
 
	   if (authFailed) {
          CMS.debug("authentication failed");
		  log(ILogger.LL_SECURITY, CMS.getLogMessage("CMSGW_ENROLL_FAIL_NO_AUTH"));	  
		  crsResp.setFailInfo(crsResp.mFailInfo_badIdentity);
		  crsResp.setPKIStatus(crsResp.mStatus_FAILURE);


          // perform audit log
          String auditMessage = CMS.getLogMessage(
                            "LOGGING_SIGNED_AUDIT_NON_PROFILE_CERT_REQUEST_5",
                            httpReq.getRemoteAddr(),
                            ILogger.FAILURE,
                            req.getTransactionID(),
                            "CRSEnrollment",
                            ILogger.SIGNED_AUDIT_EMPTY_VALUE);
          ILogger signedAuditLogger = CMS.getSignedAuditLogger();
          if (signedAuditLogger != null) {
            signedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                     null, ILogger.S_SIGNED_AUDIT,
                     ILogger.LL_SECURITY, auditMessage);
          }

		  return null;
	   }
	   else {
		  IRequest ireq = postRequest(httpReq, req,crsResp);
		

          CMS.debug("created response");
		  return makeResponseFromRequest(req,crsResp, ireq);
	   }
	} catch (CryptoContext.CryptoContextException e) {
        CMS.debug("failed to decrypt the request " + e);
		log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ENROLL_FAIL_NO_DECRYPT_PKCS10",
			e.getMessage()));	  
		crsResp.setFailInfo(crsResp.mFailInfo_badMessageCheck);
		crsResp.setPKIStatus(crsResp.mStatus_FAILURE);
	} catch (EBaseException e) {
        CMS.debug("operation failure - " + e);
		log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERNOLL_FAIL_NO_NEW_REQUEST_POSTED",
			e.getMessage()));	  
		crsResp.setFailInfo(crsResp.mFailInfo_internalCAError);
		crsResp.setPKIStatus(crsResp.mStatus_FAILURE);
	}
	return null;
  }


//////   post the request 

/*
  needed:

  token (authtoken)
  certInfo
  fingerprints       x
  req.transactionID
  crsResp
*/  

private IRequest postRequest(HttpServletRequest httpReq, CRSPKIMessage req, CRSPKIMessage crsResp) 
throws EBaseException {
	 X500Name subject = (X500Name)req.get(SUBJECTNAME);

     if (mCreateEntry) {
		 if (subject == null) {
             CMS.debug( "CRSEnrollment::postRequest() - subject is null!" );
             return null;
		 }
         createEntry(subject.toString());
     }

     // use profile framework to handle SCEP
     if (mProfileId != null) {
       PKCS10 pkcs10data = (PKCS10)req.getP10();
       String pkcs10blob = CMS.BtoA(pkcs10data.toByteArray());

       // XXX authentication handling
       CMS.debug("Found profile=" + mProfileId);
       IProfile profile = mProfileSubsystem.getProfile(mProfileId);
       if (profile == null) {
         CMS.debug("profile " + mProfileId + " not found");
         return null;
       }
       IProfileContext ctx = profile.createContext();

       IProfileAuthenticator authenticator = null;
       try {
            CMS.debug("Retrieving authenticator");
            authenticator = profile.getAuthenticator();
            if (authenticator == null) {
              CMS.debug("No authenticator Found");
            } else {
              CMS.debug("Got authenticator=" + authenticator.getClass().getName());
            }
       } catch (EProfileException e) {
            // authenticator not installed correctly
       }

       IAuthToken authToken = null;

       // for ssl authentication; pass in servlet for retrieving
       // ssl client certificates
       SessionContext context = SessionContext.getContext();


        // insert profile context so that input parameter can be retrieved
       context.put("profileContext", ctx);
       context.put("sslClientCertProvider",
            new SSLClientCertProvider(httpReq));

       String p10Password = getPasswordFromP10(pkcs10data);
        AuthCredentials credentials = new AuthCredentials();
        credentials.set("UID", httpReq.getRemoteAddr());
        credentials.set("PWD", p10Password);

       if (authenticator == null) {
          // XXX - to help caRouterCert to work, we need to 
          // add authentication to caRouterCert
          authToken = new AuthToken(null);
       } else { 
         authToken = authenticate(credentials, authenticator, httpReq);
       }

       IRequest reqs[] = null;
       CMS.debug("CRSEnrollment: Creating profile requests");
       ctx.set(IEnrollProfile.CTX_CERT_REQUEST_TYPE, "pkcs10");
       ctx.set(IEnrollProfile.CTX_CERT_REQUEST, pkcs10blob);
       Locale locale = Locale.getDefault();
       reqs = profile.createRequests(ctx, locale);
       if (reqs == null) {
         CMS.debug("CRSEnrollment: No request has been created");
         return null;
       } else {
         CMS.debug("CRSEnrollment: Request (" + reqs.length + ") have been created");
       }
       // set transaction id
       reqs[0].setExtData("profileId", mProfileId);
       reqs[0].setSourceId(req.getTransactionID());

       CMS.debug("CRSEnrollment: Populating inputs");
       profile.populateInput(ctx, reqs[0]);
       CMS.debug("CRSEnrollment: Populating requests");
       profile.populate(reqs[0]);

       CMS.debug("CRSEnrollment: Submitting request");
       profile.submit(authToken, reqs[0]);
       CMS.debug("CRSEnrollment: Done submitting request");

       return reqs[0];

     }

     IRequestQueue rq = ca.getRequestQueue();
     IRequest pkiReq = rq.newRequest(IRequest.ENROLLMENT_REQUEST);

	 AuthToken token = (AuthToken) req.get(AUTH_TOKEN);
     if (token != null) { 
          pkiReq.setExtData(IRequest.AUTH_TOKEN,token);
     }

     pkiReq.setExtData(IRequest.HTTP_PARAMS, IRequest.CERT_TYPE, IRequest.CEP_CERT);
	 X509CertInfo certInfo = (X509CertInfo) req.get(CERTINFO);
     pkiReq.setExtData(IRequest.CERT_INFO, new X509CertInfo[] { certInfo } );
     pkiReq.setExtData("cepsubstore", mSubstoreName);

	 try {
	 	String chpwd = (String)req.get(ChallengePassword.NAME);
        if (chpwd != null) {
	 		pkiReq.setExtData("challengePhrase",
				chpwd );
		}
	 } catch (Exception pwex) {
	 }

     Hashtable fingerprints = (Hashtable)req.get(IRequest.FINGERPRINTS);
     if (fingerprints.size() > 0) {
         Hashtable encodedPrints = new Hashtable(fingerprints.size());
         Enumeration e = fingerprints.keys();
         while (e.hasMoreElements()) {
             String key = (String)e.nextElement();
             byte[] value = (byte[])fingerprints.get(key);
             encodedPrints.put(key, CMS.BtoA(value));
         }
         pkiReq.setExtData(IRequest.FINGERPRINTS, encodedPrints);
	 }

     pkiReq.setSourceId(req.getTransactionID());
                 
     rq.processRequest(pkiReq);

     crsResp.setPKIStatus(crsResp.mStatus_SUCCESS);

     mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                            AuditFormat.LEVEL,
                            AuditFormat.ENROLLMENTFORMAT,
                            new Object[] {
                            pkiReq.getRequestId(),
                            AuditFormat.FROMROUTER,
                            mAuthManagerName == null ? AuditFormat.NOAUTH : mAuthManagerName,
                            "pending",
                            subject ,
                            ""}
                            );
                  
	  return pkiReq;
  }



  public Hashtable makeFingerPrints(CRSPKIMessage req) {
        Hashtable fingerprints = new Hashtable();

        MessageDigest md;
        String[] hashes = new String[] {"MD2", "MD5", "SHA1"};
        PKCS10 p10 = (PKCS10)req.getP10();

        for (int i=0;i<hashes.length;i++) {
		    try {
               	md = MessageDigest.getInstance(hashes[i]);
               	md.update(p10.getCertRequestInfo());
               	fingerprints.put(hashes[i],md.digest());
			}
			catch (NoSuchAlgorithmException nsa) {}
        }

		if (fingerprints != null) {
	    	req.put(IRequest.FINGERPRINTS,fingerprints);
		}
		return fingerprints;
  }

  
  // Take a look to see if the request was successful, and fill
  // in the response message


  private X509CertImpl makeResponseFromRequest(CRSPKIMessage crsReq, CRSPKIMessage crsResp,
                                      IRequest pkiReq)
    {

        X509CertImpl issuedCert=null;

        RequestStatus status = pkiReq.getRequestStatus();

        String profileId = pkiReq.getExtDataInString("profileId");
        if (profileId != null) {
          CMS.debug("CRSEnrollment: Found profile request");
          X509CertImpl cert =
                 pkiReq.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);
          if (cert == null) {
            CMS.debug("CRSEnrollment: No certificate has been found");
          } else {
            CMS.debug("CRSEnrollment: Found certificate");
          }
          crsResp.setPKIStatus(crsResp.mStatus_SUCCESS);
          return cert;
        }


        if ( status.equals(RequestStatus.COMPLETE)) {
            Integer success = pkiReq.getExtDataInInteger(IRequest.RESULT);


            if (success.equals(IRequest.RES_SUCCESS)) {
                // The cert was issued, lets send it back to the router
                X509CertImpl[] issuedCertBuf =
                  pkiReq.getExtDataInCertArray(IRequest.ISSUED_CERTS);
                if (issuedCertBuf == null || issuedCertBuf.length == 0) {
                    //  writeError("Internal Error: Bad operation",httpReq,httpResp);
                    CMS.debug( "CRSEnrollment::makeResponseFromRequest() - " +
                               "Bad operation" );
                    return null;
                }
                issuedCert = issuedCertBuf[0];
                crsResp.setPKIStatus(crsResp.mStatus_SUCCESS);
                            
            }
            else {  // status is not 'success' - there must've been a problem
                            
                crsResp.setPKIStatus(crsResp.mStatus_FAILURE);
                crsResp.setFailInfo(crsResp.mFailInfo_badAlg);
            }
        }
        else if (status.equals(RequestStatus.REJECTED_STRING) ||
                 status.equals(RequestStatus.CANCELED_STRING)) {
                crsResp.setPKIStatus(crsResp.mStatus_FAILURE);
                crsResp.setFailInfo(crsResp.mFailInfo_badRequest);
            }
        else  {   // not complete
            crsResp.setPKIStatus(crsResp.mStatus_PENDING);
        }

        return issuedCert;
    }






  /**
   *  This needs to be re-written to log the messages to the system log, since there
   *  will be no visual webpage feedback for the user. (he's using a router)
   */

  private void writeError(String errMsg, HttpServletRequest httpReq,
                          HttpServletResponse httpResp)
    throws IOException
    {
    }


   protected String hashPassword(String pwd) {
        String salt = "lala123";
        byte[] pwdDigest = mSHADigest.digest((salt+pwd).getBytes());
        String b64E = com.netscape.osutil.OSUtil.BtoA(pwdDigest);
        return "{SHA}"+b64E;
    }




  /**
   *  Make the CRSPKIMESSAGE response
   */


  private void processCertRep(CryptoContext cx,
                              X509CertImpl issuedCert,
                              CRSPKIMessage crsResp,
                              CRSPKIMessage crsReq) 
    throws CRSFailureException {
      byte[] msgdigest = null;
      byte[] encryptedDesKey = null;
        
      try {
          if (issuedCert != null) {
                
              SymmetricKey sk;
              SymmetricKey skinternal;

              KeyGenAlgorithm kga = KeyGenAlgorithm.DES;
              EncryptionAlgorithm ea = EncryptionAlgorithm.DES_CBC;
              if (mEncryptionAlgorithm != null && mEncryptionAlgorithm.equals("DES3")) {
                  kga = KeyGenAlgorithm.DES3;
                  ea = EncryptionAlgorithm.DES3_CBC;
              }

              // 1. Make the Degenerated PKCS7 with the recipient's certificate in it
                
              byte toBeEncrypted[] =
                crsResp.makeSignedRep(1,  // version
                                      issuedCert.getEncoded()
                                      );
                
              // 2. Encrypt the above byte array with a new random DES key
                
              sk = cx.getDESKeyGenerator().generate();
                
              skinternal = cx.getInternalToken().getKeyGenerator(kga).clone(sk);
                
              byte[] padded = Cipher.pad(toBeEncrypted, ea.getBlockSize());


              // This should be changed to generate proper DES IV.

              Cipher cipher = cx.getInternalToken().getCipherContext(ea);
              IVParameterSpec desIV =
                new IVParameterSpec(new byte[]{
                    (byte)0xff, (byte)0x00,
                      (byte)0xff, (byte)0x00,
                      (byte)0xff, (byte)0x00,
                      (byte)0xff, (byte)0x00 } );
                
              cipher.initEncrypt(sk,desIV);
              byte[] encryptedData = cipher.doFinal(padded);
                
              crsResp.makeEncryptedContentInfo(desIV.getIV(),encryptedData, mEncryptionAlgorithm);
                
              // 3. Extract the recipient's public key
                
              PublicKey rcpPK = crsReq.getSignerPublicKey();
                
                
              // 4. Encrypt the DES key with the public key
                
              // we have to move the key onto the interal token.
              //skinternal = cx.getInternalKeyStorageToken().cloneKey(sk);
              skinternal = cx.getInternalToken().cloneKey(sk);
                
              KeyWrapper kw = cx.getInternalKeyWrapper();
              kw.initWrap(rcpPK, null);
              encryptedDesKey = kw.wrap(skinternal);
                
              crsResp.setRcpIssuerAndSerialNumber(crsReq.getSgnIssuerAndSerialNumber());
              crsResp.makeRecipientInfo(0, encryptedDesKey );
                
          }

                
          byte[] ed = crsResp.makeEnvelopedData(0);

          // 7. Make Digest of SignedData Content 
          MessageDigest md = MessageDigest.getInstance(mHashAlgorithm);
          msgdigest = md.digest(ed);

          crsResp.setMsgDigest(msgdigest);
                
      }
        
      catch (Exception e) {
          throw new CRSFailureException("Failed to create inner response to CEP message: "+e.getMessage());
      }
        
                        
      // 5. Make a RecipientInfo
        
      // The issuer name & serial number here, should be that of
      // the EE's self-signed Certificate
      // [I can get it from the req blob, but later, I should
      //  store the recipient's self-signed certificate with the request
      //  so I can get at it later. I need to do this to support
      //  'PENDING']
        
        
      try {
            
          // 8. Make Authenticated Attributes
          // we can just pull the transaction ID out of the request.
          // Later, we will have to put it out of the Request queue,
          // so we can support PENDING
          crsResp.setTransactionID(crsReq.getTransactionID());
          // recipientNonce and SenderNonce have already been set
            
          crsResp.makeAuthenticatedAttributes();
          //      crsResp.makeAuthenticatedAttributes_old();                  
            


          // now package up the rest of the SignerInfo
          {
              byte[] signingcertbytes = cx.getSigningCert().getEncoded();
                

              Certificate.Template sgncert_t = new Certificate.Template();
              Certificate sgncert =
                (Certificate) sgncert_t.decode(new ByteArrayInputStream(signingcertbytes));
                
              IssuerAndSerialNumber sgniasn =
                new IssuerAndSerialNumber(sgncert.getInfo().getIssuer(),
                                          sgncert.getInfo().getSerialNumber());
                
              crsResp.setSgnIssuerAndSerialNumber(sgniasn);
                
              // 10. Make SignerInfo
              crsResp.makeSignerInfo(1, cx.getPrivateKey(), mHashAlgorithm);

              // 11. Make SignedData
              crsResp.makeSignedData(1, signingcertbytes, mHashAlgorithm);

              crsResp.debug();
          }
      }
      catch (Exception e) {
          throw new CRSFailureException("Failed to create outer response to CEP request: "+e.getMessage());
      }
        
        
      // if debugging, dump out the response into a file
        
  }



  class CryptoContext {
    private CryptoManager cm;
    private CryptoToken internalToken;
    private CryptoToken internalKeyStorageToken;
    private KeyGenerator DESkg;
	private Enumeration externalTokens = null;
    private org.mozilla.jss.crypto.X509Certificate signingCert;
    private org.mozilla.jss.crypto.PrivateKey signingCertPrivKey;
	private int signingCertKeySize = 0;


    class CryptoContextException extends Exception {
      public CryptoContextException() { super(); }
      public CryptoContextException(String s) { super(s); }
    }

    public CryptoContext(String encryptionAlgorithm)
      throws CryptoContextException
      {
          try {
              KeyGenAlgorithm kga = KeyGenAlgorithm.DES;
              if (encryptionAlgorithm != null && encryptionAlgorithm.equals("DES3")) {
                  kga = KeyGenAlgorithm.DES3;
              }
              cm = CryptoManager.getInstance();
              internalToken = cm.getInternalCryptoToken();
              internalKeyStorageToken = cm.getInternalKeyStorageToken();
              DESkg = internalToken.getKeyGenerator(kga);
              signingCert = cm.findCertByNickname(ca.getNickname());
              signingCertPrivKey = cm.findPrivKeyByCert(signingCert);
			  byte[] encPubKeyInfo = signingCert.getPublicKey().getEncoded();
			  SEQUENCE.Template outer = SEQUENCE.getTemplate();
			  outer.addElement( ANY.getTemplate() ); // algid
			  outer.addElement( BIT_STRING.getTemplate() );
			  SEQUENCE outerSeq = (SEQUENCE) ASN1Util.decode(outer, encPubKeyInfo);
			  BIT_STRING bs = (BIT_STRING) outerSeq.elementAt(1);
			  byte[] encPubKey = bs.getBits();
			  if( bs.getPadCount() != 0) {
			  	  throw new CryptoContextException("Internal error: Invalid Public key. Not an integral number of bytes.");
			  }
			  SEQUENCE.Template inner = new SEQUENCE.Template();
			  inner.addElement( INTEGER.getTemplate());
			  inner.addElement( INTEGER.getTemplate());
			  SEQUENCE pubKeySeq = (SEQUENCE) ASN1Util.decode(inner, encPubKey);
			  INTEGER modulus = (INTEGER) pubKeySeq.elementAt(0);
			  signingCertKeySize = modulus.bitLength();
			  
			  try {
              FileOutputStream fos = new FileOutputStream("pubkey.der");
              fos.write(signingCert.getPublicKey().getEncoded());
              fos.close();
			  } catch (Exception e) {}

          }
		  catch (InvalidBERException e) {
		  	  throw new CryptoContextException("Internal Error: Bad internal Certificate Representation. Not a valid RSA-signed certificate");
			  }
          catch (CryptoManager.NotInitializedException e) {
              throw new CryptoContextException("Crypto Manager not initialized");
          }
          catch (NoSuchAlgorithmException e) {
              throw new CryptoContextException("Cannot create DES key generator");
          }
          catch (ObjectNotFoundException e) {
              throw new CryptoContextException("Certificate not found"+ca.getNickname());
          }
          catch (TokenException e) {
              throw new CryptoContextException("Problem with Crypto Token: "+e.getMessage());
          }
      }


    public KeyGenerator getDESKeyGenerator() {
        return DESkg;
    }

    public CryptoToken getInternalToken() {
        return internalToken;
    }

    public void setExternalTokens( Enumeration tokens ) {
        externalTokens = tokens;
    }

    public Enumeration getExternalTokens() {
        return externalTokens;
    }

    public CryptoToken getInternalKeyStorageToken() {
        return internalKeyStorageToken;
    }

    public CryptoManager getCryptoManager() {
        return cm;
    }

    public KeyWrapper getKeyWrapper() 
      throws CryptoContextException {
        try {
            return signingCertPrivKey.getOwningToken().getKeyWrapper(KeyWrapAlgorithm.RSA);
        }
        catch (TokenException e) {
            throw new CryptoContextException("Problem with Crypto Token: "+e.getMessage());
        }
        catch (NoSuchAlgorithmException e) {
            throw new CryptoContextException(e.getMessage());
        }
    }

    public KeyWrapper getInternalKeyWrapper() 
      throws CryptoContextException {
        try {
            return getInternalToken().getKeyWrapper(KeyWrapAlgorithm.RSA);
        }
        catch (TokenException e) {
            throw new CryptoContextException("Problem with Crypto Token: "+e.getMessage());
        }
        catch (NoSuchAlgorithmException e) {
            throw new CryptoContextException(e.getMessage());
        }
    }

    public org.mozilla.jss.crypto.PrivateKey getPrivateKey() {
        return signingCertPrivKey;
    }

    public org.mozilla.jss.crypto.X509Certificate getSigningCert() {
        return signingCert;
    }
        
  }


  /* General failure. The request/response cannot be processed. */


  class CRSFailureException extends Exception {
    public CRSFailureException() { super(); }
    public CRSFailureException(String s) { super(s); }
  }

  class CRSInvalidSignatureException extends Exception {
    public CRSInvalidSignatureException() { super(); }
    public CRSInvalidSignatureException(String s) { super(s); }
  }

    

  class CRSPolicyException extends Exception {
      public CRSPolicyException() { super(); }
      public CRSPolicyException(String s) { super(s); }
  }

}

