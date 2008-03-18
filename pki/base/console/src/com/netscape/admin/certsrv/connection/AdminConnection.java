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
package com.netscape.admin.certsrv.connection;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.*;
import com.netscape.management.client.preferences.*;

/**
 * This class represents an administration connection shell
 * to the certificate server. The user need to specify the
 * connection factory
 *
 * @author thomask
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.certsrv.client.connection
 * @see com.netscape.certsrv.client
 */
public class AdminConnection {

    /*==========================================================
     * variables
     *==========================================================*/
    public static int NO_TIMEOUT = 0;
    public static int DEFAULT_TIMEOUT = 600000;      //600 sec
    
    private IConnectionFactory mFactory= null;
	private IConnection mConn = null;
	private IAuthenticator mAuth = null;
	private int mDefaultTimeout = DEFAULT_TIMEOUT;
	private int mCurrentTimeout = DEFAULT_TIMEOUT;
	private boolean mIsKeepAlive = false;
	private String mHost;
	private int mPort;
    private IConnectionListener mConnectionListener;
    private String mAuthType="";
    private String mPath=null;
    private static FilePreferenceManager mPM = null;

	/*==========================================================
     * constructors
     *==========================================================*/

    /**
     * Default Constructor<p>
     * Construct an administartion connection with keep alive disabled
     *
     * @param auth authentication mechanism object
     * @param factory factory used to create server connection
     * @param host server host name
     * @param port server port number
     *
     * @see com.netscape.certsrv.client.connection.IConnection
     * @see com.netscape.certsrv.client.connection.IConnectionFactory
     * @see com.netscape.certsrv.client.connection.IAuthenticator
     */
	public AdminConnection( IAuthenticator auth,
	                        IConnectionFactory factory,
	                        String host, int port, String path) {
               if (mPM == null) {
                 mPM = new FilePreferenceManager(Framework.IDENTIFIER, 
                       Framework.VERSION);
               }
               Preferences p = mPM.getPreferences(
                  Framework.PREFERENCES_GENERAL);
               int timeout = p.getInt("CMSConnTimeout", 600000);
               setDefaultTimeout(timeout);
               setCurrentTimeout(timeout);
               Debug.println("AdminConnection: " + timeout + " " + 
                   mPM.getClass().getName());

		mAuth = auth;
		mFactory = factory;
		mHost = host;
		mPort = port;
		mPath = path;
	}

    /**
     * Default Constructor<p>
     * Construct an administartion connection
     *
     * @param auth authentication mechanism object
     * @param factory factory used to create server connection
     * @param enableKeepAlive enable HTTP keep alive or not
     * @param host server host name
     * @param port server port number
     *
     * @see com.netscape.certsrv.client.connection.IConnection
     * @see com.netscape.certsrv.client.connection.IConnectionFactory
     * @see com.netscape.certsrv.client.connection.IAuthenticator
     */
	public AdminConnection( IAuthenticator auth,
	                        IConnectionFactory factory,
	                        boolean enableKeepAlive,
	                        String host, int port, String path) {
               if (mPM == null) {
                 mPM = new FilePreferenceManager(Framework.IDENTIFIER, 
                       Framework.VERSION);
               }
               Preferences p = mPM.getPreferences(
                  Framework.PREFERENCES_GENERAL);
               int timeout = p.getInt("CMSConnTimeout", 600000);
               setDefaultTimeout(timeout);
               setCurrentTimeout(timeout);
               Debug.println("AdminConnection: " + timeout + " " + 
                   mPM.getClass().getName());

		mAuth = auth;
		mFactory = factory;
		mIsKeepAlive = enableKeepAlive;
		mHost = host;
		mPort = port;
		mPath = path;
	}

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Set the listener. 
     */
    public void setConnectionListener(IConnectionListener l) {
        mConnectionListener = l;
    }

    /**
     * Returns the authentication object for this connection.<p>
     * The choice of authentication object is dependding on the
     * authentication method used on the server side.
     *
     * @return authentication object
     * @see com.netscape.certsrv.client.connection.IAuthenticator
     * @see com.netscape.certsrv.client.connection.BasicAuthenticator
     */
	public IAuthenticator getAuthenticator() {
		return mAuth;
	}

    /**
     * Returns the connection object used to establish the connection
     * This can be SSLavaConnection or SSLConnection. THIS OBJECT REFERENCE
     * IS NOT STABLE, SINCE IT IS RECREATED EACH TIME IF KEEPALIVE IS NOT
     * ENABLE.
     *
     * @return connection object
     */
    public IConnection getIConnection() {
        return mConn;
    }

    /**
     * Sets the one time current timeout value for specific operation
     * if less then default timeout the default timeout is used.
     *
     * @param timeout time in ms
     */
    public void setCurrentTimeout(int timeout) {
        mCurrentTimeout = timeout;    
    }


    /**
     * Sets the default timeout value
     * @param timeout time in ms
     */
    public void setDefaultTimeout(int timeout) {
        mDefaultTimeout = timeout;
    }

    /**
     * OPERATION: ADD<p>
     *
     * <pre>
     * FORMAT:
     *
     *      GET/[OP_DEST]?
     *          OP_TYPE=[OP_TYPE]&
     *          OP_SCOPE=[OP_SCOPE]&
     *          RS_ID=[RS_ID]&
     *          [NAME=VALUE][&[NAME=VALUE]]
     *
     * </pre>
     *
     * Add new entries into the scope using the NVP information provided.
     * This operation will ONLY be used by DYNAMIC content and
     * configuartion, such as Users and Groups, and Policies.
     *
     * @param dest OP_DEST
     * @param scope OP_SCOPE
     * @param id RS_ID
     * @param pairs NVP info
     *
     * @see http://warp/server/certificate/columbo/design/ui/admin-protocol-definition.html
     *
     */
    public void add(String dest, String scope, String id, NameValuePairs pairs)
        throws EAdminException {

		checkParams(dest,scope,id,pairs);
        Request request = new Request(mPath + "/" + dest);
        request.set(Constants.OP_TYPE, OpDef.OP_ADD);
        request.set(Constants.OP_SCOPE, scope);
        request.set(Constants.RS_ID, id);
        for (int i = 0; i < pairs.size(); i++) {
            NameValuePair p = (NameValuePair)pairs.elementAt(i);
            request.set(p.getName(), p.getValue());
        }
        Response response = sendRequest(request);
        if (response.getReturnCode() == Response.SUCCESS) {
            return;
        }
        throw new EAdminException(response.getErrorMessage(), true);
    }

    /**
     * OPERATION: DELETE<p>
     *
     * <pre>
     * FORMAT:
     *
     *      GET/[OP_DEST]?
     *          OP_TYPE=[OP_TYPE]&
     *          OP_SCOPE=[OP_SCOPE]&
     *          RS_ID=[RS_ID]&
     *
     * </pre>
     *
     * Removing an entry with specified id from the scope specified.
     *
     * @param dest OP_DEST
     * @param scope OP_SCOPE
     * @param id RS_ID
     *
     * @see http://warp/server/certificate/columbo/design/ui/admin-protocol-definition.html
     *
     */
    public void delete(String dest, String scope, String id)
        throws EAdminException {

		checkParams(dest,scope,id);
        Request request = new Request(mPath + "/" + dest);
        request.set(Constants.OP_TYPE, OpDef.OP_DELETE);
        request.set(Constants.OP_SCOPE, scope);
        request.set(Constants.RS_ID, id);
        Response response = sendRequest(request);
        if (response.getReturnCode() == Response.SUCCESS) {
            return;
        }
        throw new EAdminException(response.getErrorMessage(), true);
    }

    public void delete(String dest, String scope, String id, NameValuePairs pairs)
        throws EAdminException {

        checkParams(dest,scope,id,pairs);
        Request request = new Request(mPath + "/" + dest);
        request.set(Constants.OP_TYPE, OpDef.OP_DELETE);
        request.set(Constants.OP_SCOPE, scope);
        request.set(Constants.RS_ID, id);
        for (int i = 0; i < pairs.size(); i++) {
            NameValuePair p = (NameValuePair)pairs.elementAt(i);
            request.set(p.getName(), p.getValue());
        }
        Response response = sendRequest(request);
        if (response.getReturnCode() == Response.SUCCESS) {
            return;
        }
        throw new EAdminException(response.getErrorMessage(), true);
    }

    /**
     * OPERATION: AUTH<p>
     *
     * <pre>
     * FORMAT:
     *
     *      GET/[OP_DEST]?
     *          OP_TYPE=[OP_TYPE]&
     *          OP_SCOPE=[OP_SCOPE]&
     *          [NAME=VALUE][&[NAME=VALUE]]
     *
     * </pre>
     *
     * getting  properties (name-value pairs) using some criteria
     * specified in NVP.
     *
     * @param dest OP_DEST
     * @param scope OP_SCOPE
     * @param pairs NVP search filter
     *
     * @see http://warp/server/certificate/columbo/design/ui/admin-protocol-definition.html
     *
     */
    public void auth(String dest, String scope) throws EAdminException {
        Request request = new Request(mPath + "/" + dest);
        request.set(Constants.OP_TYPE, OpDef.OP_AUTH);
        request.set(Constants.OP_SCOPE, scope);
        Response response = sendRequest(request);
        if (response.getReturnCode() == Response.SUCCESS) {
            return;
        }
        throw new EAdminException(response.getErrorMessage(), true);
    }

    public String authType(String dest, String scope) throws EAdminException {
        Request request = new Request(mPath + "/" + dest);
        request.set(Constants.OP_TYPE, OpDef.OP_AUTH);
        request.set(Constants.OP_SCOPE, scope);

        Response response = sendRequest(request);
        if (response.getReturnCode() == Response.SUCCESS) {
            Enumeration e = response.getNames();
            while (e.hasMoreElements()) {
                String n = (String)e.nextElement();
                if (n.equals("authType"))
                    mAuthType = response.get(n);
                    return mAuthType;
            }
            return "";
        }
        throw new EAdminException(response.getErrorMessage(), true);
    }

    /**
     * OPERATION: SEARCH<p>
     *
     * <pre>
     * FORMAT:
     *
     *      GET/[OP_DEST]?
     *          OP_TYPE=[OP_TYPE]&
     *          OP_SCOPE=[OP_SCOPE]&
     *          [NAME=VALUE][&[NAME=VALUE]]
     *
     * </pre>
     *
     * getting  properties (name-value pairs) using some criteria
     * specified in NVP.
     *
     * @param dest OP_DEST
     * @param scope OP_SCOPE
     * @param pairs NVP search filter
     *
     * @see http://warp/server/certificate/columbo/design/ui/admin-protocol-definition.html
     *
     */
    public NameValuePairs search(String dest, String scope, NameValuePairs filters)
        throws EAdminException {

		checkParams(dest,scope,"",filters);
        Request request = new Request(mPath + "/" + dest);
        request.set(Constants.OP_TYPE, OpDef.OP_SEARCH);
        request.set(Constants.OP_SCOPE, scope);
        for (int i = 0; i < filters.size(); i++) {
            NameValuePair p = (NameValuePair)filters.elementAt(i);
            request.set(p.getName(), p.getValue());
        }

        Response response = sendRequest(request);

        if (response.getReturnCode() == Response.SUCCESS) {
            NameValuePairs newpairs = new NameValuePairs();
            Enumeration e = response.getNames();
            while (e.hasMoreElements()) {
                String n = (String)e.nextElement();
		        newpairs.add(n, response.get(n));
            }
            return newpairs;
        }
        throw new EAdminException(response.getErrorMessage(), true);
    }

    /**
     * OPERATION: READ<p>
     *
     * <pre>
     * FORMAT:
     *
     *      GET/[OP_DEST]?
     *          OP_TYPE=[OP_TYPE]&
     *          OP_SCOPE=[OP_SCOPE]&
     *          RS_ID=[RS_ID]&
     *          [NAME=VALUE][&[NAME=VALUE]]
     *
     * </pre>
     *
     * getting specific properties (name-value pairs) using
     * attributes specified in NVP.
     *
     * @param dest OP_DEST
     * @param scope OP_SCOPE
     * @param id RS_ID
     * @param pairs NVP info
     *
     * @see http://warp/server/certificate/columbo/design/ui/admin-protocol-definition.html
     *
     */
    public NameValuePairs read(String dest, String scope, String id, NameValuePairs pairs)
        throws EAdminException {

		checkParams(dest,scope,id);
        Request request = new Request(mPath + "/" + dest);
        request.set(Constants.OP_TYPE, OpDef.OP_READ);
        request.set(Constants.OP_SCOPE, scope);
        request.set(Constants.RS_ID, id);
        for (int i = 0; i < pairs.size(); i++) {
            NameValuePair p = (NameValuePair)pairs.elementAt(i);
            request.set(p.getName(), "");
        }

        Response response = sendRequest(request);

        if (response.getReturnCode() == Response.SUCCESS) {
            NameValuePairs newpairs = new NameValuePairs();
            Enumeration e = response.getNames();
            while (e.hasMoreElements()) {
                String n = (String)e.nextElement();
		        newpairs.add(n, response.get(n));
            }
            return newpairs;
        }
        throw new EAdminException(response.getErrorMessage(), true);
    }

    public NameValuePairs process(String dest, String scope, String id,
      NameValuePairs pairs) throws EAdminException {
         return process(dest, scope, id, pairs, false);
    }

    public NameValuePairs process(String dest, String scope, String id,
      NameValuePairs pairs, boolean useGET) throws EAdminException {
        Request request = new Request(mPath + "/" + dest);
        request.set(Constants.OP_TYPE, OpDef.OP_PROCESS);
        request.set(Constants.OP_SCOPE, scope);
        request.set(Constants.RS_ID, id);

        for (int i = 0; i < pairs.size(); i++) {
            NameValuePair p = (NameValuePair)pairs.elementAt(i);
            request.set(p.getName(), p.getValue());
        }

        Response response = sendRequest(request, useGET);
        if (response.getReturnCode() == Response.SUCCESS) {
            NameValuePairs newpairs = new NameValuePairs();
            Enumeration e = response.getNames();
            while (e.hasMoreElements()) {
                String n = (String)e.nextElement();
                newpairs.add(n, response.get(n));
            }
            return newpairs;
        }
        throw new EAdminException(response.getErrorMessage(), true);
    }

    public void validate(String dest, String scope, NameValuePairs pairs) 
        throws EAdminException {
        Request request = new Request(mPath + "/" + dest);
        request.set(Constants.OP_TYPE, OpDef.OP_VALIDATE);
        request.set(Constants.OP_SCOPE, scope);
        for (int i = 0; i < pairs.size(); i++) {
            NameValuePair p = (NameValuePair)pairs.elementAt(i);
            request.set(p.getName(), p.getValue());
        }

        Response response = sendRequest(request);
        if (response.getReturnCode() == Response.SUCCESS) {
            return;
        }
        throw new EAdminException(response.getErrorMessage(), true);
    }

    /**
     * OPERATION: MODIFY<p>
     *
     * <pre>
     * FORMAT:
     *
     *      GET/[OP_DEST]?
     *          OP_TYPE=[OP_TYPE]&
     *          OP_SCOPE=[OP_SCOPE]&
     *          RS_ID=[RS_ID]&
     *          [NAME=VALUE][&[NAME=VALUE]]
     *
     * </pre>
     *
     * Modify an existing entry's attributes.
     *
     * @param dest OP_DEST
     * @param scope OP_SCOPE
     * @param id RS_ID
     * @param pairs NVP info
     *
     * @see http://warp/server/certificate/columbo/design/ui/admin-protocol-definition.html
     *
     */
    public void modify(String dest, String scope, String id, NameValuePairs pairs)
        throws EAdminException {
          modify(dest, scope, id, pairs, false);
    }

    public void modify(String dest, String scope, String id, NameValuePairs pairs, boolean useGET)
        throws EAdminException {

		checkParams(dest,scope,id,pairs);
        Request request = new Request(mPath + "/" + dest);
        request.set(Constants.OP_TYPE, OpDef.OP_MODIFY);
        request.set(Constants.OP_SCOPE, scope);
        request.set(Constants.RS_ID, id);
        for (int i = 0; i < pairs.size(); i++) {
            NameValuePair p = (NameValuePair)pairs.elementAt(i);
            request.set(p.getName(), p.getValue());
        }
        Response response = sendRequest(request, useGET);
        if (response.getReturnCode() == Response.SUCCESS) {
            return;
        } else if (response.getReturnCode() == Response.RESTART) {
            mConnectionListener.restartCallback();
            return;    
        }
        throw new EAdminException(response.getErrorMessage(), true);
    }

    private synchronized void retryConnection() throws EAdminException {
        if (mConn instanceof JSSConnection) {
            JSSConnection conn = (JSSConnection)mConn;
            if (!conn.isTokenPasswordInit()) {
                mConn = null;
                if (!conn.isSamePwd()) {
                    throw new EAdminException(CMSAdminResources.SERVERCONNECTION_DIFFERENT_PWD, false);
                }
                throw new EAdminException(CMSAdminResources.SERVERCONNECTION_TOKEN_INIT_FAILED, false);
            }

            if (!conn.isServerCertImported()) {
                mConn = null;
                throw new EAdminException(CMSAdminResources.SERVERCONNECTION_SERVER_CERT_IMPORTED_FAILED, false);
            }
            if (!conn.isCertAccepted()) {
                mConn = null;
                throw new EAdminException(CMSAdminResources.SERVERCONNECTION_SERVER_CERT_DENIED, false);
            }
            if (conn != null && conn.isAbortAction() && conn.isClientAuth()) {
                mConn = null;
                throw new EAdminException(CMSAdminResources.SERVERCONNECTION_NO_CLIENT_CERT, false);
            }
            if (conn != null && !conn.hasClientCert()) {
                mConn = null;
                throw new EAdminException(CMSAdminResources.SERVERCONNECTION_NO_CLIENT_CERT, false);
            }
        }
        try {
            mConn = mFactory.create(mHost, mPort);
        } catch (UnknownHostException e) {
            mConn = null;
            throw new EAdminException(CMSAdminResources.UNKNOWNHOST, false);
        } catch (IOException e) {
            mConn = null;
    	    throw new EAdminException(CMSAdminResources.SERVER_UNREACHABLE, false);
        } catch (Exception e) {
            mConn = null;
			if (Debug.isEnabled()) {
				e.printStackTrace();
			}
            throw new EAdminException(CMSAdminResources.UNKNOWNEXCEPTION, false);
        }
    }

    /**
     * Deliver the request through the connection object
     *
     * @param request request object
     * @return response object
     * @see com.netscape.certsrv.client.connection.Response
     */
    private synchronized Response sendRequest(Request request)
        throws EAdminException {
        return sendRequest(request, false);
    }

    private synchronized Response sendRequest(Request request, boolean useGET)
        throws EAdminException {

    	try {
    	    if (mConn == null) {
    	        mConn = mFactory.create(mHost, mPort);
    	    }
    	} catch (UnknownHostException e) {
    	    mConn = null;
    	    throw new EAdminException(CMSAdminResources.UNKNOWNHOST, false);
    	} catch (IOException e) {
            retryConnection();
    	    throw new EAdminException(CMSAdminResources.SERVER_UNREACHABLE, false);
    	} catch (Exception e) {
            retryConnection();
    	    if (Debug.isEnabled()) {
				e.printStackTrace();
			}
    	    throw new EAdminException(CMSAdminResources.UNKNOWNEXCEPTION, false);
    	}

        try {
    	    return processRequest(request, useGET);    
    	//all errors will set the connection to null
    	//to force re-connection and avoid null ptr exception

    	} catch (Exception e) {
            retryConnection();
         
            try {
                return processRequest(request, useGET);
            } catch (InterruptedIOException ex) {
       
    	        //timeout occurred
    	        mConn = null;

    	        //set time out back to original
                mCurrentTimeout = mDefaultTimeout;
    	        throw new EAdminException(CMSAdminResources.SERVER_NORESPONSE, false);
    	    } catch (SocketException ex) {
    	        mConn = null;
    	        throw new EAdminException(CMSAdminResources.SERVER_UNREACHABLE, false);
    	    } catch (IOException ex) { 
 			    if (Debug.isEnabled()) {
				    ex.printStackTrace();
			}
    	        mConn = null;
    	        throw new EAdminException(CMSAdminResources.SERVER_UNREACHABLE, false);
            } catch (EAdminException ex) {
                throw ex;
    	    } catch (Exception ex) {
    	        mConn = null;
 			    if (Debug.isEnabled()) {
				    ex.printStackTrace();
			    }
    	        throw new EAdminException(CMSAdminResources.UNKNOWNEXCEPTION, false);
            }
    	}
    }

    private Response processRequest(Request request, boolean useGET) throws Exception {
        //packaging the request
        StringBuffer sb = new StringBuffer();
        if (useGET) {
          sb.append("GET /" + request.getPrefix() + "?");
          Enumeration names = request.getElements();
          while (names.hasMoreElements()) {
            String name = (String)names.nextElement();
            sb.append(name);
            sb.append("=");
            sb.append(java.net.URLEncoder.encode(request.get(name)));
            if (names.hasMoreElements())
              sb.append("&");
          }
        } else {
          sb.append("POST /" + request.getPrefix());
        }
            sb.append(" HTTP/1.0\n");

        StringBuffer sb1 = new StringBuffer();
        if (!useGET) {
            sb.append("Content-type: application/x-www-form-urlencoded\n");
          Enumeration names = request.getElements();
          while (names.hasMoreElements()) {
            String name = (String)names.nextElement();
            sb1.append(name);
            sb1.append("=");
            sb1.append(java.net.URLEncoder.encode(request.get(name)));
            if (names.hasMoreElements())
              sb1.append("&");
          }
            sb.append("Content-length: " + sb1.toString().length() + "\n");
        }
 
        sb.append("Pragma: no-cache\n");
        if (mIsKeepAlive) {
                sb.append("Connection: Keep-Alive\n");
        }
 
        if (mAuthType.equals("") || mAuthType.equals("pwd")) {
            BasicAuthenticator auth = (BasicAuthenticator)mAuth;
            sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
            sb.append("Authorization: Basic " +
                     encoder.encodeBuffer((auth.getUserid() +
                                          ":" + auth.getPassword()).getBytes()) + "\n");
        } else if (mAuthType.equals("sslclientauth")) {
            sb.append("\n");
        } else {
            throw new EAdminException(CMSAdminResources.AUTHENNOTSUPPORTED, false);
        }

        if (!useGET) {
            sb.append(sb1.toString());
        }
        //Debug.println(sb.toString());
 
        //System.out.println("AdminConnection: sendRequest() - sending");
        int timeout = mDefaultTimeout;
        if (mCurrentTimeout > mDefaultTimeout)
            timeout = mCurrentTimeout;
            mConn.setSoTimeout(timeout);
            mConn.sendRequest(sb.toString());

            Response resp = new Response(mConn.getResponse());
 
            if (!mIsKeepAlive) {
                mConn.disconnect();
                mConn = null;
            }
 
            //set time out back to original
            mConn.setSoTimeout(mDefaultTimeout);
            mCurrentTimeout = mDefaultTimeout;
            return resp;
    }
	
	private void checkParams(String dest,String scope,String id)
	{
		NameValuePairs pairs = new NameValuePairs();

		checkParams(dest,scope,id,pairs);
	}

	private void checkParams(String dest,String scope,String id, NameValuePairs pairs)
	{
		boolean bad=false;
		if (dest == null) {
			Debug.println("** WARNING **: 'dest' = null");
			bad = true;
		}
		if (scope == null) {
			Debug.println("** WARNING ** : 'scope' = null");
			bad = true;
		}
		if (id == null) {
			Debug.println("** WARNING ** : 'id' = null");
			bad = true;
		}
		if (pairs == null) {
			Debug.println("** WARNING ** : 'pairs' = null");
			bad = true;
		}
		if (bad) {
			Debug.println("dest = "+dest);
			Debug.println("scope = "+scope);
			Debug.println("id = "+id);
			Debug.println("---------");
		}
	}
}
