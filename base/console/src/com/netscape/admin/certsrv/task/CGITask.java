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
package com.netscape.admin.certsrv.task;

import com.netscape.admin.certsrv.*;
import java.util.*;
import java.io.*;
import java.net.URL;
import javax.swing.JFrame;
import com.netscape.management.client.TaskObject;
import com.netscape.management.client.IPage;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.comm.*;
import com.netscape.management.client.util.*;

/**
 *	Netscape Certificate Server 4.0 CGI base task
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class CGITask extends CMSTaskObject
    implements CommClient
{

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "CGITASK";

	protected boolean mFinished = false;
	protected String mCmd = null;
	protected String mAdminURL = null;
	protected boolean mSuccess = false;
	private String mReply = null;
	protected String mSection = "";
    protected String mErrorMsg = "";
    protected String mWarnMsg = "";

	private   boolean mForceBasicAuth = false;

	/*==========================================================
     * constructors
     *==========================================================*/
    public CGITask() {
        super();
	}

    /*==========================================================
	 * public methods
     *==========================================================*/

	/**
	 *  Force the operation to complete with basic auth, instead
	 *  of the default option, which is to first try a non
	 *  authenticated request, then an authenticated one.
	 */

	public void setForceBasicAuth(boolean value) {
		mForceBasicAuth = value;
	}

	/**
	 * Send an http request to the server and then popup a dialog if the
	 * operation is successful.
	 *
	 * @param viewInstance The calling page
	 */
	public boolean run(IPage viewInstance) {
		if ( mCmd == null ) {
			Debug.println( "Could not get execref for " + getDN() );
			return false;
		}

		return run( viewInstance, mCmd );
	}

	/**
	 * Send an http request to the server. Return true if we're sure it
	 * succeeded, otherwise false.
	 *
	 * @param viewInstance The calling page
	 * @param cmd Command to execute
	 */
	boolean run(IPage viewInstance, String cmd) {

		// get the admin URL location first
		mAdminURL = _consoleInfo.getAdminURL();
		if ( mAdminURL == null ) {
			Debug.println( "Could not get adminURL for " + getDN() );
			return false;
		}

		// Allow specifying e.g. "slapd-install" for instance
		String instance = (String)_consoleInfo.get( cmd );

		if ( instance == null )
			instance = (String)_consoleInfo.get( "ServerInstance" );
		String fullCmd = mAdminURL + instance + "/" + cmd;

		HttpManager h = new HttpManager();
		// tell the http manager to use UTF8 encoding
		h.setResponseTimeout(60000);
		h.setSendUTF8(true);

		try {
			mSuccess = false;
			mFinished = false;

			// _consoleInfo.get("arguments") is a hashtable of key/value pairs
			// to use as the arguments to the CGI
			Hashtable args = (Hashtable)_consoleInfo.get("arguments");
			ByteArrayInputStream data = null;
			if (args != null && !args.isEmpty())
				data = encode(args);
			Debug.println( "Posting " + fullCmd );
			// tell the http manager to notify us immediately of replies
			// if we're using async mode
			int flags = 0;

			if (mForceBasicAuth) {
				flags |= CommManager.FORCE_BASIC_AUTH;
			}

			if (data == null)
				h.post(new URL(fullCmd), this, null, null, 0,
					   flags);
			else
				h.post(new URL(fullCmd), this, null, data, data.available(),
					   flags);
			awaitSuccess();
			Debug.println( "Command executed: " + fullCmd );
		} catch (Exception e) {
			if ( e instanceof java.net.ConnectException ) {
				CMSAdminUtil.showMessageDialog(mResource,
                        PREFIX, "SERVERDOWN", CMSAdminUtil.ERROR_MESSAGE);
			}
			Debug.println( "Command " + fullCmd  + " failed: " + e );
		}
		return mSuccess;
	}

	/**
	 *	waiting for the http transaction to be finished.
	 */
   public synchronized void awaitSuccess() {
      while (!mFinished) {
		  try {wait();}
		  catch (Exception e) { }
      }
   }

	/**
	 *	http transaction finished, notify the process
	 */
    public synchronized void finish() {
		mFinished = true;
		notifyAll();
	}

	/**
	 *	the operation is finished after we receive the http stream
	 */
    public void replyHandler(InputStream response, CommRecord cr) {
/*
		try {
			int nBytes = response.available();
			if ( nBytes > 0 ) {
				// the response from the DS CGIs will typically be in
				// UTF8 encoding
				byte[] data = new byte[nBytes];
				nBytes = response.read( data );
				mReply = new String( data, 0, nBytes, "UTF8" );
				Debug.println( "CGITask.replyHandler: Response (" + nBytes +
							   " bytes) = " + mReply );
				int index = 0;
				if ((mReply.indexOf("NMC_") != -1) &&
					((index = mReply.indexOf(":")) != -1)) {
					String sName = mReply.substring(0, index).trim();
					String sValue = mReply.substring(index+1).trim();
					if (sName.equalsIgnoreCase("NMC_Status")) {
						int code = Integer.parseInt(sValue);
						mSuccess = (code == 0);
					} else if (sName.equalsIgnoreCase("NMC_ERRINFO")) {
                        mErrorMsg = sValue;
					} else if (sName.equalsIgnoreCase("NMC_WARNINFO")) {
                        mWarnMsg = sValue;
                    }
				}
			}
		} catch ( Exception e ) {
			Debug.println( "CGITask.replyHandler: " + e.toString() );
            mSuccess = false;
		}
		finish();
*/

        try {
            BufferedReader rspStream =
                new BufferedReader(new InputStreamReader(response, "UTF8"));
            String rspStr;

            Debug.println("replyHandler() - start");
            while ((rspStr = rspStream.readLine()) != null)
            {
                Debug.println("replyHandler() - read [" + rspStr + "]");
                // NMC_ messages are parsed, but not shown to the user
                /*
                if (_statusText != null && !rspStr.startsWith("NMC_")) {
                    _statusText.append(rspStr + "\n");
                    Thread.yield(); // allow graphics repaints
                }
                */
                Debug.println("Start parsing");
                parse(rspStr);
            }
        } catch (Exception e) {
            Debug.println("ConfigCert.Exception : " + e.toString());
        }

        Debug.println("ConfigCert.replyHandler: finished, mSuccess=" +
                      mSuccess);

        finish();
	}

    /**
     * return the value for the given keyword in the reply
     */
    private void parse(String s) {
        String sName;
        String sValue;
        int iIndex;

        Debug.println("Parse input: " + s);

        if ((iIndex=s.indexOf(":")) != (-1))
        {
            sName = s.substring(0, iIndex).trim();
            sValue = s.substring(iIndex+1).trim();
            Debug.println("Parse input: name=" + sName + " value=" + sValue);
            //mWizardInfo.put(sName, sValue);
/*
            if (mCgiResponse == null)
                mCgiResponse = new Hashtable();
            mCgiResponse.put(sName, sValue);
*/
            if (sName.equalsIgnoreCase("NMC_Status"))
            {
                int code = Integer.parseInt(sValue);
                mSuccess = (code == 0);
                Debug.println("Parse input: code=" + code + " mSuccess=" +
                  mSuccess);
            } else if (sName.equalsIgnoreCase("NMC_ERRINFO")) {
                mErrorMsg = sValue;
            } else if (sName.equalsIgnoreCase("NMC_WARNINFO")) {
                mWarnMsg = sValue;
            }
        }

        Debug.println("Parse finished");
    }

    public String getErrorMessage() {
        return mErrorMsg;
    }

	/**
	 *	this function will be called if error occurs
	 */
    public void errorHandler(Exception error, CommRecord cr) {
		Debug.println("CGITask.errorHandler: " + error );

        mSuccess = false;
		finish();
	}


    public String getDN() {
		return _consoleInfo.getCurrentDN();
	}

    public String getReply() {
		return mReply;
	}

	/**
	 *	Return the command, which should have been stored in the info.
	 */
	private String getCommand() {
		String s = (String)_consoleInfo.get( "execref" );
		if ( s != null )
			return "bin/" + s;
		return null;
	}

	/**
	 *	pass the username to the admin server
	 */
	public String username(Object authObject, CommRecord cr) {
		Debug.println( "username = " +
		    (String)_consoleInfo.getAuthenticationDN());
        return _consoleInfo.getAuthenticationDN();
	}

	/**
	 *	pass the user password to the admin server
	 */
	public String password(Object authObject, CommRecord cr) {
		Debug.println( "password = " +
					   (String)_consoleInfo.get( "AdminUserPassword" ) );
		return (String)_consoleInfo.get( "AdminUserPassword" );
	}

/*
    protected void showDialog( JFrame frame, String msg, String item,
							 boolean error  ) {
		// display a message
		if ( error ) {
			DSUtil.showErrorDialog( frame, msg, item, "dirtask" );
		} else {
			DSUtil.showInformationDialog( frame, msg, item, "dirtask" );
		}
	}

    protected void showResultDialog( boolean success ) {
		// popup a dialog
		if ( success ) {
			showDialog( new JFrame(), mSection+"-success", "",
						false );
		} else {
			showDialog( new JFrame(), mSection+"-failed", "",
						true );
		}
	}

    protected void showResultDialog( int errorCode, String arg ) {
		// popup a dialog
		String error = "error-" + Integer.toString( errorCode ) + "-msg";
		String title = mSection + "-failed-title";
		DSUtil.showErrorDialog( null,
								title,
								error,
								arg, "dirtask" );
	}

    protected void showResultDialog( CGIThread thread ) {
		CGIReportTask task = thread.getTask();
		if ( task.getStatus() != 0 ) {
			showResultDialog( task.getStatus(),
							  (String)task.getResult("NMC_ErrInfo") );
		} else {
			showResultDialog( task.getStatus() == 0 );
		}
	}
	*/

   /**
    * Translates a hashtable into <code>x-www-form-urlencoded</code> format.
	* Values are converted from Unicode to UTF8 before URL encoding.
    *
    * @param   args   <code>Hashtable</code> containing name/value pairs to be translated.
    * @return  a ByteArrayInputStream to the translated <code>Hashtable</code> contents.
    */
   public static ByteArrayInputStream encode(Hashtable args)
   {
      if ((args == null) || (args.size() == 0))
         return (null);

      String      p = "";
      Enumeration e = args.keys();

      while (e.hasMoreElements())
      {
         String name  = (String)e.nextElement();
         String value = URLByteEncoder.encodeUTF8(args.get(name).toString());
         Debug.println("********** Encoding name --> "+name+" value --> "+value);
         p += URLByteEncoder.encodeUTF8(name) + "=" +
			 value + (e.hasMoreElements()?"&":"");
      }

      return new ByteArrayInputStream(p.getBytes());
   }

}
