/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.util;

import java.io.*;
import java.util.*;
import java.net.*;
import com.netscape.management.client.comm.*;


/**
 * AdmTask is an utility class to execute a task from a Java client to
 * an HTTP CGI back-end.
 *
 * @author  yjh
 * @see CommClient
 */
public class AdmTask extends Object implements CommClient {
    protected String _username;
    protected String _password;
    protected URL _adminURL;
    protected String _adminVersion;
    protected int _error;
    protected boolean _finished = false;
    protected HttpManager _httpManager = new HttpManager();
    protected String _argumentString = null;
    protected Hashtable _arguments = new Hashtable();
    protected Hashtable _response = new Hashtable();
    protected int _timeout; // in seconds
    protected Exception _exception;
    protected StringBuffer _responseString;
    private static ResourceSet i18n = new ResourceSet("com.netscape.management.client.util.default");

    /**
     * Constructor to build a task url
     * @param url the task url
     * @param userID either username or user's DN String
     * @param userPassword password of the users The text for the menu label
     */
    public AdmTask(URL url, String userID, String userPassword) {
        _arguments = new Hashtable();
        _username = userID;
        _password = userPassword;
        _adminURL = url;
    }

    /**
      * Constructor to build a task url
      * @param admProtocol protocol used by the target Admin Server (http/https)
      * @param admServ host name of the target Admin Server
      * @param admPort port number of the target Admin Server
      * @param serverID name of the server which task will apply to
      * @param taskID task name to be executed
      * @param args arguments for the task
      * @param userID either username or user's DN String
      * @param userPassword password of the user
      */
    public AdmTask(String admProtocol, String admServ, int admPort,
            String serverID, String taskID, Vector args,
            String userID, String userPassword) {
        _username = userID;
        _password = userPassword;

        try {
            _adminURL = new URL(admProtocol, admServ, admPort,
                    serverID + "/" + taskID + "?");
        } catch (MalformedURLException e) {
            // TODO: do something here
        }

        Enumeration e = args.elements();
        while (e.hasMoreElements()) {
            AdmTaskArg arg = (AdmTaskArg) e.nextElement();
            if (arg.val() == null)
                _arguments.put(arg.name(), "");
            else
                _arguments.put(arg.name(), arg.val());
        }
    }


    private static String i18n(String id)
    {
        return i18n.getString("admtask", id);
    }

    /**
      * Set the user name of this task.
      *
      * @param sAdmin user name
      */
    public void setUsername(String sAdmin) {
        _username = sAdmin;
    }

    /**
      * Set the user's password of this task.
      *
      * @param sPassword user name
      */
    public void setPassword(String sPassword) {
        _password = sPassword;
    }

    /**
      * Set the response timeout for this task.
      * The default timeout is 30 seconds.
      *
      * @param timeout timeout in seconds
      */
    public void setResponseTimeout(int timeout) {
        _timeout = timeout;
    }

    /**
      * Get the user name of this task.This is really for CommClient interface
      *
      * @return user name
      */
    public String username(Object authObject, CommRecord cr) {
        return _username;
    }

    /**
      * Get the user password of this task. This is really for CommClient
          * interface
      *
      * @return password name
      */
    public String password(Object authObject, CommRecord cr) {
        return _password;
    }


    /**
      * Set arguments from a hashtable.
      * Only key and value in the table will get encoded.
      */
    public void setArguments(Hashtable argumentList) {
        _arguments = argumentList;
    }

    /**
      * Set arguments from a hashtable.
      * String argement WILL NOT get encoded.
      */
    public void setArguments(String arguments) {
        _argumentString = arguments;
    }


    /**
      * Retrieve argument list in the form of a Hashtable.
      */
    public Hashtable getArguments() {
        return _arguments;
    }



    /**
      * Add a new argument to the argument list
      *
      * @param  new argument
      * @return success(0) / Failure(-1)
      */
    public int addArgument(AdmTaskArg arg) {
        Object tmpVal = _arguments.get(arg.name());
        if (tmpVal != null)
            return -1;

        // Add the argument
        if (arg.val() == null)
            _arguments.put(arg.name(), "");
        else
            _arguments.put(arg.name(), arg.val());
        return 0;
    }

    /**
      * Modify the argument value on the exist argument in the argument list
      *
      * @param  desired argument
      * @return success(0) / Failure(-1)
      */
    public int modArgument(AdmTaskArg arg) {
        Object tmpVal = _arguments.get(arg.name());
        if (tmpVal == null)
            return -1;

        // Add the argument
        if (arg.val() == null)
            _arguments.put(arg.name(), "");
        else
            _arguments.put(arg.name(), arg.val());
        return 0;
    }


    /**
      * Delete argument from the argument list
      *
      * @param  targeted argument
      * @return success(0) / Failure(-1)
      */
    public int delArgument(AdmTaskArg arg) {
        // Locate the desired argument
        // remove the entry
        Object tmpVal = _arguments.get(arg.name());
        if (tmpVal != null) {
            _arguments.remove(arg.name());
            return 0;
        } else
            return -1;
    }

    /**
      * Send the request (url) out. You should not try to invoke this function
      * before the response for the previous request is completed.
      *
      * if setArgument(String) is called then exec() WILL NOT encode the string
      * if setArgument(Hashtable) is called then exec() WILL encode ONLY the key
      *    and the value.  for example hashtable[(a, A), (b, B&B), (c , C)] => a=A&b=B%26B&c=C
      */
    public int exec() {
        _responseString = new StringBuffer();
        _finished = false;
        _response.clear();
        _adminVersion = null;
        InputStream data = null;
        try {

            if (_timeout != 0) {
                _httpManager.setResponseTimeout(_timeout *1000);
            }

            if (_argumentString != null)
                data = new ByteArrayInputStream(_argumentString.getBytes());
            else if (!_arguments.isEmpty())
                data = HttpChannel.encode(_arguments);

            // Execute the request
            if (data == null)
                _httpManager.post(_adminURL, this, null, null, 0,
                        CommManager.FORCE_BASIC_AUTH);
            else
                _httpManager.post(_adminURL, this, null, data,
                        data.available(), CommManager.FORCE_BASIC_AUTH);

            waitForFinish();
            return(0);
        } catch (Exception e) {
            Debug.println(""+e);
            _exception = e;
            _error = -1;
            return -1;
        }
    }


    /**
      * Same as exec(), but the request will be sent through given HttpManager.
      *
      * @param htMgr an HttpManager
      */
    public int exec(HttpManager httpManager) {
        _httpManager = httpManager;
        return exec();
    }

    /**
      * Enable debug output.
      */
    public void trace() {
        Debug.setTrace(true);
    }

    /**
      * Wait until finish has been called.
      */
    public synchronized void waitForFinish() {
        while (!_finished) {
            try {
                wait();
            } catch (Exception e) {
                // TODO: do something
            }
        }
    }

    /**
      * When called, notify waiting threads.
      */
    public synchronized void finish() {
        _finished = true;
        notifyAll();
    }


    /**
      * Callback function for httpManager to send response back.
      * If you want to handle the input byte stream yourself, you should
      * override this method.
      *
      * @param response incoming response data stream
      * @param cr hold the command information
      */
    public void replyHandler(InputStream response, CommRecord cr) {
        _error = 0;

        try {
            BufferedReader rspStream = new BufferedReader(
                    new InputStreamReader(response, "UTF8"));
            String rspStr;

            if (_adminVersion == null) {
                HttpChannel channel = (HttpChannel)cr.getChannel();
                if (channel != null) {
                    _adminVersion = channel.getAdminVersion();
                }
            }

            while ((rspStr = rspStream.readLine()) != null) {
                parse(rspStr);
                _responseString.append(rspStr);
                _responseString.append("\n");
            }
        } catch (Exception e) {
            _exception = (Exception) e;
            _error = -1;
            Debug.println("AdmTask.replyHandler: "+e);
        }
        finish();
    }

    /**
      * Callback function for httpManager to send error response back.
      * If you want to handle the error yourself, you should override
      * this method.
      *
      * @param error exception encountered
      * @param cr hold the command information
      */
    public void errorHandler(Exception error, CommRecord cr) {
        _exception = (Exception) error;
        _error = -1;
        finish();
    }

    /**
      * Retrieves the exception encountered.
      *
      * @return  exception encountered
      */
    public Exception getException() {
        return _exception;
    }

    /**
      * This function read in the line of data, parse the data into a list of
      * name value pair, and store it to internal data structure for later
      * retrieval (through getResult); This function and be customized to
      * perform any special parsing function..
      *
      * @param s the input data line to be parsed
      */
    public void parse(String s) {
        String sName;
        String sValue;
        int iIndex;

        //Debug.println("Parse input: " + s);

        if ((iIndex = s.indexOf(":")) != (-1)) {
            sName = s.substring(0, iIndex).trim();
            sValue = s.substring(iIndex + 1).trim();
            if (sName.equalsIgnoreCase("NMC_Status")) {
                _error = Integer.parseInt(sValue);
            } else
                _response.put(sName, sValue);
        }
    }

    /**
      * This function will return the status of the request.
      *
      * @return status of the task execution
      */
    public int getStatus() {
        return _error;
    }


    /**
      * This function will return the requested response argument. This
      * will only happen after the response is completely received and the
      * response stream already parsed into an internal structure.
      *
      * @param name the name of the target information
      * @return requested response argument
      */
    public Object getResult(String name) {
        // retrieve the argument indicated by name
        Object value = _response.get(name);
        if(value == null)
            value = i18n("nomessage");
        return value;
    }

    /**
      * Retrieves a hashtable of name-value pairs.
      *
      * @return a hashtable of name-value pairs
      */
    public Hashtable getResult() {
        return _response;
    }

    /**
      * Retrieves the result string buffer.
      *
      * @return the result string buffer
      */
    public StringBuffer getResultString() {
        return _responseString;
    }

    /**
      * Retrieves the version of the admin server.
      *
      * @return the admin server version
      */
    public String getAdminVersion() {
        return _adminVersion;
    }

    /**
      * This function must be customized when parse is customized, so the
      * status can be set/retrieval consistently.
      *
      * @param status the desired status
      */
    protected void setStatus(int status) {
        //_status = status;
    }


    /**
      * This function can be used to add argument into the internal result
      * data structure.
      *
      * @param arg the new name-value pair information
      */
    protected void addResponseArgument(AdmTaskArg arg) {
        // Add arg into response data structure
        _response.put(arg.name(), arg.val());
    }
}
