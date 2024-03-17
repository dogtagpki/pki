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
package com.netscape.management.client.security;

import java.util.*;
import java.io.*;
import java.awt.*;
import javax.swing.*;
//import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.components.*;
import com.netscape.management.client.util.*;


class SecurityUtil {


    static ResourceSet _resource = null;
    public static ResourceSet getResourceSet() {
        if (_resource == null) {
            _resource = new ResourceSet("com.netscape.management.client.security.securityResource");
        }

        return _resource;
    }

    public static boolean showError(AdmTask admTask) {
	return showError(null, "", admTask);
    }

    public static boolean showError(Frame parent, AdmTask admTask) {
	return showError(parent, "", admTask);
    }

    public static boolean showError(Frame parent, String where, AdmTask admTask) {
	boolean errorDialogShown = false;

	Debug.println(where);

	if (parent == null) {
		parent = UtilConsoleGlobals.getActivatedFrame();
	}
    
	if (admTask.getStatus() != 0) {

	    ErrorDialog errorDialog; 

	    if (admTask.getException() != null) {
		errorDialog = new ErrorDialog(parent,
					      getResourceSet().getString("", "connectionError"),
					      (String)(admTask.getException().toString()));

	    } else {
		Object errType   = admTask.getResult("NMC_ErrType");
		Object errInfo   = admTask.getResult("NMC_ErrInfo");
		Object errDetail = admTask.getResult("NMC_ErrDetail");

		String extraErrInfo = extractExtraErrInfo(admTask.getResultString().toString());
        
		String detail = (errDetail == null) ? extraErrInfo : 
		                (errDetail.toString() + "\n\n" + extraErrInfo);
        
		errorDialog = new ErrorDialog(parent,
					      errType==null?"":errType.toString(),
					      errInfo==null?errType.toString():errInfo.toString(),
					      null,
					      detail,
					      ErrorDialog.OK, ErrorDialog.OK);
	    }
	    errorDialog.show();

	    errorDialogShown = true;
	}

	return errorDialogShown;
    }

    /**
     * In certain cases when working with external PK11 modules or utility
     * commands, (modutil) an external library or program can send error or
     * status message directly to stderr or stdout. This method will capture
     * that extra info by filtering well-known strings from the CGI output.
     */
    static String extractExtraErrInfo(String result) {
        BufferedReader inBuf = new BufferedReader(new InputStreamReader(
                               new ByteArrayInputStream(result.getBytes())));

        StringBuffer extraInfo = new StringBuffer("");

        try {
            String line;
            while ((line = inBuf.readLine()) != null) {
                String varName;
                int idx;

                line.trim();                
                if (line.length() == 0) {
                    continue; // skip empty lines
                }

                if (line.startsWith("<") && line.endsWith(">")) {
                    continue; // skip XLM CGI output
                }
                
                if ((idx = line.indexOf(":")) < 0) {
                    // append the line
                    if (extraInfo.length() > 0) {
                        extraInfo.append('\n');
                    }
                    extraInfo.append(line);
                    continue;
                }

                varName = line.substring(0, idx).trim();

                if (varName.equalsIgnoreCase("Content-type")) {
                    continue; // skip the line
                }
                if (varName.toUpperCase().startsWith("NMC_")) {
                    continue; // skip the line
                }
                else if (varName.toUpperCase().startsWith("SEC_")) {
                    continue; // skip the line
                }                

                // apend the line
                if (extraInfo.length() > 0) {
                    extraInfo.append('\n');
                }                    
                extraInfo.append(line);
            }
        } catch (Exception e) {}

        return extraInfo.toString();
    }

    public static void printException(String where, Exception e) {
	if (Debug.getTrace()) {
	    System.out.println(where);
	    e.printStackTrace();
	}

    }
    
    /**
     * Execute a security CGI operation with a dynamic respose to a token
     * password input request. A password input request is recognized by security
     * CGI returning extra parameters SEC_Token and SEC_Error. SEC_Error should
     * be NO_PASSWORD or INVALID_PASSWORD. 
     * 
     * Returns true if CGI was executed, false if password input was canceled.
     * 
     */
    static boolean execWithPwdInput(AdmTask admTask, Hashtable args, Hashtable pwdCache) {
        
        PromptTokenPasswordDialog pwdDialog=null;        
        boolean needLogin=false;
        String loginToken=null;
        String secError = null;

        while (true) {

            if (needLogin) {

                if (pwdDialog == null) {
                    JFrame f = UtilConsoleGlobals.getActivatedFrame();
                    pwdDialog = new PromptTokenPasswordDialog(f, "");
                }                    
                pwdDialog.setPassword("");
                pwdDialog.setToken(loginToken);
                pwdDialog.setVisible(true);
                String pwd = pwdDialog.getPassword();
                if (pwd!=null && pwd.length() > 0) {
                    args.put(loginToken + ".keypwd", pwd);
                    if (pwdCache != null) {
                        pwdCache.put(loginToken + ".keypwd", pwd);
                    }
                }
                else {                        
                    return false; // Password input aborted
                }
            }

            admTask.setArguments(args);
            admTask.exec();
                
            Debug.println(admTask.getResultString().toString());

            if (admTask.getStatus() == 0) {
                return true; // CGI compeleted with no error
            }
            else {
                Hashtable response = admTask.getResult();
                secError   = (String)response.get("SEC_Error");
                loginToken = (String)response.get("SEC_Token");
                    
                if (secError == null || loginToken == null) {
                    return true; // CGI completed with a non-password related error
                }
                    
                // Only if secError is Password related we continue
                if ("NO_PASSWORD".equalsIgnoreCase(secError)) {
                    needLogin = true;
                }
                else if ("INVALID_PASSWORD".equalsIgnoreCase(secError)) {
                    SecurityUtil.showError(admTask);
                    if (pwdCache != null) {
                        pwdCache.remove(loginToken + ".keypwd");
                    }
                    needLogin = true;
                }
                else {
                    return true; // CGI completed with a non-password related error
                }                    
            }
        }
    }
}
