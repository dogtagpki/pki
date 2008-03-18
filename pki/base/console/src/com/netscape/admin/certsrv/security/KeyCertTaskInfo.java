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
package com.netscape.admin.certsrv.security;

import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;

import javax.swing.*;

import java.awt.event.*;
import java.util.*;
import java.io.*;
import java.net.*;

import netscape.ldap.*;

/*-----IMPLEMENTATION-----*/
//need to implementation timer...if server don't response in 30 sec then
//we will pop up a message telling the user that server side cgi
//has not response in a resonable amount of time...and should check
//the server or call the cgi again.

class KeyCertTaskInfo extends Hashtable {

    //need to replace this by useful name later since the name will
    //be map and no need to use real name.
    //So a more descriptive name will probably be more useful.
    public static final String SEC_LSALIAS = "ListAlias"; //"sec-lsalias";
    public static final String SEC_GCRT = "CertRequest"; //""sec-gcrt";
    public static final String SEC_ICRT = "CertInstall"; //"sec-icrt";
    public static final String SEC_MGCRT = "CertListing"; //"sec-mgcrt"
    public static final String SEC_ECRT = "GetCertInfo"; //"sec-ecrt";
    public static final String SEC_TRUST = "CreateTrustDB"; //"sec-trust";
    public static final String SSL_ON_OFF = "SSLActivate"; //"sec-activate"
    public static final String SEC_LSTOKEN = "ListToken"; //"sec-lstoken"
    public static final String SEC_LSMODULE = "ListModule"; //"sec-lsmodule"
    public static final String SEC_MIGRATE = "KeyCertMigration"; //"sec-migrate"
    public static final String SEC_ADDMOD = "AddModule"; //"sec-addmod"
    public static final String SEC_CHANGEPW = "ChangeTrustPW"; //"sec-passwd"
    public static final String SEC_MGCRL = "CRLListing"; //"sec-mgcrl"
    public static final String SEC_ICRL = "CRLInstall"; //"sec-icrl"
    public static final String SEC_ECRL = "GetCRLInfo"; //"sec-ecrl"

    String _URL;
    ConsoleInfo _consoleInfo;

    //contains the last response from the cgi
    Response _response = null;

    private static ResourceSet resource = new ResourceSet("com.netscape.admin.certsrv.security.KeyCertTaskInfoResource");

    //Call's the appropriate cgi and pass in the appropriate arguments
    public Response exec(String operation) throws Exception {
        String operationURL = _URL + operation;

        Debug.println(operationURL + "\n"+this);

        Comm kComm = null;

        try {
            kComm = new Comm(operationURL, this, true);

            kComm.setAuth(_consoleInfo.getAuthenticationDN(),
                    _consoleInfo.getAuthenticationPassword());
            kComm.run();
            if (kComm.getError() instanceof Exception) {
                if (kComm.getError() instanceof InterruptedIOException) {
                    throw (new Exception(
                            resource.getString("KeyCertTaskInfo", "timeoutError")));
                } else if (kComm.getError() instanceof ConnectException) {
                    throw (new Exception(
                            resource.getString("KeyCertTaskInfo", "connectionError")));
                } else if (kComm.getError() instanceof IOException) {
                    throw (new Exception(
                            resource.getString("KeyCertTaskInfo", "ioError")));
                } else {
                    throw kComm.getError();
                }
            }
        } catch (Exception e) {
            throw (new Exception(resource.getString("KeyCertTaskInfo", "serverError")));
        }
        Debug.println(kComm.getData());
        _response = new Response(kComm.getData());

        return (_response);
    }

    public Response getResponse() {
        return _response;
    }

    public KeyCertTaskInfo(ConsoleInfo consoleInfo) {
        super();

        _consoleInfo = consoleInfo;
        _URL = consoleInfo.getAdminURL() + "admin-serv/tasks/configuration/";
    }

}

