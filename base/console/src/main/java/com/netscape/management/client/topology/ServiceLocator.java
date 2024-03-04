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
package com.netscape.management.client.topology;

import java.util.*;
import netscape.ldap.*;
import netscape.ldap.controls.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;

/**
 * The service locator is used to search through the directory server to find all the netscape
 * related products.
 */

public class ServiceLocator {
    LDAPConnection _ldc;
    ConsoleInfo _consoleInfo;
    LDAPSortControl _control;
    LDAPSearchConstraints _cons;

    /**
     * constructor to set up ldap search information
     *
     * @param info global information
     */
    public ServiceLocator(ConsoleInfo info) {
        _consoleInfo = info;
        _control = new LDAPSortControl(new LDAPSortKey("cn"), false);
        _ldc = info.getLDAPConnection();
        _cons = (LDAPSearchConstraints)_ldc.getSearchConstraints().clone();
        _cons.setServerControls(_control);
        _cons.setBatchSize(1);
        _cons.setMaxResults(0); // no limit, default is 1000
    }

    /**
      * get the ldap connection
      *
      * @param ldap connection
      */
    public LDAPConnection getConnection() {
        return _ldc;
    }

    /**
      *	return the host count in DS using vlists
      */
    public int getHostCount(String sDN) {
        int size = -1;
        LDAPControl[] controls = new LDAPControl[2];
        LDAPSearchResults result = null;

        // Paged results also require a sort control
        controls[0] = new LDAPSortControl(new LDAPSortKey("serverhostname"),
                true);

        // Vlist control
        controls[1] = new LDAPVirtualListControl(/*StartIndex=*/0,
                /*beforeCount=*/ 0, /*afterCount=*/ 0, /*contentCount=*/0);

        try {
            if (_ldc != null) {
                LDAPSearchConstraints vlistCons = (LDAPSearchConstraints)
                        _ldc.getSearchConstraints().clone();
                vlistCons.setBatchSize(0); // synch deliver all results at the same time
                vlistCons.setServerControls(controls);

                if (LDAPUtil.isVersion4(_ldc)) {
                    result = _ldc.search(sDN, LDAPConnection.SCOPE_SUB,
                            "(Objectclass=NsHost)", null, false, vlistCons);

                    // Response controls are at the end of data stream. Need this to clean the stream
                    while (result.hasMoreElements()) {
                        result.next();
                    }

                    controls = _ldc.getResponseControls();
                    LDAPVirtualListResponse response =
                            LDAPVirtualListResponse.parseResponse(
                            controls);

                    if (response == null) {
                        Debug.println("LDAPVirtualListResponse.parseResponse(controls)== null !");
                    }
                    size = (response != null) ?
                            response.getContentCount() : - 1;
                } else {
                    // don't do the search if it is DS 3x
                    size = -1;
                }
            }
        } catch (Exception e) {
            Debug.println("getHostCount() failed: "+e);
            return -1;
        }
        return size;
    }

    /**
      * get all the available domains
      *
      * @return a list of available domains
      */
    public Enumeration getDomains() {
        String[] cnAttr = {"ou"};
        LDAPSearchResults result = null;

        try {
            if (_ldc != null) {
                result = _ldc.search("o=NetscapeRoot",
                        LDAPConnection.SCOPE_ONE, "(Objectclass=nsAdminDomain)",
                        cnAttr, false, _cons);
            }
        } catch (LDAPException e) {
            Debug.println("ServiceLocator (getDomain): Cannot connect to: "+
                    _consoleInfo.getHost() + " "+
                    _consoleInfo.getAuthenticationDN());
        }
        return result;
    }

    /**
      *	return a list of machine which has netscape service installed
      */

    static String[]_hostAttrNames = {"serverhostname"};

    /**
     * get all the available hosts under the specified domain
     *
     * @param sDN dn of hosts
     * @return a list of available hosts
     */
    public Enumeration getHosts(String sDN) {
        LDAPSearchResults result = null;

        try {
            if (_ldc != null) {
                // Do not retrieve the whole entry, we need only the name during discovery.
                // This is important for scalability reasons.
                result = _ldc.search(sDN/*_consoleInfo.getBaseDN()*/,
                        LDAPConnection.SCOPE_SUB, "(Objectclass=NsHost)",
                        /*null,*/ _hostAttrNames, false, _cons);
            }

        } catch (LDAPException e) {
            Debug.println("ServiceLocator:getHosts: Cannot connect to: "+
                    _consoleInfo.getHost() + " "+
                    _consoleInfo.getAuthenticationDN());
        }
        return result;
    }

    /**
      * get all the available admin group under the specified hosts
      *
      * @param sDN dn of the admin group
      * @return a list of available admin group
      */
    public Enumeration getAdminGroup(String sDN) {
        LDAPSearchResults result = null;

        try {
            if (_ldc != null) {
                result =
                        _ldc.search(sDN, LDAPConnection.SCOPE_ONE, "(Objectclass=nsAdminGroup)",
                        null, false, _cons);
            }
        } catch (LDAPException e) {
            Debug.println("ServiceLocator:getAdminGroup: Cannot connect to: "+
                    _consoleInfo.getHost() + " "+
                    _consoleInfo.getAuthenticationDN() + " "+
                    _consoleInfo.getAuthenticationPassword());
        }

        return result;
    }

    /**
      * get the admin server under the specified DN
      *
      * @param sDN dn of the admin group
      * @return DN of the admin server.
      */
    public String getAdminServer(String sDN) {
        String sReturn = null;

        try {
            if (_ldc != null) {
                String getAttrs[] = {"nsAdminSIEDN"};
                LDAPEntry entry = _ldc.read(sDN, getAttrs);

                LDAPAttributeSet attrSet = entry.getAttributeSet();
                LDAPAttribute attr = attrSet.getAttribute("nsAdminSIEDN");
                sReturn = LDAPUtil.flatting(attr);
            }
        } catch (LDAPException e) {
            Debug.println("ServiceLocator:getAdminServer: Cannot connect to: "+
                    _consoleInfo.getHost() + " "+
                    _consoleInfo.getAuthenticationDN() + " "+
                    _consoleInfo.getAuthenticationPassword());
        }
        return sReturn;
    }

    /**
      * get a list of product type under the given DN
      *
      * @param sDN DN of the admin group
      * @return list of product type
      */
    public Enumeration getProductType(String sDN) {
        LDAPSearchResults result = null;

        try {
            if (_ldc != null) {
                result =
                        _ldc.search(sDN, LDAPConnection.SCOPE_ONE, "(Objectclass=nsApplication)",
                        null, false, _cons);
            }
        } catch (LDAPException e) {
            Debug.println("ServiceLocator:getProductType: Cannot connect to: "+
                    _consoleInfo.getHost() + " "+
                    _consoleInfo.getAuthenticationDN() + " "+
                    _consoleInfo.getAuthenticationPassword());
        }
        return result;
    }

    /**
      * get a list of Server Instance Entry under the product type
      *
      * @param sDN DN of product type
      * @return list of server SIE
      */
    public LDAPSearchResults getSIE(String sDN) {
        boolean fFound;

        LDAPSearchResults eReturn = null;

        try {
            if (_ldc != null) {
                eReturn =
                        _ldc.search(sDN, LDAPConnection.SCOPE_ONE, "(Objectclass=netscapeServer)",
                        null, false, _cons);
            }
        } catch (LDAPException e) {
            Debug.println("ServiceLocator:getSIE: Cannot connect to: "+
                    _consoleInfo.getHost() + " "+
                    _consoleInfo.getAuthenticationDN() + " "+
                    _consoleInfo.getAuthenticationPassword() + " "+sDN);
        }
        return eReturn;
    }

    /**
      * get the console info entry
      *
      * @return console info
      */
    public ConsoleInfo getConsoleInfo() {
        return _consoleInfo;
    }
}
