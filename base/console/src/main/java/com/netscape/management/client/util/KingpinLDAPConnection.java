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

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPRebind;
import netscape.ldap.LDAPRebindAuth;
import netscape.ldap.LDAPSocketFactory;
import netscape.ldap.LDAPv3;

/**
 * The KingpinLDAPConnection is a subclass of LDAPConnection
 * that sets UniversalConnect for socket operations.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2, 12/13/97
 */

class KingpinLDAPRebind implements LDAPRebind {
    private LDAPRebindAuth _RebindInfo;

    public KingpinLDAPRebind (String sDN, String sPW) {
        _RebindInfo = new LDAPRebindAuth(sDN, sPW);
    }

    public LDAPRebindAuth getRebindAuthentication(String host, int port) {
        return _RebindInfo;
    }
}
public class KingpinLDAPConnection extends LDAPConnection {
    KingpinLDAPRebind _rebindInfo;

    /**
     * Extension of LDAPConnection to set Privileges for the applet
     *
     * @param host DS host
     * @param port DS port
     * @param dn user DN
     * @param passwd user password
     * @exception LDAPException on error.
     */
    public void connect(String host, int port) throws LDAPException {
        if (Debug.isTraceTypeEnabled(Debug.TYPE_LDAP)) {
            Debug.println(Debug.TYPE_LDAP,
                "Ldap Connection " + host + ":" + port);
        }
        super.connect(host, port);
    }

    public void connect(String host, int port, String dn,
            String passwd) throws LDAPException {
        /* Applet permissions check disabled -- DT 4/2/98 */
        /*
        	Method m = Permissions.getEnablePrivilegeMethod();

        	if (m != null)
        	{
        		Object[] args = new Object[1];
        		args[0] = "UniversalConnect";

        		try
        		{m.invoke(null, args);} catch (Exception e)
        		{
        			System.err.println("KingpinLDAPConnection:connect():unable to grant standard privileges:" + e);
        		}
        	}
                       */
        if (Debug.isTraceTypeEnabled(Debug.TYPE_LDAP)) {
            Debug.println(Debug.TYPE_LDAP,
                "Ldap Connection " + host + ":" + port + " user=" + dn);
        }
        super.connect(host, port, dn, passwd);
    }

    public void connect(int version, String host, int port, String dn,
            String passwd) throws LDAPException {
        /* Applet permissions check disabled -- DT 4/2/98 */
        /*
        	Method m = Permissions.getEnablePrivilegeMethod();

        	if (m != null)
        	{
        		Object[] args = new Object[1];
        		args[0] = "UniversalConnect";

        		try
        		{m.invoke(null, args);} catch (Exception e)
        		{
        			System.err.println("KingpinLDAPConnection:connect():unable to grant standard privileges:" + e);
        		}
        	}
        	*/
        if (Debug.isTraceTypeEnabled(Debug.TYPE_LDAP)) {
            Debug.println(Debug.TYPE_LDAP,
                "Ldap Connection " + host + ":" + port + " user=" + dn);
        }
        super.connect(version, host, port, dn, passwd);
    }

    public KingpinLDAPConnection(LDAPSocketFactory socketFactory,
            String sBindDN, String sBindPassword) {
        super(socketFactory);
        initialize(sBindDN, sBindPassword);
    }

    public KingpinLDAPConnection(String sBindDN, String sBindPassword) {
        super();
        initialize(sBindDN, sBindPassword);
    }

    void initialize(String sBindDN, String sBindPassword) {
        _rebindInfo = new KingpinLDAPRebind(sBindDN, sBindPassword);
        try {
            setOption(LDAPv3.REFERRALS, Boolean.valueOf(true));
            setOption(LDAPv3.REFERRALS_REBIND_PROC, _rebindInfo);

            if (Debug.isTraceTypeEnabled(Debug.TYPE_LDAP)) {
                setProperty(TRACE_PROPERTY, System.err);
            }
        } catch (LDAPException e) {
            Debug.println(0, "KingpinLDAPConnection: Cannot setup referral option.");
        }
    }
}
