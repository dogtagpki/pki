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
package com.netscape.certsrv.util;

import netscape.ldap.*;
import java.io.*;
import java.net.*;
import javax.servlet.http.*;
import javax.servlet.*;
import java.util.*;
import java.math.*;
import java.util.regex.*;

public class HttpInput
{
   public static int getPortNumberInInt(HttpServletRequest request, String name)
        throws IOException
    {
        String val = request.getParameter(name);
        int p = Integer.parseInt(val);
        return p;
    }
                                                                                
    public static String getBoolean(HttpServletRequest request, String name)
        throws IOException
    {
        String val = request.getParameter(name);
        if (val.equals("true") || val.equals("false")) {
            return val;
        }
        throw new IOException("Invalid boolean value '" + val + "'");
    }

    public static String getCheckbox(HttpServletRequest request, String name)
        throws IOException
    {
        String val = request.getParameter(name);
        if (val == null || val.equals("")) {
            return "off";
        } else if (val.equals("on") || val.equals("off")) {
            return val;
        }
        throw new IOException("Invalid checkbox value '" + val + "'");
    }

    public static String getInteger(HttpServletRequest request, String name)
        throws IOException
    {
        String val = request.getParameter(name);
        int p = 0;
        try {
            p = Integer.parseInt(val);
        } catch (NumberFormatException e) {
            throw new IOException("Input '" + val + "' is not an integer");
        }

        if (!val.equals(Integer.toString(p))) {
            throw new IOException("Input '" + val + "' is not an integer");
        }
        return val;
    }

    public static String getInteger(HttpServletRequest request, String name, 
          int min, int max) throws IOException
    {
        String val = getInteger(request, name);
        int p = Integer.parseInt(val);
        if (p < min || p > max) {
            throw new IOException("Input '" + val + "' is out of range");
        }
        return val;
    }
                                                                                
    public static String getPortNumber(HttpServletRequest request, String name)
        throws IOException
    {
        String v =  getInteger(request, name);         
        return v;
    }
                                                                                
    public static String getString(HttpServletRequest request, String name)
        throws IOException
    {
        String val = request.getParameter(name);
        return val;
    }

    public static String getString(HttpServletRequest request, String name,
            int minlen, int maxlen) throws IOException
    {
        String val = request.getParameter(name);
        if (val.length() < minlen || val.length() > maxlen) {
            throw new IOException("String length of '" + val + 
               "' is out of range");
        }
        return val;
    }
                                                                                
    public static String getLdapDatabase(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }
                                                                                
    public static String getURL(HttpServletRequest request, String name)
        throws IOException
    {
        String v = getString(request, name);
        try {
            URL u = new URL(v);
        } catch (Exception e) {
            throw new IOException("Invalid URL " + v);
        }
        return v;
    }
                                                                                
    public static String getUID(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }
                                                                                
    public static String getPassword(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }

    public static String getKeyType(HttpServletRequest request, String name)
        throws IOException
    {
        String v = getString(request, name);
        if (v.equals("rsa")) {
          return v;
        }
        if (v.equals("ecc")) {
          return v;
        }
        throw new IOException("Invalid key type '" + v + "' not supported.");
    }
                                                                                
    public static String getKeySize(HttpServletRequest request, String name)
        throws IOException
    {
        String i = getInteger(request, name);
        if (i.equals("256") || i.equals("512") || i.equals("1024") ||
           i.equals("2048") || i.equals("4096")) {
          return i;
        }
        throw new IOException("Invalid key length '" + i + "'. Currently supported key lengths are 256, 512, 1024, 2048, 4096.");
    }

    public static String getKeySize(HttpServletRequest request, String name, String keyType)
        throws IOException
    {
        String i = getInteger(request, name);
        if (keyType.equals("rsa")) {
          if (i.equals("256") || i.equals("512") || i.equals("1024") ||
             i.equals("2048") || i.equals("4096")) {
            return i;
          } else {
            throw new IOException("Invalid key length '" + i + "'. Currently supported RSA key lengths are 256, 512, 1024, 2048, 4096.");
          }
        }
        if (keyType.equals("ecc")) {
          int p = 0;
          try {
            p = Integer.parseInt(i);
          } catch (NumberFormatException e) {
            throw new IOException("Input '" + i + "' is not an integer");
          }
          if ((p >= 112) && (p <= 571))
            return i;
          else {
            throw new IOException("Invalid key length '" + i + "'. Please consult your security officer for a proper length, or take the default value. Here are examples of some commonly used key lengths: 256, 384, 521.");
          }
/*

          if (i.equals("256") || i.equals("384") || i.equals("521")) { 
            return i;
          } else {
            throw new IOException("Invalid key length '" + i + "'. Currently supported ECC key lengths are 256, 384, 521.");
          }
*/
        }
        throw new IOException("Invalid key type '" + keyType + "'");
    }
                                                                                
    public static String getDN(HttpServletRequest request, String name)
        throws IOException
    {
        String v = getString(request, name);
        String dn[] = LDAPDN.explodeDN(v, true);
        if (dn == null || dn.length <= 0) {
           throw new IOException("Invalid DN " + v + " in " + name);
        }
        return v;
    }
                                                                                
    public static String getID(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }
                                                                                
    public static String getName(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }
                                                                                
    public static String getCertRequest(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }
                                                                                
    public static String getCertChain(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }
                                                                                
    public static String getCert(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }

    public static String getNickname(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }
                                                                                
    public static String getHostname(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }
                                                                                
    public static String getTokenName(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }

    public static String getReplicationAgreementName(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }
                                                                                
    public static String getEmail(HttpServletRequest request, String name)
        throws IOException
    {
        String v = getString(request, name);
        if (v.indexOf('@') == -1) {
           throw new IOException("Invalid email " + v);
        }
        return v;
    }
                                                                                
    public static String getDomainName(HttpServletRequest request, String name)
        throws IOException
    {
        return getString(request, name);
    }
                                                                                
    public static String getSecurityDomainName(HttpServletRequest request, String name)       
        throws IOException
    {
        String v = getName(request, name);
        Pattern p = Pattern.compile("[A-Za-z0-9]+[A-Za-z0-9 -]*");
        Matcher m = p.matcher(v);
        if (!m.matches()) {
            throw new IOException("Invalid characters found in Security Domain Name " + v + ". Valid characters are A-Z, a-z, 0-9, dash and space");
        }
        return v;
    }
}
