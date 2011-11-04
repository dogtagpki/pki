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
package com.netscape.cmstools;


import java.util.Enumeration;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.pkcs11.PK11Module;



/**
 * Tool used to determine which external hardware tokens are visible to the
 * Certificate System subsystem. This can be used to diagnose whether problems
 * using tokens are related to the Certificate System being unable to detect it.
 *
 * <p>
 * @version $Revision$ Date: $
 */
public class TokenInfo {
    
    /**
     *  Creates a new instance of CMCRevoke.
     */
    public static void main(String[]args) {
        try {
           if (args.length != 1) {
             System.out.println("Usage: TokenInfo <alias directory>");
             System.exit(0);
           }
           System.out.println("Database Path: " + args[0]);

                CryptoManager.InitializationValues vals = 
                   new CryptoManager.InitializationValues(args[0], 
                   "", "", "secmod.db");

                CryptoManager.initialize(vals);
                
                CryptoManager cm = CryptoManager.getInstance();
                Enumeration modules = cm.getModules();
                while (modules.hasMoreElements()) {
                    PK11Module m = (PK11Module)modules.nextElement();
                    System.out.println("Found external module '" + m.getName() + "'");
                }
                Enumeration tokens = cm.getExternalTokens();

                while (tokens.hasMoreElements()) {
                    CryptoToken t = (CryptoToken)tokens.nextElement();
                    System.out.println("Found external token '" + t.getName() + "'");
                }

            }catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }
            
    }
}
