//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2017 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---

package org.dogtagpki.common;

import org.mozilla.jss.crypto.KeyWrapAlgorithm;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Ade Lee
 */
public class CAInfoClient extends Client {

    public CAInfoClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "v2", "info");
    }

    public CAInfo getInfo() throws Exception {
        return get(CAInfo.class);
    }

    public String getKeyWrapAlgotihm() throws Exception {

        String archivalMechanism = KRAInfoResource.KEYWRAP_MECHANISM;
        String kwAlg = null;

        try {
            CAInfo info = getInfo();
            archivalMechanism = info.getArchivalMechanism();
            kwAlg = info.getKeyWrapAlgorithm();

        } catch (PKIException e) {
            if (e.getCode() == 404) {
                // assume this is an older server
                archivalMechanism = KRAInfoResource.KEYWRAP_MECHANISM;
                kwAlg = KeyWrapAlgorithm.DES3_CBC_PAD.toString();

            } else {
                throw new Exception("Failed to retrieve archive wrapping information from the CA: " + e, e);
            }

        } catch (Exception e) {
            throw new Exception("Failed to retrieve archive wrapping information from the CA: " + e, e);
        }

        if (!archivalMechanism.equals(KRAInfoResource.KEYWRAP_MECHANISM)) {
            // new server with encryption set.  Use something we know will
            // work.  AES-128-CBC
            kwAlg = KeyWrapAlgorithm.AES_CBC_PAD.toString();
        }

        return kwAlg;
    }
}

