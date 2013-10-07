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
package com.netscape.cms.servlet.request;

import java.math.BigInteger;
import java.util.Locale;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.key.KeyRecordParser;

/**
 * Output a 'pretty print' of a Key Archival request
 *
 * @version $Revision$, $Date$
 */
public class KeyReqParser extends ReqParser {

    public static final KeyReqParser PARSER = new KeyReqParser();
    public static final String OUTPUT_SERIALNO = "serialNumber";

    /**
     * Constructs a certificate request parser.
     */
    public KeyReqParser() {
    }

    /**
     * Fills in certificate specific request attributes.
     */
    public void fillRequestIntoArg(Locale l, IRequest req, CMSTemplateParams argSet, IArgBlock arg)
            throws EBaseException {
        // fill in the standard attributes
        super.fillRequestIntoArg(l, req, argSet, arg);

        String type = req.getRequestType();

        if (type.equals(IRequest.ENROLLMENT_REQUEST)) {
            BigInteger recSerialNo = req.getExtDataInBigInteger("keyRecord");
            IKeyRecoveryAuthority kra = (IKeyRecoveryAuthority) CMS.getSubsystem("kra");
            if (kra != null) {
                KeyRecordParser.fillRecordIntoArg(
                        kra.getKeyRepository().readKeyRecord(recSerialNo),
                        arg);
            } else {
                throw new EBaseException("KRA is not available");
            }

        } else if (type.equals(IRequest.KEYRECOVERY_REQUEST)) {
            BigInteger kid = req.getExtDataInBigInteger("serialNumber");

            arg.addStringValue(OUTPUT_SERIALNO, kid.toString());

            // for async recovery
            String agents = req.getExtDataInString("approvingAgents");
            arg.addStringValue("approvingAgents", agents);
        } else {
            System.out.println("Bad Request " + type);
            // invalid request
        }
    }
}
