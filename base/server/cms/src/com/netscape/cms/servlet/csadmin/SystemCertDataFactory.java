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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.servlet.csadmin;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.netscape.certsrv.system.SystemCertData;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author edewata
 */
public class SystemCertDataFactory {

    public static SystemCertData create(Cert cert) throws Exception {
        SystemCertData data = new SystemCertData();
        data.setNickname(cert.getNickname());

        byte[] binCert = cert.getCert();
        if (binCert != null) {
            data.setCert(CryptoUtil.base64Encode(binCert));
        }

        byte[] binRequest = cert.getRequest();
        if (binRequest != null) {
            String certReqs = CryptoUtil.base64Encode(binRequest);
            String certReqf = CryptoUtil.reqFormat(certReqs);
            data.setRequest(certReqf);
        }

        data.setTag(cert.getCertTag());
        return data;
    }

    public static List<SystemCertData> create(Collection<Cert> certs) throws Exception {
        List<SystemCertData> result = new ArrayList<SystemCertData>();
        for (Cert cert : certs) {
            result.add(create(cert));
        }
        return result;
    }
}
