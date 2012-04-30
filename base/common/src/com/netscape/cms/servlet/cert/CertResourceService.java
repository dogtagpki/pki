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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.servlet.cert;


import java.security.cert.CertificateEncodingException;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cms.servlet.base.BadRequestException;
import com.netscape.cms.servlet.base.CMSException;
import com.netscape.cms.servlet.base.CMSResourceService;
import com.netscape.cms.servlet.cert.model.CertDAO;
import com.netscape.cms.servlet.cert.model.CertificateData;
import com.netscape.cms.servlet.request.model.CertRetrievalRequestData;

/**
 * @author alee
 *
 */
public class CertResourceService extends CMSResourceService implements CertResource{

    private void validateRequest(CertId id) {

        if (id == null) {
            throw new BadRequestException("Invalid id in CertResourceService.validateRequest.");
        }

    }

    @Override
    public CertificateData retrieveCert(CertId id) {

        validateRequest(id);

        CertRetrievalRequestData data = new CertRetrievalRequestData();
        data.setCertId(id);
        CertDAO dao = new CertDAO();

        CertificateData certData = null;

        try {
            certData = dao.getCert(data);
        }  catch(EDBRecordNotFoundException e) {
            throw new CertNotFoundException(id);
        }  catch (EBaseException e) {
            throw new CMSException("Problem returning certificate: " + id);
        }  catch(CertificateEncodingException e) {
            throw new CMSException("Problem encoding certificate searched for: " + id);
        }

        return certData;

    }
}
