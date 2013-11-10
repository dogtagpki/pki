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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.cert;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.server.tps.TPSSubsystem;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.tps.cert.TPSCertCollection;
import com.netscape.certsrv.tps.cert.TPSCertData;
import com.netscape.certsrv.tps.cert.TPSCertResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class TPSCertService extends PKIService implements TPSCertResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public final static int DEFAULT_SIZE = 20;

    public TPSCertService() {
        System.out.println("TPSCertService.<init>()");
    }

    public TPSCertData createCertData(TPSCertRecord certRecord) {

        TPSCertData certData = new TPSCertData();
        certData.setID(certRecord.getId());
        certData.setSerialNumber(certRecord.getSerialNumber());
        certData.setSubject(certRecord.getSubject());
        certData.setTokenID(certRecord.getTokenID());
        certData.setKeyType(certRecord.getKeyType());
        certData.setStatus(certRecord.getStatus());
        certData.setUserID(certRecord.getUserID());
        certData.setCreateTime(certRecord.getCreateTime());
        certData.setModifyTime(certRecord.getModifyTime());

        String certID = certRecord.getId();
        try {
            certID = URLEncoder.encode(certID, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }

        URI uri = uriInfo.getBaseUriBuilder().path(TPSCertResource.class).path("{certID}").build(certID);
        certData.setLink(new Link("self", uri));

        return certData;
    }

    public TPSCertRecord createCertRecord(TPSCertData certData) {

        TPSCertRecord certRecord = new TPSCertRecord();
        certRecord.setId(certData.getID());
        certRecord.setSerialNumber(certData.getSerialNumber());
        certRecord.setSubject(certData.getSubject());
        certRecord.setTokenID(certData.getTokenID());
        certRecord.setKeyType(certData.getKeyType());
        certRecord.setStatus(certData.getStatus());
        certRecord.setUserID(certData.getUserID());
        certRecord.setCreateTime(certData.getCreateTime());
        certRecord.setModifyTime(certData.getModifyTime());

        return certRecord;
    }

    @Override
    public TPSCertCollection findCerts(Integer start, Integer size) {

        System.out.println("TPSCertService.findCerts()");

        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            TPSCertDatabase database = subsystem.getCertDatabase();

            Iterator<TPSCertRecord> activities = database.getRecords().iterator();

            TPSCertCollection response = new TPSCertCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && activities.hasNext(); i++) activities.next();

            // return entries up to the page size
            for ( ; i<start+size && activities.hasNext(); i++) {
                response.addEntry(createCertData(activities.next()));
            }

            // count the total entries
            for ( ; activities.hasNext(); i++) activities.next();
            response.setTotal(i);

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return response;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public TPSCertData getCert(String certID) {

        if (certID == null) throw new BadRequestException("Certificate ID is null.");

        System.out.println("TPSCertService.getCert(\"" + certID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            TPSCertDatabase database = subsystem.getCertDatabase();

            return createCertData(database.getRecord(certID));

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
