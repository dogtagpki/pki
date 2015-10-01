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
//(C) 2015 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.ca.rest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.authority.AuthorityResource;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CAEnabledException;
import com.netscape.certsrv.ca.CADisabledException;
import com.netscape.certsrv.ca.CANotFoundException;
import com.netscape.certsrv.ca.CANotLeafException;
import com.netscape.certsrv.ca.CATypeException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.ca.IssuerUnavailableException;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmsutil.util.Utils;

/**
 * @author ftweedal
 */
public class AuthorityService extends PKIService implements AuthorityResource {

    ICertificateAuthority hostCA;

    public AuthorityService() {
        hostCA = (ICertificateAuthority) CMS.getSubsystem("ca");
    }

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    /*
    private final static String LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL =
            "LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL_4";
    private final static String LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE =
            "LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE_3";
    */

    @Override
    public Response listCAs() {
        List<AuthorityData> results = new ArrayList<>();
        for (ICertificateAuthority ca : hostCA.getCAs())
            results.add(readAuthorityData(ca));

        GenericEntity<List<AuthorityData>> entity =
            new GenericEntity<List<AuthorityData>>(results) {};
        return Response.ok(entity).build();
    }

    @Override
    public Response getCA(String aidString) {
        ICertificateAuthority ca = hostCA;

        if (!AuthorityResource.HOST_AUTHORITY.equals(aidString)) {
            AuthorityID aid;
            try {
                aid = new AuthorityID(aidString);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Bad AuthorityID: " + aidString);
            }

            ca = hostCA.getCA(aid);
            if (ca == null)
                throw new ResourceNotFoundException("CA \"" + aidString + "\" not found");
        }

        return createOKResponse(readAuthorityData(ca));
    }

    @Override
    public Response getCert(String aidString) {
        AuthorityID aid;
        try {
            aid = new AuthorityID(aidString);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Bad AuthorityID: " + aidString);
        }

        ICertificateAuthority ca = hostCA.getCA(aid);
        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + aidString + "\" not found");

        try {
            return Response.ok(ca.getCaX509Cert().getEncoded()).build();
        } catch (CertificateEncodingException e) {
            // this really is a 500 Internal Server Error
            throw new PKIException("Error encoding certificate: " + e);
        }
    }

    @Override
    public Response getCertPEM(String aidString) {
        byte[] der = (byte[]) getCert(aidString).getEntity();
        return Response.ok(toPem("CERTIFICATE", der)).build();
    }

    @Override
    public Response getChain(String aidString) {
        AuthorityID aid;
        try {
            aid = new AuthorityID(aidString);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Bad AuthorityID: " + aidString);
        }

        ICertificateAuthority ca = hostCA.getCA(aid);
        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + aidString + "\" not found");

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            ca.getCACertChain().encode(out);
        } catch (IOException e) {
            throw new PKIException("Error encoding certificate chain: " + e);
        }

        return Response.ok(out.toByteArray()).build();
    }

    @Override
    public Response getChainPEM(String aidString) {
        byte[] der = (byte[]) getCert(aidString).getEntity();
        return Response.ok(toPem("PKCS7", der)).build();
    }

    @Override
    public Response createCA(AuthorityData data) {
        String parentAIDString = data.getParentID();
        AuthorityID parentAID = null;
        try {
            parentAID = new AuthorityID(parentAIDString);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Bad Authority ID: " + parentAIDString);
        }

        try {
            ICertificateAuthority subCA = hostCA.createCA(
                data.getDN(), parentAID, data.getDescription());
            return createOKResponse(readAuthorityData(subCA));
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(e.toString());
        } catch (CANotFoundException e) {
            throw new ResourceNotFoundException(e.toString());
        } catch (IssuerUnavailableException | CADisabledException e) {
            throw new ConflictingOperationException(e.toString());
        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Error creating CA: " + e.toString());
        }
    }

    @Override
    public Response modifyCA(String aidString, AuthorityData data) {
        AuthorityID aid = null;
        try {
            aid = new AuthorityID(aidString);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Bad AuthorityID: " + aidString);
        }

        ICertificateAuthority ca = hostCA.getCA(aid);
        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + aidString + "\" not found");

        try {
            ca.modifyAuthority(data.getEnabled(), data.getDescription());
            return createOKResponse(readAuthorityData(ca));
        } catch (CATypeException e) {
            throw new ForbiddenException(e.toString());
        } catch (IssuerUnavailableException e) {
            throw new ConflictingOperationException(e.toString());
        } catch (EBaseException e) {
            CMS.debug(e);
            throw new PKIException("Error modifying authority: " + e.toString());
        }
    }

    @Override
    public Response enableCA(String aidString) {
        return modifyCA(
            aidString,
            new AuthorityData(null, null, null, null, true, null));
    }

    @Override
    public Response disableCA(String aidString) {
        return modifyCA(
            aidString,
            new AuthorityData(null, null, null, null, false, null));
    }

    @Override
    public Response deleteCA(String aidString) {
        AuthorityID aid = null;
        try {
            aid = new AuthorityID(aidString);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Bad AuthorityID: " + aidString);
        }

        ICertificateAuthority ca = hostCA.getCA(aid);
        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + aidString + "\" not found");

        try {
            ca.deleteAuthority();
            return createNoContentResponse();
        } catch (CATypeException e) {
            throw new ForbiddenException(e.toString());
        } catch (CAEnabledException | CANotLeafException e) {
            throw new ConflictingOperationException(e.toString());
        } catch (EBaseException e) {
            CMS.debug(e);
            throw new PKIException("Error modifying authority: " + e.toString());
        }
    }

    private static AuthorityData readAuthorityData(ICertificateAuthority ca)
            throws PKIException {
        String dn;
        try {
            dn = ca.getX500Name().toLdapDNString();
        } catch (IOException e) {
            throw new PKIException("Error reading CA data: could not determine Issuer DN");
        }

        AuthorityID parentAID = ca.getAuthorityParentID();
        return new AuthorityData(
            ca.isHostAuthority(),
            dn,
            ca.getAuthorityID().toString(),
            parentAID != null ? parentAID.toString() : null,
            ca.getAuthorityEnabled(),
            ca.getAuthorityDescription()
        );
    }

    private String toPem(String name, byte[] data) {
        return "-----BEGIN " + name + "-----\n" +
                Utils.base64encode(data) +
                "-----END " + name + "-----\n";
    }

    /* TODO work out what audit messages are needed
    public void auditProfileChangeState(String profileId, String op, String status) {
        String msg = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL,
                auditor.getSubjectID(),
                status,
                profileId,
                op);
        auditor.log(msg);
    }

    public void auditProfileChange(String scope, String type, String id, String status, Map<String, String> params) {
        String msg = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE,
                auditor.getSubjectID(),
                status,
                auditor.getParamString(scope, type, id, params));
        auditor.log(msg);
    }
    */

}
