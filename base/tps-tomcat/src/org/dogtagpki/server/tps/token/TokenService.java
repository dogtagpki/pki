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

package org.dogtagpki.server.tps.token;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.server.tps.TPSSubsystem;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.tps.token.TokenCollection;
import com.netscape.certsrv.tps.token.TokenData;
import com.netscape.certsrv.tps.token.TokenModifyRequest;
import com.netscape.certsrv.tps.token.TokenResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class TokenService extends PKIService implements TokenResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public final static int DEFAULT_SIZE = 20;

    public TokenService() {
        CMS.debug("TokenService.<init>()");
    }

    public TokenData createTokenData(TokenRecord tokenRecord) {

        TokenData tokenData = new TokenData();
        tokenData.setID(tokenRecord.getId());
        tokenData.setUserID(tokenRecord.getUserID());
        tokenData.setStatus(tokenRecord.getStatus());
        tokenData.setReason(tokenRecord.getReason());
        tokenData.setAppletID(tokenRecord.getAppletID());
        tokenData.setKeyInfo(tokenRecord.getKeyInfo());
        tokenData.setCreateTimestamp(tokenRecord.getCreateTimestamp());
        tokenData.setModifyTimestamp(tokenRecord.getModifyTimestamp());

        String tokenID = tokenRecord.getId();
        try {
            tokenID = URLEncoder.encode(tokenID, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }

        URI uri = uriInfo.getBaseUriBuilder().path(TokenResource.class).path("{tokenID}").build(tokenID);
        tokenData.setLink(new Link("self", uri));

        return tokenData;
    }

    public TokenRecord createTokenRecord(TokenData tokenData) {

        TokenRecord tokenRecord = new TokenRecord();
        tokenRecord.setId(tokenData.getID());
        tokenRecord.setUserID(tokenData.getUserID());
        tokenRecord.setStatus(tokenData.getStatus());
        tokenRecord.setReason(tokenData.getReason());
        tokenRecord.setAppletID(tokenData.getAppletID());
        tokenRecord.setKeyInfo(tokenData.getKeyInfo());
        tokenRecord.setCreateTimestamp(tokenData.getCreateTimestamp());
        tokenRecord.setModifyTimestamp(tokenData.getModifyTimestamp());

        return tokenRecord;
    }

    @Override
    public TokenCollection findTokens(Integer start, Integer size) {

        CMS.debug("TokenService.findTokens()");

        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            TokenDatabase database = subsystem.getTokenDatabase();

            Iterator<TokenRecord> tokens = database.getRecords().iterator();

            TokenCollection response = new TokenCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && tokens.hasNext(); i++) tokens.next();

            // return entries up to the page size
            for ( ; i<start+size && tokens.hasNext(); i++) {
                response.addEntry(createTokenData(tokens.next()));
            }

            // count the total entries
            for ( ; tokens.hasNext(); i++) tokens.next();
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
    public TokenData getToken(String tokenID) {

        if (tokenID == null) throw new BadRequestException("Token ID is null.");

        CMS.debug("TokenService.getToken(\"" + tokenID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            TokenDatabase database = subsystem.getTokenDatabase();

            return createTokenData(database.getRecord(tokenID));

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response addToken(TokenData tokenData) {

        if (tokenData == null) throw new BadRequestException("Token data is null.");

        CMS.debug("TokenService.addToken(\"" + tokenData.getID() + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            TokenDatabase database = subsystem.getTokenDatabase();

            database.addRecord(tokenData.getID(), createTokenRecord(tokenData));
            tokenData = createTokenData(database.getRecord(tokenData.getID()));

            return Response
                    .created(tokenData.getLink().getHref())
                    .entity(tokenData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response updateToken(String tokenID, TokenData tokenData) {

        if (tokenID == null) throw new BadRequestException("Token ID is null.");
        if (tokenData == null) throw new BadRequestException("Token data is null.");

        CMS.debug("TokenService.updateToken(\"" + tokenID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            TokenDatabase database = subsystem.getTokenDatabase();

            TokenRecord tokenRecord = database.getRecord(tokenID);
            tokenRecord.setUserID(tokenData.getUserID());
            database.updateRecord(tokenID, tokenRecord);

            tokenData = createTokenData(database.getRecord(tokenID));

            return Response
                    .ok(tokenData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response modifyToken(String tokenID, TokenModifyRequest request) {

        if (tokenID == null) throw new BadRequestException("Token ID is null.");
        if (request == null) throw new BadRequestException("Token modification is null.");

        CMS.debug("TokenService.modifyToken(\"" + tokenID + "\", request");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            TokenDatabase database = subsystem.getTokenDatabase();

            TokenRecord tokenRecord = database.getRecord(tokenID);
            // TODO: perform modification

            TokenData tokenData = createTokenData(tokenRecord);

            return Response
                    .ok(tokenData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public void removeToken(String tokenID) {

        if (tokenID == null) throw new BadRequestException("Token ID is null.");

        CMS.debug("TokenService.removeToken(\"" + tokenID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            TokenDatabase database = subsystem.getTokenDatabase();
            database.removeRecord(tokenID);

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
