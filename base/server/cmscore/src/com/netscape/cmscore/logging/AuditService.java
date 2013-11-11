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

package com.netscape.cmscore.logging;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.Collection;
import java.util.LinkedHashSet;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.lang.StringUtils;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.logging.AuditConfig;
import com.netscape.certsrv.logging.AuditResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class AuditService extends PKIService implements AuditResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public final static int DEFAULT_SIZE = 20;

    public AuditService() {
        CMS.debug("AuditService.<init>()");
    }

    public AuditConfig createAuditConfig() throws UnsupportedEncodingException, EBaseException {

        IConfigStore cs = CMS.getConfigStore();

        AuditConfig auditConfig = new AuditConfig();
        auditConfig.setEnabled(cs.getBoolean("log.instance.SignedAudit.enable", false));
        auditConfig.setSigned(cs.getBoolean("log.instance.SignedAudit.logSigning", false));
        auditConfig.setInterval(cs.getInteger("log.instance.SignedAudit.flushInterval", 5));
        auditConfig.setBufferSize(cs.getInteger("log.instance.SignedAudit.bufferSize", 512));

        // unselected events
        for (String event : StringUtils.split(cs.getString("log.instance.SignedAudit.unselected.events", ""), ", ")) {
            auditConfig.setOptionalEvent(event.trim(), false);
        }

        // in case of duplicates, selected events override unselected events
        for (String event : StringUtils.split(cs.getString("log.instance.SignedAudit.events", ""), ", ")) {
            auditConfig.setOptionalEvent(event.trim(), true);
        }

        // mandatory events
        for (String event : StringUtils.split(cs.getString("log.instance.SignedAudit.mandatory.events", ""), ", ")) {
            auditConfig.addMandatoryEvent(event.trim());
        }

        URI uri = uriInfo.getBaseUriBuilder().path(AuditResource.class).build();
        auditConfig.setLink(new Link("self", uri));

        return auditConfig;
    }

    @Override
    public AuditConfig getAuditConfig() {

        CMS.debug("AuditService.getAuditConfig()");

        try {
            return createAuditConfig();

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response updateAuditConfig(AuditConfig auditConfig) {

        if (auditConfig == null) throw new BadRequestException("Audit config is null.");

        CMS.debug("AuditService.updateAuditConfig()");

        try {
            IConfigStore cs = CMS.getConfigStore();

            if (auditConfig.getEnabled() != null) {
                cs.putBoolean("log.instance.SignedAudit.enable", auditConfig.getEnabled());
            }

            if (auditConfig.getSigned() != null) {
                cs.putBoolean("log.instance.SignedAudit.logSigning", auditConfig.getSigned());
            }

            if (auditConfig.getInterval() != null) {
                cs.putInteger("log.instance.SignedAudit.flushInterval", auditConfig.getInterval());
            }

            if (auditConfig.getBufferSize() != null) {
                cs.putInteger("log.instance.SignedAudit.bufferSize", auditConfig.getBufferSize());
            }

            // update events selection
            Collection<String> selected = new LinkedHashSet<String>();
            Collection<String> unselected = new LinkedHashSet<String>();

            for (String name : auditConfig.getOptionalEvents().keySet()) {
                Boolean value = auditConfig.getOptionalEvent(name);

                if (value) {
                    selected.add(name);

                } else {
                    unselected.add(name);
                }
            }

            cs.putString("log.instance.SignedAudit.events", StringUtils.join(selected, ","));
            cs.putString("log.instance.SignedAudit.unselected.events", StringUtils.join(unselected, ","));

            // mandatory events cannot be updated

            cs.commit(true);

            auditConfig = createAuditConfig();

            return Response
                    .ok(auditConfig)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
