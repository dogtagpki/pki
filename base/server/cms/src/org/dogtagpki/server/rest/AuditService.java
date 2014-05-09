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

package org.dogtagpki.server.rest;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
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

    public AuditService() {
        CMS.debug("AuditService.<init>()");
    }

    public AuditConfig createAuditConfig() throws UnsupportedEncodingException, EBaseException {

        IConfigStore cs = CMS.getConfigStore();

        AuditConfig auditConfig = new AuditConfig();
        auditConfig.setStatus(cs.getBoolean("log.instance.SignedAudit.enable", false) ? "Enabled" : "Disabled");
        auditConfig.setSigned(cs.getBoolean("log.instance.SignedAudit.logSigning", false));
        auditConfig.setInterval(cs.getInteger("log.instance.SignedAudit.flushInterval", 5));
        auditConfig.setBufferSize(cs.getInteger("log.instance.SignedAudit.bufferSize", 512));

        Map<String, String> eventConfigs = new TreeMap<String, String>();

        // unselected optional events
        for (String event : StringUtils.split(cs.getString("log.instance.SignedAudit.unselected.events", ""), ", ")) {
            eventConfigs.put(event.trim(), "disabled");
        }

        // selected optional events
        for (String event : StringUtils.split(cs.getString("log.instance.SignedAudit.events", ""), ", ")) {
            eventConfigs.put(event.trim(), "enabled");
        }

        // always selected mandatory events
        for (String event : StringUtils.split(cs.getString("log.instance.SignedAudit.mandatory.events", ""), ", ")) {
            eventConfigs.put(event.trim(), "mandatory");
        }

        auditConfig.setEventConfigs(eventConfigs);

        URI uri = uriInfo.getBaseUriBuilder().path(AuditResource.class).build();
        auditConfig.setLink(new Link("self", uri));

        return auditConfig;
    }

    @Override
    public Response getAuditConfig() {

        CMS.debug("AuditService.getAuditConfig()");

        try {
            return createOKResponse(createAuditConfig());

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
            AuditConfig currentAuditConfig = createAuditConfig();
            Map<String, String> currentEventConfigs = currentAuditConfig.getEventConfigs();

            IConfigStore cs = CMS.getConfigStore();

            if (auditConfig.getSigned() != null) {
                cs.putBoolean("log.instance.SignedAudit.logSigning", auditConfig.getSigned());
            }

            if (auditConfig.getInterval() != null) {
                cs.putInteger("log.instance.SignedAudit.flushInterval", auditConfig.getInterval());
            }

            if (auditConfig.getBufferSize() != null) {
                cs.putInteger("log.instance.SignedAudit.bufferSize", auditConfig.getBufferSize());
            }

            Map<String, String> eventConfigs = auditConfig.getEventConfigs();

            if (eventConfigs != null) {
                // update events if specified

                Collection<String> selected = new TreeSet<String>();
                Collection<String> unselected = new TreeSet<String>();

                for (Map.Entry<String, String> entry : eventConfigs.entrySet()) {
                    String name = entry.getKey();
                    String value = entry.getValue();
                    String currentValue = currentEventConfigs.get(name);

                    // make sure no event is added
                    if (currentValue == null) {
                        throw new PKIException("Unable to add event: " + name);
                    }

                    // make sure no optional event becomes mandatory
                    if ("mandatory".equals(value)) {
                        if (!"mandatory".equals(currentValue)) {
                            throw new PKIException("Unable to add mandatory event: " + name);
                        }
                        continue;
                    }

                    // make sure no mandatory event becomes optional
                    if ("mandatory".equals(currentValue)) {
                        throw new PKIException("Unable to remove mandatory event: " + name);
                    }

                    if ("enabled".equals(value)) {
                        selected.add(name);

                    } else if ("disabled".equals(value)) {
                        unselected.add(name);

                    } else {
                        throw new PKIException("Invalid event configuration: " + name + "=" + value);
                    }
                }

                cs.putString("log.instance.SignedAudit.events", StringUtils.join(selected, ","));
                cs.putString("log.instance.SignedAudit.unselected.events", StringUtils.join(unselected, ","));
            }

            for (String name : currentEventConfigs.keySet()) {
                // make sure no event is removed
                if (!eventConfigs.containsKey(name)) {
                    throw new PKIException("Unable to remove event: " + name);
                }
            }

            cs.commit(true);

            auditConfig = createAuditConfig();

            return createOKResponse(auditConfig);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response changeAuditStatus(String action) {

        CMS.debug("AuditService.changeAuditStatus()");

        try {
            IConfigStore cs = CMS.getConfigStore();

            if ("enable".equals(action)) {
                cs.putBoolean("log.instance.SignedAudit.enable", true);

            } else if ("disable".equals(action)) {
                cs.putBoolean("log.instance.SignedAudit.enable", false);

            } else {
                throw new BadRequestException("Invalid action " + action);
            }

            cs.commit(true);

            AuditConfig auditConfig = createAuditConfig();

            return createOKResponse(auditConfig);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
