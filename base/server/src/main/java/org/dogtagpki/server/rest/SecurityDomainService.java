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
package org.dogtagpki.server.rest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.system.SecurityDomainResource;
import com.netscape.certsrv.system.SecurityDomainSubsystem;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.csadmin.SecurityDomainProcessor;

/**
 * @author alee
 */
public class SecurityDomainService extends PKIService implements SecurityDomainResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SecurityDomainService.class);

    public boolean isEnabled() {
        return true;
    }

    @Override
    public Response getInstallToken(String hostname, String subsystem) {

        if (!isEnabled()) {
            throw new WebApplicationException(Response.Status.NOT_FOUND);
        }

        logger.debug("SecurityDomainService.getInstallToken(" + hostname + ", " + subsystem + ")");
        try {
            // Get uid from realm authentication.
            String user = servletRequest.getUserPrincipal().getName();

            SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));
            processor.setCMSEngine(getCMSEngine());

            InstallToken installToken = processor.getInstallToken(user, hostname, subsystem);
            return createOKResponse(installToken);

        } catch (PKIException e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response getDomainInfo() {

        if (!isEnabled()) {
            throw new WebApplicationException(Response.Status.NOT_FOUND);
        }

        try {
            SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));
            processor.setCMSEngine(getCMSEngine());

            DomainInfo domainInfo = processor.getDomainInfo();
            return createOKResponse(domainInfo);

        } catch (PKIException e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response getHosts() {

        if (!isEnabled()) {
            throw new WebApplicationException(Response.Status.NOT_FOUND);
        }

        logger.info("SecurityDomainService: Getting all security domain hosts");
        try {
            Collection<SecurityDomainHost> hosts = new ArrayList<>();

            SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));
            processor.setCMSEngine(getCMSEngine());

            DomainInfo domainInfo = processor.getDomainInfo();
            logger.debug("SecurityDomainService: domain: " + domainInfo.getName());

            for (SecurityDomainSubsystem subsystem : domainInfo.getSubsystems().values()) {
                for (SecurityDomainHost host : subsystem.getHosts().values()) {
                    logger.debug("SecurityDomainService: - " + host.getId());
                    hosts.add(host);
                }
            }

            GenericEntity<Collection<SecurityDomainHost>> entity =
                    new GenericEntity<>(hosts) {};

            return createOKResponse(entity);

        } catch (PKIException e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response getHost(String hostID) {

        if (!isEnabled()) {
            throw new WebApplicationException(Response.Status.NOT_FOUND);
        }

        logger.info("SecurityDomainService: Getting security domain host \"" + hostID + "\"");
        try {
            SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));
            processor.setCMSEngine(getCMSEngine());

            DomainInfo domainInfo = processor.getDomainInfo();
            logger.debug("SecurityDomainService: domain: " + domainInfo.getName());

            for (SecurityDomainSubsystem subsystem : domainInfo.getSubsystems().values()) {
                for (SecurityDomainHost host : subsystem.getHosts().values()) {

                    logger.debug("SecurityDomainService: - " + host.getId());

                    if (host.getId().equals(hostID)) {
                        logger.debug("SecurityDomainService: Found security domain host " + hostID);
                        return createOKResponse(host);
                    }
                }
            }

            throw new ResourceNotFoundException("Security domain host not found: " + hostID);

        } catch (PKIException e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response addHost(SecurityDomainHost host) {

        if (!isEnabled()) {
            throw new WebApplicationException(Response.Status.NOT_FOUND);
        }

        String hostID = host.getId();
        logger.info("SecurityDomainService: Adding security domain host \"" + hostID + "\"");

        try {
            // Host ID: <type> <hostname> <port>
            Pattern pattern = Pattern.compile("^(\\S+) (\\S+) (\\d+)$");
            Matcher matcher = pattern.matcher(hostID);

            if (!matcher.find()) {
                throw new BadRequestException("Invalid security domain host: " + hostID);
            }

            String type = matcher.group(1);
            logger.debug("SecurityDomainService: type: " + type);

            String hostname = matcher.group(2);
            logger.debug("SecurityDomainService: hostname: " + hostname);

            String securePort = matcher.group(3);
            logger.debug("SecurityDomainService: secure port: " + securePort);

            String unsecurePort = host.getPort();
            logger.debug("SecurityDomainService: unsecure port: " + unsecurePort);

            String eeCAPort = host.getSecureEEClientAuthPort();
            logger.debug("SecurityDomainService: secure EE port: " + eeCAPort);

            if (!securePort.equals(eeCAPort)) {
                throw new BadRequestException("Invalid secure (EE) port: " + eeCAPort);
            }

            String adminSecurePort = host.getSecureAdminPort();
            logger.debug("SecurityDomainService: secure admin port: " + adminSecurePort);

            if (!securePort.equals(adminSecurePort)) {
                throw new BadRequestException("Invalid secure (admin) port: " + adminSecurePort);
            }

            String agentSecurePort = host.getSecureAgentPort();
            logger.debug("SecurityDomainService: secure agent port: " + agentSecurePort);

            if (!securePort.equals(agentSecurePort)) {
                throw new BadRequestException("Invalid secure (agent) port: " + agentSecurePort);
            }

            String domainManager = host.getDomainManager();
            logger.debug("SecurityDomainService: domain manager: " + domainManager);

            String clone = host.getClone();
            logger.debug("SecurityDomainService: clone: " + clone);

            SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));
            processor.setCMSEngine(getCMSEngine());

            String status = processor.addHost(
                    hostID,
                    type,
                    hostname,
                    securePort,
                    unsecurePort,
                    eeCAPort,
                    adminSecurePort,
                    agentSecurePort,
                    domainManager,
                    clone);
            logger.debug("SecurityDomainService: status: " + status);

            if (!SecurityDomainProcessor.SUCCESS.equals(status)) {
                throw new PKIException("Unable to add security domain host: " + hostID);
            }

            return createNoContentResponse();

        } catch (PKIException e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response removeHost(String hostID) {

        if (!isEnabled()) {
            throw new WebApplicationException(Response.Status.NOT_FOUND);
        }

        logger.info("SecurityDomainService: Removing security domain host \"" + hostID + "\"");
        try {
            // Host ID: <type> <hostname> <port>
            Pattern pattern = Pattern.compile("^(\\S+) (\\S+) (\\d+)$");
            Matcher matcher = pattern.matcher(hostID);

            if (!matcher.find()) {
                throw new BadRequestException("Invalid security domain host: " + hostID);
            }

            String type = matcher.group(1);
            logger.debug("SecurityDomainService: type: " + type);

            String hostname = matcher.group(2);
            logger.debug("SecurityDomainService: hostname: " + hostname);

            String port = matcher.group(3);
            logger.debug("SecurityDomainService: port: " + port);

            SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));
            processor.setCMSEngine(getCMSEngine());

            String status = processor.removeHost(hostID, type, hostname, port);
            logger.debug("SecurityDomainService: status: " + status);

            if (!SecurityDomainProcessor.SUCCESS.equals(status)) {
                throw new PKIException("Unable to remove security domain host: " + hostID);
            }

            return createNoContentResponse();

        } catch (PKIException e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }
}
