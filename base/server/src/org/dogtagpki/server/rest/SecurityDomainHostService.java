//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.system.SecurityDomainHostResource;
import com.netscape.certsrv.system.SecurityDomainSubsystem;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.csadmin.SecurityDomainProcessor;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainHostService extends PKIService implements SecurityDomainHostResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SecurityDomainHostService.class);

    @Override
    public Response getHosts() throws Exception {

        logger.info("SecurityDomainService: Getting all security domain hosts");

        Collection<SecurityDomainHost> hosts = new ArrayList<>();

        SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));

        DomainInfo domainInfo = processor.getDomainInfo();
        logger.debug("SecurityDomainService: domain: " + domainInfo.getName());

        for (SecurityDomainSubsystem subsystem : domainInfo.getSubsystems().values()) {
            for (SecurityDomainHost host : subsystem.getHosts().values()) {
                logger.debug("SecurityDomainService: - " + host.getId());
                hosts.add(host);
            }
        }

        GenericEntity<Collection<SecurityDomainHost>> entity =
                new GenericEntity<Collection<SecurityDomainHost>>(hosts) {};

        return createOKResponse(entity);
    }

    @Override
    public Response getHost(String hostID) throws Exception {

        logger.info("SecurityDomainService: Getting security domain host \"" + hostID + "\"");

        SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));

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
    }

    @Override
    public Response addHost(SecurityDomainHost host) throws Exception {

        String hostID = host.getId();
        logger.info("SecurityDomainService: Adding security domain host \"" + hostID + "\"");

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
    }

    @Override
    public Response removeHost(String hostID) throws Exception {

        logger.info("SecurityDomainService: Removing security domain host \"" + hostID + "\"");

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
        String status = processor.removeHost(type, hostname, port);
        logger.debug("SecurityDomainService: status: " + status);

        if (!SecurityDomainProcessor.SUCCESS.equals(status)) {
            throw new PKIException("Unable to remove security domain host: " + hostID);
        }

        return createNoContentResponse();
    }
}
