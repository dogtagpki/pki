//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.config;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.common.ConfigClient;
import org.dogtagpki.common.ConfigData;

import com.netscape.cmstools.cli.MainCLI;

public class ConfigExportCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ConfigExportCLI.class);

    public ConfigCLI configCLI;

    public ConfigExportCLI(ConfigCLI configCLI) {
        super("export", "Export configuration properties", configCLI);
        this.configCLI = configCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...] <type>", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "names", true, "Comma-separated list of configuration property names.");
        option.setArgName("names");
        options.addOption(option);

        option = new Option(null, "substores", true, "Comma-separated list of configuration property substores.");
        option.setArgName("substores");
        options.addOption(option);

        option = new Option(null, "session", true, "Session ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "install-token", true, "Install token");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: text (default), json");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String installToken = cmd.getOptionValue("install-token");
        String sessionID;

        if (installToken != null) {
            sessionID = new String(Files.readAllBytes(Paths.get(installToken)));
        } else {
            sessionID = cmd.getOptionValue("session");
        }

        if (sessionID == null) {
            throw new Exception("Missing session ID or install token");
        }

        String names = cmd.getOptionValue("names", "");
        String substores = cmd.getOptionValue("substores", "");

        String outputFormat = cmd.getOptionValue("output-format", "text");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        ConfigClient configClient = configCLI.getConfigClient();
        ConfigData config = configClient.getConfig(names, substores, sessionID);

        if ("json".equalsIgnoreCase(outputFormat)) {
            System.out.println(config.toJSON());

        } else {
            Map<String, String> properties = config.getProperties();
            for (String name : properties.keySet()) {
                String value = properties.get(name);
                System.out.println(name + ": " + value);
            }
        }
    }
}
