package com.netscape.cmstools.key;

import java.io.FileOutputStream;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.base.ResourceMessage;
import com.netscape.certsrv.key.KeyArchivalRequest;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class KeyTemplateShowCLI extends CLI {
    public KeyCLI keyCLI;

    public KeyTemplateShowCLI(KeyCLI keyCLI) {
        super("template-show", "Get request template", keyCLI);
        this.keyCLI = keyCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Template ID> [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "output", true, "Location to store the template.");
        option.setArgName("output file");
        options.addOption(option);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("No Template ID specified.");
        }

        String templateId = cmdArgs[0];
        String writeToFile = cmd.getOptionValue("output");
        String templateDir = "/usr/share/pki/key/templates/";
        String templatePath = templateDir + templateId + ".xml";
        ResourceMessage data = ResourceMessage.unmarshall(KeyArchivalRequest.class, templatePath);

        if (writeToFile != null) {
            try (FileOutputStream fOS = new FileOutputStream(writeToFile)) {
                data.marshall(fOS);
            }
        } else {
            MainCLI.printMessage(data.getAttribute("description"));
            data.marshall(System.out);
        }
    }
}
