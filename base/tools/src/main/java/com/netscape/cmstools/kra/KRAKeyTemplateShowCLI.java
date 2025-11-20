package com.netscape.cmstools.kra;

import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.base.RESTMessage;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class KRAKeyTemplateShowCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAKeyTemplateShowCLI.class);

    public KRAKeyCLI keyCLI;

    public KRAKeyTemplateShowCLI(KRAKeyCLI keyCLI) {
        super("template-show", "Get request template", keyCLI);
        this.keyCLI = keyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <Template ID> [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "output", true, "Location to store the template.");
        option.setArgName("output file");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("No Template ID specified.");
        }

        String templateId = cmdArgs[0];
        String writeToFile = cmd.getOptionValue("output");

        // TODO: Get the template from the server
        String templateDir = "/usr/share/pki/key/templates/";
        String templatePath = templateDir + templateId + ".json";
        String json = Files.readString(Path.of(templatePath));
        RESTMessage data = JSONSerializer.fromJSON(json, RESTMessage.class);

        if (writeToFile != null) {
            try (FileWriter out = new FileWriter(writeToFile)) {
                out.write(data.toJSON());
            }
        } else {
            System.out.println(data.toJSON());
        }
    }
}
