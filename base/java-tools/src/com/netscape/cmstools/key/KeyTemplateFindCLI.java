package com.netscape.cmstools.key;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.base.ResourceMessage;
import com.netscape.certsrv.key.KeyTemplate;
import com.netscape.certsrv.key.SymKeyGenerationRequest;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class KeyTemplateFindCLI extends CLI {
    public KeyCLI keyCLI;

    public ArrayList<KeyTemplate> templates = new ArrayList<KeyTemplate>();

    public KeyTemplateFindCLI(KeyCLI keyCLI) {
        super("template-find", "List request template IDs", keyCLI);
        this.keyCLI = keyCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        createTemplateList();

        MainCLI.printMessage(templates.size() + " entries matched");
        for (KeyTemplate template : templates) {
            template.printTemplateInfo();
        }
        System.out.println();
        MainCLI.printMessage("Number of entries returned " + templates.size());
    }

    public void createTemplateList() throws Exception {
        String templateDir = "/usr/share/pki/key/templates/";
        File file = new File(templateDir);
        if (!file.exists()) {
            throw new Exception("Missing template files.");
        }
        KeyTemplate template = null;
        ResourceMessage data = null;
        String[] templateFiles = file.list();
        for (String templateName : templateFiles) {
            if (templateName.indexOf(".xml") == -1) {
                continue;
            }
            String id = templateName.substring(0, templateName.indexOf(".xml"));
            data = ResourceMessage.unmarshall(SymKeyGenerationRequest.class, templateDir + templateName);
            template = new KeyTemplate(id, data.getAttribute("description"));
            templates.add(template);
        }
    }
}
