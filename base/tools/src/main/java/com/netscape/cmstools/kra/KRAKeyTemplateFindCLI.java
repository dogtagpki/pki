package com.netscape.cmstools.kra;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.base.RESTMessage;
import com.netscape.certsrv.key.KeyTemplate;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class KRAKeyTemplateFindCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAKeyTemplateFindCLI.class);

    public KRAKeyCLI keyCLI;

    public ArrayList<KeyTemplate> templates = new ArrayList<>();

    public KRAKeyTemplateFindCLI(KRAKeyCLI keyCLI) {
        super("template-find", "List request template IDs", keyCLI);
        this.keyCLI = keyCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

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
        RESTMessage data = null;
        String[] templateFiles = file.list();
        for (String templateName : templateFiles) {
            if (templateName.indexOf(".json") == -1) {
                continue;
            }
            String id = templateName.substring(0, templateName.indexOf(".json"));
            String json = Files.readString(Path.of(templateDir + templateName));
            data = JSONSerializer.fromJSON(json, RESTMessage.class);
            template = new KeyTemplate(id, data.getAttribute("description"));
            templates.add(template);
        }
    }
}
