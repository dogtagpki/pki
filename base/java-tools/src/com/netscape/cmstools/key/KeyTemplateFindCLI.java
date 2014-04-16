package com.netscape.cmstools.key;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;

import javax.xml.bind.JAXBException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

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
        formatter.printHelp(getFullName() + " [OPTIONS]", options);
    }

    public void execute(String[] args) {

        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);

        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(1);
        }
        if (cmd.hasOption("help")) {
            printHelp();
            System.exit(1);
        }

        try {
            createTemplateList();
        } catch (FileNotFoundException | JAXBException e) {
            System.err.println("Error: " + e.getMessage());
            if (verbose)
                e.printStackTrace();
            System.exit(-1);
        }
        MainCLI.printMessage("List of templates");
        for (KeyTemplate template : templates) {
            template.printTemplateInfo();
        }
        System.out.println();
    }

    public void createTemplateList() throws FileNotFoundException, JAXBException {
        String templateDir = "/usr/share/pki/key/templates/";
        File file = new File(templateDir);
        if (!file.exists()) {
            System.err.println("Error: Missing template files.");
            System.exit(-1);
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
