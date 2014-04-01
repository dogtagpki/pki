package com.netscape.cmstools.key;

import java.util.ArrayList;

import com.netscape.certsrv.key.Template;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class KeyRequestTemplateFindCLI extends CLI {
    public KeyCLI keyCLI;

    public ArrayList<Template> templates = new ArrayList<Template>();

    public KeyRequestTemplateFindCLI(KeyCLI keyCLI) {
        super("template-find", "List request template IDs", keyCLI);
        this.keyCLI = keyCLI;
        createTemplateList();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS]", options);
    }

    public void execute(String[] args) {
        MainCLI.printMessage("List of templates");
        for (Template template : templates) {
            template.printTemplateInfo();
        }
    }

    public void createTemplateList() {
        Template template = new Template("archiveKey", "Key Archival Request",
                "Template file for submitting a key archival request");
        templates.add(template);
        template = new Template("retrieveKey", "Key retrieval request",
                "Template for submitting a key retrieval or key recovery request.");
        templates.add(template);
        template = new Template("generateKey", "Symmetric Key generation request",
                "Template for submitting a request for generating a symmetric key.");
        templates.add(template);
    }

}
