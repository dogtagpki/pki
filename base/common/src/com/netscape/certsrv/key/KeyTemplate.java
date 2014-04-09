package com.netscape.certsrv.key;

public class KeyTemplate {

    String id;
    String description;

    public KeyTemplate(String id, String description) {
        this.id = id;
        this.description = description;
    }

    public void printTemplateInfo() {
        System.out.println();
        System.out.println("  Template ID: " + id);
        System.out.println("  Template Description: " + description);
    }
}