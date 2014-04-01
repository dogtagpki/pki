package com.netscape.certsrv.key;


public class Template{
    String templateID;
    String templateName;
    String templateDescription;
    public Template(String templateID, String templateName, String templateDescription) {
        super();
        this.templateID = templateID;
        this.templateName = templateName;
        this.templateDescription = templateDescription;
    }

    public void printTemplateInfo(){
        System.out.println();
        System.out.println("  Template ID: " + templateID);
        System.out.println("  Template Name: " + templateName);
        System.out.println("  Template Description: " + templateDescription);
    }
}