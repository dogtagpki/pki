package com.netscape.cmstools.profile;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;

import javax.ws.rs.core.UriBuilder;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.profile.ProfileOutput;
import com.netscape.certsrv.profile.ProfileResource;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class ProfileCLI extends CLI {
    public MainCLI parent;
    public ProfileClient client;

    public ProfileCLI(MainCLI parent) {
        super("profile", "Profile management commands");
        this.parent = parent;

        addModule(new ProfileFindCLI(this));
        addModule(new ProfileShowCLI(this));
        addModule(new ProfileAddCLI(this));
        addModule(new ProfileModifyCLI(this));
        addModule(new ProfileRemoveCLI(this));
        addModule(new ProfileEnableCLI(this));
        addModule(new ProfileDisableCLI(this));
    }

    public void printHelp() {

        System.out.println("Commands:");

        int leftPadding = 1;
        int rightPadding = 25;

        for (CLI module : modules.values()) {
            String label = name + "-" + module.getName();

            int padding = rightPadding - leftPadding - label.length();
            if (padding < 1)
                padding = 1;

            System.out.print(StringUtils.repeat(" ", leftPadding));
            System.out.print(label);
            System.out.print(StringUtils.repeat(" ", padding));
            System.out.println(module.getDescription());
        }
    }

    public void execute(String[] args) throws Exception {

        client = new ProfileClient(parent.client);

        if (args.length == 0) {
            printHelp();
            System.exit(1);
        }

        String command = args[0];
        String[] commandArgs = Arrays.copyOfRange(args, 1, args.length);

        if (command == null) {
            printHelp();
            System.exit(1);
        }

        CLI module = getModule(command);
        if (module != null) {
            module.execute(commandArgs);

        } else {
            System.err.println("Error: Invalid command \"" + command + "\"");
            printHelp();
            System.exit(1);
        }
    }

    public static void printProfileDataInfo(ProfileDataInfo info) {
        System.out.println("Profile ID:  " + info.getProfileId());
        System.out.println("Profile URL: " + info.getProfileURL());
        System.out.println("Profile Name: " + info.getProfileName());
        System.out.println("Profile Description: " + info.getProfileDescription());
    }

    public static void printProfile(ProfileData data, URI baseUri) {

        UriBuilder profileBuilder = UriBuilder.fromUri(baseUri);
        URI uri = profileBuilder.path(ProfileResource.class).path("{id}").
                build(data.getId());

        System.out.println("Profile ID:  " + data.getId());
        System.out.println("Profile URL: " + uri.toString());
        System.out.println("Profile Name: " + data.getName());
        System.out.println("Profile Description: " + data.getDescription() + "\n");

        System.out.println("Profile Inputs:  " + data.getId());
        int count =0;
        for (Map.Entry<String, ProfileInput> entry: data.getInputs().entrySet()) {
            ProfileInput input = entry.getValue();
            System.out.println("Input " + count + " Id: " + entry.getKey());
            System.out.println("Input " + count + " Name: " + input.getName());
            System.out.println("Input " + count + " Class: " + input.getClassId());
            for (ProfileAttribute attr: input.getAttrs()) {
                System.out.println("Input " + count + " Attribute Name: " + attr.getName());
                System.out.println("Input " + count + " Attribute Description: " +
                    attr.getDescriptor().getDescription(Locale.getDefault()));
                System.out.println("Input " + count + " Attribute Syntax: " +
                    attr.getDescriptor().getSyntax());
            }
            count ++;
        }

        count = 0;
        for (Map.Entry<String, ProfileOutput> entry: data.getOutputs().entrySet()) {
            ProfileOutput output = entry.getValue();
            System.out.println("Output " + count + " Id: " + entry.getKey());
            System.out.println("Output " + count + " Name: " + output.getName());
            System.out.println("Output " + count + " Class: " + output.getClassId());
            for (ProfileAttribute attr: output.getAttrs()) {
                System.out.println("Output " + count + " Attribute Name: " + attr.getName());
                System.out.println("Output " + count + " Attribute Description: " +
                    attr.getDescriptor().getDescription(Locale.getDefault()));
                System.out.println("Output " + count + " Attribute Syntax: " +
                    attr.getDescriptor().getSyntax());
            }
            count ++;
        }
    }

    public static void saveProfileToFile(String filename, ProfileData data)
            throws JAXBException, FileNotFoundException {
        JAXBContext context = JAXBContext.newInstance(ProfileData.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        FileOutputStream stream = new FileOutputStream(filename);
        marshaller.marshal(data, stream);

        MainCLI.printMessage("Saved profile " + data.getId() + " to " + filename);
    }

    public static ProfileData readProfileFromFile(String filename)
            throws JAXBException, FileNotFoundException {
        ProfileData data = null;
        JAXBContext context = JAXBContext.newInstance(ProfileData.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        FileInputStream fis = new FileInputStream(filename);
        data = (ProfileData) unmarshaller.unmarshal(fis);
        return data;
    }
}
