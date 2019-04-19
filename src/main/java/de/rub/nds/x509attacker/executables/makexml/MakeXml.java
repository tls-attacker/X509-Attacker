package de.rub.nds.x509attacker.executables.makexml;

import org.apache.commons.cli.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class MakeXml {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        Option input = new Option("i", "input", true, "Input PEM-emcoded certificate file");
        input.setRequired(true);

        Option output = new Option("o", "output", true, "Output XML file");
        output.setRequired(true);

        Options options = new Options();
        options.addOption(input);
        options.addOption(output);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
            run(cmd.getOptionValue("input"), cmd.getOptionValue("output"));
        } catch (ParseException e) {
            System.out.println(e.getMessage() + "\r\n");
            formatter.printHelp("utility-name", options);
        }
    }

    private static void run(final String inputFilename, final String outputFilename) {

    }
}
