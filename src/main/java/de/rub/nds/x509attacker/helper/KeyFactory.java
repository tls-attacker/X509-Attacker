/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.x509attacker.helper;

import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.signatureengine.keyparsers.KeyType;
import de.rub.nds.signatureengine.keyparsers.PemUtil;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author josh
 */
public class KeyFactory {

    static final Logger LOGGER = LogManager.getLogger(KeyFactory.class);

    public static File getRandomKeyFile(File keyFolder, KeyType keyType) throws IOException {
        return getRandomKeyFileFromFolder(keyFolder, keyType);
    }

    public static File getRandomKeyFileFromFolder(File keyFolder) throws IOException {
        return getRandomKeyFileFromFolder(keyFolder, null);
    }

    /**
     * Returns a random KeyFile from the given keyFolder. If the given keyType != null it searches for the corresponding
     * keyFiles in a direct subfolder with the name "keyFolder/keyType" (for example: "keyfolder/rsa", "keyFolder/dsa")
     * If keyType == null it search for every key in the keyFolder. The function search recursively for all files in the
     * searched folder
     *
     * @param  keyFolder
     *                     Folder which contains the keys
     * @param  keyType
     *                     KeyType to search for
     * @return             File with a random Key corresponding the keyType
     * @throws IOException
     *                     when the file could not be selected
     */
    public static File getRandomKeyFileFromFolder(File keyFolder, KeyType keyType) throws IOException {
        if (keyFolder == null) {
            throw new IOException("keyFolder is null");
        }

        if (keyFolder.exists() && keyFolder.isDirectory()) {

            File keyFolderToSearch;
            if (keyType != null) {
                keyFolderToSearch = new File(keyFolder.getAbsoluteFile() + "/" + keyType.name().toLowerCase());
            } else {
                keyFolderToSearch = keyFolder;
            }

            if (keyFolderToSearch.exists() && keyFolderToSearch.isDirectory()) {

                List<Path> filePathes = Files.walk(Paths.get(keyFolderToSearch.getAbsolutePath()))
                    .filter(Files::isRegularFile).collect(Collectors.toList());

                int maxTries = 10;
                for (int tries = 0; tries < maxTries; tries++) {
                    Random r = RandomHelper.getRandom();
                    File chosenFile = filePathes.get(r.nextInt(filePathes.size())).toFile();

                    if (keyType == null) { // if no keyType is given, return first keyFile
                        return chosenFile;
                    } else if (PemUtil.getKeyType(chosenFile) == keyType) { // if keyFile is given, return only if
                        // keyType of the keyFile is correct.
                        return chosenFile;
                    }
                }

                throw new IOException("getRandomKeyFileFromFolder(): Cannot find a key from Type: " + keyType + " in :"
                    + keyFolderToSearch.getAbsolutePath() + " after: " + maxTries + " tries");

            } else {
                throw new IOException("getRandomKeyFileFromFolder(): Cannot select a random keyFile from from "
                    + keyFolderToSearch.getAbsolutePath() + " (does not exists or is no directory)");
            }

        } else {
            throw new IOException("getRandomKeyFileFromFolder(): Cannot select a random keyFile from from "
                + keyFolder.getAbsolutePath() + " (does not exists or is no directory)");
        }
    }

}
