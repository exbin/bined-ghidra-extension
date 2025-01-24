BinEd - Binary/Hex Editor Ghidra SRE Extension
==============================================

Hex viewer/editor extension for Ghidra SRE. See https://ghidra-sre.org  

Homepage: https://bined.exbin.org/ghidra-extension/  

Screenshot
----------

![BinEd-Editor Screenshot](images/bined-ghidra-screenshot.png?raw=true)

Features
--------

  * Visualize data as numerical (hexadecimal) codes and text representation
  * Codes can be also binary, octal or decimal
  * Support for Unicode, UTF-8 and other charsets
  * Insert and overwrite edit modes
  * Searching for text / hexadecimal code with found matches highlighting
  * Support for undo/redo
  * Support for files with size up to exabytes

Compiling
---------

Java Development Kit (JDK) version 21 or later is required to build this project.

Currently dependency libraries from the bined editor are expected to be present in the local maven repository.

You can try to run following commands. Start at parent directory to "bined" repo directory.

    git clone https://github.com/exbin/exbin-auxiliary-java.git
    cd exbin-auxiliary-java
    gradlew build publish
    cd ..
    git clone https://github.com/exbin/bined-lib-java.git
    cd bined-lib-java
    gradlew build publish
    cd ..
    git clone https://github.com/exbin/exbin-framework-java.git
    cd exbin-framework-java
    gradlew build publish
    cd .. 
    git clone https://github.com/exbin/bined.git
    cd bined
    gradlew build publish
    cd .. 


Set GHIDRA_INSTALL_DIR property to path to Ghidra installation.

Run:

`gradle buildPack`

or

`gradle buildExtension`

License
-------

Apache License, Version 2.0 - see LICENSE.txt
