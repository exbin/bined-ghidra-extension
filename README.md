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

Set GHIDRA_INSTALL_DIR property to path to Ghidra installation.

Java Development Kit (JDK) version 17 or later is required to build this project.

Run:

`gradle buildPack`

or

`gradle buildExtension`

License
-------

Apache License, Version 2.0 - see LICENSE.txt
