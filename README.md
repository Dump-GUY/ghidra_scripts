# ghidra_scripts
Scripts for the Ghidra software reverse engineering suite.
For developing python scripts in context of Ghidra SRE please visit WIKI.

## Installation
Insert script to Ghidra script directory. Example:$USER_HOME/ghidra_scripts.

## tiny_tracer_tag_annotate.py
The tags generated by the Tiny Tracer are helpful in deobfuscating obfuscated API calls.<br/>
This script will annotate and bookmark the code with tags produced by tool Tiny Tracer.<br/>
Tiny Tracer repo: https://github.com/hasherezade/tiny_tracer.<br/>
Tested on Tiny_tracer version 1.4

How to use:<br/>
Run script via Ghidra Script Manager, import relevant .tag file for analyzed sample, produced by Tiny Tracer.

Ghidra annotated Graph_View:

![Ghidra annotated Graph view](/Images/GHIDRA_GRAPHVIEW_annotated.PNG)


Ghidra annotated Listing_View and Bookmarks:

![Ghidra annotated_Listing_bookmark_view](/Images/GHIDRA_listing%20view_bookmarks_annotated.PNG)



## CAPA_Importer.py
This script works with exported .txt or .json results of CAPA tool.<br/>
Capa detects capabilities in executable files. You run it against a PE file or shellcode and it tells you what it thinks the program can do.<br/>
For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate.<br/>
CAPA repo: https://github.com/fireeye/capa<br/>
CAPA blog post: https://www.fireeye.com/blog/threat-research/2020/07/capa-automatically-identify-malware-capabilities.html

Script "CAPA_Importer.py" will annotate (PRE_COMMENT) code with Capability, bookmark the code with Capability, Matched RVA location and Scope. If more than one Capability for relevant RVA is presented, script will add annotation for the capability to RVA in code and <br/>
also edit bookmark so the bookmark with location (RVA) will contain all Capabilities.<br/>
If matched capability in CAPA result has scope 'file', no annotation (PRE_COMMENT) will be presented in code, bookmark will be created with RVA = ImageBase.<br/>
Tested on CAPA version 1.0.0 - 1.2.0<br/>
<br/>

How to use:<br/>
Analyze sample with CAPA.<br/>
Example1: CAPA -v malware.exe > exported.txt<br/>
Example2: CAPA -j malware.exe > exported.json<br/>
Parameter '-v' must be presented in cmdline argument to export Capa results in supported text format.<br/>
Parameter '-j' must be presented in cmdline argument to export Capa results in supported json format.<br/>
Run this script, import exported.txt or exported.json and it will annotate (with PRE_COMMENT) and bookmark the code with Capability, Matched RVA location and Scope.
<br/>
If no PRE_COMMENT presented in Decompile window or Graph window --> Check if you have in relevant windows option "Display PRE comments" enabled.

Ghidra annotated Listing view, Decompile view and Bookmarks (1):

![Ghidra annotated Listing view](/Images/CAPA_Importer_All_in_one_view.PNG)


Ghidra annotated Listing view, Decompile view and Bookmarks (2):

![Ghidra annotated Listing view2](/Images/CAPA_Importer_All_in_one_view2.PNG)



Ghidra annotated Function Graph view and Bookmarks:

![Ghidra annotated Graph view](/Images/CAPA_Importer_Graph_Bookmarks_view.PNG)


