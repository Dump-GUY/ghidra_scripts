#This script works with exported results of CAPA tool.
#Simply analyze sample with CAPA. Example: CAPA -v malware.exe > exported.txt
#Run this script, import exported.txt and it will annotate (with PRE_COMMENT) and bookmark the code with Capability, Matched RVA location and Scope.
#capa detects capabilities in executable files. You run it against a PE file or shellcode and it tells you what it thinks the program can do.
#For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate.
#CAPA repo: https://github.com/fireeye/capa

#@author Jiri_Vinopal
#@category Annotation
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.listing import CodeUnit
from ghidra.program.database.bookmark import BookmarkDBManager
import re

def add_bookmark_comment(scope,capability,RVAaddr):	
	if RVAaddr == 0:
		bookmarks= getBookmarks(currentProgram.getMinAddress())
		if not bookmarks:
			minAddress = currentProgram.getMinAddress()
			createBookmark(minAddress, "CAPA_ANALYZER",scope.upper() + ': ' + capability)	
		else:
			originalCapabiliy = bookmarks[0].getComment()
			minAddress = currentProgram.getMinAddress()
			createBookmark(minAddress, "CAPA_ANALYZER",originalCapabiliy + '; ' + scope.upper() + ': ' + capability)
		
	else:
		bookmarks= getBookmarks(toAddr(RVAaddr))
		if not bookmarks:
			cu = currentProgram.getListing().getCodeUnitAt(toAddr(RVAaddr))
			createBookmark(toAddr(RVAaddr), "CAPA_ANALYZER",scope.upper() + ': ' + capability)
			cu.setComment(CodeUnit.PRE_COMMENT, "CAPA_ANALYZER: Scope - " + scope.upper() + ': ' + capability)		
		else:
			cu = currentProgram.getListing().getCodeUnitAt(toAddr(RVAaddr))
			originalPreComment = cu.getComment(CodeUnit.PRE_COMMENT)
			cu.setComment(CodeUnit.PRE_COMMENT,originalPreComment + "\n" + "CAPA_ANALYZER: Scope - " + scope.upper() + ': ' + capability)
			originalCapabiliy = bookmarks[0].getComment()
			createBookmark(toAddr(RVAaddr), "CAPA_ANALYZER",originalCapabiliy + '; ' + scope.upper() + ': ' + capability)
			
file_imported = askFile("Give me a .txt file to import!", "Import")
text_file = open(file_imported.absolutePath,'r').read()
x= text_file.split("\n\n")

for i in range(1, len(x)): 
    if x[i] != "":
        Capability = x[i].split("\n")[0]
        Capability = re.sub(r'\(.*','',Capability) 
        for j in range(1, len(x[i].split("\n"))):
            if "scope" in x[i].split("\n")[j]:
                Scope = x[i].split("\n")[j].split(" ")[-1]
            	if Scope == 'file':
            	   add_bookmark_comment(Scope,Capability,int(0))
            if "matches" in x[i].split("\n")[j]:
                Matches = []
                for k in range (j,len(x[i].split("\n"))):
                    if "0x" in x[i].split("\n")[k]:
                        Matches.append(x[i].split("\n")[k].split("0x")[-1])
                for l in range (0,len(Matches)):
		    		add_bookmark_comment(Scope,Capability,int(Matches[l], 16))
		

