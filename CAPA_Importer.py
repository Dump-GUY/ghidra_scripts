#This script works with exported .txt or .json results of CAPA tool.
#Simply analyze sample with CAPA. Example: CAPA -v malware.exe > exported.txt
#                                 Example: CAPA -j malware.exe > exported.json
#Run this script, import exported.txt or exported.json and it will annotate (with PRE_COMMENT) and bookmark the code with Capability, Matched RVA location and Scope.
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
import json

def Parse_json(data):
    Capabilities = list(data['rules'].keys())
    for i in range (0,len(Capabilities)):    
        Current_capability = Capabilities[i]
        Current_scope = data['rules'][Capabilities[i]]['meta']['scope']
        Matches_list = list(data['rules'][Capabilities[i]]['matches'].keys())
        if 'lib' in data['rules'][Capabilities[i]]['meta'].keys() and data['rules'][Capabilities[i]]['meta']['lib'] == True:
            pass
        else:
            if Current_scope == 'file':
                add_bookmark_comment(Current_scope,Current_capability,int(0))
            else:
                for j in range (0,len(Matches_list)):
                    add_bookmark_comment(Current_scope,Current_capability,int(Matches_list[j]))

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
			
file_imported = askFile("Give me a .txt or .json file to import!", "Import")
filename= file_imported.name
#txt import
if filename.endswith('.txt'):
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

#Json import
if filename.endswith('.json'):
    with open(file_imported.absolutePath) as f:
            data = json.load(f)		
            Parse_json(data)
else:
    print 'No .json or .txt file !!!'


