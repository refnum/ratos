ratos
=====
ratos is an atos-like tool for Mach-O/DWARF address symbolification.

It is distributed under the BSD licence.


Usage
-----
    ratos.rb --app=xxx --dsym=xxxx --out=xxxx


Example
-----
    Thread 0 Crashed:
    0   AppName                  0x0000451a 0x1000 + 13260
                                 ^          ^
                   runtime address          load address
    1   CoreFoundation           0x37d7342e 0x37d60000 + 78894
    2   UIKit                    0x351ec9e4 0x351ce000 + 125412
    3   UIKit                    0x351ec9a0 0x351ce000 + 125344
	 
    $ ./ratos.rb  --app=/tmp/MyApp.app --dsym=/tmp/MyApp.app.dSYM --out=/tmp/appsym.rb
    $ ./appsym.rb --arch=armv7 --raddr=0x0000451a --laddr=0x1000
    -[CPrefsViewController pickImage:] (CPrefsViewController.mm:374)

Notes
-----
Since it invokes the Xcode developer tools, ratos requires Mac OS X.

However the output script is pure Ruby so can be run on a non-Mac OS host.

The output script can perform an address->symbol lookup for any of the architectures
that were present in the original app.


