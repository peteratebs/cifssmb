
Cifs SMB Version 1.1 for Embedded FAT systems


* Copyright, Peter Van Oudenaren
*  EBS Inc. 1987-2015
* All rights reserved.
* This code may not be redistributed in source or linkable object form
* without the consent of its author.

* contact sales@ebsembeddedsoftware.com

CIFS/SMB is a fully functional SMB client and server capabilites for embedded devices.
This software has been used commercially for many years.

<b> Does not support SMBV2 and above but V2 is under development and some V2 is included</b>


Instructions:
 Building
  cifssmb\smb\project\msvs.net2003          - Old VC project, needs to be updated
  cifssmb/smb/project/linuxserver/makefile  - Linux server application
  cifssmb\smb\project\linuxclient/makefile  - Linux client application

 Running:
  Shut off firewalls or disable firewalls for all SMB ports (fill in).
    sudo service iptables stop
  Shut down samba daemons
    sudo service smbd stop
    sudo service nmdb stop

 Running the server :

 Build:
  cd /cifssmb/smb/project/linuxserver
  make clean
  make

 Run: (must run with root priveleges)
  sudo ./rtsmbserverapplication.out
   The server application will run and automatically bind to "eth0"
   If "eth0" is the wrong default you should recompile.

   Select s for share based passwords  (u will work as well)
   Now select the default share:
     By default /media is exported as share0 but you can edit it to, for example, /home

   Now select a password for the share (mypassword) in this case:
     Share Password (leave empty for no passwords): mypassword
   Next choose read_write.

   Next select Y/N at the follwoing prompt:
     Poll keyboard for commands (y/n) : Y
    Answering Y allows you to do things like add more shares (press return to show help).
    The Y option may cause  problems corrupting data packets under heavy loads, if things behave badly restart and select the N option.

    Now from Windows command line (for example, with the server running on 192.168.1.8)
    type:
      net use z: \\192.168.1.8\share0 mypassword
    type a DIR command and you should see a directory listing:
      dir z:
        Volume in drive Z is RTSMB VOL
        Volume Serial Number is 000F-AD32
        ..

    To view the share from Windows file explorer, paste this to the URL bar:

       \\192.168.1.8\share0


 Running the client :

    Needs update.
