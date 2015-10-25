
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

<br>
Instructions:<br>
 Building<br>
  cifssmb\smb\project\msvs.net2003          - Old VC project, needs to be updated<br>
  cifssmb/smb/project/linuxserver/makefile  - Linux server application<br>
  cifssmb\smb\project\linuxclient/makefile  - Linux client application<br><br>
<br>
 Running:<br>
  Shut off firewalls or disable firewalls for all SMB ports (fill in).<br>
    sudo service iptables stop<br>
  Shut down samba daemons<br>
    sudo service smbd stop<br>
    sudo service nmdb stop<br><br>
<br>
 Running the server :<br>
<br>
 Build:<br>
  The makefile forces it to build a 32 bit application.
   This should be fixed, but for now it must be built as a 32 bit application.

   These packages must be installed:
     sudo apt-get install libc6-dev-i386
     sudo apt-get install g++-multilib

  cd /cifssmb/smb/project/linuxserver<br>
  make clean<br>
  make<br>
<br>
 Run: (must run with root priveleges)<br>
  sudo ./rtsmbserverapplication.out<br>
   The server application will run and automatically bind to "eth0"<br>
   If "eth0" is the wrong default you should recompile.<br>
<br>
   Select s for share based passwords  (u will work as well)<br>
   Now select the default share:<br>
     By default /media is exported as share0 but you can edit it to, for example, /home<br>
<br>
   Now select a password for the share (mypassword) in this case:<br>
     Share Password (leave empty for no passwords): mypassword<br>
   Next choose read_write.<br>
<br>
   Next select Y/N at the follwoing prompt:<br>
     Poll keyboard for commands (y/n) : Y<br>
    Answering Y allows you to do things like add more shares (press return to show help).<br>
    The Y option may cause  problems corrupting data packets under heavy loads, if things behave badly restart and select the N option.<br>
<br>
    Now from Windows command line (for example, with the server running on 192.168.1.8)<br>
    type:<br>
      net use z: \\192.168.1.8\share0 mypassword<br>
    type a DIR command and you should see a directory listing:<br>
      dir z:<br>
        Volume in drive Z is RTSMB VOL<br>
        Volume Serial Number is 000F-AD32<br>
        ..<br>
<br>
    To view the share from Windows file explorer, paste this to the URL bar:<br>
       \\192.168.1.8\share0<br>

 Running the client :<br>
    Needs update.<br>
