
Running the server:
.. A pre-built binary is provided in the directory RTSMB_3.2.6/RtSMB/smb/v3.2.6/project/linuxserver
.. To run the application type: ./rtsmbserverapplication.out
.. To run the server and capture diagnostics to a file type: ./rtsmbserverapplication.out 2>filename
.. To run the server and discard diagnostics type: ./rtsmbserverapplication.out 2>/dev/null

Building the server:
.. To rebuild the server type: make clean<cr>make all

Changing default values:
.. Even though most parameters can be editted from the command line, it is convenient to permantly modify default values
.. for network address, mask etc.
.. To change defaults modify the source code RTSMB_3.2.6/RtSMB/smb/v3.2.6/source/serverexample/serverexample.c


The following text contains content pasted from the console showing how to run sth server.
Comments have been added to the text to explain things.
All comments are preceeded by <<

There different sample sessions are documented:

<< Example 1: Start a session with simple share based password protection.

<< Example 2: Start a session with user based password protection. Allow guest logins. User names are "readwr" with 
password "mypass" and "readonly" with no password.

<< Example 3: Start a session with share based password protection. Poll the console for user commands.
Demonstrates removing a share dynamically and then adding another share while the server is running.
 
Additional notes:

.. I suggest experimenting with example 1 first.
.. If you are succesful with example 1 you may want to try using the server as in example 3 to see dynamic share addition 
and removal in use.(Note: The example removes a share and then adds another. This does not imply that only one directory 
may be shared at a time. Shares can be added without first removing other shares.)
.. Managing user based password support can be awkward when running against windows clients. 
.... I haven't had a lot of luck with reliably forcing the Windows client to prompt for a user name and password when connecting to the share.
.... Configure the server to use the same user name and password that you log in to windows with.
.... Guest access can be enabled from the example application, but I have not tested that yet. I will update you when I have tested it.
.... I have tested enough with user names and passwords to feel confident but I'm not happy with our current state of the art for testing user and guest logins, due mainly to problems with the windows client I believe. I'l spend a little more time on this and update you with any new information.


The full text of the sessions are provided below. 

========================================================
<< Example 1: Start a session with share based password protection.
<< Do not poll the console for user commands.
<< Console polling is only necessary if you want to demonstrate
<< adding and removing of shares while the server is processing network traffic.
<< It is suspected that console polling may interfere with sockets IO so disable it unless
<< you are testing dynamic share addition and removal.


<< Start the server and send diagnostics to a file name servererrors.dat
./rtsmbserverapplication.out 2>servererrors.dat

<< Instructions printed by the server application.
Configure Rtsmb server...  

Press return to use defaults.. 
Use BACKSPACE to change the values.. 

Linux users: Try control B, if backspace on your terminal does not work.. 
Note: The default values can be changed by editing serverexample.c and recompiling.
=========================================================

<< Type the IP address in decimal. Backspace and then enter your values.
<< Edit the source code to reduce typing
Byte 0 IP Address: 192
Byte 1 IP Address: 168
Byte 2 IP Address: 1
Byte 3 IP Address: 9

<< Same with the mask.
<< Note: Non class C masks where broken in the previous demo.
Byte 0 IP Mask: 255
Byte 1 IP Mask: 255
Byte 2 IP Mask: 255
Byte 3 IP Mask: 0

IP Address: 192.168.1.9
IP Mask   : 255.255.255.0

Enter server name and group name. 
Note: Change the name if more than one Rtsmb server is running on the network. 

Enter server name or press return for the default : EBSRTSMB
Enter group name or press return for the default : MSHOME

Initialized rtsmb

Note: The demo does not actually print data, it just captures print data to a temporary file.

<< Press N if you do not want t printer advertised
Add a printer (y/n) ? Y

Set up printer. press enter to keep defaults. 
Printer name : SmbPrinter
Driver name : HP LaserJet 1100
Print Capture Path : /tmp
Print Capture File : SmbPrintData.prn

<< Pressing 's' <cr> in this example to used shre based passwords.
press '?' for help or ..
Press 's' for share based passwords, 'u' for user passwords: s

<< Adding a share using the default name "share0"
<< Setting the password to "mypass"
<< Setting access to read write
<< By default you can just press return for no password.
<<  If keyboard polling is enabled (see below). You can remove this share at run time by pressing return and selecting 's'.
<<  If keyboard polling is enabled You can add additional shares at run time by pressing return and selecting 'S'. 

Set up shares press enter to keep defaults. 
Share name : share0
Share Path : /usr
Share Description : Rtsmbshare
Share Password (leave empty for no passwords): mypass
0==READONLY, 1==WRITEONLY, 2==READWRITE, 3==NOACCES, 4==NO SECRITY
Share Security 0,1,2,3,4: 2

Share added.

<< Do not poll the console for user commands.
 
Type N or n to disable keyboard polling while the server is executing 
 If keyboard polling is enabled you may add and remove shares, add and remove users and display statistics
 from the console while the server is running.
 Note: Linux users should disable keyboard polling if polling appears to interfere with socket IO
Poll keyboard for commands (y/n) : N

 The Server is running.. Press control C to exit
=====================================================

<< Example 2: Start a session with user based password protection.
<< Allow guest logins
<< User names are "readwr" with password "mypass" and "readonly" with no password.

[root@localhost linuxserver]# ./rtsmbserverapplication.out 2>servererrors.dat

Configure Rtsmb server... Just press return to use defaults.. 
Press return to use defaults.. 
Use BACKSPACE to change the values.. 

Linux users: Try control B, if backspace on your terminal doe not work.. 
Note: The default values can be changed by editing serverexample.c and recompiling.
=========================================================

Byte 0 IP Address: 192
Byte 1 IP Address: 168
Byte 2 IP Address: 1
Byte 3 IP Address: 9
Byte 0 IP Mask: 255
Byte 1 IP Mask: 255
Byte 2 IP Mask: 255
Byte 3 IP Mask: 0
IP Address: 192.168.1.9
IP Mask   : 255.255.255.0
Enter server name and group name. 
Note: Change the name if more than one Rtsmb server is running on the network. 

Enter server name or press return for the default : EBSRTSMB
Enter group name or press return for the default : MSHOME

Initialized rtsmb
Note: The demo does not actually print data, it just captures print data to a temporary file.

Add a printer (y/n) ? N

press '?' for help or ..
Press 's' for share based passwords, 'u' for user passwords: u

Set up shares press enter to keep defaults. 
Share name : share0
Share Path : /usr
Share Description : Rtsmbshare

Share added.
Allow Guest login (y/n) : Y
Add users, enter a blank user name to stop adding .. 
To stop adding users press BACKSPACE until the input field is empty followed by <return>.. 
Add a new user .. 
User Name  : readwr  
Password  : mypass  
Select access rights , 'r'ead or 'rw' read-write  : rw

rtsmb_srv_register_user() succeeded.
Add a new user .. 
User Name  : readonly
Password  :         
Select access rights , 'r'ead or 'rw' read-write  : r 

rtsmb_srv_register_user() succeeded.
Add a new user .. 
User Name  :         

Type N or n to disable keyboard polling while the server is executing 
 If keyboard polling is enabled you may add and remove shares, add and remove users and display statistics
 from the console while the server is running.
 Note: Linux users should disable keyboard polling if polling appears to interfere with socket IO
Poll keyboard for commands (y/n) : N

 The Server is running.. Press control C to exit
==========================
<< Example 3: Start a session with share based password protection.
<< Poll the console for user commands.
<< Demonstrate removing a share dynamically and then adding another share while the server is running.



<< Start the server and send diagnostics to a file name servererrors.dat
./rtsmbserverapplication.out 2>servererrors.dat

<< Instructions printed by the server application.
Configure Rtsmb server...  

Press return to use defaults.. 
Use BACKSPACE to change the values.. 

Linux users: Try control B, if backspace on your terminal does not work.. 
Note: The default values can be changed by editing serverexample.c and recompiling.
=========================================================

<< Type the IP address in decimal. Backspace and then enter your values.
<< Edit the source code to reduce typing
Byte 0 IP Address: 192
Byte 1 IP Address: 168
Byte 2 IP Address: 1
Byte 3 IP Address: 9

<< Same with the mask.
<< Note: Non class C masks where broken in the previous demo.
Byte 0 IP Mask: 255
Byte 1 IP Mask: 255
Byte 2 IP Mask: 255
Byte 3 IP Mask: 0

IP Address: 192.168.1.9
IP Mask   : 255.255.255.0

Enter server name and group name. 
Note: Change the name if more than one Rtsmb server is running on the network. 

Enter server name or press return for the default : EBSRTSMB
Enter group name or press return for the default : MSHOME

Initialized rtsmb

Note: The demo does not actually print data, it just captures print data to a temporary file.

<< Press N if you do not want t printer advertised
Add a printer (y/n) ? Y

Set up printer. press enter to keep defaults. 
Printer name : SmbPrinter
Driver name : HP LaserJet 1100
Print Capture Path : /tmp
Print Capture File : SmbPrintData.prn

<< Pressing 's' <cr> in this example to used shre based passwords.
press '?' for help or ..
Press 's' for share based passwords, 'u' for user passwords: s

<< Adding a share using the default name "share0"
<< Setting the password to "mypass"
<< Setting access to read write
<< By default you can just press return for no password.
<<  If keyboard polling is enabled (see below). You can remove this share at run time by pressing return and selecting 's'.
<<  If keyboard polling is enabled You can add additional shares at run time by pressing return and selecting 'S'. 

Set up shares press enter to keep defaults. 
Share name : share0
Share Path : /usr
Share Description : Rtsmbshare
Share Password (leave empty for no passwords): mypass
0==READONLY, 1==WRITEONLY, 2==READWRITE, 3==NOACCES, 4==NO SECRITY
Share Security 0,1,2,3,4: 2

Share added.

<< Type Y to poll the console for user commands.
 
Type N or n to disable keyboard polling while the server is executing 
 If keyboard polling is enabled you may add and remove shares, add and remove users and display statistics
 from the console while the server is running.
 Note: Linux users should disable keyboard polling if polling appears to interfere with socket IO
Poll keyboard for commands (y/n) : Y

 The Server is running.. Press control C to exit
... Press return to enter a command or to quit

<< We pressed enter. this diagnostic is printed.
-Okay you got me
Press 'S' to add a share.
Press 's' to remove a share.
Press 'q' to quit.

<< type lowercase s <cr> to remove a share.
Command : s
<< type in the share to remove.
Share to remove  : share0
Removed

<< Press return again and 'S' <cr> to add a share.
-Okay you got me
Press 'S' to add a share.
Press 's' to remove a share.
Press 'q' to quit.

Command : S

<< Add a share named "newshare" attached to /usr 
<< give it a password of "newpass"
<< give it read write permission.

Set up shares press enter to keep defaults. 
Share name : newshare
Share Path : /usr
Share Description : Rtsmbnew  
Share Password (leave empty for no passwords): newpass
0==READONLY, 1==WRITEONLY, 2==READWRITE, 3==NOACCES, 4==NO SECRITY
Share Security 0,1,2,3,4: 2

Share added.
