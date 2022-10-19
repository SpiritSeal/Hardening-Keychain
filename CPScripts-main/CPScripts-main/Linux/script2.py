## Firewall, users, files, software, password config, update
## Key files: PAM files (passwords), sysctl.conf (network policies)
import subprocess
import time
import os
import pickle

def s2r(process):
    return process.split()

class auto:
    def __init__(self):
        self.options={1:'r.fw()', 2:'r.f_sft()', 3:'r.pswd()', 4:'r.usr()', 5:'r.upd()', 6:'r.pre()', 7:'r.extras()'}
        self.numbs=[1, 2, 3, 4, 5, 6, 7]
        self.uo="1. Firewall, 2. Files+Software, 3. Passwords, 4. Users, 5. Update, 6. Prequisites!, 7. Extras (CIS)"
        self.sysctl='''#
# /etc/sysctl.conf - Configuration file for setting system variables
# See /etc/sysctl.d/ for additional system variables.
# See sysctl.conf (5) for information.
#

#kernel.domainname = example.com

# Uncomment the following to stop low-level messages on console
#kernel.printk = 3 4 1 3

##############################################################3
# Functions previously found in netbase
#

# Uncomment the next two lines to enable Spoof protection (reverse-path filter)
# Turn on Source Address Verification in all interfaces to
# prevent some spoofing attacks
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1

# Uncomment the next line to enable TCP/IP SYN cookies
# See http://lwn.net/Articles/277146/
# Note: This may impact IPv6 TCP sessions too
net.ipv4.tcp_syncookies=1

# Uncomment the next line to enable packet forwarding for IPv4
#net.ipv4.ip_forward=1

# Uncomment the next line to enable packet forwarding for IPv6
#  Enabling this option disables Stateless Address Autoconfiguration
#  based on Router Advertisements for this host
#net.ipv6.conf.all.forwarding=1


###################################################################
# Additional settings - these settings can improve the network
# security of the host and prevent against some network attacks
# including spoofing attacks and man in the middle attacks through
# redirection. Some network environments, however, require that these
# settings are disabled so review and enable them as needed.
#
# Do not accept ICMP redirects (prevent MITM attacks)
net.ipv4.conf.all.accept_redirects = 0
#net.ipv6.conf.all.accept_redirects = 0
# _or_
# Accept ICMP redirects only for gateways listed in our default
# gateway list (enabled by default)
net.ipv4.conf.all.secure_redirects = 0
#
# Do not send ICMP redirects (we are not a router)
net.ipv4.conf.all.send_redirects = 0
#
# Do not accept IP source route packets (we are not a router)
net.ipv4.conf.all.accept_source_route = 0
#net.ipv6.conf.all.accept_source_route = 0
#
# Log Martian Packets
net.ipv4.conf.all.log_martians = 1
#
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

###################################################################
# Magic system request Key
# 0=disable, 1=enable all, >1 bitmask of sysrq functions
# See https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html
# for what other values do
#kernel.sysrq=438
'''

## Seperator
## Seperator

        self.pamcomat='''#
# /etc/pam.d/common-auth - authentication settings common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of the authentication modules that define
# the central authentication scheme for use on the system
# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the
# traditional Unix authentication mechanisms.
#
# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.
# To take advantage of this, it is recommended that you configure any
# local modules either before or after the default block, and use
# pam-auth-update to manage selection of other modules.  See
# pam-auth-update(8) for details.

# here are the per-package modules (the "Primary" block)
auth	[success=1 default=ignore]	pam_unix.so nullok_secure
# here's the fallback if no module succeeds
auth	requisite			pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
auth	required			pam_permit.so
# and here are more per-package modules (the "Additional" block)
auth	optional			pam_cap.so 
auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800
# end of pam-auth-update config
'''

## Seperator

        self.pamconf='''#
# /etc/pam.d/common-password - password-related modules common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of modules that define the services to be
# used to change user passwords.  The default is pam_unix.

# Explanation of pam_unix options:
#
# The "sha512" option enables salted SHA512 passwords.  Without this option,
# the default is Unix crypt.  Prior releases used the option "md5".
#
# The "obscure" option replaces the old `OBSCURE_CHECKS_ENAB' option in
# login.defs.
#
# See the pam_unix manpage for other options.

# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.
# To take advantage of this, it is recommended that you configure any
# local modules either before or after the default block, and use
# pam-auth-update to manage selection of other modules.  See
# pam-auth-update(8) for details.

# here are the per-package modules (the "Primary" block)
password	requisite			pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass sha512 minlen=8 remember=5
# here's the fallback if no module succeeds
password	requisite			pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
password	required			pam_permit.so
# and here are more per-package modules (the "Additional" block)
password	optional	pam_gnome_keyring.so 
# end of pam-auth-update config
'''

## Just as a seperator.

        self.pswdpol='''#
# /etc/login.defs - Configuration control definitions for the login package.
#
# Three items must be defined:  MAIL_DIR, ENV_SUPATH, and ENV_PATH.
# If unspecified, some arbitrary (and possibly incorrect) value will
# be assumed.  All other items are optional - if not specified then
# the described action or option will be inhibited.
#
# Comment lines (lines beginning with "#") and blank lines are ignored.
#
# Modified for Linux.  --marekm

# REQUIRED for useradd/userdel/usermod
#   Directory where mailboxes reside, _or_ name of file, relative to the
#   home directory.  If you _do_ define MAIL_DIR and MAIL_FILE,
#   MAIL_DIR takes precedence.
#
#   Essentially:
#      - MAIL_DIR defines the location of users mail spool files
#        (for mbox use) by appending the username to MAIL_DIR as defined
#        below.
#      - MAIL_FILE defines the location of the users mail spool files as the
#        fully-qualified filename obtained by prepending the user home
#        directory before $MAIL_FILE
#
# NOTE: This is no more used for setting up users MAIL environment variable
#       which is, starting from shadow 4.0.12-1 in Debian, entirely the
#       job of the pam_mail PAM modules
#       See default PAM configuration files provided for
#       login, su, etc.
#
# This is a temporary situation: setting these variables will soon
# move to /etc/default/useradd and the variables will then be
# no more supported
MAIL_DIR        /var/mail
#MAIL_FILE      .mail

#
# Enable logging and display of /var/log/faillog login failure info.
# This option conflicts with the pam_tally PAM module.
#
FAILLOG_ENAB		yes

#
# Enable display of unknown usernames when login failures are recorded.
#
# WARNING: Unknown usernames may become world readable. 
# See #290803 and #298773 for details about how this could become a security
# concern
LOG_UNKFAIL_ENAB	no

#
# Enable logging of successful logins
#
LOG_OK_LOGINS		no

#
# Enable "syslog" logging of su activity - in addition to sulog file logging.
# SYSLOG_SG_ENAB does the same for newgrp and sg.
#
SYSLOG_SU_ENAB		yes
SYSLOG_SG_ENAB		yes

#
# If defined, all su activity is logged to this file.
#
#SULOG_FILE	/var/log/sulog

#
# If defined, file which maps tty line to TERM environment parameter.
# Each line of the file is in a format something like "vt100  tty01".
#
#TTYTYPE_FILE	/etc/ttytype

#
# If defined, login failures will be logged here in a utmp format
# last, when invoked as lastb, will read /var/log/btmp, so...
#
FTMP_FILE	/var/log/btmp

#
# If defined, the command name to display when running "su -".  For
# example, if this is defined as "su" then a "ps" will display the
# command is "-su".  If not defined, then "ps" would display the
# name of the shell actually being run, e.g. something like "-sh".
#
SU_NAME		su

#
# If defined, file which inhibits all the usual chatter during the login
# sequence.  If a full pathname, then hushed mode will be enabled if the
# user's name or shell are found in the file.  If not a full pathname, then
# hushed mode will be enabled if the file exists in the user's home directory.
#
HUSHLOGIN_FILE	.hushlogin
#HUSHLOGIN_FILE	/etc/hushlogins

#
# *REQUIRED*  The default PATH settings, for superuser and normal users.
#
# (they are minimal, add the rest in the shell startup files)
ENV_SUPATH	PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH	PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

#
# Terminal permissions
#
#	TTYGROUP	Login tty will be assigned this group ownership.
#	TTYPERM		Login tty will be set to this permission.
#
# If you have a "write" program which is "setgid" to a special group
# which owns the terminals, define TTYGROUP to the group number and
# TTYPERM to 0620.  Otherwise leave TTYGROUP commented out and assign
# TTYPERM to either 622 or 600.
#
# In Debian /usr/bin/bsd-write or similar programs are setgid tty
# However, the default and recommended value for TTYPERM is still 0600
# to not allow anyone to write to anyone else console or terminal

# Users can still allow other people to write them by issuing 
# the "mesg y" command.

TTYGROUP	tty
TTYPERM		0600

#
# Login configuration initializations:
#
#	ERASECHAR	Terminal ERASE character ('\010' = backspace).
#	KILLCHAR	Terminal KILL character ('\025' = CTRL/U).
#	UMASK		Default "umask" value.
#
# The ERASECHAR and KILLCHAR are used only on System V machines.
# 
# UMASK is the default umask value for pam_umask and is used by
# useradd and newusers to set the mode of the new home directories.
# 022 is the "historical" value in Debian for UMASK
# 027, or even 077, could be considered better for privacy
# There is no One True Answer here : each sysadmin must make up his/her
# mind.
#
# If USERGROUPS_ENAB is set to "yes", that will modify this UMASK default value
# for private user groups, i. e. the uid is the same as gid, and username is
# the same as the primary group name: for these, the user permissions will be
# used as group permissions, e. g. 022 will become 002.
#
# Prefix these values with "0" to get octal, "0x" to get hexadecimal.
#
ERASECHAR	0177
KILLCHAR	025
UMASK		027

#
# Password aging controls:
#
#	PASS_MAX_DAYS	Maximum number of days a password may be used.
#	PASS_MIN_DAYS	Minimum number of days allowed between password changes.
#	PASS_WARN_AGE	Number of days warning given before a password expires.
#
PASS_MAX_DAYS	90
PASS_MIN_DAYS	7
PASS_WARN_AGE	14

#
# Min/max values for automatic uid selection in useradd
#
UID_MIN			  999
UID_MAX			60000
# System accounts
#SYS_UID_MIN		  100
#SYS_UID_MAX		  999

#
# Min/max values for automatic gid selection in groupadd
#
GID_MIN			  999
GID_MAX			60000
# System accounts
#SYS_GID_MIN		  100
#SYS_GID_MAX		  999

#
# Max number of login retries if password is bad. This will most likely be
# overriden by PAM, since the default pam_unix module has it's own built
# in of 3 retries. However, this is a safe fallback in case you are using
# an authentication module that does not enforce PAM_MAXTRIES.
#
LOGIN_RETRIES		5

#
# Max time in seconds for login
#
LOGIN_TIMEOUT		60

#
# Which fields may be changed by regular users using chfn - use
# any combination of letters "frwh" (full name, room number, work
# phone, home phone).  If not defined, no changes are allowed.
# For backward compatibility, "yes" = "rwh" and "no" = "frwh".
# 
CHFN_RESTRICT		rwh

#
# Should login be allowed if we can't cd to the home directory?
# Default in no.
#
DEFAULT_HOME	yes

#
# If defined, this command is run when removing a user.
# It should remove any at/cron/print jobs etc. owned by
# the user to be removed (passed as the first argument).
#
#USERDEL_CMD	/usr/sbin/userdel_local

#
# Enable setting of the umask group bits to be the same as owner bits
# (examples: 022 -> 002, 077 -> 007) for non-root users, if the uid is
# the same as gid, and username is the same as the primary group name.
#
# If set to yes, userdel will remove the user's group if it contains no
# more members, and useradd will create by default a group with the name
# of the user.
#
USERGROUPS_ENAB yes

#
# Instead of the real user shell, the program specified by this parameter
# will be launched, although its visible name (argv[0]) will be the shell's.
# The program may do whatever it wants (logging, additional authentification,
# banner, ...) before running the actual shell.
#
# FAKE_SHELL /bin/fakeshell

#
# If defined, either full pathname of a file containing device names or
# a ":" delimited list of device names.  Root logins will be allowed only
# upon these devices.
#
# This variable is used by login and su.
#
#CONSOLE	/etc/consoles
#CONSOLE	console:tty01:tty02:tty03:tty04

#
# List of groups to add to the user's supplementary group set
# when logging in on the console (as determined by the CONSOLE
# setting).  Default is none.
#
# Use with caution - it is possible for users to gain permanent
# access to these groups, even when not logged in on the console.
# How to do it is left as an exercise for the reader...
#
# This variable is used by login and su.
#
#CONSOLE_GROUPS		floppy:audio:cdrom

#
# If set to "yes", new passwords will be encrypted using the MD5-based
# algorithm compatible with the one used by recent releases of FreeBSD.
# It supports passwords of unlimited length and longer salt strings.
# Set to "no" if you need to copy encrypted passwords to other systems
# which don't understand the new algorithm.  Default is "no".
#
# This variable is deprecated. You should use ENCRYPT_METHOD.
#
#MD5_CRYPT_ENAB	no

#
# If set to MD5 , MD5-based algorithm will be used for encrypting password
# If set to SHA256, SHA256-based algorithm will be used for encrypting password
# If set to SHA512, SHA512-based algorithm will be used for encrypting password
# If set to DES, DES-based algorithm will be used for encrypting password (default)
# Overrides the MD5_CRYPT_ENAB option
#
# Note: It is recommended to use a value consistent with
# the PAM modules configuration.
#
ENCRYPT_METHOD SHA512

#
# Only used if ENCRYPT_METHOD is set to SHA256 or SHA512.
#
# Define the number of SHA rounds.
# With a lot of rounds, it is more difficult to brute forcing the password.
# But note also that it more CPU resources will be needed to authenticate
# users.
#
# If not specified, the libc will choose the default number of rounds (5000).
# The values must be inside the 1000-999999999 range.
# If only one of the MIN or MAX values is set, then this value will be used.
# If MIN > MAX, the highest value will be used.
#
# SHA_CRYPT_MIN_ROUNDS 5000
# SHA_CRYPT_MAX_ROUNDS 5000

################# OBSOLETED BY PAM ##############
#						#
# These options are now handled by PAM. Please	#
# edit the appropriate file in /etc/pam.d/ to	#
# enable the equivelants of them.
#
###############

#MOTD_FILE
#DIALUPS_CHECK_ENAB
#LASTLOG_ENAB
#MAIL_CHECK_ENAB
#OBSCURE_CHECKS_ENAB
#PORTTIME_CHECKS_ENAB
#SU_WHEEL_ONLY
#CRACKLIB_DICTPATH
#PASS_CHANGE_TRIES
#PASS_ALWAYS_WARN
#ENVIRON_FILE
#NOLOGINS_FILE
#ISSUE_FILE
#PASS_MIN_LEN
#PASS_MAX_LEN
#ULIMIT
#ENV_HZ
#CHFN_AUTH
#CHSH_AUTH
#FAIL_DELAY

################# OBSOLETED #######################
#						  #
# These options are no more handled by shadow.    #
#                                                 #
# Shadow utilities will display a warning if they #
# still appear.                                   #
#                                                 #
###################################################

# CLOSE_SESSIONS
# LOGIN_STRING
# NO_PASSWORD_CONSOLE
# QMAIL_DIR


'''
    def ask(self):
        while True:
            print(self.uo)
            self.job=int(input("What do you want to do?"))
            if self.job in self.numbs:
                eval(str(self.options[self.job]))
                break

    def upd(self):
        subprocess.run(s2r("add-apt-repository -y ppa:libreoffice/ppa"))
        subprocess.run(s2r("apt-get update && sudo apt-get upgrade"))
        subprocess.run(s2r("apt-get dist-upgrade -y"))
        subprocess.run(s2r("apt-get --purge --reinstall install firefox -y"))
        subprocess.run(s2r("apt-get autoclean"))
        subprocess.run(s2r("apt-get install --only-upgrade bash"))
        subprocess.run(s2r("apt-get upgrade"))
        print("Enable all updates w/ security in GUI and then rerun")
    def usr(self):
        os.system("cat /etc/group | grep sudo")
        print("These are the admins. Change them manually")
        users=os.popen('cut -d: -f1 /etc/passwd').read().split()
        print("Bad users, they should be deleted.")
        ##append authorized users to the 'auth' list >
        auth='''root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
systemd-network
systemd-resolve
syslog
messagebus
_apt
uuidd
avahi-autoipd
usbmux
dnsmasq
rtkit
cups-pk-helper
speech-dispatcher
whoopsie
kernoops
saned
avahi
colord
hplip
geoclue
pulse
gnome-initial-setup
gdm
lightdm
clamav
hypnos
thanatos
megaera
eurydice
orpheus
sisyphus
charon
achilles
dusa
broker
skelly
chaos
hades
persephone
nyx
zagreus
        '''.split()
        for i in range(0, len(users)):
            if users[i] not in auth:
                print(users[i])

    def pswd(self):
        subprocess.run(s2r("chmod u+w /etc/pam.d/common-password /etc/login.defs /etc/pam.d/common-auth"))
        subprocess.run(s2r("cp /etc/pam.d/common-password /etc/pam.d/common-password-1"))
        subprocess.run(s2r("cp /etc/pam.d/common-auth /etc/pam.d/common-auth-1"))
        com_pass=open('/etc/pam.d/common-password', 'w')
        com_aut=open('/etc/pam.d/common-auth', 'w')
        log_defs=open('/etc/login.defs', 'w')
        a=com_pass.write(str(self.pamconf))
        b=com_aut.write(str(self.pamcomat))
        c=log_defs.write(str(self.pswdpol))
        log_defs.close()
        com_aut.close()
        com_pass.close()
        subprocess.run(s2r("chmod u-w /etc/pam.d/common-password /etc/login.defs /etc/pam.d/common-auth"))
        
    def f_sft(self):
        os.system('touch /home/files.txt')
        ftypes=['.txt', '.jpg', '.jpeg', '.pdf', '.png', '.stl', '.xcf', '.php', '.zip', '.tar.gz', '.gif', '.wav', '.mp3', '.mp4', 'gif']
        for x in range(0, len(ftypes)):
            os.system("find /home/ -name *'%s' >> /home/files.txt" % ftypes[x])
        subprocess.run(s2r("sudo apt-get remove pure-ftpd"))
        subprocess.run(s2r("sudo apt-get autoremove -y --purge john nmap zenmap hydra samba nginx "))
        subprocess.run(s2r("sudo apt-get remove --purge *game*"))
        
    def fw(self):
        subprocess.run(s2r("apt-get install ufw"))
        subprocess.run(s2r("apt-get install clamtk"))
        subprocess.run(s2r("ufw enable"))
        subprocess.run(s2r("apt-get install auditd"))
        subprocess.run(s2r("auditctl –e 1"))
        clam=str(input("Do you want to scan for viruses now? (y/n)"))
        if clam=="n":
            pass
        if clam=="y":
            subprocess.run(s2r("clamscan -r /home/"))
        else:
            pass

    def pre(self):
        subprocess.run(s2r("apt-get install libpam-cracklib"))
        subprocess.run(s2r("apt-get install auditd"))
        subprocess.run(s2r("apt-get install clamtk -y"))

    def extras(self):
        fsys=['cramfs', 'freevxfs', 'jffs2', 'hfs', 'hfsplus', 'udf']
        for x in range(0, len(fsys)):
            os.system('touch /etc/modprobe.d/%s.conf' % fsys[x])
            os.system('echo "install %s /bin/true" > /etc/modprobe.d/%s.conf' % (fsys[x], fsys[x]))
            subprocess.run(s2r("rmmod %s" % fsys[x]))

        os.system("cp -v /usr/share/systemd/tmp.mount /etc/systemd/system/")
        os.system('''cat<<EOF
[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,nosuid,nodev,noexec
EOF > /etc/systemd/system/tmp.mount''')
        subprocess.run(s2r("systemctl daemon-reload"))
        subprocess.run(s2r("systemctl --now enable tmp.mount"))

        subprocess.run(s2r("mount -o remount,nodev /tmp"))
        subprocess.run(s2r("mount -o remount,nosuid /tmp"))
        subprocess.run(s2r("mount -o remount,noexec /tmp"))
        subprocess.run(s2r("echo 'tmpfs    /dev/shm    tmpfs    defaults,noexec,nodev,nosuid,seclabel    0 0' >> /etc/fstab"))
        subprocess.run(s2r("mount -o remount,noexec,nodev,nosuid /dev/shm"))
        subprocess.run(s2r("mount -o remount,nodev /home"))
        ##Location marker
        subprocess.run(s2r("systemctl --now disable autofs"))
        subprocess.run(s2r("install usb-storage /bin/true"))
        subprocess.run(s2r("rmmod usb-storage"))
        subprocess.run(s2r("apt install aide aide-common"))
        ##subprocess.run(s2r("aideinit"))
        subprocess.run(s2r("mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"))
        ##              subprocess.run(s2r(""))
        subprocess.run(s2r('''sed -ri 's/chmod\s+[0-7][0-7][0-7]\s+\$\{grub_cfg\}\.new/chmod 400 ${grub_cfg}.new/' /usr/sbin/grub-mkconfig'''))
        subprocess.run(s2r('''sed -ri 's/ && ! grep "\^password" \$\{grub_cfg\}.new >\/dev\/null//' /usr/sbin/grub-mkconfig'''))
        subprocess.run(s2r("chown root:root /boot/grub/grub.cfg"))
        subprocess.run(s2r("chmod u-wx,go-rwx /boot/grub/grub.cfg"))
        subprocess.run(s2r("passwd root"))
##        subprocess.run(s2r("prelink -ua"))
        subprocess.run(s2r("apt purge prelink"))
        subprocess.run(s2r("apt install apparmor"))
        subprocess.run(s2r('''echo "GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"" >> /etc/default/grub'''))
        subprocess.run(s2r("update-grub"))
##        subprocess.run(s2r("apparmor --enforce /etc/apparmor.d/*"))
        subprocess.run(s2r("rm /etc/motd"))
        subprocess.run(s2r("chown root:root /etc/issue.net"))
        subprocess.run(s2r("chmod u-x,go-wx /etc/issue.net"))
        subprocess.run(s2r("chown root:root /etc/issue"))
        subprocess.run(s2r("chmod u-x,go-wx /etc/issue"))
        subprocess.run(s2r("chown root:root /etc/motd"))
        subprocess.run(s2r("chmod u-x,go-wx /etc/motd"))
        subprocess.run(s2r('''echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net'''))
        subprocess.run(s2r('''echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue'''))
        subprocess.run(s2r("apt purge gdm3"))
        os.system("touch /etc/gdm3/greeter.dconf-defaults")
        subprocess.run(s2r('''echo "[org/gnome/login-screen]
banner-message-enable=true\nbanner-message-text='<banner message>'
disable-user-list=true' >> /etc/gdm3/greeter.dconf-defaults'''))
        subprocess.run(s2r("dpkg-reconfigure gdm3"))
        os.system("touch /etc/gdm3/greeter.dconf-defaults")
        subprocess.run(s2r('''echo "[org/gnome/login-screen]
banner-message-enable=true\nbanner-message-text='<banner message>'
disable-user-list=true" >> /etc/gdm3/greeter.dconf-defaults'''))
        subprocess.run(s2r("dpkg-reconfigure gdm3"))
        ##2.1.1.1
        subprocess.run(s2r("apt install chrony"))
        subprocess.run(s2r("apt purge xserver-xorg*"))
        subprocess.run(s2r("systemctl stop avahi-daaemon.service"))
        subprocess.run(s2r("systemctl stop avahi-daemon.socket"))
        subprocess.run(s2r("apt purge avahi-daemon"))
        subprocess.run(s2r("apt purge cups"))
        ##              subprocess.run(s2r(""))
        subprocess.run(s2r("apt purge isc-dhcp-server"))
        subprocess.run(s2r("apt purge slapd"))
        subprocess.run(s2r("apt purge nfs-kernel-server"))
        subprocess.run(s2r("apt purge bind9"))
        subprocess.run(s2r("apt purge vsftpd"))
        subprocess.run(s2r("apt purge apache2"))
        subprocess.run(s2r("apt purge dovecot-imapd dovecot-pop3d"))
        subprocess.run(s2r("apt purge samba"))
        subprocess.run(s2r("apt purge squid"))
        subprocess.run(s2r("apt purge snmpd"))
        subprocess.run(s2r("apt purge rsync"))
        subprocess.run(s2r("apt purge nis"))
        subprocess.run(s2r("apt purge rsh-client"))
        subprocess.run(s2r("apt purge talk"))
        subprocess.run(s2r("apt purge telnet"))
        subprocess.run(s2r("apt purge ldap-utils"))
        subprocess.run(s2r("apt purge rpcbind"))
        subprocess.run(s2r('''grep -Els "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv4\.ip_forward\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; sysctl -w net.ipv4.ip_forward=0; sysctl -w net.ipv4.route.flush=1'''))
        subprocess.run(s2r("chmod u+w /etc/sysctl.conf"))
        subprocess.run(s2r("cp /etc/sysctl.conf /etc/sysctl.conf.1"))
        sysconf=open('/etc/sysctl.conf', 'w')
        d=sysconf.write(str(self.sysctl))
        sysconf.close()
        subprocess.run(s2r("chmod u-w /etc/sysctl.conf"))
        subprocess.run(s2r("apt purge iptables-persistent"))
        subprocess.run(s2r("ufw allow in on lo"))
        subprocess.run(s2r("ufw allow out on lo"))
        subprocess.run(s2r("ufw deny in from 127.0.0.0/8"))
        subprocess.run(s2r("ufw deny in from ::1"))
        subprocess.run(s2r("ufw allow out on all"))
        ##              subprocess.run(s2r(""))
        subprocess.run(s2r("ufw default deny routed"))
        ##Auditing is a level 2 fix. I'lll proceed. (4.1.1.2)
        subprocess.run(s2r("apt install auditd audispd-plugins"))
        subprocess.run(s2r("systemctl --now enable auditd"))
        os.system("touch /etc/audit/rules.d/50-time-change.rules")
        os.system('''echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change" > /etc/audit/rules.d/50-time-change.rules''')
        os.system("touch /etc/audit/rules.d/50-identity.rules")
        os.system('''echo "-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/security/opasswd -p wa -k identity" > /etc/audit/rules.d/50-identity.rules''')
        os.system("touch /etc/audit/rules.d/50-system-locale.rules")
        os.system('''echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale" > /etc/audit/rules.d/50-system-locale.rules''')
        os.system("touch /etc/audit/rules.d/50-MAC-policy.rules")
        os.system('''echo "-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy" > /etc/audit/rules.d/50-MAC-policy.rules''')
        os.system("touch /etc/audit/rules.d/50-logins.rules")
        os.system('''echo "-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins" > /etc/audit/rules.d/50-logins.rules''')
        os.system("touch /etc/audit/rules.d/50-session.rules")
        os.system('''echo "-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins" > /etc/audit/rules.d/50-session.rules''')
        os.system('touch /etc/audit/rules.d/50-perm_mod.rules')
        os.system('''echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295
-k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295
-k perm_mod" > /etc/audit/rules.d/50-perm_mod.rules''')
        os.system("touch /etc/audit/rules.d/50-access.rules")
        os.system('''echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" > /etc/audit/rules.d/50-access.rules''')
        os.system("touch /etc/audit/rules.d/50-mounts.rules")
        os.system('''echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" > /etc/audit/rules.d/50-mounts.rules''')
        os.system("touch /etc/audit/rules.d/50-delete.rules")
        os.system('''echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" > /etc/audit/rules.d/50-delete.rules''')
        os.system("touch /etc/audit/rules.d/50-scope.rules")
        os.system('''echo "-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope" > /etc/audit/rules.d/50-scope.rules''')
        os.system("touch /etc/audit/rules.d/50-actions.rules")
        os.system('''echo "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions
-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions" > /etc/audit/rules.d/50-actions.rules''')
        os.system("touch /etc/audit/rules.d/50-modules.rules")
        os.system('''echo "-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules\n-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" > /etc/audit/rules.d/50-modules.rules''')
        os.system("touch /etc/audit/rules.d/99-finalize.rules")
        os.system("echo '-e 2' > /etc/audit/rules.d/99-finalize.rules")
        subprocess.run(s2r("apt install rsyslog"))
        subprocess.run(s2r("systemctl --now enable rsyslog"))
        subprocess.run(s2r('''find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx {} +'''))
        subprocess.run(s2r("systemctl --now enable cron"))
        subprocess.run(s2r("chown root:root /etc/crontab"))
        subprocess.run(s2r("chmod og-rwx /etc/crontab"))
        subprocess.run(s2r("chown root:root /etc/cron.hourly/"))
        subprocess.run(s2r("chmod og-rwx /etc/cron.hourly/"))
        subprocess.run(s2r("chown root:root /etc/cron.daily/"))
        subprocess.run(s2r("chmod og-rwx /etc/cron.daily/"))
        subprocess.run(s2r("chown root:root /etc/cron.weekly/"))
        subprocess.run(s2r("chmod og-rwx /etc/cron.weekly/"))
        subprocess.run(s2r("chown root:root /etc/cron.monthly/"))
        subprocess.run(s2r("chmod og-rwx /etc/cron.monthly/"))
        subprocess.run(s2r("chown root:root /etc/cron.d/"))
        subprocess.run(s2r("chmod og-rwx /etc/cron.d/"))
        subprocess.run(s2r("rm /etc/cron.deny"))
        os.system("touch /etc/cron.allow")
        subprocess.run(s2r("chmod g-wx,o-rwx /etc/cron.allow"))
        subprocess.run(s2r("chown root:root /etc/cron.allow"))
        subprocess.run(s2r("rm /etc/at.deny"))
        os.system("touch /etc/at.allow")
        subprocess.run(s2r("chmod g-wx,o-rwx /etc/at.allow"))
        subprocess.run(s2r("chown root:root /etc/at.allow"))
        subprocess.run(s2r("apt install sudo"))
        subprocess.run(s2r("echo 'Defaults use_pty' >> /etc/sudoers"))
        subprocess.run(s2r("chown root:root /etc/ssh/sshd_config"))
        subprocess.run(s2r("chmod og-rwx /etc/ssh/sshd_config"))
        subprocess.run(s2r('''find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;'''))
        subprocess.run(s2r("find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,go-rwx {} \;"))
        subprocess.run(s2r("find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} \;"))
        subprocess.run(s2r("find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;"))
        subprocess.run(s2r("useradd -D -f 30"))
        subprocess.run(s2r("usermod -g 0 root"))
        






        
r=auto()
r.ask()
