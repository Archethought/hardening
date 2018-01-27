#!/bin/bash -e
# run as root


#### Linux Hardening Settings

##############################
# ERROR HANDLING
#
# QUESTION &| tee -a occludes the error signal so the trap is not triggered
#  &>> sends nothing to std out. 
# Think the best option is to echo all to terminal & tee to log file from there

# Pipe any actionable items to a log file specific for that purpose
LOGFILE=piH.log

# /bin/bash -e causes script to exit upon non-zero exit code. Might not ultimately be what we want.

error() 
{
	# https://stackoverflow.com/questions/64786/error-handling-in-bash
	# -lots of good ideas in this thread
	
	local parent_lineno="$1"
	local message="$2"
	local code="${3:-1}"
	if [[ -n "$message" ]] ; then
		echo "Error on or near line ${parent_lineno}: ${message}; exiting with status ${code}" 
	else
		echo "Error on or near line ${parent_lineno}; exiting with status ${code}"
	fi
	exit "${code}"
}

#trap 'echo "Encountered exit signal; closing script" | tee -a $LOGFILE' INT TERM EXIT
trap 'error ${LINENO} | tee -a $LOGFILE' ERR INT TERM EXIT

##############################
# NOTES 
# meaning of which mostly now escapes me

#nubs inits card with partitioning with option to download image. 10 options exist, 'debian stretch' is what we use
# Ensure US instead of UK (default)
#sdformatter

function set_var
{
	# Set variable value within a file.
	# Add line if variable does not exist, modify if it does.
	# Usage:
	#	set_var var delimeter value filename
	
	var=$1
	delimeter=$2 #(= or space)
	value=$3
	filename=$4

	
	if grep -q "^[ \t]*${var}" ${filename}
	then
		pat="/^[ \t]*${var}/s/${delimeter}.*$/${delimeter}${value}/"
		sed -i "${pat}" ${filename}
	else
		echo ${var}${delimeter}${value} | cat >> ${filename}
	fi	
}
##############################
# HARDENING METHODS

function secure_passwords
{
	# Might merge this with secure_logins, the root password section
	#
	# libpam_cracklib is a PAM module that tests password strength
	#
	# TODO/QUESTION Can't install to test on my VM; moving on for now. Getting
	# E: Could not get lock /var/lib/dpkg/lock - open (11: Resource temporarily unavailable)
	# E: Unable to lock the administration directory (/var/lib/dpkg/), is another process using it?
    #

	#Install the libpam-cracklib package:
	apt-get install libpam-cracklib 
	
	#Set the pam_cracklib.so parameters as follows in /etc/pam.d/common-password: 
	#password required pam_cracklib.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
	
	#Edit the /etc/pam.d/login file and add the auth line below: 
	#auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
	
	#Set the pam_unix.so remember parameter to 5 in /etc/pam.d/common-password: 
	#password [success=1 default=ignore] pam_unix.so obscure sha512 remember=5

}

function interactive_tasks
{
	#Create a boot password
	# generates password hashes for GRUB
	# TODO requires interaction
	grub-mkpasswd-pbkdf2 
	#Enter password: Reenter password: Your PBKDF2 is

	#Make sure the root user has a password set
	#TODO requires interaction
	passwd root

}

function secure_logins
{
	# Do permission related stuff here

	#Set User/Group Owner on bootloader config
	chown root:root /boot/grub/grub.cfg
	chmod og-rwx /boot/grub/grub.cfg


	#Add the following line to the /etc/sysctl.conf file. 
	echo "kernel.randomize_va_space = 2" | cat >> /etc/sysctl.conf

	#TODO - document
	/usr/sbin/prelink –ua
	apt-get purge nis

}
function secure_misc_login_and_pswd_stuff
{
	# Put all login & password activities together, or better delineate.

	# add the following line to the /etc/pam.d/su file. auth required pam_wheel.so use_uid Once this is done, create a comma separated list of users in the wheel statement in the /etc/group file.
	
	# Set the PASS_MAX_DAYS parameter to 90 in /etc/login.defs: PASS_MAX_DAYS 90 Modify user parameters for all users with a password set to match: # chage --maxdays 90
	
	#Set the PASS_WARN_AGE parameter to 7 in /etc/login.defs: 129 | P a g e PASS_WARN_AGE 7 Modify user parameters for all users with a password set to match: # chage --warndays 7
	#TODO debug:
	#for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do if [ $user != "root" ] then /usr/sbin/usermod -L $user if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ] then /usr/sbin/usermod -s /usr/sbin/nologin $user fi 130 | P a g e fi done
	usermod -g 0 root
	
	# Edit the /etc/bash.bashrc and /etc/profile.d/cis.sh files (and the appropriate files for any other shell supported on your system) and add the following the UMASK parameter as shown: umask 077
	echo umask 077  >> /etc/bash.bashrc
	echo umask 077  >> /etc/profile.d/cis.sh
	
	useradd -D -f 35
	touch /etc/motd 
	chown root:root /etc/motd 
	chmod 644 /etc/motd
	chown root:root /etc/issue 
	chmod 644 /etc/issue
	chown root:root /etc/issue.net
	chmod 644 /etc/issue.net
	echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue 
	echo "Authorized uses only. All activity may be monitored and reported." >> /etc/issue.net  
	
	#QUESTION are these strings, or control characters?
	#Edit the /etc/motd, /etc/issue and /etc/issue.net files and remove any lines containing \m, \r, \s or \v
	sed -i 's/\m//g' /etc/motd
	
	banner-message-enable=true 
	banner-message-text=''
	/bin/chmod 644 /etc/passwd
	/bin/chmod 640 /etc/shadow
	/bin/chmod 644 /etc/group
	/bin/chown root:root /etc/passwd
	/bin/chown root:shadow /etc/shadow
	/bin/chown root:root /etc/group
	#/usr/bin/passwd –l <username>

}


function secure_folders 
{
	# Make sure folders are secure
	# Do all mount related stuff here
	# TODO/QUESTION Document options; meaning is not clear from man page.
	# TODO this function must be verified/tested on R-Pi
	
	#/tmp
	mount -o remount,nodev,nosuid,noexec /tmp
	mount --bind /tmp /var/tmp
	#TODO QUESTION what is this?
	#/tmp /var/tmp none bind 0 0

	#/home
	mount -o remount,nodev /home

	#/run/shm
	mount -o remount,nodev,nosuid,noexec /run/shm

	#Disable automounting *Very important
	update-rc.d autofs disable

	#Audit: Ensure autofs is not enabled: 
	# (Ensure no S* lines are returned.)
	#TODO complete
	# QUESTION how does automount work? autofs is a program; what is wanted here? 
	# QUESTION What does "no S* lines are returned" mean?
	# ls /etc/rc*.d | grep autofs 

	#Set Sticky bit on writable directories
	#TODO document: what is the purpose here?
	df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

}


function secure_inetd
{
	# Everything /etc/inetd.conf related, plus a bit more

	#DOCUMENT what these do and why	
	apt-get purge rsh-client rsh-reload-client
	apt-get purge xserver-xorg-core*

	# Repository manager
	#DOCUMENT what this does
	update-rc.d xinetd disable

	#QUESTION: talk matches ntalk as well. Is there more to the pattern to limit conflicts? 
	#	I.e., are these keywords only at line start?
	#Remove or comment out any talk or ntalk lines in /etc/inetd.conf: 
	#examples:
	#	talk dgram udp wait nobody.tty /usr/sbin/in.talkd in.ta lkd 
	#	ntalk dgram udp wait nobody.tty /usr/sbin/in.ntalkd in.nt alkd
	sed -i '/^[ \t]*n*talk/s/^/#  /' /etc/inetd.conf
	apt-get purge talk

	
	#Remove or comment out any  lines in /etc/inetd.conf prefixed as:
	#shell stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.rshd 
	#login stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.rlogind 
	#exec stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.rexecd
	#telnet stream tcp nowait telnetd /usr/sbin/tcpd /usr/sbin/in.telnetd
	#tftp stream tcp nowait root internal
	#chargen stream tcp nowait root internal
	#echo stream tcp nowait root internal
	#discard stream tcp nowait root internal
	sed -i '/^[ \t]*discard/s/^/#  /' /etc/inetd.conf
	sed -i '/^[ \t]*echo/s/^/#  /' /etc/inetd.conf
	sed -i '/^[ \t]*chargen/s/^/#  /' /etc/inetd.conf
	sed -i '/^[ \t]*tftp/s/^/#  /' /etc/inetd.conf
	sed -i '/^[ \t]*telnet/s/^/#  /' /etc/inetd.conf
	sed -i '/^[ \t]*shell/s/^/#  /' /etc/inetd.conf
	sed -i '/^[ \t]*lobin/s/^/#  /' /etc/inetd.conf
	sed -i '/^[ \t]*exec/s/^/#  /' /etc/inetd.conf
	
}

function secure_services
{
	# The systemctl command is the basic command that is used to manage and control systemd
	#TODO test & figure out how to trap
	
	#Disable Services
	systemctl disable avahi-daemon
	systemctl disable cups
	systemctl disable bind9
	systemctl disable vsftpd
	systemctl disable dovecot

	update-rc.d isc-dhcp-server disable
	update-rc.d rpcbind disable
	update-rc.d nfs-kernel-server disable
	update-rc.d apache2 disable
	update-rc.d smbd disable
	update-rc.d squid3 disable
	update-rc.d snmpd disable

	apt-get purge slapd
	
	#Set RSYNC_ENABLE to false in /etc/default/rsync:
	# RSYNC_ENABLE=false
	sed -i '/^[ \t]*RSYNC_ENABLE/s/true/false/' /etc/default/rsync
	

}

function secure_time
{
	# NTP, Network Time Protocol, synchronizes the clock
	
	#Install ntp: 
	apt-get install ntp 
	
	#Ensure the following lines are in /etc/ntp.conf:
	#restrict -4 default kod nomodify notrap nopeer noquery 
	#restrict -6 default kod nomodify notrap nopeer noquery 
	#(this will fail if the file does not exist)
	if !grep -Fxq "restrict -4 default kod nomodify notrap nopeer noquery" /etc/ntp.conf
	then
		echo "restrict -4 default kod nomodify notrap nopeer noquery" | cat >> /etc/ntp.conf
	fi
	if !grep -Fxq "restrict -6 default kod nomodify notrap nopeer noquery" /etc/ntp.conf
	then
		echo "restrict -6 default kod nomodify notrap nopeer noquery" | cat >> /etc/ntp.conf
	fi
	
	#Also, make sure /etc/ntp.conf has at least one NTP server specified: server
	#QUESTION: HOW? What pattern to check for and what to add if not present?
}

function secure_internet_protocol
{
	# All things IPv4 & IPv6 / /etc/sysctl.conf related

	# http://mashable.com/2011/02/03/ipv4-ipv6-guide/#n3tedW35kOqZ
	# IPv4 & IPv6 are internet protocols version 4 & 6, respectively
	# IPv4 uses 32 bit Internet addresses
	# IPv6 3128 bits Internet addresses
	

	#QUESTION is it ok if these lines don't exist at all?
	#Set variables in /etc/sysctl.conf:
	#	net.ipv4.ip_forward=0
	#	net.ipv4.conf.all.send_redirects=0 
	#	net.ipv4.conf.default.send_redirects=0	
	#	net.ipv4.conf.all.accept_source_route=0 
	#	net.ipv4.conf.default.accept_source_route=0
	#	net.ipv4.conf.all.accept_redirects=0 
	#	net.ipv4.conf.default.accept_redirects=0 
	#	net.ipv4.conf.all.secure_redirects=0 
	#	net.ipv4.conf.default.secure_redirects=0 
	#	net.ipv4.icmp_ignore_bogus_error_responses=1 
	#	net.ipv4.tcp_syncookies=1
	sed -i '/^[ \t]*net.ipv4.ip_forward/s/=.*$/=0/' /etc/sysctl.conf
	sed -i '/^[ \t]*net.ipv4.conf.all.send_redirects/s/=.*$/=0/' /etc/sysctl.conf
	sed -i '/^[ \t]*net.ipv4.conf.default.send_redirects/s/=.*$/=0/' /etc/sysctl.conf 
	sed -i '/^[ \t]*net.ipv4.conf.all.accept_source_route/s/=.*$/=0/' /etc/sysctl.conf
	sed -i '/^[ \t]*net.ipv4.conf.default.accept_source_route/s/=.*$/=0/' /etc/sysctl.conf
	sed -i '/^[ \t]*net.ipv4.conf.all.accept_redirects/s/=.*$/=0/' /etc/sysctl.conf
	sed -i '/^[ \t]*net.ipv4.conf.all.secure_redirects/s/=.*$/=0/' /etc/sysctl.conf
	sed -i '/^[ \t]*net.ipv4.conf.default.secure_redirects/s/=.*$/=0/'	 /etc/sysctl.conf
	sed -i '/^[ \t]*net.ipv4.conf.default.accept_redirects/s/=.*$/=0/' /etc/sysctl.conf
	sed -i '/^[ \t]*net.ipv4.icmp_ignore_bogus_error_responses/s/=.*$/=1/' /etc/sysctl.conf
	sed -i '/^[ \t]*net.ipv4.tcp_syncookies/s/=.*$/=1/' /etc/sysctl.conf

	sed -i '/^[ \t]*net.ipv4.route.flush/s/=.*$/=1/' /etc/sysctl.conf
	

	#Modify active kernel parameters to match:	
	/sbin/sysctl -w net.ipv4.ip_forward=0
	/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0
	/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0 
	/sbin/sysctl -w net.ipv4.conf.all.accept_source_route=0
	/sbin/sysctl -w net.ipv4.conf.default.accept_source_route=0 
	/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0 
	/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0
	/sbin/sysctl -w net.ipv4.conf.all.secure_redirects=0
	/sbin/sysctl -w net.ipv4.conf.default.secure_redirects=0 
	/sbin/sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 
	/sbin/sysctl -w net.ipv4.tcp_syncookies=1
	
	/sbin/sysctl -w net.ipv4.route.flush=1
	
	#Create or edit the file /etc/sysctl.conf and add the following lines:
	#	net.ipv6.conf.all.disable_ipv6=1 
	#	net.ipv6.conf.default.disable_ipv6=1 
	#	net.ipv6.conf.lo.disable_ipv6=1 
	set_var net.ipv6.conf.all.disable_ipv6 = 1 /etc/sysctl.conf
	set_var net.ipv6.conf.default.disable_ipv6 = 1 /etc/sysctl.conf
	set_var net.ipv6.conf.lo.disable_ipv6 = 1 	/etc/sysctl.conf
		
	
	#QUESTION need to run sysctl on the above vars too?
	

	#Run the following command or reboot to apply the changes:  
	sysctl –p
	
	#QUESTION what is this? Need to verify if these lines already exist?
	echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
	echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
	echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
	echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf

}

function secure_cron
{
	# cron is a time-based job scheduler
	# set permissions on all things cron
	
	# Enable cron and anacron: 
	systemctl enable cron 
	systemctl enable anacron
	chown root:root /etc/crontab
	chmod og-rwx /etc/crontab
	chown root:root /etc/cron.hourly
	chmod og-rwx /etc/cron.hourly
	chown root:root /etc/cron.daily 
	chmod og-rwx /etc/cron.daily
	chown root:root /etc/cron.weekly 
	chmod og-rwx /etc/cron.weekly
	chown root:root /etc/cron.monthly
	chmod og-rwx /etc/cron.monthly
	chown root:root /etc/cron.d 
	chmod og-rwx /etc/cron.d
	/bin/rm /etc/cron.deny 
	/bin/rm /etc/at.deny
	touch /etc/cron.allow 
	touch /etc/at.allow 
	chmod og-rwx /etc/cron.allow
	chmod og-rwx /etc/at.allow
	chown root:root /etc/cron.allow 
	chown root:root /etc/at.allow

}

function secure_iptables
{
	# iptables is a user-space utility program that allows a system administrator to configure the tables
	#  provided by the Linux kernel firewall (implemented as different Netfilter modules) and the 
	#  chains and rules it stores. 
	# iptables applies to IPv4, ip6tables to IPv6
	
	#Install the iptables and iptables-persistent packages: 
	apt-get install iptables iptables-persistent 
	
	#Enable the netfilter-persistent service: 
	update-rc.d netfilter-persistent enable

}


function secure_ssh
{
	# Mostly /etc/ssh/sshd_config edits

	dpkg -s openssh-server
	
	chown root:root /etc/ssh/sshd_config
	chmod 600 /etc/ssh/sshd_config
	
	#QUESTION will all these vars be in this file already, or do I need to test?
	# Edit the /etc/ssh/sshd_config file to set the parameters as follows: 
	#	Protocol 2
	#	LogLevel INFO
	#	X11Forwarding no
	#	MaxAuthTries 4
	#	IgnoreRhosts yes
	#	HostbasedAuthentication no
	#	PermitRootLogin no
	#	PermitEmptyPasswords no
	#	PermitUserEnvironment no
	#	Ciphers aes128-ctr,aes192-ctr,aes256-ctr
	#	ClientAliveInterval 300 
	#	ClientAliveCountMax 0
	#	Banner /etc/issue.net

	
	
	#QUESTION to what are these being set?
	# Edit the /etc/ssh/sshd_config file to set one or more of the parameter as follows: 
	#	AllowUsers AllowGroups DenyUsers DenyGroups
}


function secure_os_services
{
	#TODO/QUESTION what services can be safely disabled
	
	# While applying system updates and patches helps correct known vulnerabilities, 
	# one of the best ways to protect the system against as yet unreported vulnerabilities 
	# is to disable all services that are not required for normal system operation. 
	# This prevents the exploitation of vulnerabilities discovered at a later date. If a service 
	# is not enabled, it cannot be exploited. The actions in this section of the document provide 
	# guidance on what services can be safely disabled and under which circumstances, greatly reducing 
	# the number of possible threats to the resulting system.

	# noop for now
	pwd
}

function secure_unneeded_filesystems
{
	# Optional – I would play with this if you have the time
	# 2.18 Disable Mounting of cramfs Filesystems (Not Scored) 
	# Profile Applicability:  
	# Level 2 Description: The cramfs filesystem type is a compressed read-only Linux filesystem 
	# embedded in small footprint systems. A cramfs image can be used without having to first decompress the image. 
	# Rationale: Removing support for unneeded filesystem types reduces the local attack surface of the server. 
	# If this filesystem type is not needed, disable it. 

	#Audit: 
	# /sbin/modprobe -n -v cramfs install /bin/true 
	# /sbin/lsmod | grep cramfs 

	#Remediation: Edit or create the file /etc/modprobe.d/CIS.conf and add the following line:
	#	install cramfs /bin/true
	#QUESTION: Need to check what this file contains before just adding the line?
	if [ ! -f /tmp/foo.txt ]
	then
		#touch /etc/modprobe.d/CIS.conf
		echo "install cramfs /bin/true" | cat >> /etc/modprobe.d/CIS.conf
	else
		if !grep -Fxq "install cramfs /bin/true" /etc/modprobe.d/CIS.conf
		then
			echo "install cramfs /bin/true" | cat >> /etc/modprobe.d/CIS.conf
		fi
	fi

}

##########
## Make sure OS is getting patched on a regular basis –
#apt-get upgrade









