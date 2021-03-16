# Module info

## Stats:
- Total modules: 273
- Auxiliary 0

- Exploits 265
	- 14 Manual
	- 18 Average
	- 56 Normal
	- 33 Good
	- 23 Great
	- 121 Excellent
- Evasion 8
	- 8 Normal


## Exploits (265)

### Manual Ranking (14)

#### 1999 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Serve DLL via webdav server|exploit/windows/misc/webdav_delivery|Required|-|-|-|-

#### 2013 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Script Web Delivery|exploit/multi/script/web_delivery|Required|-|-|-|-

#### 2014 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Mac OS X IOKit Keyboard Driver Root Privilege Escalation|exploit/osx/local/iokit_keyboard_root|Required|-|-|-|-
2|Chkrootkit Local Privilege Escalation|exploit/unix/local/chkrootkit|Required|-|-|-|-

#### 2015 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Watchguard XCS FixCorruptMail Local Privilege Escalation|exploit/freebsd/local/watchguard_fix_corrupt_mail|Required|-|-|-|-
2|MS15-078 Microsoft Windows Font Driver Buffer Overflow|exploit/windows/local/ms15_078_atmfd_bof|Required|-|-|-|-
3|Generic DLL Injection From Shared Resource|exploit/windows/smb/generic_smb_dll_injection|Required|-|-|-|-
4|Group Policy Script Execution From Shared Resource|exploit/windows/smb/group_policy_startup|Required|-|-|-|-

#### 2016 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HTA Web Server|exploit/windows/misc/hta_server|Required|-|-|-|-

#### 2018 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Windows NtUserSetWindowFNID Win32k User Callback|exploit/windows/local/cve_2018_8453_win32k_priv_esc|Required|-|-|-|-

#### 2019 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Windows 10 UAC Protection Bypass Via Windows Store (WSReset.exe)|exploit/windows/local/bypassuac_windows_store_filesys|Required|-|-|-|-
2|Windows 10 UAC Protection Bypass Via Windows Store (WSReset.exe) and Registry|exploit/windows/local/bypassuac_windows_store_reg|Required|-|-|-|-
3|Docker-Credential-Wincred.exe Privilege Escalation|exploit/windows/local/docker_credential_wincred|Required|-|-|-|-

#### No Disclosure Date (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Generic Payload Handler|exploit/multi/handler|Required|-|-|-|-


### Average Ranking (18)

#### 2002 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SecureCRT SSH1 Buffer Overflow|exploit/windows/ssh/securecrt_ssh1|Required|-|-|-|-

#### 2007 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MacOS X QuickTime RTSP Content-Type Overflow|exploit/osx/rtsp/quicktime_rtsp_content_type|Required|-|-|-|-

#### 2008 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Novell Client 4.91 SP4 nwfs.sys Local Privilege Escalation|exploit/windows/local/novell_client_nwfs|Required|-|-|-|-

#### 2009 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|UFO: Alien Invasion IRC Client Buffer Overflow|exploit/osx/misc/ufo_ai|Required|-|-|-|-
2|UFO: Alien Invasion IRC Client Buffer Overflow|exploit/windows/misc/ufo_ai|Required|-|-|-|-

#### 2011 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS11-080 AfdJoinLeaf Privilege Escalation|exploit/windows/local/ms11_080_afdjoinleaf|Required|-|-|-|-

#### 2012 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Nvidia (nvsvc) Display Driver Service Local Privilege Escalation|exploit/windows/local/nvidia_nvsvc|Required|-|-|-|-

#### 2013 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Windows NTUserMessageCall Win32k Kernel Pool Overflow (Schlamperei)|exploit/windows/local/ms13_053_schlamperei|Required|-|-|-|-
2|Windows TrackPopupMenuEx Win32k NULL Page|exploit/windows/local/ms13_081_track_popup_menu|Required|-|-|-|-
3|MS14-002 Microsoft Windows ndproxy.sys Local Privilege Escalation|exploit/windows/local/ms_ndproxy|Required|-|-|-|-
4|Novell Client 2 SP3 nicm.sys Local Privilege Escalation|exploit/windows/local/novell_client_nicm|Required|-|-|-|-
5|Windows EPATHOBJ::pprFlattenRec Local Privilege Escalation|exploit/windows/local/ppr_flatten_rec|Required|-|-|-|-

#### 2014 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS14-062 Microsoft Bluetooth Personal Area Networking (BthPan.sys) Privilege Escalation|exploit/windows/local/bthpan|Required|-|-|-|-
2|MQAC.sys Arbitrary Write Privilege Escalation|exploit/windows/local/mqac_write|Required|-|-|-|-
3|MS14-070 Windows tcpip!SetAddrOptions NULL Pointer Dereference|exploit/windows/local/ms14_070_tcpip_ioctl|Required|-|-|-|-
4|VirtualBox Guest Additions VBoxGuest.sys Privilege Escalation|exploit/windows/local/virtual_box_guest_additions|Required|-|-|-|-
5|VirtualBox 3D Acceleration Virtual Machine Escape|exploit/windows/local/virtual_box_opengl_escape|Required|-|-|-|-

#### 2020 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|OpenSMTPD OOB Read Local Privilege Escalation|exploit/unix/local/opensmtpd_oob_read_lpe|Required|-|-|-|-


### Normal Ranking (56)

#### 1971 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Login to Another User with Su on Linux / Unix Systems|exploit/linux/local/su_login|Required|Required|-|-|-

#### 1989 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Bash Profile Persistence|exploit/linux/local/bash_profile_persistence|Required|-|-|-|-

#### 1999 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Windows Capcom.sys Kernel Execution Exploit (x64 only)|exploit/windows/local/capcom_sys_exec|Required|-|-|-|-

#### 2001 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|RealVNC 3.3.7 Client Buffer Overflow|exploit/windows/vnc/realvnc_client|Required|-|-|-|-

#### 2002 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|PuTTY Buffer Overflow|exploit/windows/ssh/putty_msg_debug|Required|-|-|-|-

#### 2003 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|LeapWare LeapFTP v2.7.3.600 PASV Reply Client Overflow|exploit/windows/ftp/leapftp_pasv_reply|Required|-|-|-|-

#### 2005 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS05-030 Microsoft Outlook Express NNTP Response Parsing Buffer Overflow|exploit/windows/nntp/ms05_030_nntp|Required|-|-|-|-

#### 2006 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|UltraVNC 1.0.1 Client Buffer Overflow|exploit/windows/vnc/ultravnc_client|Required|-|-|-|-

#### 2007 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apple QuickTime 7.3 RTSP Response Header Buffer Overflow|exploit/windows/misc/apple_quicktime_rtsp_response|Required|-|-|-|-
2|MS07-064 Microsoft DirectX DirectShow SAMI Buffer Overflow|exploit/windows/misc/ms07_064_sami|Required|-|-|-|-

#### 2008 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|mIRC PRIVMSG Handling Stack Buffer Overflow|exploit/windows/misc/mirc_privmsg_server|Required|-|-|-|-
2|Novell GroupWise Messenger Client Buffer Overflow|exploit/windows/novell/groupwisemessenger_client|Required|-|-|-|-
3|UltraVNC 1.0.2 Client (vncviewer.exe) Buffer Overflow|exploit/windows/vnc/ultravnc_viewer_bof|Required|-|-|-|-

#### 2009 (7)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|ProFTP 2.9 Banner Remote Buffer Overflow|exploit/windows/ftp/proftp_banner|Required|-|-|-|-
2|Xlink FTP Client Buffer Overflow|exploit/windows/ftp/xlink_client|Required|-|-|-|-
3|Eureka Email 2.2q ERR Remote Buffer Overflow|exploit/windows/misc/eureka_mail_err|Required|-|-|-|-
4|Mini-Stream 3.0.1.1 Buffer Overflow|exploit/windows/misc/mini_stream|Required|-|-|-|-
5|POP Peeper v3.4 DATE Buffer Overflow|exploit/windows/misc/poppeeper_date|Required|-|-|-|-
6|POP Peeper v3.4 UIDL Buffer Overflow|exploit/windows/misc/poppeeper_uidl|Required|-|-|-|-
7|Talkative IRC v0.4.4.16 Response Buffer Overflow|exploit/windows/misc/talkative_response|Required|-|-|-|-

#### 2010 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Trellian FTP Client 3.01 PASV Remote Buffer Overflow|exploit/windows/ftp/trellian_client_pasv|Required|-|-|-|-
2|Xftp FTP Client 3.0 PWD Remote Buffer Overflow|exploit/windows/ftp/xftp_client_pwd|Required|-|-|-|-

#### 2011 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AbsoluteFTP 1.9.6 - 2.2.10 LIST Command Remote Buffer Overflow|exploit/windows/ftp/absolute_ftp_list_bof|Required|-|-|-|-
2|SPlayer 3.7 Content-Type Buffer Overflow|exploit/windows/misc/splayer_content_type|Required|-|-|-|-

#### 2012 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apple iTunes 10 Extended M3U Stack Buffer Overflow|exploit/windows/misc/itunes_extm3u_bof|Required|-|-|-|-

#### 2013 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP System Management Homepage Local Privilege Escalation|exploit/linux/local/hp_smhstart|Required|-|-|-|-
2|Mac OS X Sudo Password Bypass|exploit/osx/local/sudo_password_bypass|Required|-|-|-|-

#### 2014 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Mac OS X NFS Mount Privilege Escalation Exploit|exploit/osx/local/nfs_mount_root|Required|-|-|-|-
2|OS X VMWare Fusion Privilege Escalation via Bash Environment Code Injection (Shellshock)|exploit/osx/local/vmware_bash_function_root|Required|-|-|-|-
3|Windows TrackPopupMenu Win32k NULL Pointer Dereference|exploit/windows/local/ms14_058_track_popup_menu|Required|-|-|-|-
4|MS15-001 Microsoft Windows NtApphelpCacheControl Improper Authorization Check|exploit/windows/local/ntapphelpcachecontrol|Required|-|-|-|-

#### 2015 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Mac OS X 10.9.5 / 10.10.5 - rsh/libmalloc Privilege Escalation|exploit/osx/local/rsh_libmalloc|Required|-|-|-|-
2|Mac OS X "tpwn" Privilege Escalation|exploit/osx/local/tpwn|Required|-|-|-|-
3|Windows ClientCopyImage Win32k Exploit|exploit/windows/local/ms15_051_client_copy_image|Required|-|-|-|-
4|Windows WMI Receive Notification Exploit|exploit/windows/local/ms16_014_wmi_recv_notif|Required|-|-|-|-

#### 2016 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS16-032 Secondary Logon Handle Privilege Escalation|exploit/windows/local/ms16_032_secondary_logon_handle_privesc|Required|-|-|-|-
2|Windows Net-NTLMv2 Reflection DCOM/RPC|exploit/windows/local/ms16_075_reflection|Required|-|-|-|-
3|DLL Side Loading Vulnerability in VMware Host Guest Client Redirector|exploit/windows/misc/vmhgfs_webdav_dll_sideload|Required|-|-|-|-

#### 2017 (8)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Clickjacking Vulnerability In CSRF Error Page pfSense|exploit/unix/http/pfsense_clickjacking|Required|-|-|-|Required
2|Ayukov NFTP FTP Client Buffer Overflow|exploit/windows/ftp/ayukov_nftp|Required|-|-|-|-
3|FTPShell client 6.70 (Enterprise edition) Stack Buffer Overflow|exploit/windows/ftp/ftpshell_cli_bof|Required|-|-|-|-
4|LabF nfsAxe 3.7 FTP Client Stack Buffer Overflow|exploit/windows/ftp/labf_nfsaxe|Required|-|-|-|-
5|DnsAdmin ServerLevelPluginDll Feature Abuse Privilege Escalation|exploit/windows/local/dnsadmin_serverlevelplugindll|Required|-|-|-|-
6|Razer Synapse rzpnk.sys ZwOpenProcess|exploit/windows/local/razer_zwopenprocess|Required|-|-|-|-
7|WMI Event Subscription Persistence|exploit/windows/local/wmi_persistence|Required|-|-|-|-
8|SysGauge SMTP Validation Buffer Overflow|exploit/windows/smtp/sysgauge_client_bof|Required|-|-|-|-

#### 2018 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|glibc 'realpath()' Privilege Escalation|exploit/linux/local/glibc_realpath_priv_esc|Required|-|-|-|-
2|Microsoft Windows ALPC Task Scheduler Local Privilege Elevation|exploit/windows/local/alpc_taskscheduler|Required|-|-|-|-

#### 2019 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Docker Privileged Container Escape|exploit/linux/local/docker_privileged_container_escape|Required|-|-|-|-
2|AppXSvc Hard Link Privilege Escalation|exploit/windows/local/appxsvc_hard_link_privesc|Required|-|-|-|-
3|Microsoft Windows Uninitialized Variable Local Privilege Elevation|exploit/windows/local/cve_2019_1458_wizardopium|Required|-|-|-|-
4|Microsoft Windows NtUserMNDragOver Local Privilege Elevation|exploit/windows/local/ntusermndragover|Required|-|-|-|-
5|Anviz CrossChex Buffer Overflow|exploit/windows/misc/crosschex_device_bof|Required|-|-|-|-

#### 2020 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Microsoft Windows DrawIconEx OOB Write Local Privilege Elevation|exploit/windows/local/cve_2020_1054_drawiconex_lpe|Required|-|-|-|-
2|CVE-2020-1170 Cloud Filter Arbitrary File Creation EOP|exploit/windows/local/cve_2020_17136|Required|-|-|-|-
3|Ricoh Driver Privilege Escalation|exploit/windows/local/ricoh_driver_privesc|Required|-|-|-|-


### Good Ranking (33)

#### 2010 (11)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|32bit FTP Client Stack Buffer Overflow |exploit/windows/ftp/32bitftp_list_reply|Required|-|-|-|-
2|AASync v2.2.1.0 (Win32) Stack Buffer Overflow (LIST)|exploit/windows/ftp/aasync_list_reply|Required|-|-|-|-
3|FileWrangler 5.30 Stack Buffer Overflow|exploit/windows/ftp/filewrangler_list_reply|Required|-|-|-|-
4|FTPGetter Standard v3.55.0.05 Stack Buffer Overflow (PWD)|exploit/windows/ftp/ftpgetter_pwd_reply|Required|-|-|-|-
5|FTPPad 1.2.0 Stack Buffer Overflow|exploit/windows/ftp/ftppad_list_reply|Required|-|-|-|-
6|FTPShell 5.1 Stack Buffer Overflow|exploit/windows/ftp/ftpshell51_pwd_reply|Required|-|-|-|-
7|FTP Synchronizer Professional 4.0.73.274 Stack Buffer Overflow|exploit/windows/ftp/ftpsynch_list_reply|Required|-|-|-|-
8|Gekko Manager FTP Client Stack Buffer Overflow|exploit/windows/ftp/gekkomgr_list_reply|Required|-|-|-|-
9|LeapFTP 3.0.1 Stack Buffer Overflow|exploit/windows/ftp/leapftp_list_reply|Required|-|-|-|-
10|Odin Secure FTP 4.1 Stack Buffer Overflow (LIST)|exploit/windows/ftp/odin_list_reply|Required|-|-|-|-
11|Seagull FTP v3.3 Build 409 Stack Buffer Overflow|exploit/windows/ftp/seagull_list_reply|Required|-|-|-|-

#### 2011 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|ScriptFTP LIST Remote Buffer Overflow|exploit/windows/ftp/scriptftp_list|Required|-|-|-|-
2|CoCSoft StreamDown 6.8.0 Buffer Overflow|exploit/windows/misc/stream_down_bof|Required|-|-|-|-
3|Wireshark packet-dect.c Stack Buffer Overflow|exploit/windows/misc/wireshark_packet_dect|Required|-|-|-|-
4|ICONICS WebHMI ActiveX Buffer Overflow|exploit/windows/scada/iconics_webhmi_setactivexguid|Required|-|-|-|-

#### 2012 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|IKE and AuthIP IPsec Keyring Modules Service (IKEEXT) Missing DLL|exploit/windows/local/ikeext_service|Required|-|-|-|-

#### 2014 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Linux Kernel recvmmsg Privilege Escalation|exploit/linux/local/recvmmsg_priv_esc|Required|-|-|-|-

#### 2015 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Overlayfs Privilege Escalation|exploit/linux/local/overlayfs_priv_esc|Required|-|-|-|-
2|MS15-004 Microsoft Remote Desktop Services Web Proxy IE Sandbox Escape|exploit/windows/local/ms15_004_tswbproxy|Required|-|-|-|-

#### 2016 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AF_PACKET chocobo_root Privilege Escalation|exploit/linux/local/af_packet_chocobo_root_priv_esc|Required|-|-|-|-
2|Linux BPF doubleput UAF Privilege Escalation|exploit/linux/local/bpf_priv_esc|Required|-|-|-|-
3|Linux Kernel 4.6.3 Netfilter Privilege Escalation|exploit/linux/local/netfilter_priv_esc_ipv4|Required|-|-|-|-
4|WinaXe 7.7 FTP Client Remote Buffer Overflow|exploit/windows/ftp/winaxe_server_ready|Required|-|-|-|-

#### 2017 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AF_PACKET packet_set_ring Privilege Escalation|exploit/linux/local/af_packet_packet_set_ring_priv_esc|Required|-|-|-|-
2|Debian/Ubuntu ntfs-3g Local Privilege Escalation|exploit/linux/local/ntfs3g_priv_esc|Required|-|-|-|-
3|Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation|exploit/linux/local/ufo_privilege_escalation|Required|-|-|-|-
4|Solaris RSH Stack Clash Privilege Escalation|exploit/solaris/local/rsh_stack_clash_priv_esc|Required|-|-|-|-

#### 2018 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation|exploit/linux/local/rds_atomic_free_op_null_pointer_deref_priv_esc|Required|-|-|-|-
2|Xorg X11 Server SUID logfile Privilege Escalation|exploit/multi/local/xorg_x11_suid_server|Required|-|-|-|-
3|Xorg X11 Server SUID modulepath Privilege Escalation|exploit/multi/local/xorg_x11_suid_server_modulepath|Required|-|-|-|-
4|Windows SetImeInfoEx Win32k NULL Pointer Dereference|exploit/windows/local/ms18_8120_win32k_privesc|Required|-|-|-|-
5|WebEx Local Service Permissions Exploit|exploit/windows/local/webexec|Required|-|-|-|-

#### 2020 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SMBv3 Compression Buffer Overflow|exploit/windows/local/cve_2020_0796_smbghost|Required|-|-|-|-


### Great Ranking (23)

#### 2008 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Realtek Media Player Playlist Buffer Overflow|exploit/windows/misc/realtek_playlist|Required|-|-|-|-

#### 2009 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Linux Kernel Sendpage Local Privilege Escalation|exploit/linux/local/sock_sendpage|Required|-|-|-|-
2|Linux udev Netlink Local Privilege Escalation|exploit/linux/local/udev_netlink|Required|-|-|-|-

#### 2010 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Reliable Datagram Sockets (RDS) rds_page_copy_user Privilege Escalation|exploit/linux/local/rds_rds_page_copy_user_priv_esc|Required|-|-|-|-
2|Windows SYSTEM Escalation via KiTrap0D|exploit/windows/local/ms10_015_kitrap0d|Required|-|-|-|-
3|MOXA Device Manager Tool 2.1 Buffer Overflow|exploit/windows/scada/moxa_mdmtool|Required|-|-|-|-

#### 2011 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Linux PolicyKit Race Condition Privilege Escalation|exploit/linux/local/pkexec|Required|-|-|-|-

#### 2012 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|FreeBSD Intel SYSRET Privilege Escalation|exploit/freebsd/local/intel_sysret_priv_esc|Required|-|-|-|-
2|Windows Escalate Service Permissions Local Privilege Escalation|exploit/windows/local/service_permissions|Required|-|-|-|-

#### 2013 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|FreeBSD 9 Address Space Manipulation Privilege Escalation|exploit/freebsd/local/mmap|Required|-|-|-|-
2|MS13-097 Registry Symlink IE Sandbox Escape|exploit/windows/local/ms13_097_ie_registry_symlink|Required|-|-|-|-

#### 2014 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP Performance Monitoring xglance Priv Esc|exploit/linux/local/hp_xglance_priv_esc|Required|-|-|-|-
2|MS14-009 .NET Deployment Service IE Sandbox Escape|exploit/windows/local/ms14_009_ie_dfsvc|Required|-|-|-|-

#### 2015 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Libuser roothelper Privilege Escalation|exploit/linux/local/libuser_roothelper_priv_esc|Required|-|-|-|-
2|Apple OS X DYLD_PRINT_TO_FILE Privilege Escalation|exploit/osx/local/dyld_print_to_file_root|Required|-|-|-|-
3|Apple OS X Rootpipe Privilege Escalation|exploit/osx/local/rootpipe|Required|-|-|-|-
4|Apple OS X Entitlements Rootpipe Privilege Escalation|exploit/osx/local/rootpipe_entitlements|Required|-|-|-|-

#### 2016 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Windows Net-NTLMv2 Reflection DCOM/RPC (Juicy)|exploit/windows/local/ms16_075_reflection_juicy|Required|-|-|-|-

#### 2017 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Linux BPF Sign Extension Local Privilege Escalation|exploit/linux/local/bpf_sign_extension_priv_esc|Required|-|-|-|-

#### 2018 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Xorg X11 Server Local Privilege Escalation|exploit/aix/local/xorg_x11_server|Required|-|-|-|-
2|Linux Nested User Namespace idmap Limit Local Privilege Escalation|exploit/linux/local/nested_namespace_idmap_limit_priv_esc|Required|-|-|-|-

#### 2019 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SYSTEM token impersonation through NTLM bits authentication on missing WinRM Service.|exploit/windows/local/bits_ntlm_token_impersonation|Required|-|-|-|-

#### 2020 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|FreeBSD ip6_setpktopt Use-After-Free Privilege Escalation|exploit/freebsd/local/ip6_setpktopt_uaf_priv_esc|Required|-|-|-|-


### Excellent Ranking (121)

#### 1900 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Windows Escalate UAC Protection Bypass (Via COM Handler Hijack)|exploit/windows/local/bypassuac_comhijack|Required|-|-|-|-

#### 1979 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Cron Persistence|exploit/linux/local/cron_persistence|Required|-|-|-|-

#### 1980 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|rc.local Persistence|exploit/linux/local/rc_local_persistence|Required|-|-|-|-

#### 1983 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Service Persistence|exploit/linux/local/service_persistence|Required|-|-|-|-

#### 1986 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Emacs movemail Privilege Escalation|exploit/unix/local/emacs_movemail|Required|-|-|-|-

#### 1997 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|at(1) Persistence|exploit/unix/local/at_persistence|Required|-|-|-|-

#### 1999 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|APT Package Manager Persistence|exploit/linux/local/apt_package_manager_persistence|Required|-|-|-|-
2|PsExec via Current User Token|exploit/windows/local/current_user_psexec|Required|-|-|-|-
3|Windows Command Shell Upgrade (Powershell)|exploit/windows/local/powershell_cmd_upgrade|Required|-|-|-|-
4|Powershell Remoting Remote Command Execution|exploit/windows/local/powershell_remoting|Required|-|-|-|-
5|Windows Run Command As User|exploit/windows/local/run_as|Required|-|-|-|-

#### 2001 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Windows Unquoted Service Path Privilege Escalation|exploit/windows/local/unquoted_service_path|Required|-|-|-|-
2|MS08-068 Microsoft Windows SMB Relay Code Execution|exploit/windows/smb/smb_relay|Required|-|-|-|-

#### 2003 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Yum Package Manager Persistence|exploit/linux/local/yum_package_manager_persistence|Required|-|-|-|-

#### 2006 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Autostart Desktop Item Persistence|exploit/linux/local/autostart_persistence|Required|-|-|-|-
2|Solaris libnspr NSPR_LOG_FILE Privilege Escalation|exploit/solaris/local/libnspr_nspr_log_file_priv_esc|Required|-|-|-|-

#### 2008 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Windows Silent Process Exit Persistence|exploit/windows/local/persistence_image_exec_options|Required|-|-|-|-

#### 2009 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|FreeBSD rtld execl() Privilege Escalation|exploit/freebsd/local/rtld_execl_priv_esc|Required|-|-|-|-

#### 2010 (8)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|glibc LD_AUDIT Arbitrary DSO Load Privilege Escalation|exploit/linux/local/glibc_ld_audit_dso_load_priv_esc|Required|-|-|-|-
2|glibc '$ORIGIN' Expansion Privilege Escalation|exploit/linux/local/glibc_origin_expansion_priv_esc|Required|-|-|-|-
3|SystemTap MODPROBE_OPTIONS Privilege Escalation|exploit/linux/local/systemtap_modprobe_options_priv_esc|Required|-|-|-|-
4|Windows AlwaysInstallElevated MSI|exploit/windows/local/always_install_elevated|Required|-|-|-|-
5|Windows Escalate UAC Protection Bypass|exploit/windows/local/bypassuac|Required|-|-|-|-
6|Windows Escalate UAC Protection Bypass (In Memory Injection)|exploit/windows/local/bypassuac_injection|Required|-|-|-|-
7|Windows Escalate Task Scheduler XML Privilege Escalation|exploit/windows/local/ms10_092_schelevator|Required|-|-|-|-
8|Microsoft Windows Shell LNK Code Execution|exploit/windows/smb/ms10_046_shortcut_icon_dllloader|Required|-|-|-|-

#### 2011 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|ktsuss suid Privilege Escalation|exploit/linux/local/ktsuss_suid_priv_esc|Required|-|-|-|-
2|Windows Manage Memory Payload Injection|exploit/windows/local/payload_inject|Required|-|-|-|-
3|Windows Persistent Registry Startup Payload Installer|exploit/windows/local/persistence|Required|-|-|-|-
4|PXE Exploit Server|exploit/windows/local/pxeexploit|Required|-|-|-|-
5|Persistent Payload in Windows Volume Shadow Copy|exploit/windows/local/vss_persistence|Required|-|-|-|-
6|Wireshark console.lua Pre-Loading Script Execution|exploit/windows/misc/wireshark_lua|Required|-|-|-|-

#### 2012 (10)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Kloxo Local Privilege Escalation|exploit/linux/local/kloxo_lxsuexec|Required|-|-|-|-
2|Squiggle 1.7 SVG Browser Java Code Execution|exploit/multi/misc/batik_svg_java|Required|-|-|-|-
3|Mac OS X Persistent Payload Installer|exploit/osx/local/persistence|Required|-|-|-|-
4|Setuid Tunnelblick Privilege Escalation|exploit/osx/local/setuid_tunnelblick|Required|-|-|-|-
5|Viscosity setuid-set ViscosityHelper Privilege Escalation|exploit/osx/local/setuid_viscosity|Required|-|-|-|-
6|Setuid Nmap Exploit|exploit/unix/local/setuid_nmap|Required|-|-|-|-
7|Windows Escalate UAC Execute RunAs|exploit/windows/local/ask|Required|-|-|-|-
8|MS13-005 HWND_BROADCAST Low to Medium Integrity Privilege Escalation|exploit/windows/local/ms13_005_hwnd_broadcast|Required|-|-|-|-
9|Powershell Payload Execution|exploit/windows/local/ps_persist|Required|-|-|-|-
10|Authenticated WMI Exec via Powershell|exploit/windows/local/ps_wmi_exec|Required|-|-|-|-

#### 2013 (7)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|ibstat $PATH Privilege Escalation|exploit/aix/local/ibstat_path|Required|-|-|-|-
2|Diamorphine Rootkit Signal Privilege Escalation|exploit/linux/local/diamorphine_rootkit_signal_priv_esc|Required|-|-|-|-
3|Sophos Web Protection Appliance clear_keys.pl Local Privilege Escalation|exploit/linux/local/sophos_wpa_clear_keys|Required|-|-|-|-
4|VMWare Setuid vmware-mount Unsafe popen(3)|exploit/linux/local/vmware_mount|Required|-|-|-|-
5|ZPanel zsudo Local Privilege Escalation Exploit|exploit/linux/local/zpanel_zsudo|Required|-|-|-|-
6|Agnitum Outpost Internet Security Local Privilege Escalation|exploit/windows/local/agnitum_outpost_acs|Required|-|-|-|-
7|Windows Manage User Level Persistent Payload Installer|exploit/windows/local/s4u_persistence|Required|-|-|-|-

#### 2014 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Firefox Exec Shellcode from Privileged Javascript Shell|exploit/firefox/local/exec_shellcode|Required|-|-|-|-
2|Desktop Linux Password Stealer and Privilege Escalation|exploit/linux/local/desktop_privilege_escalation|Required|-|-|-|-
3|Malicious Git and Mercurial HTTP Server For CVE-2014-9390|exploit/multi/http/git_client_command_exec|Required|-|-|-|-
4|ifwatchd Privilege Escalation|exploit/qnx/local/ifwatchd_priv_esc|Required|-|-|-|-
5|tnftp "savefile" Arbitrary Command Execution|exploit/unix/http/tnftp_savefile|Required|-|-|-|-

#### 2015 (10)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|ABRT raceabrt Privilege Escalation|exploit/linux/local/abrt_raceabrt_priv_esc|Required|-|-|-|-
2|ABRT sosreport Privilege Escalation|exploit/linux/local/abrt_sosreport_priv_esc|Required|-|-|-|-
3|Apport / ABRT chroot Privilege Escalation|exploit/linux/local/apport_abrt_chroot_priv_esc|Required|-|-|-|-
4|blueman set_dhcp_handler D-Bus Privilege Escalation|exploit/linux/local/blueman_set_dhcp_handler_dbus_priv_esc|Required|-|-|-|-
5|AppLocker Execution Prevention Bypass|exploit/windows/local/applocker_bypass|Required|-|-|-|-
6|Windows Escalate UAC Protection Bypass (ScriptHost Vulnerability)|exploit/windows/local/bypassuac_vbs|Required|-|-|-|-
7|iPass Mobile Client Service Privilege Escalation|exploit/windows/local/ipass_launch_app|Required|-|-|-|-
8|Lenovo System Update Privilege Escalation|exploit/windows/local/lenovo_systemupdate|Required|-|-|-|-
9|Windows Registry Only Persistence|exploit/windows/local/registry_persistence|Required|-|-|-|-
10|Microsoft Windows Shell LNK Code Execution|exploit/windows/smb/ms15_020_shortcut_icon_dllloader|Required|-|-|-|-

#### 2016 (11)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AddressSanitizer (ASan) SUID Executable Privilege Escalation|exploit/linux/local/asan_suid_executable_priv_esc|Required|-|-|-|-
2|Docker Daemon Privilege Escalation|exploit/linux/local/docker_daemon_privilege_escalation|Required|-|-|-|-
3|lastore-daemon D-Bus Privilege Escalation|exploit/linux/local/lastore_daemon_dbus_priv_esc|Required|-|-|-|-
4|Allwinner 3.4 Legacy Kernel Local Privilege Escalation|exploit/multi/local/allwinner_backdoor|Required|-|-|-|-
5|MagniComp SysInfo mcsiwrapper Privilege Escalation|exploit/multi/local/magnicomp_sysinfo_mcsiwrapper_priv_esc|Required|-|-|-|-
6|Exim "perl_startup" Privilege Escalation|exploit/unix/local/exim_perl_startup|Required|-|-|-|-
7|NetBSD mail.local Privilege Escalation|exploit/unix/local/netbsd_mail_local|Required|-|-|-|-
8|Windows Escalate UAC Protection Bypass (Via Eventvwr Registry Key)|exploit/windows/local/bypassuac_eventvwr|Required|-|-|-|-
9|MS16-016 mrxdav.sys WebDav Local Privilege Escalation|exploit/windows/local/ms16_016_webdav|Required|-|-|-|-
10|Panda Security PSEvents Privilege Escalation|exploit/windows/local/panda_psevents|Required|-|-|-|-
11|SMB Delivery|exploit/windows/smb/smb_delivery|Required|-|-|-|-

#### 2017 (11)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Juju-run Agent Privilege Escalation|exploit/linux/local/juju_run_agent_priv_esc|Required|-|-|-|-
2|VMware Workstation ALSA Config File Local Privilege Escalation|exploit/linux/local/vmware_alsa_config|Required|-|-|-|-
3|Malicious Git HTTP Server For CVE-2017-1000117|exploit/multi/http/git_submodule_command_exec|Required|-|-|-|-
4|Apache OpenOffice Text Document Malicious Macro Execution|exploit/multi/misc/openoffice_document_macro|Required|-|-|-|-
5|Mac OS X Root Privilege Escalation|exploit/osx/local/root_no_password|Required|-|-|-|-
6|Solaris 'EXTREMEPARR' dtappgather Privilege Escalation|exploit/solaris/local/extremeparr_dtappgather_priv_esc|Required|-|-|-|-
7|Windows Escalate UAC Protection Bypass (Via dot net profiler)|exploit/windows/local/bypassuac_dotnet_profiler|Required|-|-|-|-
8|Windows UAC Protection Bypass (Via FodHelper Registry Key)|exploit/windows/local/bypassuac_fodhelper|Required|-|-|-|-
9|Windows Escalate UAC Protection Bypass (In Memory Injection) abusing WinSXS|exploit/windows/local/bypassuac_injection_winsxs|Required|-|-|-|-
10|Windows Escalate UAC Protection Bypass (Via Shell Open Registry Key)|exploit/windows/local/bypassuac_sdclt|Required|-|-|-|-
11|LNK Code Execution Vulnerability|exploit/windows/local/cve_2017_8464_lnk_lpe|Required|-|-|-|-

#### 2018 (10)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Cisco Prime Infrastructure Runrshell Privilege Escalation|exploit/linux/local/cpi_runrshell_priv_esc|Required|-|-|-|-
2|Network Manager VPNC Username Privilege Escalation|exploit/linux/local/network_manager_vpnc_username_priv_esc|Required|-|-|-|-
3|Reptile Rootkit reptile_cmd Privilege Escalation|exploit/linux/local/reptile_rootkit_reptile_cmd_priv_esc|Required|-|-|-|-
4|Unitrends Enterprise Backup bpserverd Privilege Escalation|exploit/linux/local/ueb_bpserverd_privesc|Required|-|-|-|-
5|Malicious Git HTTP Server For CVE-2018-17456|exploit/multi/http/git_submodule_url_exec|Required|-|-|-|-
6|Mac OS X libxpc MITM Privilege Escalation|exploit/osx/local/libxpc_mitm_ssudo|Required|-|-|-|-
7|Windows UAC Protection Bypass (Via Slui File Handler Hijack)|exploit/windows/local/bypassuac_sluihijack|Required|-|-|-|-
8|Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability|exploit/windows/local/mov_ss|Required|-|-|-|-
9|Windows Persistent Service Installer|exploit/windows/local/persistence_service|Required|-|-|-|-
10|Windscribe WindscribeService Named Pipe Privilege Escalation|exploit/windows/local/windscribe_windscribeservice_priv_esc|Required|-|-|-|-

#### 2019 (15)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Exim 4.87 - 4.91 Local Privilege Escalation|exploit/linux/local/exim4_deliver_message_priv_esc|Required|-|-|-|-
2|Micro Focus (HPE) Data Protector SUID Privilege Escalation|exploit/linux/local/omniresolve_suid_priv_esc|Required|-|-|-|-
3|ptrace Sudo Token Privilege Escalation|exploit/linux/local/ptrace_sudo_token_priv_esc|Required|-|-|-|-
4|Linux Polkit pkexec helper PTRACE_TRACEME local root exploit|exploit/linux/local/ptrace_traceme_pkexec_helper|Required|-|-|-|-
5|Serv-U FTP Server prepareinstallation Privilege Escalation|exploit/linux/local/servu_ftp_server_prepareinstallation_priv_esc|Required|-|-|-|-
6|OpenBSD Dynamic Loader chpass Privilege Escalation|exploit/openbsd/local/dynamic_loader_chpass_privesc|Required|-|-|-|-
7|Mac OS X Feedback Assistant Race Condition|exploit/osx/local/feedback_assistant_root|Required|-|-|-|-
8|Mac OS X TimeMachine (tmdiagnose) Command Injection Privilege Escalation|exploit/osx/local/timemachine_cmd_injection|Required|-|-|-|-
9|Solaris xscreensaver log Privilege Escalation|exploit/solaris/local/xscreensaver_log_priv_esc|Required|-|-|-|-
10|Windows Escalate UAC Protection Bypass (Via SilentCleanup)|exploit/windows/local/bypassuac_silentcleanup|Required|-|-|-|-
11|Microsoft UPnP Local Privilege Elevation Vulnerability|exploit/windows/local/comahawk|Required|-|-|-|-
12|Microsoft Spooler Local Privilege Elevation Vulnerability|exploit/windows/local/cve_2020_1048_printerdemon|Required|-|-|-|-
13|Windows Update Orchestrator unchecked ScheduleWork call|exploit/windows/local/cve_2020_1313_system_orchestrator|Required|-|-|-|-
14|Microsoft Spooler Local Privilege Elevation Vulnerability|exploit/windows/local/cve_2020_1337_printerdemon|Required|-|-|-|-
15|Plantronics Hub SpokesUpdateService Privilege Escalation|exploit/windows/local/plantronics_hub_spokesupdateservice_privesc|Required|-|-|-|-

#### 2020 (8)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|macOS cfprefsd Arbitrary File Write Local Privilege Escalation|exploit/osx/local/cfprefsd_race_condition|Required|-|-|-|-
2|VMware Fusion USB Arbitrator Setuid Privilege Escalation|exploit/osx/local/vmware_fusion_lpe|Required|-|-|-|-
3|Cisco AnyConnect Privilege Escalations (CVE-2020-3153 and CVE-2020-3433)|exploit/windows/local/anyconnect_lpe|Required|-|-|-|-
4|Service Tracing Privilege Elevation Vulnerability|exploit/windows/local/cve_2020_0668_service_tracing|Required|-|-|-|-
5|Background Intelligent Transfer Service Arbitrary File Move Privilege Elevation Vulnerability|exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move|Required|-|-|-|-
6|Druva inSync inSyncCPHwnet64.exe RPC Type 5 Privilege Escalation|exploit/windows/local/druva_insync_insynccphwnet64_rcp_type_5_priv_esc|Required|-|-|-|-
7|GOG GalaxyClientService Privilege Escalation|exploit/windows/local/gog_galaxyclientservice_privesc|Required|-|-|-|-
8|Micro Focus Operations Bridge Manager Local Privilege Escalation|exploit/windows/local/microfocus_operations_privesc|Required|-|-|Required|Required

#### 2021 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Sudo Heap-Based Buffer Overflow|exploit/linux/local/sudo_baron_samedit|Required|-|-|-|-
2|Windows Server 2012 SrClient DLL hijacking|exploit/windows/local/srclient_dll_hijacking|Required|-|-|-|-

## Evasion (8)

### Normal Ranking (8)

#### No Disclosure Date (8)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Applocker Evasion - .NET Framework Installation Utility|evasion/windows/applocker_evasion_install_util|Required|-|-|-|-
2|Applocker Evasion - MSBuild|evasion/windows/applocker_evasion_msbuild|Required|-|-|-|-
3|Applocker Evasion - Windows Presentation Foundation Host|evasion/windows/applocker_evasion_presentationhost|Required|-|-|-|-
4|Applocker Evasion - Microsoft .NET Assembly Registration Utility|evasion/windows/applocker_evasion_regasm_regsvcs|Required|-|-|-|-
5|Applocker Evasion - Microsoft Workflow Compiler|evasion/windows/applocker_evasion_workflow_compiler|Required|-|-|-|-
6|Process Herpaderping evasion technique|evasion/windows/process_herpaderping|Required|-|-|-|-
7|Microsoft Windows Defender Evasive Executable|evasion/windows/windows_defender_exe|Required|-|-|-|-
8|Microsoft Windows Defender Evasive JS.Net and HTA|evasion/windows/windows_defender_js_hta|Required|-|-|-|-
