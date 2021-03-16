## Module info

### Stats:
- Total modules: 96
- Auxiliary 15
	- 15 Normal
- Exploits 73
	- 6 Manual
	- 4 Average
	- 29 Normal
	- 16 Good
	- 4 Great
	- 14 Excellent
- Evasion 8
	- 8 Normal

### Auxiliary (15)

### Normal Ranking (15)
---
### 2011 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Microsoft Windows DNSAPI.dll LLMNR Buffer Underrun DoS|auxiliary/dos/windows/llmnr/ms11_030_dnsapi|-|-|Required|-

### 2012 (2)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|General Electric D20 Password Recovery|auxiliary/gather/d20pass|-|-|Required|-
2|DarkComet Server Remote File Download Exploit|auxiliary/gather/darkcomet_filedownloader|-|-|Required|-

### 2013 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Huawei Datacard Information Disclosure Vulnerability|auxiliary/gather/huawei_wifi_info|-|-|Required|-

### 2019 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Grafana 2.0 through 5.2.2 authentication bypass for LDAP and OAuth|auxiliary/admin/http/grafana_auth_bypass|-|-|Required|-

### 2020 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|"Cablehaunt" Cable Modem WebSocket DoS|auxiliary/dos/http/cable_haunt_websocket_dos|-|Required|Required|-

### No Disclosure Date (9)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Discover External IP via Ifconfig.me|auxiliary/gather/external_ip|-|-|Required|-
2|LLMNR Query|auxiliary/scanner/llmnr/query|-|-|Required|-
3|mDNS Query|auxiliary/scanner/mdns/query|-|-|Required|-
4|Oracle iSQLPlus SID Check|auxiliary/scanner/oracle/isqlplus_sidbrute|-|-|Required|-
5|WS-Discovery Information Discovery|auxiliary/scanner/wsdd/wsdd_query|-|-|Required|-
6|Native DNS Server (Example)|auxiliary/server/dns/native_server|-|-|Required|-
7|Native DNS Spoofer (Example)|auxiliary/spoof/dns/native_spoofer|-|-|Required|-
8|SIP Deregister Extension|auxiliary/voip/sip_deregister|-|-|Required|-
9|SIP Invite Spoof|auxiliary/voip/sip_invite_spoof|-|-|Required|-

### Exploits (73)

### Manual Ranking (6)
---
### 1999 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Serve DLL via webdav server|exploit/windows/misc/webdav_delivery|Required|-|-|-

### 2013 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Script Web Delivery|exploit/multi/script/web_delivery|Required|-|-|-

### 2015 (2)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Generic DLL Injection From Shared Resource|exploit/windows/smb/generic_smb_dll_injection|Required|-|-|-
2|Group Policy Script Execution From Shared Resource|exploit/windows/smb/group_policy_startup|Required|-|-|-

### 2016 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|HTA Web Server|exploit/windows/misc/hta_server|Required|-|-|-

### No Disclosure Date (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Generic Payload Handler|exploit/multi/handler|Required|-|-|-


### Average Ranking (4)
---
### 2002 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|SecureCRT SSH1 Buffer Overflow|exploit/windows/ssh/securecrt_ssh1|Required|-|-|-

### 2007 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|MacOS X QuickTime RTSP Content-Type Overflow|exploit/osx/rtsp/quicktime_rtsp_content_type|Required|-|-|-

### 2009 (2)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|UFO: Alien Invasion IRC Client Buffer Overflow|exploit/osx/misc/ufo_ai|Required|-|-|-
2|UFO: Alien Invasion IRC Client Buffer Overflow|exploit/windows/misc/ufo_ai|Required|-|-|-


### Normal Ranking (29)
---
### 2001 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|RealVNC 3.3.7 Client Buffer Overflow|exploit/windows/vnc/realvnc_client|Required|-|-|-

### 2002 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|PuTTY Buffer Overflow|exploit/windows/ssh/putty_msg_debug|Required|-|-|-

### 2003 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|LeapWare LeapFTP v2.7.3.600 PASV Reply Client Overflow|exploit/windows/ftp/leapftp_pasv_reply|Required|-|-|-

### 2005 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|MS05-030 Microsoft Outlook Express NNTP Response Parsing Buffer Overflow|exploit/windows/nntp/ms05_030_nntp|Required|-|-|-

### 2006 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|UltraVNC 1.0.1 Client Buffer Overflow|exploit/windows/vnc/ultravnc_client|Required|-|-|-

### 2007 (2)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Apple QuickTime 7.3 RTSP Response Header Buffer Overflow|exploit/windows/misc/apple_quicktime_rtsp_response|Required|-|-|-
2|MS07-064 Microsoft DirectX DirectShow SAMI Buffer Overflow|exploit/windows/misc/ms07_064_sami|Required|-|-|-

### 2008 (3)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|mIRC PRIVMSG Handling Stack Buffer Overflow|exploit/windows/misc/mirc_privmsg_server|Required|-|-|-
2|Novell GroupWise Messenger Client Buffer Overflow|exploit/windows/novell/groupwisemessenger_client|Required|-|-|-
3|UltraVNC 1.0.2 Client (vncviewer.exe) Buffer Overflow|exploit/windows/vnc/ultravnc_viewer_bof|Required|-|-|-

### 2009 (7)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|ProFTP 2.9 Banner Remote Buffer Overflow|exploit/windows/ftp/proftp_banner|Required|-|-|-
2|Xlink FTP Client Buffer Overflow|exploit/windows/ftp/xlink_client|Required|-|-|-
3|Eureka Email 2.2q ERR Remote Buffer Overflow|exploit/windows/misc/eureka_mail_err|Required|-|-|-
4|Mini-Stream 3.0.1.1 Buffer Overflow|exploit/windows/misc/mini_stream|Required|-|-|-
5|POP Peeper v3.4 DATE Buffer Overflow|exploit/windows/misc/poppeeper_date|Required|-|-|-
6|POP Peeper v3.4 UIDL Buffer Overflow|exploit/windows/misc/poppeeper_uidl|Required|-|-|-
7|Talkative IRC v0.4.4.16 Response Buffer Overflow|exploit/windows/misc/talkative_response|Required|-|-|-

### 2010 (2)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Trellian FTP Client 3.01 PASV Remote Buffer Overflow|exploit/windows/ftp/trellian_client_pasv|Required|-|-|-
2|Xftp FTP Client 3.0 PWD Remote Buffer Overflow|exploit/windows/ftp/xftp_client_pwd|Required|-|-|-

### 2011 (2)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|AbsoluteFTP 1.9.6 - 2.2.10 LIST Command Remote Buffer Overflow|exploit/windows/ftp/absolute_ftp_list_bof|Required|-|-|-
2|SPlayer 3.7 Content-Type Buffer Overflow|exploit/windows/misc/splayer_content_type|Required|-|-|-

### 2012 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Apple iTunes 10 Extended M3U Stack Buffer Overflow|exploit/windows/misc/itunes_extm3u_bof|Required|-|-|-

### 2016 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|DLL Side Loading Vulnerability in VMware Host Guest Client Redirector|exploit/windows/misc/vmhgfs_webdav_dll_sideload|Required|-|-|-

### 2017 (5)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Clickjacking Vulnerability In CSRF Error Page pfSense|exploit/unix/http/pfsense_clickjacking|Required|-|-|Required
2|Ayukov NFTP FTP Client Buffer Overflow|exploit/windows/ftp/ayukov_nftp|Required|-|-|-
3|FTPShell client 6.70 (Enterprise edition) Stack Buffer Overflow|exploit/windows/ftp/ftpshell_cli_bof|Required|-|-|-
4|LabF nfsAxe 3.7 FTP Client Stack Buffer Overflow|exploit/windows/ftp/labf_nfsaxe|Required|-|-|-
5|SysGauge SMTP Validation Buffer Overflow|exploit/windows/smtp/sysgauge_client_bof|Required|-|-|-

### 2019 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Anviz CrossChex Buffer Overflow|exploit/windows/misc/crosschex_device_bof|Required|-|-|-


### Good Ranking (16)
---
### 2010 (11)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|32bit FTP Client Stack Buffer Overflow |exploit/windows/ftp/32bitftp_list_reply|Required|-|-|-
2|AASync v2.2.1.0 (Win32) Stack Buffer Overflow (LIST)|exploit/windows/ftp/aasync_list_reply|Required|-|-|-
3|FileWrangler 5.30 Stack Buffer Overflow|exploit/windows/ftp/filewrangler_list_reply|Required|-|-|-
4|FTPGetter Standard v3.55.0.05 Stack Buffer Overflow (PWD)|exploit/windows/ftp/ftpgetter_pwd_reply|Required|-|-|-
5|FTPPad 1.2.0 Stack Buffer Overflow|exploit/windows/ftp/ftppad_list_reply|Required|-|-|-
6|FTPShell 5.1 Stack Buffer Overflow|exploit/windows/ftp/ftpshell51_pwd_reply|Required|-|-|-
7|FTP Synchronizer Professional 4.0.73.274 Stack Buffer Overflow|exploit/windows/ftp/ftpsynch_list_reply|Required|-|-|-
8|Gekko Manager FTP Client Stack Buffer Overflow|exploit/windows/ftp/gekkomgr_list_reply|Required|-|-|-
9|LeapFTP 3.0.1 Stack Buffer Overflow|exploit/windows/ftp/leapftp_list_reply|Required|-|-|-
10|Odin Secure FTP 4.1 Stack Buffer Overflow (LIST)|exploit/windows/ftp/odin_list_reply|Required|-|-|-
11|Seagull FTP v3.3 Build 409 Stack Buffer Overflow|exploit/windows/ftp/seagull_list_reply|Required|-|-|-

### 2011 (4)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|ScriptFTP LIST Remote Buffer Overflow|exploit/windows/ftp/scriptftp_list|Required|-|-|-
2|CoCSoft StreamDown 6.8.0 Buffer Overflow|exploit/windows/misc/stream_down_bof|Required|-|-|-
3|Wireshark packet-dect.c Stack Buffer Overflow|exploit/windows/misc/wireshark_packet_dect|Required|-|-|-
4|ICONICS WebHMI ActiveX Buffer Overflow|exploit/windows/scada/iconics_webhmi_setactivexguid|Required|-|-|-

### 2016 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|WinaXe 7.7 FTP Client Remote Buffer Overflow|exploit/windows/ftp/winaxe_server_ready|Required|-|-|-


### Great Ranking (4)
---
### 2005 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Linksys WRT54 Access Point apply.cgi Buffer Overflow|exploit/linux/http/linksys_apply_cgi|Required|-|Required|-

### 2008 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Realtek Media Player Playlist Buffer Overflow|exploit/windows/misc/realtek_playlist|Required|-|-|-

### 2010 (2)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow (loop)|exploit/multi/misc/wireshark_lwres_getaddrbyname_loop|Required|-|Required|-
2|MOXA Device Manager Tool 2.1 Buffer Overflow|exploit/windows/scada/moxa_mdmtool|Required|-|-|-


### Excellent Ranking (14)
---
### 2001 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|MS08-068 Microsoft Windows SMB Relay Code Execution|exploit/windows/smb/smb_relay|Required|-|-|-

### 2010 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Microsoft Windows Shell LNK Code Execution|exploit/windows/smb/ms10_046_shortcut_icon_dllloader|Required|-|-|-

### 2011 (2)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|PXE Exploit Server|exploit/windows/local/pxeexploit|Required|-|-|-
2|Wireshark console.lua Pre-Loading Script Execution|exploit/windows/misc/wireshark_lua|Required|-|-|-

### 2012 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Squiggle 1.7 SVG Browser Java Code Execution|exploit/multi/misc/batik_svg_java|Required|-|-|-

### 2014 (2)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Malicious Git and Mercurial HTTP Server For CVE-2014-9390|exploit/multi/http/git_client_command_exec|Required|-|-|-
2|tnftp "savefile" Arbitrary Command Execution|exploit/unix/http/tnftp_savefile|Required|-|-|-

### 2015 (3)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Hak5 WiFi Pineapple Preconfiguration Command Injection|exploit/linux/http/pineapple_bypass_cmdinject|Required|-|Required|Required
2|Hak5 WiFi Pineapple Preconfiguration Command Injection|exploit/linux/http/pineapple_preconfig_cmdinject|Required|Required|Required|Required
3|Microsoft Windows Shell LNK Code Execution|exploit/windows/smb/ms15_020_shortcut_icon_dllloader|Required|-|-|-

### 2016 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|SMB Delivery|exploit/windows/smb/smb_delivery|Required|-|-|-

### 2017 (2)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Malicious Git HTTP Server For CVE-2017-1000117|exploit/multi/http/git_submodule_command_exec|Required|-|-|-
2|Apache OpenOffice Text Document Malicious Macro Execution|exploit/multi/misc/openoffice_document_macro|Required|-|-|-

### 2018 (1)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Malicious Git HTTP Server For CVE-2018-17456|exploit/multi/http/git_submodule_url_exec|Required|-|-|-

### Evasion (8)

### Normal Ranking (8)
---
### No Disclosure Date (8)
| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
1|Applocker Evasion - .NET Framework Installation Utility|evasion/windows/applocker_evasion_install_util|Required|-|-|-
2|Applocker Evasion - MSBuild|evasion/windows/applocker_evasion_msbuild|Required|-|-|-
3|Applocker Evasion - Windows Presentation Foundation Host|evasion/windows/applocker_evasion_presentationhost|Required|-|-|-
4|Applocker Evasion - Microsoft .NET Assembly Registration Utility|evasion/windows/applocker_evasion_regasm_regsvcs|Required|-|-|-
5|Applocker Evasion - Microsoft Workflow Compiler|evasion/windows/applocker_evasion_workflow_compiler|Required|-|-|-
6|Process Herpaderping evasion technique|evasion/windows/process_herpaderping|Required|-|-|-
7|Microsoft Windows Defender Evasive Executable|evasion/windows/windows_defender_exe|Required|-|-|-
8|Microsoft Windows Defender Evasive JS.Net and HTA|evasion/windows/windows_defender_js_hta|Required|-|-|-
