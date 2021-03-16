# Module info

## Stats:
- Total modules: 1920
- Auxiliary 757
	- 757 Normal
- Exploits 1163
	- 34 Manual
	- 2 Low
	- 122 Average
	- 125 Normal
	- 105 Good
	- 163 Great
	- 612 Excellent
- Evasion 0



## Exploits (1163)

### Manual Ranking (34)

#### 1999 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Microsoft Windows Authenticated User Code Execution|exploit/windows/smb/psexec|Required|-|Required|Required|-

#### 2007 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Alcatel-Lucent OmniPCX Enterprise masterCGI Arbitrary Command Execution|exploit/linux/http/alcatel_omnipcx_mastercgi_exec|Required|-|Required|Required|-
2|MS07-029 Microsoft DNS RPC Service extractQuotedChar() Overflow (SMB)|exploit/windows/smb/ms07_029_msdns_zonename|Required|-|Required|Required|-

#### 2008 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Generic PHP Code Evaluation|exploit/unix/webapp/php_eval|Required|-|Required|Required|-
2|Trixbox langChoice PHP Local File Inclusion|exploit/unix/webapp/trixbox_langchoice|Required|-|Required|Required|-

#### 2012 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|D-Link DIR-605L Captcha Handling Buffer Overflow|exploit/linux/http/dlink_dir605l_captcha_bof|Required|-|Required|Required|-
2|FreePBX 2.10.0 / 2.9.0 callmenum Remote Code Execution|exploit/unix/http/freepbx_callmenum|Required|-|Required|Required|-
3|MoinMoin twikidraw Action Traversal File Upload|exploit/unix/webapp/moinmoin_twikidraw|Required|Required|Required|Required|Required

#### 2013 (8)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Astium Remote Code Execution|exploit/linux/http/astium_sqli_upload|Required|-|Required|Required|Required
2|Linksys WRT54GL apply.cgi Command Execution|exploit/linux/http/linksys_wrt54gl_apply_exec|Required|Required|Required|Required|-
3|Netgear DGN2200B pppoe.cgi Remote Command Execution|exploit/linux/http/netgear_dgn2200b_pppoe_exec|Required|Required|Required|Required|-
4|NETGEAR ReadyNAS Perl Code Evaluation|exploit/linux/http/netgear_readynas_exec|Required|-|Required|Required|-
5|Raidsonic NAS Devices Unauthenticated Remote Command Execution|exploit/linux/http/raidsonic_nas_ib5220_exec_noauth|Required|-|Required|Required|-
6|GLPI install.php Remote Command Execution|exploit/multi/http/glpi_install_rce|Required|-|Required|Required|Required
7|HP SiteScope Remote Code Execution|exploit/windows/http/hp_sitescope_runomagentcommand|Required|-|Required|Required|Required
8|Intrasrv 1.0 Buffer Overflow|exploit/windows/http/intrasrv_bof|Required|-|Required|Required|-

#### 2014 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Kloxo SQL Injection and Remote Code Execution|exploit/linux/http/kloxo_sqli|Required|-|Required|Required|Required
2|Apache Struts ClassLoader Manipulation Remote Code Execution|exploit/multi/http/struts_code_exec_classloader|Required|-|Required|Required|Required
3|Vtiger Install Unauthenticated Remote Command Execution|exploit/multi/http/vtiger_install_rce|Required|-|Required|Required|Required
4|HybridAuth install.php PHP Code Execution|exploit/unix/webapp/hybridauth_install_php_exec|Required|-|Required|Required|Required
5|Cogent DataHub Command Injection|exploit/windows/http/cogent_datahub_command|Required|-|Required|Required|-

#### 2015 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Generic Web Application DLL Injection|exploit/windows/http/generic_http_dll_injection|Required|-|Required|Required|Required
2|ManageEngine OpManager Remote Code Execution|exploit/windows/http/manage_engine_opmanager_rce|Required|-|Required|Required|-
3|ManageEngine EventLog Analyzer Remote Code Execution|exploit/windows/misc/manageengine_eventlog_analyzer_rce|Required|Required|Required|Required|-

#### 2016 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apache Jetspeed Arbitrary File Upload|exploit/multi/http/apache_jetspeed_file_upload|Required|-|Required|Required|-
2|PHPMailer Sendmail Argument Injection|exploit/multi/http/phpmailer_arg_injection|Required|-|Required|Required|Required
3|Oracle Weblogic Server Deserialization RCE - MarshalledObject|exploit/multi/misc/weblogic_deserialize_marshalledobject|Required|-|Required|Required|-

#### 2017 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Microsoft IIS WebDav ScStoragePathFromUrl Overflow|exploit/windows/iis/iis_webdav_scstoragepathfromurl|Required|-|Required|Required|Required

#### 2018 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Nagios XI Chained Remote Code Execution|exploit/linux/http/nagios_xi_chained_rce_2_electric_boogaloo|Required|-|Required|Required|-
2|Snap Creek Duplicator WordPress plugin code injection|exploit/multi/php/wp_duplicator_code_inject|Required|-|Required|Required|Required
3|Nuuo Central Management Server Authenticated Arbitrary File Upload|exploit/windows/nuuo/nuuo_cms_fu|Required|-|Required|Required|-
4|WebExec Authenticated User Code Execution|exploit/windows/smb/webexec|Required|-|Required|Required|-

#### 2020 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|vBulletin /ajax/api/content_infraction/getIndexableContent nodeid Parameter SQL Injection|exploit/multi/http/vbulletin_getindexablecontent|Required|-|Required|Required|Required
2|WordPress InfiniteWP Client Authentication Bypass|exploit/unix/webapp/wp_infinitewp_auth_bypass|Required|Required|Required|Required|Required


### Low Ranking (2)

#### 2004 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS04-007 Microsoft ASN.1 Library Bitstring Heap Overflow|exploit/windows/smb/ms04_007_killbill|Required|-|Required|Required|-

#### 2013 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Sami FTP Server LIST Command Buffer Overflow|exploit/windows/ftp/sami_ftpd_list|Required|-|Required|Required|-


### Average Ranking (122)

#### 1988 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Morris Worm sendmail Debug Mode Shell Escape|exploit/unix/smtp/morris_sendmail_debug|Required|-|Required|Required|-

#### 1998 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|War-FTPD 1.65 Password Overflow|exploit/windows/ftp/warftpd_165_pass|Required|-|Required|Required|-
2|War-FTPD 1.65 Username Overflow|exploit/windows/ftp/warftpd_165_user|Required|-|Required|Required|-

#### 2000 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|GAMSoft TelSrv 1.5 Username Buffer Overflow|exploit/windows/telnet/gamsoft_telsrv_username|Required|-|Required|Required|-

#### 2001 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|WinVNC Web Server GET Overflow|exploit/windows/vnc/winvnc_http_get|Required|-|Required|Required|-

#### 2002 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Webster HTTP Server GET Buffer Overflow|exploit/windows/http/webster_http|Required|-|Required|Required|-
2|TFTPD32 Long Filename Buffer Overflow|exploit/windows/tftp/tftpd32_long_filename|Required|-|Required|Required|-

#### 2003 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Samba 2.2.2 - 2.2.6 nttrans Buffer Overflow|exploit/multi/samba/nttrans|Required|-|Required|Required|-
2|Kerio Firewall 2.1.4 Authentication Packet Overflow|exploit/windows/firewall/kerio_auth|Required|-|Required|Required|-
3|Alt-N WebAdmin USER Buffer Overflow|exploit/windows/http/altn_webadmin|Required|-|Required|Required|-
4|IA WebMail 3.x Buffer Overflow|exploit/windows/http/ia_webmail|Required|-|Required|Required|-

#### 2004 (14)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Subversion Date Svnserve|exploit/multi/svn/svnserve_date|Required|-|Required|Required|-
2|AppleFileServer LoginExt PathName Overflow|exploit/osx/afp/loginext|Required|-|Required|Required|-
3|WebSTAR FTP Server USER Overflow|exploit/osx/ftp/webstar_ftp_user|Required|-|Required|Required|-
4|Veritas Backup Exec Name Service Overflow|exploit/windows/backupexec/name_service|Required|-|Required|Required|-
5|CA BrightStor Discovery Service Stack Buffer Overflow|exploit/windows/brightstor/discovery_udp|Required|-|Required|Required|-
6|Sasser Worm avserve FTP PORT Buffer Overflow|exploit/windows/ftp/sasser_ftpd_port|Required|-|Required|Required|-
7|Minishare 1.4.1 Buffer Overflow|exploit/windows/http/minishare_get_overflow|Required|-|Required|Required|-
8|PSO Proxy v0.91 Stack Buffer Overflow|exploit/windows/http/psoproxy91_overflow|Required|-|Required|Required|-
9|SHOUTcast DNAS/win32 1.9.4 File Request Format String Overflow|exploit/windows/http/shoutcast_format|Required|-|Required|Required|-
10|IMail IMAP4D Delete Overflow|exploit/windows/imap/imail_delete|Required|-|Required|Required|-
11|Mercury/32 v4.01a IMAP RENAME Buffer Overflow|exploit/windows/imap/mercury_rename|Required|-|Required|Required|-
12|IMail LDAP Service Buffer Overflow|exploit/windows/ldap/imail_thc|Required|-|Required|Required|-
13|CCProxy Telnet Proxy Ping Overflow|exploit/windows/proxy/ccproxy_telnet_ping|Required|-|Required|Required|-
14|YPOPS 0.6 Buffer Overflow|exploit/windows/smtp/ypops_overflow1|Required|-|Required|Required|-

#### 2005 (20)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Berlios GPSD Format String Vulnerability|exploit/linux/http/gpsd_format_string|Required|-|Required|Required|-
2|Arkeia Backup Client Type 77 Overflow (Mac OS X)|exploit/osx/arkeia/type77|Required|-|Required|Required|-
3|CA BrightStor Discovery Service TCP Overflow|exploit/windows/brightstor/discovery_tcp|Required|-|Required|Required|-
4|CA BrightStor ARCserve License Service GCR NETWORK Buffer Overflow|exploit/windows/brightstor/license_gcr|Required|-|Required|Required|-
5|CA BrightStor Agent for Microsoft SQL Overflow|exploit/windows/brightstor/sql_agent|Required|-|Required|Required|-
6|CA BrightStor Universal Agent Overflow|exploit/windows/brightstor/universal_agent|Required|-|Required|Required|-
7|3Com 3CDaemon 2.0 FTP Username Overflow|exploit/windows/ftp/3cdaemon_ftp_user|Required|-|Required|Required|-
8|freeFTPd 1.0 Username Overflow|exploit/windows/ftp/freeftpd_user|Required|-|Required|Required|-
9|CA iTechnology iGateway Debug Mode Buffer Overflow|exploit/windows/http/ca_igateway_debug|Required|-|Required|Required|-
10|Sybase EAServer 5.2 Remote Stack Buffer Overflow|exploit/windows/http/sybase_easerver|Required|-|Required|Required|-
11|TrackerCam PHP Argument Buffer Overflow|exploit/windows/http/trackercam_phparg_overflow|Required|-|Required|Required|-
12|Novell NetMail IMAP STATUS Buffer Overflow|exploit/windows/imap/novell_netmail_status|Required|-|Required|Required|-
13|Computer Associates License Client GETCONFIG Overflow|exploit/windows/license/calicclnt_getconfig|Required|-|Required|Required|-
14|SentinelLM UDP Buffer Overflow|exploit/windows/license/sentinel_lm7_udp|Required|-|Required|Required|-
15|Hummingbird Connectivity 10 SP5 LPD Buffer Overflow|exploit/windows/lpd/hummingbird_exceed|Required|-|Required|Required|-
16|BakBone NetVault Remote Heap Overflow|exploit/windows/misc/bakbone_netvault_heap|Required|-|Required|Required|-
17|Mercury/32 PH Server Module Buffer Overflow|exploit/windows/misc/mercury_phonebook|Required|-|Required|Required|-
18|SoftiaCom WMailserver 1.0 Buffer Overflow|exploit/windows/smtp/wmailserver|Required|-|Required|Required|-
19|GoodTech Telnet Server Buffer Overflow|exploit/windows/telnet/goodtech_telnet|Required|-|Required|Required|-
20|FutureSoft TFTP Server 2000 Transfer-Mode Overflow|exploit/windows/tftp/futuresoft_transfermode|Required|-|Required|Required|-

#### 2006 (25)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|PeerCast URL Handling Buffer Overflow|exploit/linux/http/peercast_url|Required|-|Required|Required|-
2|CA BrightStor ARCserve Message Engine Heap Overflow|exploit/windows/brightstor/message_engine_heap|Required|-|Required|Required|-
3|CA BrightStor ARCserve Tape Engine Buffer Overflow|exploit/windows/brightstor/tape_engine|Required|-|Required|Required|-
4|Cesar FTP 0.99g MKD Command Buffer Overflow|exploit/windows/ftp/cesarftp_mkd|Required|-|Required|Required|-
5|Easy File Sharing FTP Server 2.0 PASS Overflow|exploit/windows/ftp/easyfilesharing_pass|Required|-|Required|Required|-
6|FileCopa FTP Server Pre 18 Jul Version|exploit/windows/ftp/filecopa_list_overflow|Required|-|Required|Required|-
7|Texas Imperial Software WFTPD 3.23 SIZE Overflow|exploit/windows/ftp/wftpd_size|Required|-|Required|Required|-
8|Ipswitch WS_FTP Server 5.05 XMD5 Overflow|exploit/windows/ftp/wsftp_server_505_xmd5|Required|-|Required|Required|-
9|McAfee ePolicy Orchestrator / ProtectionPilot Overflow|exploit/windows/http/mcafee_epolicy_source|Required|-|Required|Required|-
10|Novell Messenger Server 2.0 Accept-Language Overflow|exploit/windows/http/novell_messenger_acceptlang|Required|-|Required|Required|-
11|PeerCast URL Handling Buffer Overflow|exploit/windows/http/peercast_url|Required|-|Required|Required|-
12|Private Wire Gateway Buffer Overflow|exploit/windows/http/privatewire_gateway|Required|-|Required|Required|-
13|SHTTPD URI-Encoded POST Request Overflow|exploit/windows/http/shttpd_post|Required|-|Required|Required|-
14|Mercur v5.0 IMAP SP3 SELECT Buffer Overflow|exploit/windows/imap/mercur_imap_select_overflow|Required|-|Required|Required|-
15|Mercur Messaging 2005 IMAP Login Buffer Overflow|exploit/windows/imap/mercur_login|Required|-|Required|Required|-
16|Novell NetMail IMAP APPEND Buffer Overflow|exploit/windows/imap/novell_netmail_append|Required|-|Required|Required|-
17|Novell NetMail IMAP SUBSCRIBE Buffer Overflow|exploit/windows/imap/novell_netmail_subscribe|Required|-|Required|Required|-
18|Bomberclone 0.11.6 Buffer Overflow|exploit/windows/misc/bomberclone_overflow|Required|-|Required|Required|-
19|eIQNetworks ESA License Manager LICMGR_ADDLICENSE Overflow|exploit/windows/misc/eiqnetworks_esa|Required|-|Required|Required|-
20|eIQNetworks ESA Topology DELETEDEVICE Overflow|exploit/windows/misc/eiqnetworks_esa_topology|Required|-|Required|Required|-
21|Omni-NFS Server Buffer Overflow|exploit/windows/nfs/xlink_nfsd|Required|-|Required|Required|-
22|Novell NetMail NMAP STOR Buffer Overflow|exploit/windows/novell/nmap_stor|Required|-|Required|Required|-
23|MS06-025 Microsoft RRAS Service Overflow|exploit/windows/smb/ms06_025_rras|Required|-|Required|Required|-
24|FreeFTPd 1.0.10 Key Exchange Algorithm String Buffer Overflow|exploit/windows/ssh/freeftpd_key_exchange|Required|-|Required|Required|-
25|FreeSSHd 1.0.9 Key Exchange Algorithm String Buffer Overflow|exploit/windows/ssh/freesshd_key_exchange|Required|-|Required|Required|-

#### 2007 (22)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|PHP 4 unserialize() ZVAL Reference Counter Overflow (Cookie)|exploit/multi/php/php_unserialize_zval_cookie|Required|-|Required|Required|-
2|Novell NetWare LSASS CIFS.NLM Driver Stack Buffer Overflow|exploit/netware/smb/lsass_cifs|Required|-|Required|Required|-
3|Samba lsa_io_trans_names Heap Overflow|exploit/osx/samba/lsa_transnames_heap|Required|-|Required|Required|-
4|Samba lsa_io_trans_names Heap Overflow|exploit/solaris/samba/lsa_transnames_heap|Required|-|Required|Required|-
5|CA BrightStor ARCserve for Laptops and Desktops LGServer Buffer Overflow|exploit/windows/brightstor/lgserver|Required|-|Required|Required|-
6|CA BrightStor ARCserve for Laptops and Desktops LGServer Multiple Commands Buffer Overflow|exploit/windows/brightstor/lgserver_multi|Required|-|Required|Required|-
7|CA BrightStor ARCserve for Laptops and Desktops LGServer Buffer Overflow|exploit/windows/brightstor/lgserver_rxrlogin|Required|-|Required|Required|-
8|CA BrightStor ARCserve for Laptops and Desktops LGServer rxsSetDataGrowthScheduleAndFilter Buffer Overflow|exploit/windows/brightstor/lgserver_rxssetdatagrowthscheduleandfilter|Required|-|Required|Required|-
9|CA BrightStor ARCserve for Laptops and Desktops LGServer Buffer Overflow|exploit/windows/brightstor/lgserver_rxsuselicenseini|Required|-|Required|Required|-
10|CA BrightStor ArcServe Media Service Stack Buffer Overflow|exploit/windows/brightstor/mediasrv_sunrpc|Required|-|Required|Required|-
11|CA BrightStor ARCserve Message Engine Buffer Overflow|exploit/windows/brightstor/message_engine|Required|-|Required|Required|-
12|Xitami 2.5c2 Web Server If-Modified-Since Overflow|exploit/windows/http/xitami_if_mod_since|Required|-|Required|Required|-
13|Ipswitch IMail IMAP SEARCH Buffer Overflow|exploit/windows/imap/ipswitch_search|Required|-|Required|Required|-
14|Novell NetMail IMAP AUTHENTICATE Buffer Overflow|exploit/windows/imap/novell_netmail_auth|Required|-|Required|Required|-
15|Borland Interbase Create-Request Buffer Overflow|exploit/windows/misc/borland_interbase|Required|-|Required|Required|-
16|Firebird Relational Database isc_attach_database() Buffer Overflow|exploit/windows/misc/fb_isc_attach_database|Required|-|Required|Required|-
17|Firebird Relational Database isc_create_database() Buffer Overflow|exploit/windows/misc/fb_isc_create_database|Required|-|Required|Required|-
18|Firebird Relational Database SVC_attach() Buffer Overflow|exploit/windows/misc/fb_svc_attach|Required|-|Required|Required|-
19|HP OpenView Operations OVTrace Buffer Overflow|exploit/windows/misc/hp_ovtrace|Required|-|Required|Required|-
20|LANDesk Management Suite 8.7 Alert Service Buffer Overflow|exploit/windows/misc/landesk_aolnsrvr|Required|-|Required|Required|-
21|TinyIdentD 2.2 Stack Buffer Overflow|exploit/windows/misc/tiny_identd_overflow|Required|-|Required|Required|-
22|Windows RSH Daemon Buffer Overflow|exploit/windows/misc/windows_rsh|Required|-|Required|Required|-

#### 2008 (12)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|XTACACSD report() Buffer Overflow|exploit/freebsd/tacacs/xtacacsd_report|Required|-|Required|Required|-
2|Computer Associates Alert Notification Buffer Overflow|exploit/windows/brightstor/etrust_itm_alert|Required|-|Required|Required|-
3|Alt-N SecurityGateway username Buffer Overflow|exploit/windows/http/altn_securitygateway|Required|-|Required|Required|-
4|Streamcast HTTP User-Agent Buffer Overflow|exploit/windows/http/steamcast_useragent|Required|-|Required|Required|-
5|IBM Lotus Domino Web Server Accept-Language Stack Buffer Overflow|exploit/windows/lotus/domino_http_accept_language|Required|-|Required|Required|-
6|IBM Lotus Domino Sametime STMux.exe Stack Buffer Overflow|exploit/windows/lotus/domino_sametime_stmux|Required|-|Required|Required|-
7|Asus Dpcproxy Buffer Overflow|exploit/windows/misc/asus_dpcproxy_overflow|Required|-|Required|Required|-
8|BigAnt Server 2.2 Buffer Overflow|exploit/windows/misc/bigant_server|Required|-|Required|Required|-
9|Borland CaliberRM StarTeam Multicast Service Buffer Overflow|exploit/windows/misc/borland_starteam|Required|-|Required|Required|-
10|DoubleTake/HP StorageWorks Storage Mirroring Service Authentication Overflow|exploit/windows/misc/doubletake|Required|-|Required|Required|-
11|MySQL yaSSL SSL Hello Message Buffer Overflow|exploit/windows/mysql/mysql_yassl_hello|Required|-|Required|Required|-
12|OpenTFTP SP 1.4 Error Packet Overflow|exploit/windows/tftp/opentftp_error_code|Required|-|Required|Required|-

#### 2009 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Belkin Bulldog Plus Web Service Buffer Overflow|exploit/windows/http/belkin_bulldog|Required|-|Required|Required|-
2|Hewlett-Packard Power Manager Administration Buffer Overflow|exploit/windows/http/hp_power_manager_login|Required|-|Required|Required|-
3|SafeNet SoftRemote IKE Service Buffer Overflow|exploit/windows/vpn/safenet_ike_11|Required|-|Required|Required|-

#### 2010 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MacOS X EvoCam HTTP GET Buffer Overflow|exploit/osx/http/evocam_webserver|Required|-|Required|Required|-
2|CA BrightStor ARCserve Message Engine 0x72 Buffer Overflow|exploit/windows/brightstor/message_engine_72|Required|-|Required|Required|-
3|CA BrightStor ARCserve Tape Engine 0x8A Buffer Overflow|exploit/windows/brightstor/tape_engine_0x8a|Required|-|Required|Required|-

#### 2011 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|NetSupport Manager Agent Remote Buffer Overflow|exploit/linux/misc/netsupport_manager_agent|Required|-|Required|Required|-
2|CTEK SkyRouter 4200 and 4300 Command Execution|exploit/unix/http/ctek_skyrouter|Required|-|Required|Required|-
3|GoldenFTP PASS Stack Buffer Overflow|exploit/windows/ftp/goldenftp_pass_bof|Required|-|Required|Required|-
4|ManageEngine Applications Manager Authenticated Code Execution|exploit/windows/http/manageengine_apps_mngr|Required|Required|Required|Required|-
5|Siemens FactoryLink vrn.exe Opcode 9 Buffer Overflow|exploit/windows/scada/factorylink_vrn_09|Required|-|Required|Required|-

#### 2012 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SAP NetWeaver HostControl Command Injection|exploit/windows/http/sap_host_control_cmd_exec|Required|-|Required|Required|-
2|HP Diagnostics Server magentservice.exe Overflow|exploit/windows/misc/hp_magentservice|Required|-|Required|Required|-

#### 2013 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Kimai v0.9.2 'db_restore.php' SQL Injection|exploit/unix/webapp/kimai_sqli|Required|-|Required|Required|Required

#### 2014 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Yokogawa CENTUM CS 3000 BKHOdeq.exe Buffer Overflow|exploit/windows/scada/yokogawa_bkhodeq_bof|Required|-|Required|Required|-

#### 2017 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|WordPress PHPMailer Host Header Command Injection|exploit/unix/webapp/wp_phpmailer_host_header|Required|Required|Required|Required|Required
2|Microsoft Windows RRAS Service MIBEntryGet Overflow|exploit/windows/smb/smb_rras_erraticgopher|Required|-|Required|Required|-

#### 2020 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|F5 BIG-IP TMUI Directory Traversal and File Upload RCE|exploit/linux/http/f5_bigip_tmui_rce|Required|-|Required|Required|Required


### Normal Ranking (125)

#### 1988 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Morris Worm fingerd Stack Buffer Overflow|exploit/bsd/finger/morris_fingerd_bof|Required|-|Required|Required|-

#### 2000 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|LPRng use_syslog Remote Format String Vulnerability|exploit/linux/misc/lprng_format_string|Required|-|Required|Required|-

#### 2002 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS02-065 Microsoft IIS MDAC msadcs.dll RDS DataStub Content-Type Overflow|exploit/windows/iis/ms02_065_msadc|Required|-|Required|Required|-

#### 2003 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Sambar 6 Search Results Buffer Overflow|exploit/windows/http/sambar6_search_results|Required|-|Required|Required|-

#### 2004 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Net-SNMPd Write Access SNMP-EXTEND-MIB arbitrary code execution|exploit/linux/snmp/net_snmpd_rw_access|Required|-|Required|Required|-
2|Ability Server 2.34 STOR Command Stack Buffer Overflow|exploit/windows/ftp/ability_server_stor|Required|Required|Required|Required|-
3|Serv-U FTP Server Buffer Overflow|exploit/windows/ftp/servu_chmod|Required|-|Required|Required|-

#### 2005 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Computer Associates License Server GETCONFIG Overflow|exploit/windows/license/calicserv_getconfig|Required|-|Required|Required|-

#### 2006 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Cyrus IMAPD pop3d popsubfolders USER Buffer Overflow|exploit/linux/pop3/cyrus_pop3d_popsubfolders|Required|-|Required|Required|-
2|PHP Remote File Include Generic Code Execution|exploit/unix/webapp/php_include|Required|-|Required|Required|-
3|KarjaSoft Sami FTP Server v2.0.2 USER Overflow|exploit/windows/ftp/sami_ftpd_user|Required|-|Required|Required|-

#### 2007 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Mercury/32 4.01 IMAP LOGIN SEH Buffer Overflow|exploit/windows/imap/mercury_login|Required|-|Required|Required|-

#### 2008 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Symantec Altiris DS SQL Injection|exploit/windows/misc/altiris_ds_sqli|Required|-|Required|Required|-
2|CitectSCADA/CitectFacilities ODBC Buffer Overflow|exploit/windows/scada/citect_scada_odbc|Required|-|Required|Required|-
3|TFTP Server for Windows 1.4 ST WRQ Buffer Overflow|exploit/windows/tftp/tftpserver_wrq_bof|Required|-|Required|Required|-

#### 2009 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP OpenView Network Node Manager Toolbar.exe CGI Cookie Handling Buffer Overflow|exploit/windows/http/hp_nnm_toolbar_02|Required|-|Required|Required|-

#### 2010 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|JBoss Seam 2 File Upload and Execute|exploit/multi/http/jboss_seam_upload_exec|Required|-|Required|Required|Required
2|Amlibweb NetOpacs webquery.dll Stack Buffer Overflow|exploit/windows/http/amlibweb_webquerydll_app|Required|-|Required|Required|-
3|HP Data Protector DtbClsLogin Buffer Overflow|exploit/windows/misc/hp_dataprotector_dtbclslogin|Required|-|Required|Required|-
4|NetTransport Download Manager 2.90.510 Buffer Overflow|exploit/windows/misc/nettransport|Required|-|Required|Required|-
5|Novell ZENworks Configuration Management Preboot Service 0x21 Buffer Overflow|exploit/windows/novell/zenworks_preboot_op21_bof|Required|-|Required|Required|-
6|Novell ZENworks Configuration Management Preboot Service 0x06 Buffer Overflow|exploit/windows/novell/zenworks_preboot_op6_bof|Required|-|Required|Required|-

#### 2011 (17)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|BisonWare BisonFTP Server Buffer Overflow|exploit/windows/ftp/bison_ftp_bof|Required|-|Required|Required|-
2|HP OpenView NNM nnmRptConfig nameParams Buffer Overflow|exploit/windows/http/hp_nnm_nnmrptconfig_nameparams|Required|-|Required|Required|-
3|HP OpenView NNM nnmRptConfig.exe schdParams Buffer Overflow|exploit/windows/http/hp_nnm_nnmrptconfig_schdparams|Required|-|Required|Required|-
4|HP OpenView Network Node Manager ov.dll _OVBuildPath Buffer Overflow|exploit/windows/http/hp_nnm_ovbuildpath_textfile|Required|-|Required|Required|-
5|HP Power Manager 'formExportDataLogs' Buffer Overflow|exploit/windows/http/hp_power_manager_filename|Required|-|Required|Required|-
6|Avaya WinPMD UniteHostRouter Buffer Overflow|exploit/windows/misc/avaya_winpmd_unihostrouter|Required|-|Required|Required|-
7|Avid Media Composer 5.5 - Avid Phonetic Indexer Buffer Overflow|exploit/windows/misc/avidphoneticindexer|Required|-|Required|Required|-
8|Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020000 Buffer Overflow|exploit/windows/misc/citrix_streamprocess_data_msg|Required|-|Required|Required|-
9|Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020004 Buffer Overflow|exploit/windows/misc/citrix_streamprocess_get_boot_record_request|Required|-|Required|Required|-
10|Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020002 Buffer Overflow|exploit/windows/misc/citrix_streamprocess_get_footer|Required|-|Required|Required|-
11|Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020006 Buffer Overflow|exploit/windows/misc/citrix_streamprocess_get_objects|Required|-|Required|Required|-
12|Enterasys NetSight nssyslogd.exe Buffer Overflow|exploit/windows/misc/enterasys_netsight_syslog_bof|Required|-|Required|Required|-
13|SCADA 3S CoDeSys CmpWebServer Stack Buffer Overflow|exploit/windows/scada/codesys_web_server|Required|-|Required|Required|-
14|Siemens FactoryLink 8 CSService Logging Path Param Buffer Overflow|exploit/windows/scada/factorylink_csservice|Required|-|Required|Required|-
15|7-Technologies IGSS 9 IGSSdataServer .RMS Rename Buffer Overflow|exploit/windows/scada/igss9_igssdataserver_rename|Required|-|Required|-|-
16|Procyon Core Server HMI Coreservice.exe Stack Buffer Overflow|exploit/windows/scada/procyon_core_server|Required|-|Required|Required|-
17|NJStar Communicator 3.00 MiniSMTP Buffer Overflow|exploit/windows/smtp/njstar_smtp_bof|Required|-|Required|Required|-

#### 2012 (23)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP System Management Anonymous Access Code Execution|exploit/linux/http/hp_system_management|Required|-|Required|Required|-
2|Novell eDirectory 8 Buffer Overflow|exploit/linux/misc/novell_edirectory_ncp_bof|Required|-|Required|Required|-
3|Samba SetInformationPolicy AuditEventsInfo Heap Overflow|exploit/linux/samba/setinfopolicy_heap|Required|-|Required|Required|-
4|phpMyAdmin 3.5.2.2 server_sync.php Backdoor|exploit/multi/http/phpmyadmin_3522_backdoor|Required|-|Required|Required|-
5|EMC Networker Format String|exploit/windows/emc/networker_format_string|Required|-|Required|Required|-
6|Free Float FTP Server USER Command Buffer Overflow|exploit/windows/ftp/freefloatftp_user|Required|-|Required|Required|-
7|Ricoh DC DL-10 SR10 FTP USER Command Buffer Overflow|exploit/windows/ftp/ricoh_dl_bof|Required|-|Required|Required|-
8|NetDecision 4.5.1 HTTP Server Buffer Overflow|exploit/windows/http/netdecision_http_bof|Required|-|Required|Required|-
9|PHP apache_request_headers Function Buffer Overflow|exploit/windows/http/php_apache_request_headers_bof|Required|-|Required|Required|Required
10|RabidHamster R4 Log Entry sprintf() Buffer Overflow|exploit/windows/http/rabidhamster_r4_log|Required|-|Required|Required|-
11|Simple Web Server Connection Header Buffer Overflow|exploit/windows/http/sws_connection_bof|Required|-|Required|Required|-
12|FlexNet License Server Manager lmgrd Buffer Overflow|exploit/windows/license/flexnet_lmgrd_bof|Required|-|Required|Required|-
13|ALLMediaServer 0.8 Buffer Overflow|exploit/windows/misc/allmediaserver_bof|Required|-|Required|Required|-
14|GIMP script-fu Server Buffer Overflow|exploit/windows/misc/gimp_script_fu|Required|-|Required|Required|-
15|HP Data Protector Create New Folder Buffer Overflow|exploit/windows/misc/hp_dataprotector_new_folder|Required|Required|Required|Required|-
16|HP Intelligent Management Center UAM Buffer Overflow|exploit/windows/misc/hp_imc_uam|Required|-|Required|Required|-
17|IBM Cognos tm1admsd.exe Overflow|exploit/windows/misc/ibm_cognos_tm1admsd_bof|Required|-|Required|Required|-
18|Poison Ivy Server Buffer Overflow|exploit/windows/misc/poisonivy_bof|Required|-|Required|Required|-
19|SAP NetWeaver Dispatcher DiagTraceR3Info Buffer Overflow|exploit/windows/misc/sap_netweaver_dispatcher|Required|-|Required|Required|-
20|Novell ZENworks Configuration Management Preboot Service 0x4c Buffer Overflow|exploit/windows/novell/zenworks_preboot_op4c_bof|Required|-|Required|Required|-
21|Novell ZENworks Configuration Management Preboot Service 0x6c Buffer Overflow|exploit/windows/novell/zenworks_preboot_op6c_bof|Required|-|Required|Required|-
22|Sielco Sistemi Winlog Buffer Overflow 2.07.14 - 2.07.16|exploit/windows/scada/winlog_runtime_2|Required|-|Required|Required|-
23|Sysax 5.53 SSH Username Buffer Overflow|exploit/windows/ssh/sysax_ssh_username|Required|-|Required|-|-

#### 2013 (18)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|D-Link authentication.cgi Buffer Overflow|exploit/linux/http/dlink_authentication_cgi_bof|Required|-|Required|Required|-
2|D-Link hedwig.cgi Buffer Overflow in Cookie Header|exploit/linux/http/dlink_hedwig_cgi_bof|Required|-|Required|Required|-
3|D-Link Devices UPnP SOAP Command Execution|exploit/linux/http/dlink_upnp_exec_noauth|Required|-|Required|Required|-
4|HP StorageWorks P4000 Virtual SAN Appliance Login Buffer Overflow|exploit/linux/misc/hp_vsa_login_bof|Required|-|Required|Required|-
5|MiniUPnPd 1.0 Stack Buffer Overflow Remote Code Execution|exploit/linux/upnp/miniupnpd_soap_bof|Required|-|Required|Required|-
6|FTP JCL Execution|exploit/mainframe/ftp/ftp_jcl_creds|Required|-|Required|Required|-
7|Portable UPnP SDK unique_service_name() Remote Code Execution|exploit/multi/upnp/libupnp_ssdp_overflow|Required|-|Required|Required|-
8|Polycom Command Shell Authorization Bypass|exploit/unix/misc/polycom_hdx_auth_bypass|Required|-|Required|Required|-
9|WordPress Plugin Google Document Embedder Arbitrary File Disclosure|exploit/unix/webapp/wp_google_document_embedder_exec|Required|-|Required|Required|Required
10|freeFTPd PASS Command Buffer Overflow|exploit/windows/ftp/freeftpd_pass|Required|Required|Required|Required|-
11|PCMAN FTP Server Post-Authentication STOR Command Stack Buffer Overflow|exploit/windows/ftp/pcman_stor|Required|-|Required|Required|-
12|Cogent DataHub HTTP Server Buffer Overflow|exploit/windows/http/cogent_datahub_request_headers_bof|Required|-|Required|Required|-
13|Ultra Mini HTTPD Stack Buffer Overflow|exploit/windows/http/ultraminihttp_bof|Required|-|Required|Required|-
14|BigAnt Server 2 SCH And DUPF Buffer Overflow|exploit/windows/misc/bigant_server_sch_dupf_bof|Required|-|Required|Required|-
15|Firebird Relational Database CNCT Group Number Buffer Overflow|exploit/windows/misc/fb_cnct_group|Required|-|Required|Required|-
16|HP Data Protector Cell Request Service Buffer Overflow|exploit/windows/misc/hp_dataprotector_crs|Required|-|Required|-|-
17|HP LoadRunner magentproc.exe Overflow|exploit/windows/misc/hp_loadrunner_magentproc|Required|-|Required|Required|-
18|Lianja SQL 1.0.0RC5.1 db_netserver Stack Buffer Overflow|exploit/windows/misc/lianja_db_net|Required|-|Required|Required|-

#### 2014 (14)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Belkin Play N750 login.cgi Buffer Overflow|exploit/linux/http/belkin_login_bof|Required|-|Required|Required|-
2|D-Link info.cgi POST Request Buffer Overflow|exploit/linux/http/dlink_dspw215_info_cgi_bof|Required|-|Required|Required|-
3|D-Link HNAP Request Remote Buffer Overflow|exploit/linux/http/dlink_hnap_bof|Required|-|Required|Required|-
4|Arris VAP2500 tools_command.php Command Execution|exploit/linux/http/vap2500_tools_command_exec|Required|-|Required|Required|-
5|Hikvision DVR RTSP Request Remote Code Execution|exploit/linux/misc/hikvision_rtsp_bof|Required|-|Required|Required|-
6|HP Network Node Manager I PMD Buffer Overflow|exploit/linux/misc/hp_nnmi_pmd_bof|Required|-|Required|Required|-
7|Netcore Router Udp 53413 Backdoor|exploit/linux/misc/netcore_udp_53413_backdoor|Required|-|Required|Required|-
8|Qmail SMTP Bash Environment Variable Injection (Shellshock)|exploit/unix/smtp/qmail_bash_env_exec|Required|-|Required|Required|-
9|Easy File Management Web Server Stack Buffer Overflow|exploit/windows/http/efs_fmws_userid_bof|Required|-|Required|Required|Required
10|Ericom AccessNow Server Buffer Overflow|exploit/windows/http/ericom_access_now_bof|Required|-|Required|Required|-
11|Achat Unicode SEH Buffer Overflow|exploit/windows/misc/achat_bof|Required|-|Required|Required|-
12|Yokogawa CENTUM CS 3000 BKBCopyD.exe Buffer Overflow|exploit/windows/scada/yokogawa_bkbcopyd_bof|Required|-|Required|Required|-
13|Yokogawa CS3000 BKESimmgr.exe Buffer Overflow|exploit/windows/scada/yokogawa_bkesimmgr_bof|Required|-|Required|Required|-
14|Yokogawa CS3000 BKFSim_vhfd.exe Buffer Overflow|exploit/windows/scada/yokogawa_bkfsim_vhfd|Required|-|Required|Required|-

#### 2015 (10)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Airties login-cgi Buffer Overflow|exploit/linux/http/airties_login_cgi_bof|Required|-|Required|Required|-
2|D-Link Cookie Command Execution|exploit/linux/http/dlink_dspw110_cookie_noauth_exec|Required|-|Required|Required|-
3|D-Link Devices HNAP SOAPAction-Header Command Execution|exploit/linux/http/dlink_hnap_header_exec_noauth|Required|-|Required|Required|-
4|D-Link/TRENDnet NCC Service Command Injection|exploit/linux/http/multi_ncc_ping_exec|Required|-|Required|Required|Required
5|Realtek SDK Miniigd UPnP SOAP Command Execution|exploit/linux/http/realtek_miniigd_upnp_exec_noauth|Required|-|Required|Required|-
6|Seagate Business NAS Unauthenticated Remote Command Execution|exploit/linux/http/seagate_nas_php_exec_noauth|Required|-|Required|Required|Required
7|OpenNMS Java Object Unserialization Remote Code Execution|exploit/linux/misc/opennms_java_serialize|Required|-|Required|Required|-
8|Apache James Server 2.3.2 Insecure User Creation Arbitrary File Write|exploit/linux/smtp/apache_james_exec|Required|Required|Required|Required|-
9|Konica Minolta FTP Utility 1.00 Post Auth CWD Command SEH Overflow|exploit/windows/ftp/kmftp_utility_cwd|Required|-|Required|Required|-
10|PCMAN FTP Server Buffer Overflow - PUT Command|exploit/windows/ftp/pcman_put|Required|-|Required|Required|-

#### 2016 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Zyxel/Eir D1000 DSL Modem NewNTPServer Command Injection Over TR-064|exploit/linux/http/tr064_ntpserver_cmdinject|Required|-|Required|Required|-
2|Poison Ivy 2.1.x C2 Buffer Overflow|exploit/windows/misc/poisonivy_21x_bof|Required|-|Required|Required|-

#### 2017 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP Jetdirect Path Traversal Arbitrary Code Execution|exploit/linux/misc/hp_jetdirect_path_traversal|Required|-|Required|Required|-
2|Quest Privilege Manager pmmasterd Buffer Overflow|exploit/linux/misc/quest_pmmasterd_bof|Required|-|Required|Required|-
3|Easy Chat Server User Registeration Buffer Overflow (SEH)|exploit/windows/http/easychatserver_seh|Required|-|Required|Required|-
4|Geutebrueck GCore - GCoreServer.exe Buffer Overflow RCE|exploit/windows/http/geutebrueck_gcore_x64_rce_bo|Required|-|Required|Required|-
5|Gh0st Client buffer Overflow|exploit/windows/misc/gh0st|Required|-|Required|Required|-
6|PlugX Controller Stack Buffer Overflow|exploit/windows/misc/plugx|Required|-|Required|Required|-

#### 2018 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Cisco RV320 and RV325 Unauthenticated Remote Code Execution|exploit/linux/http/cisco_rv32x_rce|Required|-|Required|Required|-
2|Nuuo Central Management Authenticated SQL Server SQLi|exploit/windows/nuuo/nuuo_cms_sqli|Required|-|Required|Required|-
3|Delta Electronics Delta Industrial Automation COMMGR 1.08 Stack Buffer Overflow|exploit/windows/scada/delta_ia_commgr_bof|Required|-|Required|Required|-

#### 2019 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|OpenMRS Java Deserialization RCE|exploit/multi/http/openmrs_deserialization|Required|-|Required|Required|Required
2|PHP-FPM Underflow RCE|exploit/multi/http/php_fpm_rce|Required|-|Required|Required|Required
3|Drupal RESTful Web Services unserialize() RCE|exploit/unix/webapp/drupal_restws_unserialize|Required|-|Required|Required|Required
4|File Sharing Wizard - POST SEH Overflow|exploit/windows/http/file_sharing_wizard_seh|Required|-|Required|Required|-

#### 2020 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SpamTitan Unauthenticated RCE|exploit/freebsd/webapp/spamtitan_unauth_rce|Required|-|Required|Required|Required
2|AnyDesk GUI Format String Write|exploit/linux/misc/cve_2020_13160_anydesk|Required|-|Required|Required|-
3|WordPress File Manager Unauthenticated Remote Code Execution|exploit/multi/http/wp_file_manager_rce|Required|-|Required|Required|Required
4|WebLogic Server Deserialization RCE BadAttributeValueExpException ExtComp|exploit/multi/misc/weblogic_deserialize_badattr_extcomp|Required|-|Required|Required|-
5|WebLogic Server Deserialization RCE - BadAttributeValueExpException|exploit/multi/misc/weblogic_deserialize_badattrval|Required|-|Required|Required|-
6|Veeam ONE Agent .NET Deserialization|exploit/windows/misc/veeam_one_agent_deserialization|Required|-|Required|Required|-


### Good Ranking (105)

#### 2000 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|UoW IMAP Server LSUB Buffer Overflow|exploit/linux/imap/imap_uw_lsub|Required|-|Required|Required|-
2|MS00-094 Microsoft IIS Phone Book Service Overflow|exploit/windows/isapi/ms00_094_pbserver|Required|-|Required|Required|-

#### 2001 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|NTP Daemon readvar Buffer Overflow|exploit/multi/ntp/ntp_overflow|Required|-|Required|Required|-
2|MS01-023 Microsoft IIS 5.0 Printer Host Header Overflow|exploit/windows/iis/ms01_023_printer|Required|-|Required|Required|-
3|MS01-033 Microsoft IIS 5.0 IDQ Path Overflow|exploit/windows/iis/ms01_033_idq|Required|-|Required|Required|-
4|Network Associates PGP KeyServer 7 LDAP Buffer Overflow|exploit/windows/ldap/pgp_keyserver7|Required|-|Required|Required|-
5|Oracle 8i TNS Listener (ARGUMENTS) Buffer Overflow|exploit/windows/oracle/tns_arguments|Required|-|Required|Required|-

#### 2002 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apache Win32 Chunked Encoding|exploit/windows/http/apache_chunked|Required|-|Required|Required|-
2|MS02-018 Microsoft IIS 4.0 .HTR Path Overflow|exploit/windows/iis/ms02_018_htr|Required|-|Required|Required|-
3|MS02-039 Microsoft SQL Server Resolution Overflow|exploit/windows/mssql/ms02_039_slammer|Required|-|Required|Required|-
4|MS02-056 Microsoft SQL Server Hello Overflow|exploit/windows/mssql/ms02_056_hello|Required|-|Required|Required|-
5|Oracle 8i TNS Listener SERVICE_NAME Buffer Overflow|exploit/windows/oracle/tns_service_name|Required|-|Required|Required|-

#### 2003 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS03-022 Microsoft IIS ISAPI nsiislog.dll ISAPI POST Overflow|exploit/windows/isapi/ms03_022_nsiislog_post|Required|-|Required|Required|-
2|MS03-051 Microsoft IIS ISAPI FrontPage fp30reg.dll Chunked Overflow|exploit/windows/isapi/ms03_051_fp30reg_chunked|Required|-|Required|Required|-
3|NIPrint LPD Request Overflow|exploit/windows/lpd/niprint|Required|-|Required|Required|-
4|MS03-049 Microsoft Workstation Service NetAddAlternateComputerName Overflow|exploit/windows/smb/ms03_049_netapi|Required|-|Required|Required|-
5|MS03-046 Exchange 2000 XEXCH50 Heap Overflow|exploit/windows/smtp/ms03_046_exchange2000_xexch50|Required|-|Required|Required|-

#### 2004 (7)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Unreal Tournament 2004 "secure" Overflow (Linux)|exploit/linux/games/ut2004_secure|Required|-|Required|Required|-
2|BolinTech Dream FTP Server 1.02 Format String|exploit/windows/ftp/dreamftp_format|Required|-|Required|Required|-
3|Serv-U FTPD MDTM Overflow|exploit/windows/ftp/servu_mdtm|Required|-|Required|Required|-
4|Unreal Tournament 2004 "secure" Overflow (Win32)|exploit/windows/games/ut2004_secure|Required|-|Required|Required|-
5|Microsoft IIS ISAPI w3who.dll Query String Overflow|exploit/windows/isapi/w3who_query|Required|-|Required|Required|-
6|MS04-011 Microsoft LSASS Service DsRolerUpgradeDownlevelServer Overflow|exploit/windows/smb/ms04_011_lsass|Required|-|Required|Required|-
7|MS04-031 Microsoft NetDDE Service Overflow|exploit/windows/smb/ms04_031_netdde|Required|-|Required|Required|-

#### 2005 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Snort Back Orifice Pre-Preprocessor Buffer Overflow|exploit/linux/ids/snortbopre|Required|-|Required|Required|-
2|GLD (Greylisting Daemon) Postfix Buffer Overflow|exploit/linux/misc/gld_postfix|Required|-|Required|Required|-
3|Arkeia Backup Client Type 77 Overflow (Win32)|exploit/windows/arkeia/type77|Required|-|Required|Required|-
4|MaxDB WebDBM GET Buffer Overflow|exploit/windows/http/maxdb_webdbm_get_overflow|Required|-|Required|Required|-
5|Microsoft IIS ISAPI RSA WebAgent Redirect Overflow|exploit/windows/isapi/rsa_webagent_redirect|Required|-|Required|Required|-
6|MS05-039 Microsoft Plug and Play Service Overflow|exploit/windows/smb/ms05_039_pnp|Required|-|Required|Required|-

#### 2006 (7)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Symantec Remote Management Buffer Overflow|exploit/windows/antivirus/symantec_rtvscan|Required|-|Required|Required|-
2|MaxDB WebDBM Database Parameter Overflow|exploit/windows/http/maxdb_webdbm_database|Required|-|Required|Required|-
3|Qbik WinGate WWW Proxy Server URL Processing Overflow|exploit/windows/proxy/qbik_wingate_wwwproxy|Required|-|Required|Required|-
4|MS06-025 Microsoft RRAS Service RASMAN Registry Overflow|exploit/windows/smb/ms06_025_rasmans_reg|Required|-|Required|Required|-
5|MS06-040 Microsoft Server Service NetpwPathCanonicalize Overflow|exploit/windows/smb/ms06_040_netapi|Required|-|Required|Required|-
6|MS06-066 Microsoft Services nwapi32.dll Module Exploit|exploit/windows/smb/ms06_066_nwapi|Required|-|Required|Required|-
7|MS06-066 Microsoft Services nwwks.dll Module Exploit|exploit/windows/smb/ms06_066_nwwks|Required|-|Required|Required|-

#### 2007 (15)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Borland InterBase INET_connect() Buffer Overflow|exploit/linux/misc/ib_inet_connect|Required|-|Required|Required|-
2|Borland InterBase jrd8_create_database() Buffer Overflow|exploit/linux/misc/ib_jrd8_create_database|Required|-|Required|Required|-
3|Borland InterBase open_marker_file() Buffer Overflow|exploit/linux/misc/ib_open_marker_file|Required|-|Required|Required|-
4|Borland InterBase PWD_db_aliased() Buffer Overflow|exploit/linux/misc/ib_pwd_db_aliased|Required|-|Required|Required|-
5|Samba lsa_io_trans_names Heap Overflow|exploit/linux/samba/lsa_transnames_heap|Required|-|Required|Required|-
6|Trend Micro ServerProtect 5.58 Buffer Overflow|exploit/windows/antivirus/trendmicro_serverprotect|Required|-|Required|Required|-
7|Trend Micro ServerProtect 5.58 CreateBinding() Buffer Overflow|exploit/windows/antivirus/trendmicro_serverprotect_createbinding|Required|-|Required|Required|-
8|Trend Micro ServerProtect 5.58 EarthAgent.EXE Buffer Overflow|exploit/windows/antivirus/trendmicro_serverprotect_earthagent|Required|-|Required|Required|-
9|IBM TPM for OS Deployment 5.1.0.x rembo.exe Buffer Overflow|exploit/windows/http/ibm_tpmfosd_overflow|Required|-|Required|Required|-
10|IBM Tivoli Storage Manager Express CAD Service Buffer Overflow|exploit/windows/http/ibm_tsm_cad_header|Required|-|Required|Required|-
11|Trend Micro OfficeScan Remote Stack Buffer Overflow|exploit/windows/http/trendmicro_officescan|Required|-|Required|Required|-
12|Borland InterBase isc_attach_database() Buffer Overflow|exploit/windows/misc/ib_isc_attach_database|Required|-|Required|Required|-
13|Borland InterBase isc_create_database() Buffer Overflow|exploit/windows/misc/ib_isc_create_database|Required|-|Required|Required|-
14|Borland InterBase SVC_attach() Buffer Overflow|exploit/windows/misc/ib_svc_attach|Required|-|Required|Required|-
15|D-Link TFTP 1.0 Long Filename Buffer Overflow|exploit/windows/tftp/dlink_long_filename|Required|-|Required|Required|-

#### 2008 (7)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MySQL yaSSL SSL Hello Message Buffer Overflow|exploit/linux/mysql/mysql_yassl_hello|Required|-|Required|Required|-
2|HP OpenView NNM 7.53, 7.51 OVAS.EXE Pre-Authentication Stack Buffer Overflow|exploit/windows/http/hp_nnm_ovas|Required|-|Required|Required|-
3|Now SMS/MMS Gateway Buffer Overflow|exploit/windows/http/nowsms|Required|-|Required|Required|-
4|SAP SAPLPD 6.28 Buffer Overflow|exploit/windows/lpd/saplpd|Required|-|Required|Required|-
5|WinComLPD Buffer Overflow|exploit/windows/lpd/wincomlpd_admin|Required|-|Required|Required|-
6|MS09-004 Microsoft SQL Server sp_replwritetovarbin Memory Corruption|exploit/windows/mssql/ms09_004_sp_replwritetovarbin|Required|-|Required|Required|-
7|Quick FTP Pro 2.1 Transfer-Mode Overflow|exploit/windows/tftp/quick_tftp_pro_mode|Required|-|Required|Required|-

#### 2009 (9)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|NetWare 6.5 SunRPC Portmapper CALLIT Stack Buffer Overflow|exploit/netware/sunrpc/pkernel_callit|Required|-|Required|Required|-
2|Symantec Alert Management System Intel Alert Originator Service Buffer Overflow|exploit/windows/antivirus/symantec_iao|Required|-|Required|Required|-
3|Xlink FTP Server Buffer Overflow|exploit/windows/ftp/xlink_server|Required|-|Required|Required|-
4|BEA WebLogic JSESSIONID Cookie Value Overflow|exploit/windows/http/bea_weblogic_jsessionid|Required|-|Required|Required|-
5|Rhinosoft Serv-U Session Cookie Buffer Overflow|exploit/windows/http/servu_session_cookie|Required|-|Required|Required|-
6|Bopup Communications Server Buffer Overflow|exploit/windows/misc/bopup_comm|Required|-|Required|Required|-
7|IBM Tivoli Storage Manager Express CAD Service Buffer Overflow|exploit/windows/misc/ibm_tsm_cad_ping|Required|-|Required|Required|-
8|Oracle Secure Backup NDMP_CONNECT_CLIENT_AUTH Buffer Overflow|exploit/windows/oracle/osb_ndmp_auth|Required|-|Required|Required|-
9|MS09-050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference|exploit/windows/smb/ms09_050_smb2_negotiate_func_index|Required|-|Required|Required|-

#### 2010 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MySQL yaSSL CertDecoder::GetName Buffer Overflow|exploit/linux/mysql/mysql_yassl_getname|Required|-|Required|Required|-
2|Samba chain_reply Memory Corruption (Linux x86)|exploit/linux/samba/chain_reply|Required|-|Required|Required|-
3|Java Debug Wire Protocol Remote Code Execution|exploit/multi/misc/java_jdwp_debugger|Required|-|Required|Required|-
4|Kolibri HTTP Server HEAD Buffer Overflow|exploit/windows/http/kolibri_http|Required|-|Required|Required|-
5|AgentX++ Master AgentX::receive_agentx Stack Buffer Overflow|exploit/windows/misc/agentxpp_receive_agentx|Required|-|Required|Required|-

#### 2011 (7)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|IBM Tivoli Endpoint Manager POST Query Buffer Overflow|exploit/windows/http/ibm_tivoli_endpoint_bof|Required|-|Required|Required|-
2|Blue Coat Authentication and Authorization Agent (BCAAA) 5 Buffer Overflow|exploit/windows/misc/bcaaa_bof|Required|-|Required|Required|-
3|Citrix Provisioning Services 5.6 streamprocess.exe Buffer Overflow|exploit/windows/misc/citrix_streamprocess|Required|-|Required|Required|-
4|HP OmniInet.exe Opcode 20 Buffer Overflow|exploit/windows/misc/hp_omniinet_4|Required|-|Required|Required|-
5|TrendMicro Control Manger CmdProcessor.exe Stack Buffer Overflow|exploit/windows/misc/trendmicro_cmdprocessor_addtask|Required|-|Required|Required|-
6|Iconics GENESIS32 Integer Overflow Version 9.21.201.01|exploit/windows/scada/iconics_genbroker|Required|-|Required|Required|-
7|7-Technologies IGSS IGSSdataServer.exe Stack Buffer Overflow|exploit/windows/scada/igss9_igssdataserver_listall|Required|-|Required|Required|-

#### 2012 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Zenoss 3 showDaemonXMLConfig Command Execution|exploit/linux/http/zenoss_showdaemonxmlconfig_exec|Required|Required|Required|Required|-
2|HP SiteScope Remote Code Execution|exploit/multi/http/hp_sitescope_uploadfileshandler|Required|-|Required|Required|Required
3|Netwin SurgeFTP Remote Command Execution|exploit/multi/http/netwin_surgeftp_exec|Required|Required|Required|Required|-
4|Splunk Custom App Remote Code Execution|exploit/multi/http/splunk_upload_app_exec|Required|Required|Required|Required|-
5|Xerox Multifunction Printers (MFP) "Patch" DLM Vulnerability|exploit/unix/misc/xerox_mfp|Required|-|Required|Required|-
6|ComSndFTP v1.3.7 Beta USER Format String (Write4) Vulnerability|exploit/windows/ftp/comsnd_ftpd_fmtstr|Required|-|Required|Required|-

#### 2013 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Supermicro Onboard IPMI close_window.cgi Buffer Overflow|exploit/linux/http/smt_ipmi_close_window_bof|Required|-|Required|Required|-
2|Jenkins-CI Script-Console Java Execution|exploit/multi/http/jenkins_script_console|Required|-|Required|Required|Required

#### 2014 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SolidWorks Workgroup PDM 2014 pdmwService.exe Arbitrary File Write|exploit/windows/misc/solidworks_workgroup_pdmwservice_file_write|Required|-|Required|Required|-

#### 2015 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SixApart MovableType Storable Perl Code Execution|exploit/unix/webapp/sixapart_movabletype_storable_exec|Required|-|Required|Required|Required
2|HP SiteScope DNS Tool Command Injection|exploit/windows/http/hp_sitescope_dns_tool|Required|-|Required|Required|Required

#### 2016 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|PostgreSQL CREATE LANGUAGE Execution|exploit/multi/postgres/postgres_createlang|Required|Required|Required|Required|-

#### 2017 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Samsung SRN-1670D Web Viewer Version 1.0.0.193 Arbitrary File Read and Upload|exploit/linux/http/samsung_srv_1670d_upload_exec|Required|-|Required|Required|-
2|MediaWiki SyntaxHighlight extension option injection vulnerability|exploit/multi/http/mediawiki_syntaxhighlight|Required|-|Required|Required|Required
3|OrientDB 2.2.x Remote Code Execution|exploit/multi/http/orientdb_exec|Required|Required|Required|Required|Required
4|Commvault Communications Service (cvd) Command Injection|exploit/windows/misc/commvault_cmd_exec|Required|-|Required|Required|-
5|Advantech WebAccess Webvrpcs Service Opcode 80061 Stack Buffer Overflow|exploit/windows/scada/advantech_webaccess_webvrpcs_bof|Required|-|Required|Required|-

#### 2018 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|php imap_open Remote Code Execution|exploit/linux/http/php_imap_open_rce|Required|-|Required|Required|Required
2|Redis Replication Code Execution|exploit/linux/redis/redis_replication_cmd_exec|Required|-|Required|Required|-
3|phpMyAdmin Authenticated Remote Code Execution|exploit/multi/http/phpmyadmin_lfi_rce|Required|Required|Required|Required|Required

#### 2019 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Cisco RV110W/RV130(W)/RV215W Routers Management Interface Remote Command Execution|exploit/linux/http/cve_2019_1663_cisco_rmi_rce|Required|-|Required|Required|-
2|Nostromo Directory Traversal Remote Command Execution|exploit/multi/http/nostromo_code_exec|Required|-|Required|Required|-

#### 2020 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Rconfig 3.x Chained Remote Code Execution|exploit/linux/http/rconfig_ajaxarchivefiles_rce|Required|-|Required|Required|Required
2|WordPress Simple File List Unauthenticated Remote Code Execution|exploit/multi/http/wp_simple_file_list_rce|Required|-|Required|Required|Required
3|Pi-Hole DHCP MAC OS Command Execution|exploit/unix/http/pihole_dhcp_mac_exec|Required|-|Required|Required|Required


### Great Ranking (163)

#### 2000 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|WU-FTPD SITE EXEC/INDEX Format String Vulnerability|exploit/multi/ftp/wuftpd_site_exec_format|Required|-|Required|Required|-

#### 2002 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|RealServer Describe Buffer Overflow|exploit/multi/realserver/describe|Required|-|Required|Required|-
2|Solaris dtspcd Heap Overflow|exploit/solaris/dtspcd/heap_noir|Required|-|Required|Required|-
3|Savant 3.1 Web Server Overflow|exploit/windows/http/savant_31_overflow|Required|-|Required|Required|-

#### 2003 (13)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Samba trans2open Overflow (*BSD x86)|exploit/freebsd/samba/trans2open|Required|-|Required|Required|-
2|Poptop Negative Read Overflow|exploit/linux/pptp/poptop_negative_read|Required|-|Required|Required|-
3|Samba trans2open Overflow (Linux x86)|exploit/linux/samba/trans2open|Required|-|Required|Required|-
4|Samba trans2open Overflow (Mac OS X PPC)|exploit/osx/samba/trans2open|Required|-|Required|Required|-
5|Samba trans2open Overflow (Solaris SPARC)|exploit/solaris/samba/trans2open|Required|-|Required|Required|-
6|MS03-026 Microsoft RPC DCOM Interface Overflow|exploit/windows/dcerpc/ms03_026_dcom|Required|-|Required|Required|-
7|Oracle 9i XDB FTP PASS Overflow (win32)|exploit/windows/ftp/oracle9i_xdb_ftp_pass|Required|-|Required|Required|-
8|Oracle 9i XDB FTP UNLOCK Overflow (win32)|exploit/windows/ftp/oracle9i_xdb_ftp_unlock|Required|Required|Required|Required|-
9|BadBlue 2.5 EXT.dll Buffer Overflow|exploit/windows/http/badblue_ext_overflow|Required|-|Required|Required|-
10|MDaemon WorldClient form2raw.cgi Stack Buffer Overflow|exploit/windows/http/mdaemon_worldclient_form2raw|Required|-|Required|Required|-
11|Oracle 9i XDB HTTP PASS Overflow (win32)|exploit/windows/http/oracle9i_xdb_pass|Required|-|Required|Required|-
12|MS03-007 Microsoft IIS 5.0 WebDAV ntdll.dll Path Overflow|exploit/windows/iis/ms03_007_ntdll_webdav|Required|-|Required|Required|-
13|Seattle Lab Mail 5.5 POP3 Buffer Overflow|exploit/windows/pop3/seattlelab_pass|Required|-|Required|Required|-

#### 2004 (10)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Mercantec SoftCart CGI Overflow|exploit/bsdi/softcart/mercantec_softcart|Required|-|Required|Required|-
2|ISS PAM.dll ICQ Parser Buffer Overflow|exploit/windows/firewall/blackice_pam_icq|Required|-|Required|Required|-
3|WS-FTP Server 5.03 MKD Overflow|exploit/windows/ftp/wsftp_server_503_mkd|Required|-|Required|Required|-
4|Medal of Honor Allied Assault getinfo Stack Buffer Overflow|exploit/windows/games/mohaa_getinfo|Required|-|Required|Required|-
5|Icecast Header Overwrite|exploit/windows/http/icecast_header|Required|-|Required|Required|-
6|Ipswitch WhatsUp Gold 8.03 Buffer Overflow|exploit/windows/http/ipswitch_wug_maincfgret|Required|Required|Required|Required|-
7|Mdaemon 8.0.3 IMAPD CRAM-MD5 Authentication Overflow|exploit/windows/imap/mdaemon_cram_md5|Required|-|Required|Required|-
8|ShixxNOTE 6.net Font Field Overflow|exploit/windows/misc/shixxnote_font|Required|-|Required|Required|-
9|Proxy-Pro Professional GateKeeper 4.7 GET Request Overflow|exploit/windows/proxy/proxypro_http_get|Required|-|Required|Required|-
10|MS04-045 Microsoft WINS Service Memory Overwrite|exploit/windows/wins/ms04_045_wins|Required|-|Required|Required|-

#### 2005 (11)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Linksys WRT54 Access Point apply.cgi Buffer Overflow|exploit/linux/http/linksys_apply_cgi|Required|-|Required|Required|-
2|Veritas Backup Exec Windows Remote Agent Overflow|exploit/windows/backupexec/remote_agent|Required|-|Required|Required|-
3|GlobalSCAPE Secure FTP Server Input Overflow|exploit/windows/ftp/globalscapeftp_input|Required|-|Required|Required|-
4|NetTerm NetFTPD USER Buffer Overflow|exploit/windows/ftp/netterm_netftpd_user|Required|-|Required|Required|-
5|SlimFTPd LIST Concatenation Overflow|exploit/windows/ftp/slimftpd_list_concat|Required|-|Required|Required|-
6|eDirectory 8.7.3 iMonitor Remote Stack Buffer Overflow|exploit/windows/http/edirectory_imonitor|Required|-|Required|Required|-
7|MailEnable Authorization Header Buffer Overflow|exploit/windows/http/mailenable_auth_header|Required|-|Required|Required|-
8|Qualcomm WorldMail 3.0 IMAPD LIST Buffer Overflow|exploit/windows/imap/eudora_list|Required|-|Required|Required|-
9|MailEnable IMAPD (1.54) STATUS Request Buffer Overflow|exploit/windows/imap/mailenable_status|Required|-|Required|Required|-
10|MailEnable IMAPD W3C Logging Buffer Overflow|exploit/windows/imap/mailenable_w3c_select|Required|-|Required|Required|-
11|Blue Coat WinProxy Host Header Overflow|exploit/windows/proxy/bluecoat_winproxy_host|Required|-|Required|Required|-

#### 2006 (10)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|ProFTPD 1.2 - 1.3.0 sreplace Buffer Overflow (Linux)|exploit/linux/ftp/proftp_sreplace|Required|-|Required|Required|-
2|Apache Module mod_rewrite LDAP Protocol Buffer Overflow|exploit/windows/http/apache_mod_rewrite_ldap|Required|-|Required|Required|-
3|Novell eDirectory NDS Server Host Header Overflow|exploit/windows/http/edirectory_host|Required|-|Required|Required|-
4|NaviCOPA 2.0.1 URL Handling Buffer Overflow|exploit/windows/http/navicopa_get_overflow|Required|-|Required|Required|-
5|MailEnable IMAPD (2.34/2.35) Login Request Buffer Overflow|exploit/windows/imap/mailenable_login|Required|-|Required|Required|-
6|AIM Triton 1.0.4 CSeq Buffer Overflow|exploit/windows/sip/aim_triton_cseq|Required|-|Required|Required|-
7|SIPfoundry sipXezPhone 0.35a CSeq Field Overflow|exploit/windows/sip/sipxezphone_cseq|Required|-|Required|Required|-
8|SIPfoundry sipXphone 2.6.0.27 CSeq Buffer Overflow|exploit/windows/sip/sipxphone_cseq|Required|-|Required|Required|-
9|TFTPDWIN v0.4.2 Long Filename Buffer Overflow|exploit/windows/tftp/tftpdwin_long_filename|Required|-|Required|Required|-
10|3CTftpSvc TFTP Long Mode Buffer Overflow|exploit/windows/tftp/threectftpsvc_long_mode|Required|-|Required|Required|-

#### 2007 (8)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|CA BrightStor HSM Buffer Overflow|exploit/windows/brightstor/hsmserver|Required|-|Required|Required|-
2|MS07-029 Microsoft DNS RPC Service extractQuotedChar() Overflow (TCP)|exploit/windows/dcerpc/ms07_029_msdns_zonename|Required|-|Required|Required|-
3|Apache mod_jk 1.2.20 Buffer Overflow|exploit/windows/http/apache_modjk_overflow|Required|-|Required|Required|-
4|BadBlue 2.72b PassThru Buffer Overflow|exploit/windows/http/badblue_passthru|Required|-|Required|Required|-
5|EFS Easy Chat Server Authentication Request Handling Buffer Overflow|exploit/windows/http/efs_easychatserver_username|Required|-|Required|Required|-
6|HP OpenView Network Node Manager OpenView5.exe CGI Buffer Overflow|exploit/windows/http/hp_nnm_openview5|Required|-|Required|Required|-
7|SAP DB 7.4 WebTools Buffer Overflow|exploit/windows/http/sapdb_webtools|Required|-|Required|Required|-
8|Mercury Mail SMTP AUTH CRAM-MD5 Buffer Overflow|exploit/windows/smtp/mercury_cram_md5|Required|-|Required|Required|-

#### 2008 (9)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Sun Solaris sadmind adm_build_path() Buffer Overflow|exploit/solaris/sunrpc/sadmind_adm_build_path|Required|-|Required|Required|-
2|EMC AlphaStor Agent Buffer Overflow|exploit/windows/emc/alphastor_agent|Required|-|Required|Required|-
3|Racer v0.5.3 Beta 5 Buffer Overflow|exploit/windows/games/racer_503beta5|Required|-|Required|Required|-
4|Oracle Weblogic Apache Connector POST Request Buffer Overflow|exploit/windows/http/bea_weblogic_post_bof|Required|-|Required|Required|Required
5|BEA Weblogic Transfer-Encoding Buffer Overflow|exploit/windows/http/bea_weblogic_transfer_encoding|Required|-|Required|Required|-
6|MDaemon 9.6.4 IMAPD FETCH Buffer Overflow|exploit/windows/imap/mdaemon_fetch|Required|-|Required|Required|-
7|BigAnt Server 2.50 SP1 Buffer Overflow|exploit/windows/misc/bigant_server_250|Required|-|Required|Required|-
8|DATAC RealWin SCADA Server Buffer Overflow|exploit/windows/scada/realwin|Required|-|Required|Required|-
9|MS08-067 Microsoft Server Service Relative Path Stack Corruption|exploit/windows/smb/ms08_067_netapi|Required|-|Required|Required|-

#### 2009 (22)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow|exploit/aix/rpc_cmsd_opcode21|Required|-|Required|Required|-
2|ToolTalk rpc.ttdbserverd _tt_internal_realpath Buffer Overflow (AIX)|exploit/aix/rpc_ttdbserverd_realpath|Required|-|Required|Required|-
3|Open Flash Chart v2 Arbitrary File Upload|exploit/unix/webapp/open_flash_chart_upload_exec|Required|-|Required|Required|Required
4|HTTPDX tolog() Function Format String Vulnerability|exploit/windows/ftp/httpdx_tolog_format|Required|Required|Required|Required|-
5|MS09-053 Microsoft IIS FTP Server NLST Response Overflow|exploit/windows/ftp/ms09_053_ftpd_nlst|Required|-|Required|Required|-
6|Vermillion FTP Daemon PORT Command Memory Corruption|exploit/windows/ftp/vermillion_ftpd_port|Required|-|Required|Required|-
7|Free Download Manager Remote Control Server Buffer Overflow|exploit/windows/http/fdm_auth_header|Required|-|Required|Required|-
8|HP OpenView Network Node Manager ovalarm.exe CGI Buffer Overflow|exploit/windows/http/hp_nnm_ovalarm_lang|Required|-|Required|Required|-
9|HP OpenView Network Node Manager OvWebHelp.exe CGI Buffer Overflow|exploit/windows/http/hp_nnm_ovwebhelp|Required|-|Required|Required|-
10|HP OpenView Network Node Manager Snmp.exe CGI Buffer Overflow|exploit/windows/http/hp_nnm_snmp|Required|-|Required|Required|-
11|HP OpenView Network Node Manager Toolbar.exe CGI Buffer Overflow|exploit/windows/http/hp_nnm_toolbar_01|Required|-|Required|Required|-
12|HTTPDX h_handlepeer() Function Buffer Overflow|exploit/windows/http/httpdx_handlepeer|Required|-|Required|Required|-
13|HTTPDX tolog() Function Format String Vulnerability|exploit/windows/http/httpdx_tolog_format|Required|-|Required|Required|-
14|InterSystems Cache UtilConfigHome.csp Argument Buffer Overflow|exploit/windows/http/intersystems_cache|Required|-|Required|Required|-
15|BigAnt Server 2.52 USV Buffer Overflow|exploit/windows/misc/bigant_server_usv|Required|-|Required|Required|-
16|HP OmniInet.exe MSG_PROTOCOL Buffer Overflow|exploit/windows/misc/hp_omniinet_1|Required|-|Required|Required|-
17|HP OmniInet.exe MSG_PROTOCOL Buffer Overflow|exploit/windows/misc/hp_omniinet_2|Required|-|Required|Required|-
18|IBM Tivoli Storage Manager Express RCA Service Buffer Overflow|exploit/windows/misc/ibm_tsm_rca_dicugetidentify|Required|-|Required|Required|-
19|SAP Business One License Manager 2005 Buffer Overflow|exploit/windows/misc/sap_2005_license|Required|-|Required|Required|-
20|Oracle 10gR2 TNS Listener AUTH_SESSKEY Buffer Overflow|exploit/windows/oracle/tns_auth_sesskey|Required|-|Required|Required|-
21|Novell NetIdentity Agent XTIERRPCPIPE Named Pipe Buffer Overflow|exploit/windows/smb/netidentity_xtierrpcpipe|Required|Required|Required|Required|-
22|Timbuktu PlughNTCommand Named Pipe Buffer Overflow|exploit/windows/smb/timbuktu_plughntcommand_bof|Required|-|Required|Required|-

#### 2010 (24)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (FreeBSD)|exploit/freebsd/ftp/proftp_telnet_iac|Required|-|Required|Required|-
2|ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (Linux)|exploit/linux/ftp/proftp_telnet_iac|Required|-|Required|Required|-
3|FreeNAS exec_raw.php Arbitrary Command Execution|exploit/multi/http/freenas_exec_raw|Required|-|Required|Required|-
4|Sun Java System Web Server WebDAV OPTIONS Buffer Overflow|exploit/multi/http/sun_jsws_dav_options|Required|-|Required|Required|-
5|Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow|exploit/multi/misc/wireshark_lwres_getaddrbyname|Required|-|Required|Required|-
6|Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow (loop)|exploit/multi/misc/wireshark_lwres_getaddrbyname_loop|Required|-|Required|Required|-
7|EasyFTP Server CWD Command Stack Buffer Overflow|exploit/windows/ftp/easyftp_cwd_fixret|Required|-|Required|Required|-
8|EasyFTP Server LIST Command Stack Buffer Overflow|exploit/windows/ftp/easyftp_list_fixret|Required|-|Required|Required|-
9|EasyFTP Server MKD Command Stack Buffer Overflow|exploit/windows/ftp/easyftp_mkd_fixret|Required|-|Required|Required|-
10|EasyFTP Server list.html path Stack Buffer Overflow|exploit/windows/http/easyftp_list|Required|Required|Required|Required|-
11|HP OpenView Network Node Manager getnnmdata.exe (Hostname) CGI Buffer Overflow|exploit/windows/http/hp_nnm_getnnmdata_hostname|Required|-|Required|Required|-
12|HP OpenView Network Node Manager getnnmdata.exe (ICount) CGI Buffer Overflow|exploit/windows/http/hp_nnm_getnnmdata_icount|Required|-|Required|Required|-
13|HP OpenView Network Node Manager getnnmdata.exe (MaxAge) CGI Buffer Overflow|exploit/windows/http/hp_nnm_getnnmdata_maxage|Required|-|Required|Required|-
14|HP OpenView Network Node Manager ovwebsnmpsrv.exe main Buffer Overflow|exploit/windows/http/hp_nnm_ovwebsnmpsrv_main|Required|-|Required|Required|-
15|HP OpenView Network Node Manager ovwebsnmpsrv.exe ovutil Buffer Overflow|exploit/windows/http/hp_nnm_ovwebsnmpsrv_ovutil|Required|-|Required|Required|-
16|HP OpenView Network Node Manager ovwebsnmpsrv.exe Unrecognized Option Buffer Overflow|exploit/windows/http/hp_nnm_ovwebsnmpsrv_uro|Required|-|Required|Required|-
17|HP OpenView Network Node Manager snmpviewer.exe Buffer Overflow|exploit/windows/http/hp_nnm_snmpviewer_actapp|Required|-|Required|Required|-
18|HP OpenView Network Node Manager execvp_nc Buffer Overflow|exploit/windows/http/hp_nnm_webappmon_execvp|Required|-|Required|Required|-
19|HP NNM CGI webappmon.exe OvJavaLocale Buffer Overflow|exploit/windows/http/hp_nnm_webappmon_ovjavalocale|Required|-|Required|Required|-
20|Race River Integard Home/Pro LoginAdmin Password Stack Buffer Overflow|exploit/windows/http/integard_password_bof|Required|-|Required|Required|-
21|Windows Media Services ConnectFunnel Stack Buffer Overflow|exploit/windows/mmsp/ms10_025_wmss_connect_funnel|Required|-|Required|Required|-
22|DATAC RealWin SCADA Server SCPC_INITIALIZE Buffer Overflow|exploit/windows/scada/realwin_scpc_initialize|Required|-|Required|Required|-
23|DATAC RealWin SCADA Server SCPC_INITIALIZE_RF Buffer Overflow|exploit/windows/scada/realwin_scpc_initialize_rf|Required|-|Required|Required|-
24|DATAC RealWin SCADA Server SCPC_TXTEVENT Buffer Overflow|exploit/windows/scada/realwin_scpc_txtevent|Required|-|Required|Required|-

#### 2011 (9)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|FreeBSD Telnet Service Encryption Key ID Buffer Overflow|exploit/freebsd/telnet/telnet_encrypt_keyid|Required|-|Required|Required|-
2|Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow|exploit/linux/telnet/telnet_encrypt_keyid|Required|-|Required|Required|-
3|Zend Server Java Bridge Arbitrary Java Code Execution|exploit/multi/misc/zend_java_bridge|Required|-|Required|Required|-
4|EMC Replication Manager Command Execution|exploit/windows/emc/replication_manager_exec|Required|-|Required|Required|-
5|HP OmniInet.exe Opcode 27 Buffer Overflow|exploit/windows/misc/hp_omniinet_3|Required|-|Required|Required|-
6|DATAC RealWin SCADA Server 2 On_FC_CONNECT_FCS_a_FILE Buffer Overflow|exploit/windows/scada/realwin_on_fc_binfile_a|Required|-|Required|Required|-
7|RealWin SCADA Server DATAC Login Buffer Overflow|exploit/windows/scada/realwin_on_fcs_login|Required|-|Required|Required|-
8|Sunway Forcecontrol SNMP NetDBServer.exe Opcode 0x57|exploit/windows/scada/sunway_force_control_netdbsrv|Required|-|Required|Required|-
9|Sielco Sistemi Winlog Buffer Overflow|exploit/windows/scada/winlog_runtime|Required|-|Required|Required|-

#### 2012 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SAP SOAP RFC SXPG_COMMAND_EXECUTE Remote Command Execution|exploit/multi/sap/sap_soap_rfc_sxpg_command_exec|Required|Required|Required|Required|-
2|Nagios3 history.cgi Host Command Execution|exploit/unix/webapp/nagios3_history_cgi|Required|Required|Required|Required|Required
3|Turbo FTP Server 1.30.823 PORT Overflow|exploit/windows/ftp/turboftp_port|Required|-|Required|Required|-
4|SAP ConfigServlet Remote Code Execution|exploit/windows/http/sap_configservlet_exec_noauth|Required|-|Required|Required|Required
5|NFR Agent FSFUI Record File Upload RCE|exploit/windows/novell/file_reporter_fsfui_upload|Required|-|Required|Required|-

#### 2013 (16)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|OpenPLI Webif Arbitrary Command Execution|exploit/linux/http/dreambox_openpli_shell|Required|-|Required|Required|-
2|Nginx HTTP Server 1.3.9-1.4.0 Chunked Encoding Stack Buffer Overflow|exploit/linux/http/nginx_chunked_size|Required|-|Required|Required|-
3|SerComm Device Remote Code Execution|exploit/linux/misc/sercomm_exec|Required|-|Required|Required|-
4|Adobe ColdFusion RDS Authentication Bypass|exploit/multi/http/coldfusion_rds_auth_bypass|Required|-|Required|Required|-
5|HP SiteScope issueSiebelCmd Remote Code Execution|exploit/multi/http/hp_sitescope_issuesiebelcmd|Required|-|Required|Required|Required
6|NAS4Free Arbitrary Remote Code Execution|exploit/multi/http/nas4free_php_exec|Required|Required|Required|Required|-
7|Rocket Servergraph Admin Center fileRequestor Remote Code Execution|exploit/multi/http/rocket_servergraph_file_requestor_rce|Required|-|Required|Required|-
8|Apache Struts includeParams Remote Code Execution|exploit/multi/http/struts_include_params|Required|-|Required|Required|Required
9|STUNSHELL Web Shell Remote PHP Code Execution|exploit/multi/http/stunshell_eval|Required|-|Required|Required|Required
10|STUNSHELL Web Shell Remote Code Execution|exploit/multi/http/stunshell_exec|Required|-|Required|Required|Required
11|v0pCr3w Web Shell Remote Code Execution|exploit/multi/http/v0pcr3w_exec|Required|-|Required|Required|Required
12|Novell ZENworks Configuration Management Remote Execution|exploit/multi/http/zenworks_control_center_upload|Required|-|Required|Required|-
13|Ra1NX PHP Bot PubCall Authentication Bypass Remote Code Execution|exploit/multi/misc/ra1nx_pubcall_exec|Required|-|Required|Required|-
14|SAP SOAP RFC SXPG_CALL_SYSTEM Remote Command Execution|exploit/multi/sap/sap_soap_rfc_sxpg_call_system_exec|Required|Required|Required|Required|-
15|Carberp Web Panel C2 Backdoor Remote PHP Code Execution|exploit/unix/webapp/carberp_backdoor_exec|Required|-|Required|Required|Required
16|HP Intelligent Management Center Arbitrary File Upload|exploit/windows/http/hp_imc_mibfileupload|Required|-|Required|Required|Required

#### 2014 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MantisBT XmlImportExport Plugin PHP Code Injection Vulnerability|exploit/multi/http/mantisbt_php_exec|Required|Required|Required|Required|Required
2|Oracle Forms and Reports Remote Code Execution|exploit/multi/http/oracle_reports_rce|Required|-|Required|Required|-
3|HP Data Protector EXEC_INTEGUTIL Remote Code Execution|exploit/multi/misc/hp_data_protector_exec_integutil|Required|-|Required|Required|-
4|HP Client Automation Command Injection|exploit/multi/misc/persistent_hpca_radexec_exec|Required|-|Required|Required|-
5|HP AutoPass License Server File Upload|exploit/windows/http/hp_autopass_license_traversal|Required|-|Required|Required|Required
6|HP Data Protector Backup Client Service Directory Traversal|exploit/windows/misc/hp_dataprotector_traversal|Required|-|Required|Required|-

#### 2015 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|D-Link DCS-931L File Upload|exploit/linux/http/dlink_dcs931l_upload|Required|Required|Required|Required|-
2|Western Digital Arkeia Remote Code Execution|exploit/multi/misc/arkeia_agent_exec|Required|-|Required|Required|-
3|VNC Keyboard Remote Code Execution|exploit/multi/vnc/vnc_keyboard_exec|Required|-|Required|Required|-

#### 2016 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|D-Link DSL-2750B OS Command Injection|exploit/linux/http/dlink_dsl2750b_exec_noauth|Required|-|Required|Required|-

#### 2017 (8)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Disk Sorter Enterprise GET Buffer Overflow|exploit/windows/http/disksorter_bof|Required|-|Required|Required|-
2|Dup Scout Enterprise Login Buffer Overflow|exploit/windows/http/dup_scout_enterprise_login_bof|Required|-|Required|Required|-
3|Dup Scout Enterprise GET Buffer Overflow|exploit/windows/http/dupscts_bof|Required|-|Required|Required|-
4|Sync Breeze Enterprise GET Buffer Overflow|exploit/windows/http/syncbreeze_bof|Required|-|Required|Required|-
5|VX Search Enterprise GET Buffer Overflow|exploit/windows/http/vxsrchs_bof|Required|-|Required|Required|-
6|Disk Savvy Enterprise v10.4.18|exploit/windows/misc/disk_savvy_adm|Required|-|Required|Required|-
7|RDP DOUBLEPULSAR Remote Code Execution|exploit/windows/rdp/rdp_doublepulsar_rce|Required|-|Required|Required|-
8|SMB DOUBLEPULSAR Remote Code Execution|exploit/windows/smb/smb_doublepulsar_rce|Required|-|Required|Required|-

#### 2018 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|VyOS restricted-shell Escape and Privilege Escalation|exploit/linux/ssh/vyos_restricted_shell_privesc|Required|Required|Required|Required|-
2|GitStack Unsanitized Argument RCE|exploit/windows/http/gitstack_rce|Required|-|Required|Required|-
3|CloudMe Sync v1.10.9|exploit/windows/misc/cloudme_sync|Required|-|Required|Required|-

#### 2020 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Aerospike Database UDF Lua Code Execution|exploit/linux/misc/aerospike_database_udf_cmd_exec|Required|-|Required|Required|-


### Excellent Ranking (612)

#### 1993 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Generic Web Application Unix Command Execution|exploit/unix/webapp/generic_exec|Required|-|Required|Required|-

#### 1994 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Solaris ypupdated Command Execution|exploit/solaris/sunrpc/ypupdated_exec|Required|-|Required|Required|-

#### 1998 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS99-025 Microsoft IIS MDAC msadcs.dll RDS Arbitrary Remote Command Execution|exploit/windows/iis/msadc|Required|Required|Required|Required|-

#### 1999 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Matt Wright guestbook.pl Arbitrary Command Execution|exploit/unix/webapp/guestbook_ssi_exec|Required|-|Required|Required|-
2|Windows Management Instrumentation (WMI) Remote Command Execution|exploit/windows/local/wmi|Required|-|Required|-|-
3|Microsoft SQL Server Clr Stored Procedure Payload Execution|exploit/windows/mssql/mssql_clr_payload|Required|-|Required|Required|-

#### 2000 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|RedHat Piranha Virtual Server Package passwd.php3 Arbitrary Command Execution|exploit/linux/http/piranha_passwd_exec|Required|Required|Required|Required|-
2|Microsoft SQL Server Payload Execution|exploit/windows/mssql/mssql_payload|Required|-|Required|Required|-
3|Microsoft SQL Server Payload Execution via SQL Injection|exploit/windows/mssql/mssql_payload_sqli|Required|-|Required|Required|-

#### 2001 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Irix LPD tagprinter Command Execution|exploit/irix/lpd/tagprinter_exec|Required|-|Required|Required|-
2|HP OpenView OmniBack II Command Execution|exploit/multi/misc/openview_omniback_exec|Required|-|Required|Required|-
3|Solaris LPD Command Execution|exploit/solaris/lpd/sendmail_exec|Required|-|Required|Required|-
4|MS01-026 Microsoft IIS/PWS CGI Filename Double Decode Command Execution|exploit/windows/iis/ms01_026_dbldecode|Required|-|Required|Required|-

#### 2002 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP-UX LPD Command Execution|exploit/hpux/lpd/cleanup_exec|Required|-|Required|Required|-
2|Solaris in.telnetd TTYPROMPT Buffer Overflow|exploit/solaris/telnet/ttyprompt|Required|Required|Required|Required|-
3|DistCC Daemon Command Execution|exploit/unix/misc/distcc_exec|Required|-|Required|Required|-

#### 2003 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Solaris sadmind Command Execution|exploit/solaris/sunrpc/sadmind_exec|Required|-|Required|Required|-
2|QuickTime Streaming Server parse_xml.cgi Remote Execution|exploit/unix/webapp/qtss_parse_xml_exec|Required|-|Required|Required|-

#### 2004 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|phpBB viewtopic.php Arbitrary Code Execution|exploit/unix/webapp/phpbb_highlight|Required|-|Required|Required|-
2|TWiki Search Function Arbitrary Command Execution|exploit/unix/webapp/twiki_search|Required|-|Required|Required|-
3|Microsoft IIS WebDAV Write Access Code Execution|exploit/windows/iis/iis_webdav_upload_asp|Required|-|Required|Required|-

#### 2005 (11)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AWStats configdir Remote Command Execution|exploit/unix/webapp/awstats_configdir_exec|Required|-|Required|Required|-
2|Barracuda IMG.PL Remote Command Execution|exploit/unix/webapp/barracuda_img_exec|Required|-|Required|Required|-
3|Cacti graph_view.php Remote Command Execution|exploit/unix/webapp/cacti_graphimage_exec|Required|-|Required|Required|-
4|Google Appliance ProxyStyleSheet Command Execution|exploit/unix/webapp/google_proxystylesheet_exec|Required|-|Required|Required|-
5|HP Openview connectedNodes.ovpl Remote Command Execution|exploit/unix/webapp/openview_connectednodes_exec|Required|-|Required|Required|-
6|vBulletin misc.php Template Name Arbitrary Code Execution|exploit/unix/webapp/php_vbulletin_template|Required|-|Required|Required|-
7|PHP XML-RPC Arbitrary Code Execution|exploit/unix/webapp/php_xmlrpc_eval|Required|-|Required|Required|-
8|Simple PHP Blog Remote Command Execution|exploit/unix/webapp/sphpblog_file_upload|Required|-|Required|Required|-
9|TWiki History TWikiUsers rev Parameter Command Execution|exploit/unix/webapp/twiki_history|Required|-|Required|Required|-
10|WordPress cache_lastpostdate Arbitrary Code Execution|exploit/unix/webapp/wp_lastpost_exec|Required|-|Required|Required|-
11|Lyris ListManager MSDE Weak sa Password|exploit/windows/mssql/lyris_listmanager_weak_pass|Required|-|Required|Required|-

#### 2006 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SpamAssassin spamd Remote Command Execution|exploit/unix/misc/spamassassin_exec|Required|-|Required|Required|-
2|AWStats migrate Remote Command Execution|exploit/unix/webapp/awstats_migrate_exec|Required|-|Required|Required|-
3|PAJAX Remote Command Execution|exploit/unix/webapp/pajax_remote_exec|Required|-|Required|Required|-
4|TikiWiki jhot Remote Command Execution|exploit/unix/webapp/tikiwiki_jhot_exec|Required|-|Required|Required|-

#### 2007 (9)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apple iOS Default SSH Password Vulnerability|exploit/apple_ios/ssh/cydia_default_ssh|Required|-|Required|Required|-
2|HPLIP hpssd.py From Address Arbitrary Command Execution|exploit/linux/misc/hplip_hpssd_exec|Required|-|Required|Required|-
3|PostgreSQL for Linux Payload Execution|exploit/linux/postgres/postgres_payload|Required|Required|Required|Required|-
4|JBoss DeploymentFileRepository WAR Deployment (via JMXInvokerServlet)|exploit/multi/http/jboss_invoke_deploy|Required|-|Required|Required|Required
5|Samba "username map script" Command Execution|exploit/multi/samba/usermap_script|Required|-|Required|Required|-
6|Sun Solaris Telnet Remote Authentication Bypass Vulnerability|exploit/solaris/telnet/fuser|Required|Required|Required|Required|-
7|ClamAV Milter Blackhole-Mode Remote Code Execution|exploit/unix/smtp/clamav_milter_blackhole|Required|-|Required|Required|-
8|TikiWiki tiki-graph_formula Remote PHP Code Execution|exploit/unix/webapp/tikiwiki_graph_formula_exec|Required|-|Required|Required|-
9|Oracle Job Scheduler Named Pipe Command Execution|exploit/windows/oracle/extjob|Required|-|Required|Required|-

#### 2008 (9)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Mantis manage_proj_page PHP Code Execution|exploit/multi/http/mantisbt_manage_proj_page_rce|Required|Required|Required|Required|Required
2|Openfire Admin Console Authentication Bypass|exploit/multi/http/openfire_auth_bypass|Required|-|Required|Required|Required
3|phpScheduleIt PHP reserve.php start_date Parameter Arbitrary Code Injection|exploit/multi/http/phpscheduleit_start_date|Required|-|Required|Required|-
4|AWStats Totals multisort Remote Command Execution|exploit/unix/webapp/awstatstotals_multisort|Required|-|Required|Required|-
5|BASE base_qry_common Remote File Include|exploit/unix/webapp/base_qry_common|Required|-|Required|Required|-
6|Coppermine Photo Gallery picEditor.php Command Execution|exploit/unix/webapp/coppermine_piceditor|Required|-|Required|Required|-
7|Mambo Cache_Lite Class mosConfig_absolute_path Remote File Include|exploit/unix/webapp/mambo_cache_lite|Required|-|Required|Required|-
8|Timbuktu Pro Directory Traversal/File Upload|exploit/windows/motorola/timbuktu_fileupload|Required|-|Required|Required|-
9|MS09-004 Microsoft SQL Server sp_replwritetovarbin Memory Corruption via SQL Injection|exploit/windows/mssql/ms09_004_sp_replwritetovarbin_sqli|Required|-|Required|Required|-

#### 2009 (20)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|DD-WRT HTTP Daemon Arbitrary Command Execution|exploit/linux/http/ddwrt_cgibin_exec|Required|-|Required|Required|-
2|Zabbix Server Arbitrary Command Execution|exploit/linux/misc/zabbix_server_exec|Required|-|Required|Required|-
3|NETGEAR TelnetEnable|exploit/linux/telnet/netgear_telnetenable|Required|-|Required|Required|-
4|Apache Tomcat Manager Application Deployer Authenticated Code Execution|exploit/multi/http/tomcat_mgr_deploy|Required|-|Required|Required|-
5|Apache Tomcat Manager Authenticated Upload Code Execution|exploit/multi/http/tomcat_mgr_upload|Required|-|Required|Required|Required
6|PHP IRC Bot pbot eval() Remote Code Execution|exploit/multi/misc/pbot_exec|Required|-|Required|Required|-
7|Oracle MySQL UDF Payload Execution|exploit/multi/mysql/mysql_udf_payload|Required|-|Required|Required|-
8|Wyse Rapport Hagent Fake Hserver Command Execution|exploit/multi/wyse/hagent_untrusted_hsdata|Required|-|Required|Required|-
9|ContentKeeper Web Remote Command Execution|exploit/unix/http/contentkeeperweb_mimencode|Required|-|Required|Required|-
10|Zabbix Agent net.tcp.listen Command Injection|exploit/unix/misc/zabbix_agent_exec|Required|-|Required|Required|-
11|Dogfood CRM spell.php Remote Command Execution|exploit/unix/webapp/dogfood_spell_exec|Required|-|Required|Required|-
12|Joomla 1.5.12 TinyBrowser File Upload Code Execution|exploit/unix/webapp/joomla_tinybrowser|Required|-|Required|Required|-
13|Nagios3 statuswml.cgi Ping Command Execution|exploit/unix/webapp/nagios3_statuswml_ping|Required|Required|Required|Required|-
14|osCommerce 2.2 Arbitrary PHP Code Execution|exploit/unix/webapp/oscommerce_filemanager|Required|-|Required|Required|-
15|PhpMyAdmin Config File Code Injection|exploit/unix/webapp/phpmyadmin_config|Required|-|Required|Required|-
16|Symantec System Center Alert Management System (xfr.exe) Arbitrary Command Execution|exploit/windows/antivirus/ams_xfr|Required|-|Required|Required|-
17|Adobe RoboHelp Server 8 Arbitrary File Upload and Execute|exploit/windows/http/adobe_robohelper_authbypass|Required|-|Required|Required|-
18|ColdFusion 8.0.1 Arbitrary File Upload and Execute|exploit/windows/http/coldfusion_fckeditor|Required|-|Required|Required|-
19|IBM System Director Agent DLL Injection|exploit/windows/misc/ibm_director_cim_dllinject|Required|-|Required|Required|-
20|PostgreSQL for Microsoft Windows Payload Execution|exploit/windows/postgres/postgres_payload|Required|Required|Required|Required|-

#### 2010 (23)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AjaXplorer checkInstall.php Remote Command Execution|exploit/multi/http/ajaxplorer_checkinstall_exec|Required|-|Required|Required|Required
2|Axis2 / SAP BusinessObjects Authenticated Code Execution (via SOAP)|exploit/multi/http/axis2_deployer|Required|Required|Required|Required|-
3|JBoss JMX Console Beanshell Deployer WAR Upload and Deployment|exploit/multi/http/jboss_bshdeployer|Required|-|Required|Required|Required
4|JBoss Java Class DeploymentFileRepository WAR Deployment|exploit/multi/http/jboss_deploymentfilerepository|Required|-|Required|Required|Required
5|Pandora FMS v3.1 Auth Bypass and Arbitrary File Upload Vulnerability|exploit/multi/http/pandora_upload_exec|Required|-|Required|Required|Required
6|ProcessMaker Plugin Upload|exploit/multi/http/processmaker_plugin_upload|Required|Required|Required|Required|-
7|ProFTPD-1.3.3c Backdoor Command Execution|exploit/unix/ftp/proftpd_133c_backdoor|Required|-|Required|Required|-
8|UnrealIRCD 3.2.8.1 Backdoor Command Execution|exploit/unix/irc/unreal_ircd_3281_backdoor|Required|-|Required|Required|-
9|Exim4 string_format Function Heap Buffer Overflow|exploit/unix/smtp/exim4_string_format|Required|-|Required|Required|-
10|CakePHP Cache Corruption Code Execution|exploit/unix/webapp/cakephp_cache_corruption|Required|-|Required|Required|-
11|Citrix Access Gateway Command Execution|exploit/unix/webapp/citrix_access_gateway_exec|Required|-|Required|Required|-
12|Mitel Audio and Web Conferencing Command Injection|exploit/unix/webapp/mitel_awc_exec|Required|-|Required|Required|-
13|Redmine SCM Repository Arbitrary Command Execution|exploit/unix/webapp/redmine_scm_exec|Required|-|Required|Required|-
14|Symantec System Center Alert Management System (hndlrsvc.exe) Arbitrary Command Execution|exploit/windows/antivirus/ams_hndlrsvc|Required|-|Required|Required|-
15|Energizer DUO USB Battery Charger Arucer.dll Trojan Code Execution|exploit/windows/backdoor/energizer_duo_payload|Required|-|Required|Required|-
16|Novell iManager getMultiPartParameters Arbitrary File Upload|exploit/windows/http/novell_imanager_upload|Required|-|Required|Required|-
17|Oracle BeeHive 2 voice-servlet processEvaluation() Vulnerability|exploit/windows/http/oracle_beehive_evaluation|Required|-|Required|Required|Required
18|Oracle Secure Backup Authentication Bypass/Command Injection Vulnerability|exploit/windows/http/osb_uname_jlist|Required|-|Required|Required|-
19|Novell ZENworks Configuration Management Remote Execution|exploit/windows/http/zenworks_uploadservlet|Required|-|Required|Required|-
20|HP Mercury LoadRunner Agent magentproc.exe Remote Command Execution|exploit/windows/misc/hp_loadrunner_magentproc_cmdexec|Required|-|Required|Required|-
21|MS10-104 Microsoft Office SharePoint Server 2007 Remote Code Execution|exploit/windows/misc/ms10_104_sharepoint|Required|-|Required|Required|-
22|MS10-061 Microsoft Print Spooler Service Impersonation Vulnerability|exploit/windows/smb/ms10_061_spoolss|Required|-|Required|Required|-
23|Freesshd Authentication Bypass|exploit/windows/ssh/freesshd_authbypass|Required|-|Required|Required|-

#### 2011 (33)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|V-CMS PHP File Upload and Execute|exploit/linux/http/vcms_upload|Required|-|Required|Required|Required
2|WeBid converter.php Remote PHP Code Injection|exploit/linux/http/webid_converter|Required|-|Required|Required|Required
3|Accellion FTA MPIPE2 Command Execution|exploit/linux/misc/accellion_fta_mpipe2|Required|-|Required|Required|-
4|HP Data Protector 6 EXEC_CMD Remote Code Execution|exploit/linux/misc/hp_data_protector_cmd_exec|Required|-|Required|Required|-
5|Family Connections less.php Remote Command Execution|exploit/multi/http/familycms_less_exec|Required|-|Required|Required|-
6|LotusCMS 3.0 eval() Remote Command Execution|exploit/multi/http/lcms_php_exec|Required|-|Required|Required|-
7|Log1 CMS writeInfo() PHP Code Injection|exploit/multi/http/log1cms_ajax_create_folder|Required|-|Required|Required|Required
8|phpLDAPadmin query_engine Remote PHP Code Injection|exploit/multi/http/phpldapadmin_query_engine|Required|-|Required|Required|-
9|Plone and Zope XMLTools Remote Command Execution|exploit/multi/http/plone_popen2|Required|-|Required|Required|-
10|PmWiki pagelist.php Remote PHP Code Injection Exploit|exploit/multi/http/pmwiki_pagelist|Required|-|Required|Required|-
11|Snortreport nmap.php/nbtscan.php Remote Command Execution|exploit/multi/http/snortreport_exec|Required|-|Required|Required|-
12|Splunk Search Remote Code Execution|exploit/multi/http/splunk_mappy_exec|Required|Required|Required|Required|-
13|Spreecommerce 0.60.1 Arbitrary Command Execution|exploit/multi/http/spree_search_exec|Required|-|Required|Required|-
14|Spreecommerce Arbitrary Command Execution|exploit/multi/http/spree_searchlogic_exec|Required|-|Required|Required|-
15|Apache Struts ParametersInterceptor Remote Code Execution|exploit/multi/http/struts_code_exec_parameters|Required|-|Required|Required|Required
16|Traq admincp/common.php Remote Code Execution|exploit/multi/http/traq_plugin_exec|Required|-|Required|Required|-
17|HP StorageWorks P4000 Virtual SAN Appliance Command Execution|exploit/multi/misc/hp_vsa_exec|Required|-|Required|Required|-
18|VSFTPD v2.3.4 Backdoor Command Execution|exploit/unix/ftp/vsftpd_234_backdoor|Required|-|Required|Required|-
19|LifeSize Room Command Injection|exploit/unix/http/lifesize_room|Required|-|Required|Required|-
20|myBB 1.6.4 Backdoor Arbitrary Command Execution|exploit/unix/webapp/mybb_backdoor|Required|-|Required|Required|-
21|QuickShare File Server 1.2.1 Directory Traversal Vulnerability|exploit/windows/ftp/quickshare_traversal_write|Required|-|Required|Required|-
22|CA Arcserve D2D GWT RPC Credential Information Disclosure|exploit/windows/http/ca_arcserve_rpc_authbypass|Required|-|Required|Required|-
23|CA Total Defense Suite reGenerateReports Stored Procedure SQL Injection|exploit/windows/http/ca_totaldefense_regeneratereports|Required|-|Required|Required|-
24|HP Managed Printing Administration jobAcct Remote Command Execution|exploit/windows/http/hp_mpa_job_acct|Required|-|Required|Required|-
25|HP OpenView Performance Insight Server Backdoor Account Code Execution|exploit/windows/http/hp_openview_insight_backdoor|Required|Required|Required|Required|-
26|Solarwinds Storage Manager 5.1.0 SQL Injection|exploit/windows/http/solarwinds_storage_manager_sql|Required|-|Required|Required|-
27|Novell ZENworks Asset Management Remote Execution|exploit/windows/http/zenworks_assetmgmt_uploadservlet|Required|-|Required|Required|-
28|HP Data Protector 6.10/6.11/6.20 Install Service|exploit/windows/misc/hp_dataprotector_install_service|Required|-|Required|Required|-
29|Oracle Database Client System Analyzer Arbitrary File Upload|exploit/windows/oracle/client_system_analyzer_upload|Required|-|Required|Required|-
30|7-Technologies IGSS 9 Data Server/Collector Packet Handling Vulnerabilities|exploit/windows/scada/igss9_misc|Required|-|Required|-|-
31|Interactive Graphical SCADA System Remote Command Injection|exploit/windows/scada/igss_exec_17|Required|-|Required|Required|-
32|InduSoft Web Studio Arbitrary Upload Remote Code Execution|exploit/windows/scada/indusoft_webstudio_exec|Required|-|Required|Required|-
33|Measuresoft ScadaPro Remote Command Execution|exploit/windows/scada/scadapro_cmdexe|Required|-|Required|Required|-

#### 2012 (69)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Dolibarr ERP/CRM Post-Auth OS Command Injection|exploit/linux/http/dolibarr_cmd_exec|Required|Required|Required|Required|Required
2|E-Mail Security Virtual Appliance learn-msg.cgi Command Injection|exploit/linux/http/esva_exec|Required|-|Required|Required|-
3|Openfiler v2.x NetworkCard Command Execution|exploit/linux/http/openfiler_networkcard_exec|Required|Required|Required|Required|-
4|Symantec Web Gateway 5.0.2.8 ipchange.php Command Injection|exploit/linux/http/symantec_web_gateway_exec|Required|-|Required|Required|-
5|Symantec Web Gateway 5.0.2.8 Arbitrary PHP File Upload Vulnerability|exploit/linux/http/symantec_web_gateway_file_upload|Required|-|Required|Required|-
6|Symantec Web Gateway 5.0.2.8 relfile File Inclusion Vulnerability|exploit/linux/http/symantec_web_gateway_lfi|Required|-|Required|Required|-
7|Symantec Web Gateway 5.0.2.18 pbcontrol.php Command Injection|exploit/linux/http/symantec_web_gateway_pbcontrol|Required|-|Required|Required|Required
8|WAN Emulator v2.3 Command Execution|exploit/linux/http/wanem_exec|Required|-|Required|Required|-
9|WebCalendar 1.2.4 Pre-Auth Remote Code Injection|exploit/linux/http/webcalendar_settings_exec|Required|-|Required|Required|Required
10|ZEN Load Balancer Filelog Command Execution|exploit/linux/http/zen_load_balancer_exec|Required|Required|Required|Required|-
11|F5 BIG-IP SSH Private Key Exposure|exploit/linux/ssh/f5_bigip_known_privkey|Required|-|Required|Required|-
12|Symantec Messaging Gateway 9.5 Default SSH Password Vulnerability|exploit/linux/ssh/symantec_smg_ssh|Required|-|Required|Required|-
13|appRain CMF Arbitrary PHP File Upload Vulnerability|exploit/multi/http/apprain_upload_exec|Required|-|Required|Required|Required
14|Auxilium RateMyPet Arbitrary File Upload Vulnerability|exploit/multi/http/auxilium_upload_exec|Required|-|Required|Required|Required
15|CuteFlow v2.11.2 Arbitrary File Upload Vulnerability|exploit/multi/http/cuteflow_upload_exec|Required|-|Required|Required|Required
16|Network Shutdown Module (sort_values) Remote PHP Code Injection|exploit/multi/http/eaton_nsm_code_exec|Required|-|Required|Required|-
17|eXtplorer v2.1 Arbitrary File Upload Vulnerability|exploit/multi/http/extplorer_upload_exec|Required|Required|Required|Required|Required
18|Gitorious Arbitrary Command Execution|exploit/multi/http/gitorious_graph|Required|-|Required|Required|-
19|Horde 3.3.12 Backdoor Arbitrary PHP Code Execution|exploit/multi/http/horde_href_backdoor|Required|-|Required|Required|-
20|ManageEngine Security Manager Plus 5.5 Build 5505 SQL Injection|exploit/multi/http/manageengine_search_sqli|Required|-|Required|Required|-
21|Th3 MMA mma.php Backdoor Arbitrary File Upload|exploit/multi/http/mma_backdoor_upload|Required|-|Required|Required|Required
22|MobileCartly 1.0 Arbitrary File Creation Vulnerability|exploit/multi/http/mobilecartly_upload_exec|Required|-|Required|Required|Required
23|Mutiny Remote Command Execution|exploit/multi/http/mutiny_subnetmask_exec|Required|Required|Required|Required|Required
24|OP5 license.php Remote Command Execution|exploit/multi/http/op5_license|Required|-|Required|Required|-
25|OP5 welcome Remote Command Execution|exploit/multi/http/op5_welcome|Required|-|Required|Required|-
26|PHP CGI Argument Injection|exploit/multi/http/php_cgi_arg_injection|Required|-|Required|Required|-
27|PHP Volunteer Management System v1.0.2 Arbitrary File Upload Vulnerability|exploit/multi/http/php_volunteer_upload_exec|Required|Required|Required|Required|Required
28|PhpTax pfilez Parameter Exec Remote Code Injection|exploit/multi/http/phptax_exec|Required|-|Required|Required|Required
29|PolarBear CMS PHP File Upload Vulnerability|exploit/multi/http/polarcms_upload_exec|Required|-|Required|Required|Required
30|Sflog! CMS 1.0 Arbitrary File Upload Vulnerability|exploit/multi/http/sflog_upload_exec|Required|Required|Required|Required|Required
31|SonicWALL GMS 6 Arbitrary File Upload|exploit/multi/http/sonicwall_gms_upload|Required|-|Required|Required|Required
32|Apache Struts 2 Developer Mode OGNL Execution|exploit/multi/http/struts_dev_mode|Required|-|Required|Required|Required
33|TestLink v1.9.3 Arbitrary File Upload Vulnerability|exploit/multi/http/testlink_upload_exec|Required|-|Required|Required|Required
34|vBSEO proc_deutf() Remote PHP Code Injection|exploit/multi/http/vbseo_proc_deutf|Required|-|Required|Required|-
35|WebPageTest Arbitrary PHP File Upload|exploit/multi/http/webpagetest_upload_exec|Required|-|Required|Required|Required
36|Zemra Botnet CnC Web Panel Remote Code Execution|exploit/multi/http/zemra_panel_rce|Required|-|Required|Required|Required
37|Adobe IndesignServer 5.5 SOAP Server Arbitrary Script Execution|exploit/multi/misc/indesign_server_soap|Required|-|Required|Required|-
38|QNX qconn Command Execution|exploit/qnx/qconn/qconn_exec|Required|-|Required|Required|-
39|Tectia SSH USERAUTH Change Request Password Reset Vulnerability|exploit/unix/ssh/tectia_passwd_changereq|Required|Required|Required|Required|-
40|Basilic 1.5.14 diff.php Arbitrary Command Execution|exploit/unix/webapp/basilic_diff_exec|Required|-|Required|Required|Required
41|EGallery PHP File Upload Vulnerability|exploit/unix/webapp/egallery_upload_exec|Required|-|Required|Required|Required
42|Foswiki MAKETEXT Remote Command Execution|exploit/unix/webapp/foswiki_maketext|Required|Required|Required|Required|Required
43|Invision IP.Board unserialize() PHP Code Execution|exploit/unix/webapp/invision_pboard_unserialize_exec|Required|-|Required|Required|Required
44|Joomla Component JCE File Upload Remote Code Execution|exploit/unix/webapp/joomla_comjce_imgmanager|Required|-|Required|Required|Required
45|Narcissus Image Configuration Passthru Vulnerability|exploit/unix/webapp/narcissus_backend_exec|Required|-|Required|Required|Required
46|Project Pier Arbitrary File Upload Vulnerability|exploit/unix/webapp/projectpier_upload_exec|Required|-|Required|Required|Required
47|SPIP connect Parameter PHP Injection|exploit/unix/webapp/spip_connect_exec|Required|-|Required|Required|Required
48|Tiki Wiki unserialize() PHP Code Execution|exploit/unix/webapp/tikiwiki_unserialize_exec|Required|-|Required|Required|Required
49|TWiki MAKETEXT Remote Command Execution|exploit/unix/webapp/twiki_maketext|Required|-|Required|Required|Required
50|WordPress Plugin Advanced Custom Fields Remote File Inclusion|exploit/unix/webapp/wp_advanced_custom_fields_exec|Required|-|Required|Required|Required
51|WordPress Asset-Manager PHP File Upload Vulnerability|exploit/unix/webapp/wp_asset_manager_upload_exec|Required|-|Required|Required|Required
52|WordPress Plugin Foxypress uploadify.php Arbitrary Code Execution|exploit/unix/webapp/wp_foxypress_upload|Required|-|Required|Required|Required
53|Wordpress Front-end Editor File Upload|exploit/unix/webapp/wp_frontend_editor_file_upload|Required|-|Required|Required|Required
54|WordPress WP-Property PHP File Upload Vulnerability|exploit/unix/webapp/wp_property_upload_exec|Required|-|Required|Required|Required
55|Wordpress Reflex Gallery Upload Vulnerability|exploit/unix/webapp/wp_reflexgallery_file_upload|Required|-|Required|Required|Required
56|XODA 0.4.5 Arbitrary PHP File Upload Vulnerability|exploit/unix/webapp/xoda_file_upload|Required|-|Required|Required|Required
57|FreeFloat FTP Server Arbitrary File Upload|exploit/windows/ftp/freefloatftp_wbem|Required|-|Required|Required|-
58|Open-FTPD 1.2 Arbitrary File Upload|exploit/windows/ftp/open_ftpd_wbem|Required|-|Required|Required|-
59|Avaya IP Office Customer Call Reporter ImageUpload.ashx Remote Command Execution|exploit/windows/http/avaya_ccr_imageupload_exec|Required|-|Required|Required|Required
60|Cyclope Employee Surveillance Solution v6 SQL Injection|exploit/windows/http/cyclope_ess_sqli|Required|-|Required|Required|Required
61|Ektron 8.02 XSLT Transform Remote Code Execution|exploit/windows/http/ektron_xslt_exec|Required|-|Required|Required|Required
62|EZHomeTech EzServer Stack Buffer Overflow Vulnerability|exploit/windows/http/ezserver_http|Required|-|Required|Required|-
63|LANDesk Lenovo ThinkManagement Console Remote Command Execution|exploit/windows/http/landesk_thinkmanagement_upload_asp|Required|-|Required|Required|-
64|Oracle Business Transaction Management FlashTunnelService Remote Code Execution|exploit/windows/http/oracle_btm_writetofile|Required|-|Required|Required|-
65|Dell SonicWALL (Plixer) Scrutinizer 9 SQL Injection|exploit/windows/http/sonicwall_scrutinizer_sqli|Required|-|Required|Required|Required
66|Umbraco CMS Remote Command Execution|exploit/windows/http/umbraco_upload_aspx|Required|-|Required|Required|Required
67|XAMPP WebDAV PHP Upload|exploit/windows/http/xampp_webdav_upload_php|Required|Required|Required|Required|-
68|Plixer Scrutinizer NetFlow and sFlow Analyzer 9 Default MySQL Credential|exploit/windows/mysql/scrutinizer_upload_exec|Required|Required|Required|-|Required
69|NetIQ Privileged User Manager 2.3.1 ldapagnt_eval() Remote Perl Code Execution|exploit/windows/novell/netiq_pum_eval|Required|-|Required|Required|-

#### 2013 (80)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Red Hat CloudForms Management Engine 5.1 agent/linuxpkgs Path Traversal|exploit/linux/http/cfme_manageiq_evm_upload_exec|Required|-|Required|Required|Required
2|D-Link Devices Unauthenticated Remote Command Execution|exploit/linux/http/dlink_command_php_exec_noauth|Required|-|Required|Required|-
3|D-Link DIR-645 / DIR-815 diagnostic.php Command Execution|exploit/linux/http/dlink_diagnostic_exec_noauth|Required|-|Required|Required|-
4|D-Link Devices Unauthenticated Remote Command Execution|exploit/linux/http/dlink_dir300_exec_telnet|Required|Required|Required|Required|-
5|D-Link DIR615h OS Command Injection|exploit/linux/http/dlink_dir615_up_exec|Required|Required|Required|Required|-
6|F5 iControl Remote Root Command Execution|exploit/linux/http/f5_icontrol_exec|Required|Required|Required|Required|Required
7|Foreman (Red Hat OpenStack/Satellite) bookmarks/create Code Injection|exploit/linux/http/foreman_openstack_satellite_code_exec|Required|Required|Required|Required|Required
8|GroundWork monarch_scan.cgi OS Command Injection|exploit/linux/http/groundwork_monarch_cmd_exec|Required|Required|Required|Required|-
9|Linksys E1500/E2500 apply.cgi Remote Command Injection|exploit/linux/http/linksys_e1500_apply_exec|Required|Required|Required|Required|-
10|Linksys Devices pingstr Remote Command Injection|exploit/linux/http/linksys_wrt110_cmd_exec|Required|Required|Required|Required|-
11|Mutiny 5 Arbitrary File Upload|exploit/linux/http/mutiny_frontend_upload|Required|Required|Required|Required|Required
12|Netgear DGN1000 Setup.cgi Unauthenticated RCE|exploit/linux/http/netgear_dgn1000_setup_unauth_exec|Required|-|Required|Required|-
13|Netgear DGN1000B setup.cgi Remote Command Execution|exploit/linux/http/netgear_dgn1000b_setup_exec|Required|Required|Required|Required|-
14|PineApp Mail-SeCure ldapsyncnow.php Arbitrary Command Execution|exploit/linux/http/pineapp_ldapsyncnow_exec|Required|-|Required|Required|-
15|PineApp Mail-SeCure livelog.html Arbitrary Command Execution|exploit/linux/http/pineapp_livelog_exec|Required|-|Required|Required|-
16|PineApp Mail-SeCure test_li_connection.php Arbitrary Command Execution|exploit/linux/http/pineapp_test_li_conn_exec|Required|-|Required|Required|-
17|Sophos Web Protection Appliance sblistpack Arbitrary Command Execution|exploit/linux/http/sophos_wpa_sblistpack_exec|Required|-|Required|Required|-
18|Synology DiskStation Manager SLICEUPLOAD Remote Command Execution|exploit/linux/http/synology_dsm_sliceupload_exec_noauth|Required|-|Required|Required|-
19|Zabbix 2.0.8 SQL Injection and Remote Code Execution|exploit/linux/http/zabbix_sqli|Required|-|Required|Required|Required
20|Nagios Remote Plugin Executor Arbitrary Command Execution|exploit/linux/misc/nagios_nrpe_arguments|Required|-|Required|Required|-
21|Exim and Dovecot Insecure Configuration Command Injection|exploit/linux/smtp/exim4_dovecot_exec|Required|-|Required|Required|-
22|D-Link Unauthenticated UPnP M-SEARCH Multicast Command Injection|exploit/linux/upnp/dlink_upnp_msearch_exec|Required|-|Required|Required|-
23|ElasticSearch Dynamic Script Arbitrary Java Execution|exploit/multi/elasticsearch/script_mvel_rce|Required|-|Required|Required|Required
24|Apache Roller OGNL Injection|exploit/multi/http/apache_roller_ognl_injection|Required|-|Required|Required|Required
25|Cisco Prime Data Center Network Manager Arbitrary File Upload|exploit/multi/http/cisco_dcnm_upload|Required|-|Required|Required|Required
26|GestioIP Remote Command Execution|exploit/multi/http/gestioip_exec|Required|-|Required|Required|Required
27|Gitlab-shell Code Execution|exploit/multi/http/gitlab_shell_exec|Required|Required|Required|Required|Required
28|Glossword v1.8.8 - 1.8.12 Arbitrary File Upload Vulnerability|exploit/multi/http/glossword_upload_exec|Required|Required|Required|Required|Required
29|HP System Management Homepage JustGetSNMPQueue Command Injection|exploit/multi/http/hp_sys_mgmt_exec|Required|-|Required|Required|-
30|VMware Hyperic HQ Groovy Script-Console Java Execution|exploit/multi/http/hyperic_hq_script_console|Required|Required|Required|Required|Required
31|ISPConfig Authenticated Arbitrary PHP Code Execution|exploit/multi/http/ispconfig_php_exec|Required|Required|Required|Required|Required
32|Kordil EDMS v2.2.60rc3 Unauthenticated Arbitrary File Upload Vulnerability|exploit/multi/http/kordil_edms_upload_exec|Required|-|Required|Required|Required
33|Movable Type 4.2x, 4.3x Web Upgrade Remote Code Execution|exploit/multi/http/movabletype_upgrade_exec|Required|-|Required|Required|Required
34|OpenMediaVault Cron Remote Command Execution|exploit/multi/http/openmediavault_cmd_exec|Required|Required|Required|Required|-
35|OpenX Backdoor PHP Code Execution|exploit/multi/http/openx_backdoor_php|Required|-|Required|Required|Required
36|phpMyAdmin Authenticated Remote Code Execution via preg_replace()|exploit/multi/http/phpmyadmin_preg_replace|Required|Required|Required|Required|Required
37|ProcessMaker Open Source Authenticated PHP Code Execution|exploit/multi/http/processmaker_exec|Required|Required|Required|Required|-
38|Ruby on Rails JSON Processor YAML Deserialization Code Execution|exploit/multi/http/rails_json_yaml_code_exec|Required|-|Required|Required|Required
39|Ruby on Rails XML Processor YAML Deserialization Code Execution|exploit/multi/http/rails_xml_yaml_code_exec|Required|-|Required|Required|-
40|Apache Struts 2 DefaultActionMapper Prefixes OGNL Code Execution|exploit/multi/http/struts_default_action_mapper|Required|-|Required|Required|Required
41|Idera Up.Time Monitoring Station 7.0 post2file.php Arbitrary File Upload|exploit/multi/http/uptime_file_upload_1|Required|-|Required|Required|Required
42|Idera Up.Time Monitoring Station 7.4 post2file.php Arbitrary File Upload|exploit/multi/http/uptime_file_upload_2|Required|Required|Required|Required|-
43|vTigerCRM v5.4.0/v5.3.0 Authenticated Remote Code Execution|exploit/multi/http/vtiger_php_exec|Required|Required|Required|Required|Required
44|vTiger CRM SOAP AddEmailAttachment Arbitrary File Upload|exploit/multi/http/vtiger_soap_upload|Required|-|Required|Required|Required
45|Zabbix Authenticated Remote Command Execution|exploit/multi/http/zabbix_script_exec|Required|Required|Required|Required|Required
46|Western Digital Arkeia Remote Code Execution|exploit/unix/webapp/arkeia_upload_exec|Required|-|Required|Required|Required
47|ClipBucket Remote Code Execution|exploit/unix/webapp/clipbucket_upload_exec|Required|-|Required|Required|Required
48|DataLife Engine preview.php PHP Code Injection|exploit/unix/webapp/datalife_preview_exec|Required|-|Required|Required|Required
49|FlashChat Arbitrary File Upload|exploit/unix/webapp/flashchat_upload_exec|Required|-|Required|Required|Required
50|Graphite Web Unsafe Pickle Handling|exploit/unix/webapp/graphite_pickle_exec|Required|-|Required|Required|Required
51|Havalite CMS Arbitary File Upload Vulnerability|exploit/unix/webapp/havalite_upload_exec|Required|-|Required|Required|Required
52|Horde Framework Unserialize PHP Code Execution|exploit/unix/webapp/horde_unserialize_exec|Required|-|Required|Required|Required
53|InstantCMS 1.6 Remote PHP Code Execution|exploit/unix/webapp/instantcms_exec|Required|-|Required|Required|Required
54|LibrettoCMS File Manager Arbitary File Upload Vulnerability|exploit/unix/webapp/libretto_upload_exec|Required|-|Required|Required|Required
55|OpenEMR PHP File Upload Vulnerability|exploit/unix/webapp/openemr_upload_exec|Required|-|Required|Required|Required
56|PHP-Charts v1.0 PHP Code Execution Vulnerability|exploit/unix/webapp/php_charts_exec|Required|-|Required|Required|Required
57|Squash YAML Code Execution|exploit/unix/webapp/squash_yaml_exec|Required|-|Required|Required|Required
58|vBulletin index.php/ajax/api/reputation/vote nodeid Parameter SQL Injection|exploit/unix/webapp/vbulletin_vote_sqli_exec|Required|-|Required|Required|Required
59|VICIdial Manager Send OS Command Injection|exploit/unix/webapp/vicidial_manager_send_cmd_exec|Required|Required|Required|Required|-
60|WebTester 5.x Command Execution|exploit/unix/webapp/webtester_exec|Required|-|Required|Required|Required
61|WordPress OptimizePress Theme File Upload Vulnerability|exploit/unix/webapp/wp_optimizepress_upload|Required|-|Required|Required|Required
62|WordPress W3 Total Cache PHP Code Execution|exploit/unix/webapp/wp_total_cache_exec|Required|-|Required|Required|Required
63|ZeroShell Remote Code Execution|exploit/unix/webapp/zeroshell_exec|Required|-|Required|Required|Required
64|Zimbra Collaboration Server LFI|exploit/unix/webapp/zimbra_lfi|Required|-|Required|Required|Required
65|ZoneMinder Video Server packageControl Command Execution|exploit/unix/webapp/zoneminder_packagecontrol_exec|Required|Required|Required|Required|Required
66|EMC AlphaStor Device Manager Opcode 0x75 Command Injection|exploit/windows/emc/alphastor_device_manager_exec|Required|-|Required|Required|-
67|ManageEngine Desktop Central AgentLogUpload Arbitrary File Upload|exploit/windows/http/desktopcentral_file_upload|Required|-|Required|Required|-
68|HP Intelligent Management Center BIMS UploadServlet Directory Traversal|exploit/windows/http/hp_imc_bims_upload|Required|-|Required|Required|-
69|HP LoadRunner EmulationAdmin Web Service Directory Traversal|exploit/windows/http/hp_loadrunner_copyfiletoserver|Required|-|Required|Required|-
70|HP ProCurve Manager SNAC UpdateCertificatesServlet File Upload|exploit/windows/http/hp_pcm_snac_update_certificates|Required|-|Required|Required|-
71|HP ProCurve Manager SNAC UpdateDomainControllerServlet File Upload|exploit/windows/http/hp_pcm_snac_update_domain|Required|-|Required|Required|-
72|Kaseya uploadImage Arbitrary File Upload|exploit/windows/http/kaseya_uploadimage_file_upload|Required|-|Required|Required|-
73|MiniWeb (Build 300) Arbitrary File Upload|exploit/windows/http/miniweb_upload_wbem|Required|-|Required|Required|-
74|Novell Zenworks Mobile Managment MDM.php Local File Inclusion Vulnerability|exploit/windows/http/novell_mdm_lfi|Required|-|Required|Required|Required
75|Oracle Endeca Server Remote Command Execution|exploit/windows/http/oracle_endeca_exec|Required|-|Required|Required|Required
76|VMware vCenter Chargeback Manager ImageUploadServlet Arbitrary File Upload|exploit/windows/http/vmware_vcenter_chargeback_upload|Required|-|Required|Required|-
77|BigAnt Server DUPF Command Arbitrary File Upload|exploit/windows/misc/bigant_server_dupf_upload|Required|-|Required|Required|-
78|Nvidia Mental Ray Satellite Service Arbitrary DLL Injection|exploit/windows/misc/nvidia_mental_ray|Required|-|Required|Required|-
79|ABB MicroSCADA wserver.exe Remote Code Execution|exploit/windows/scada/abb_wserver_exec|Required|-|Required|Required|-
80|SCADA 3S CoDeSys Gateway Server Directory Traversal|exploit/windows/scada/codesys_gateway_server_traversal|Required|-|Required|Required|-

#### 2014 (55)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AlienVault OSSIM SQL Injection and Remote Code Execution|exploit/linux/http/alienvault_sqli_exec|Required|-|Required|Required|Required
2|Centreon SQL and Command Injection|exploit/linux/http/centreon_sqli_exec|Required|-|Required|Required|Required
3|Fritz!Box Webcm Unauthenticated Command Injection|exploit/linux/http/fritzbox_echo_exec|Required|-|Required|Required|-
4|Gitlist Unauthenticated Remote Command Execution|exploit/linux/http/gitlist_exec|Required|-|Required|Required|Required
5|IPFire Bash Environment Variable Injection (Shellshock)|exploit/linux/http/ipfire_bashbug_exec|Required|Required|Required|Required|-
6|LifeSize UVC Authenticated RCE via Ping|exploit/linux/http/lifesize_uvc_ping_rce|Required|Required|Required|Required|Required
7|Linksys E-Series TheMoon Remote Command Injection|exploit/linux/http/linksys_themoon_exec|Required|-|Required|Required|-
8|Pandora FMS Remote Code Execution|exploit/linux/http/pandora_fms_exec|Required|-|Required|Required|Required
9|Pandora FMS Default Credential / SQLi Remote Code Execution|exploit/linux/http/pandora_fms_sqli|Required|-|Required|Required|Required
10|Railo Remote File Include|exploit/linux/http/railo_cfml_rfi|Required|-|Required|Required|Required
11|AlienVault OSSIM av-centerd Command Injection|exploit/linux/ids/alienvault_centerd_soap_exec|Required|-|Required|Required|-
12|Loadbalancer.org Enterprise VA SSH Private Key Exposure|exploit/linux/ssh/loadbalancerorg_enterprise_known_privkey|Required|-|Required|Required|-
13|Quantum DXi V1000 SSH Private Key Exposure|exploit/linux/ssh/quantum_dxi_known_privkey|Required|-|Required|Required|-
14|Quantum vmPRO Backdoor Command|exploit/linux/ssh/quantum_vmpro_backdoor|Required|Required|Required|Required|-
15|Belkin Wemo UPnP Remote Code Execution|exploit/linux/upnp/belkin_wemo_upnp_exec|Required|-|Required|Required|-
16|Pure-FTPd External Authentication Bash Environment Variable Code Injection (Shellshock)|exploit/multi/ftp/pureftpd_bash_env_exec|Required|-|Required|Required|-
17|Dexter (CasinoLoader) SQL Injection|exploit/multi/http/dexter_casinoloader_exec|Required|-|Required|Required|Required
18|Drupal HTTP Parameter Key/Value SQL Injection|exploit/multi/http/drupal_drupageddon|Required|-|Required|Required|Required
19|ManageEngine Eventlog Analyzer Arbitrary File Upload|exploit/multi/http/eventlog_file_upload|Required|-|Required|Required|-
20|ManageEngine Desktop Central / Password Manager LinkViewFetchServlet.dat SQL Injection|exploit/multi/http/manage_engine_dc_pmp_sqli|Required|-|Required|Required|-
21|ManageEngine Multiple Products Authenticated File Upload|exploit/multi/http/manageengine_auth_upload|Required|Required|Required|Required|-
22|MediaWiki Thumb.php Remote Command Execution|exploit/multi/http/mediawiki_thumb|Required|-|Required|Required|Required
23|ManageEngine OpManager and Social IT Arbitrary File Upload|exploit/multi/http/opmanager_socialit_file_upload|Required|-|Required|Required|-
24|Phpwiki Ploticus Remote Code Execution|exploit/multi/http/phpwiki_ploticus_exec|Required|-|Required|Required|Required
25|SolarWinds Storage Manager Authentication Bypass|exploit/multi/http/solarwinds_store_manager_auth_filter|Required|-|Required|Required|-
26|Dell SonicWALL Scrutinizer 11.01 methodDetail SQL Injection|exploit/multi/http/sonicwall_scrutinizer_methoddetail_sqli|Required|Required|Required|Required|Required
27|Visual Mining NetCharts Server Remote Code Execution|exploit/multi/http/visual_mining_netcharts_upload|Required|Required|Required|Required|-
28|Zpanel Remote Unauthenticated RCE|exploit/multi/http/zpanel_information_disclosure_rce|Required|-|Required|Required|Required
29|Dell KACE K1000 File Upload|exploit/unix/http/dell_kace_k1000_upload|Required|-|Required|Required|-
30|TWiki Debugenableplugins Remote Code Execution|exploit/unix/http/twiki_debug_plugins|Required|-|Required|Required|Required
31|VMTurbo Operations Manager vmtadmin.cgi Remote Command Execution|exploit/unix/http/vmturbo_vmtadmin_exec_noauth|Required|-|Required|Required|-
32|Array Networks vAPV and vxAG Private Key Privilege Escalation Code Execution|exploit/unix/ssh/array_vxag_vapv_privkey_privesc|Required|Required|Required|Required|-
33|ActualAnalyzer 'ant' Cookie Command Execution|exploit/unix/webapp/actualanalyzer_ant_cookie_exec|Required|Required|Required|Required|Required
34|FreePBX config.php Remote Code Execution|exploit/unix/webapp/freepbx_config_exec|Required|-|Required|Required|Required
35|Joomla Akeeba Kickstart Unserialize Remote Code Execution|exploit/unix/webapp/joomla_akeeba_unserialize|Required|-|Required|Required|Required
36|ProjectSend Arbitrary File Upload|exploit/unix/webapp/projectsend_upload_exec|Required|-|Required|Required|Required
37|SePortal SQLi Remote Code Execution|exploit/unix/webapp/seportal_sqli_exec|Required|Required|Required|Required|Required
38|Simple E-Document Arbitrary File Upload|exploit/unix/webapp/simple_e_document_upload_exec|Required|-|Required|Required|Required
39|SkyBlueCanvas CMS Remote Code Execution|exploit/unix/webapp/skybluecanvas_exec|Required|-|Required|Required|Required
40|Wordpress Creative Contact Form Upload Vulnerability|exploit/unix/webapp/wp_creativecontactform_file_upload|Required|-|Required|Required|Required
41|Wordpress Download Manager (download-manager) Unauthenticated File Upload|exploit/unix/webapp/wp_downloadmanager_upload|Required|-|Required|Required|Required
42|Wordpress InfusionSoft Upload Vulnerability|exploit/unix/webapp/wp_infusionsoft_upload|Required|-|Required|Required|Required
43|WordPress RevSlider File Upload and Execute Vulnerability|exploit/unix/webapp/wp_revslider_upload_execute|Required|-|Required|Required|Required
44|WordPress WP Symposium 14.11 Shell Upload|exploit/unix/webapp/wp_symposium_shell_upload|Required|-|Required|Required|Required
45|Wordpress MailPoet Newsletters (wysija-newsletters) Unauthenticated File Upload|exploit/unix/webapp/wp_wysija_newsletters_upload|Required|-|Required|Required|Required
46|Symantec Endpoint Protection Manager /servlet/ConsoleServlet Remote Command Execution|exploit/windows/antivirus/symantec_endpoint_manager_rce|Required|-|Required|Required|Required
47|Symantec Workspace Streaming ManagementAgentServer.putFile XMLRPC Request Arbitrary File Upload|exploit/windows/antivirus/symantec_workspace_streaming_exec|Required|-|Required|Required|-
48|ManageEngine Desktop Central StatusUpdate Arbitrary File Upload|exploit/windows/http/desktopcentral_statusupdate_upload|Required|-|Required|Required|-
49|Lexmark MarkVision Enterprise Arbitrary File Upload|exploit/windows/http/lexmark_markvision_gfd_upload|Required|-|Required|Required|Required
50|Oracle Event Processing FileUploadServlet Arbitrary File Upload|exploit/windows/http/oracle_event_processing_upload|Required|-|Required|Required|-
51|Rejetto HttpFileServer Remote Command Execution|exploit/windows/http/rejetto_hfs_exec|Required|-|Required|Required|Required
52|Numara / BMC Track-It! FileStorageService Arbitrary File Upload|exploit/windows/http/trackit_file_upload|Required|-|Required|Required|Required
53|HP Data Protector 8.10 Remote Command Execution|exploit/windows/misc/hp_dataprotector_cmd_exec|Required|-|Required|Required|-
54|HP Data Protector Backup Client Service Remote Code Execution|exploit/windows/misc/hp_dataprotector_exec_bar|Required|-|Required|Required|-
55|GE Proficy CIMPLICITY gefebt.exe Remote Code Execution|exploit/windows/scada/ge_proficy_cimplicity_gefebt|Required|-|Required|Required|Required

#### 2015 (54)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Watchguard XCS Remote Command Execution|exploit/freebsd/http/watchguard_cmd_exec|Required|Required|Required|Required|Required
2|Accellion FTA getStatus verify_oauth_token Command Execution|exploit/linux/http/accellion_fta_getstatus_oauth|Required|-|Required|Required|-
3|Advantech Switch Bash Environment Variable Code Injection (Shellshock)|exploit/linux/http/advantech_switch_bash_env_exec|Required|-|Required|Required|-
4|D-Link DCS-930L Authenticated Remote Command Execution|exploit/linux/http/dlink_dcs_930l_authenticated_remote_command_execution|Required|Required|Required|Required|-
5|F5 iControl iCall::Script Root Command Execution|exploit/linux/http/f5_icall_cmd|Required|Required|Required|Required|Required
6|GoAutoDial 3.3 Authentication Bypass / Command Injection|exploit/linux/http/goautodial_3_rce_command_injection|Required|-|Required|Required|Required
7|MVPower DVR Shell Unauthenticated Command Execution|exploit/linux/http/mvpower_dvr_shell_exec|Required|-|Required|Required|-
8|Hak5 WiFi Pineapple Preconfiguration Command Injection|exploit/linux/http/pineapple_bypass_cmdinject|Required|-|Required|Required|Required
9|Hak5 WiFi Pineapple Preconfiguration Command Injection|exploit/linux/http/pineapple_preconfig_cmdinject|Required|Required|Required|Required|Required
10|TP-Link SC2020n Authenticated Telnet Injection|exploit/linux/http/tp_link_sc2020n_authenticated_telnet_injection|Required|Required|Required|Required|-
11|ASUS infosvr Auth Bypass Command Execution|exploit/linux/misc/asus_infosvr_auth_bypass_exec|Required|-|Required|Required|-
12|Jenkins CLI RMI Java Deserialization Vulnerability|exploit/linux/misc/jenkins_java_deserialize|Required|-|Required|Required|Required
13|Ceragon FibeAir IP-10 SSH Private Key Exposure|exploit/linux/ssh/ceragon_fibeair_known_privkey|Required|-|Required|Required|-
14|ElasticSearch Search Groovy Sandbox Bypass|exploit/multi/elasticsearch/search_groovy_script|Required|-|Required|Required|Required
15|China Chopper Caidao PHP Backdoor Code Execution|exploit/multi/http/caidao_php_backdoor_exec|Required|Required|Required|Required|Required
16|Atlassian HipChat for Jira Plugin Velocity Template Injection|exploit/multi/http/jira_hipchat_template|Required|-|Required|Required|Required
17|Joomla HTTP Header Unauthenticated Remote Code Execution|exploit/multi/http/joomla_http_header_rce|Required|-|Required|Required|Required
18|ManageEngine ServiceDesk Plus Arbitrary File Upload|exploit/multi/http/manageengine_sd_uploader|Required|-|Required|Required|-
19|PHP Utility Belt Remote Code Execution|exploit/multi/http/php_utility_belt_rce|Required|-|Required|Required|Required
20|phpFileManager 0.9.8 Remote Code Execution|exploit/multi/http/phpfilemanager_rce|Required|-|Required|Required|Required
21|PHPMoAdmin 1.1.2 Remote Code Execution|exploit/multi/http/phpmoadmin_exec|Required|-|Required|Required|Required
22|Ruby on Rails Web Console (v2) Whitelist Bypass Code Execution|exploit/multi/http/rails_web_console_v2_code_exec|Required|-|Required|Required|Required
23|Simple Backdoor Shell Remote Code Execution|exploit/multi/http/simple_backdoors_exec|Required|-|Required|Required|Required
24|SysAid Help Desk 'rdslogs' Arbitrary File Upload|exploit/multi/http/sysaid_rdslogs_file_upload|Required|-|Required|Required|Required
25|vBulletin 5.1.2 Unserialize Code Execution|exploit/multi/http/vbulletin_unserialize|Required|-|Required|Required|Required
26|Werkzeug Debug Shell Command Execution|exploit/multi/http/werkzeug_debug_rce|Required|-|Required|Required|Required
27|Novell ZENworks Configuration Management Arbitrary File Upload|exploit/multi/http/zenworks_configuration_management_upload|Required|-|Required|Required|Required
28|Legend Perl IRC Bot Remote Code Execution|exploit/multi/misc/legend_bot_exec|Required|-|Required|Required|-
29|TeamCity Agent XML-RPC Command Execution|exploit/multi/misc/teamcity_agent_xmlrpc_exec|Required|-|Required|Required|-
30|w3tw0rk / Pitbul IRC Bot  Remote Code Execution|exploit/multi/misc/w3tw0rk_exec|Required|-|Required|Required|-
31|Oracle Weblogic Server Deserialization RCE - Raw Object|exploit/multi/misc/weblogic_deserialize_rawobject|Required|-|Required|Required|-
32|Xdh / LinuxNet Perlbot / fBot IRC Bot Remote Code Execution|exploit/multi/misc/xdh_x_exec|Required|-|Required|Required|-
33|ProFTPD 1.3.5 Mod_Copy Command Execution|exploit/unix/ftp/proftpd_modcopy_exec|Required|-|Required|Required|Required
34|Cambium ePMP1000 'ping' Shell via Command Injection (up to v2.5)|exploit/unix/http/epmp1000_ping_cmd_shell|Required|Required|Required|Required|-
35|Joomla Content History SQLi Remote Code Execution|exploit/unix/webapp/joomla_contenthistory_sqli_rce|Required|-|Required|Required|Required
36|Maarch LetterBox Unrestricted File Upload|exploit/unix/webapp/maarch_letterbox_file_upload|Required|-|Required|Required|Required
37|WordPress WP EasyCart Unrestricted File Upload|exploit/unix/webapp/wp_easycart_unrestricted_file_upload|Required|-|Required|Required|Required
38|WordPress Holding Pattern Theme Arbitrary File Upload|exploit/unix/webapp/wp_holding_pattern_file_upload|Required|-|Required|Required|Required
39|Wordpress InBoundio Marketing PHP Upload Vulnerability|exploit/unix/webapp/wp_inboundio_marketing_file_upload|Required|-|Required|Required|Required
40|Wordpress N-Media Website Contact Form Upload Vulnerability|exploit/unix/webapp/wp_nmediawebsite_file_upload|Required|-|Required|Required|Required
41|WordPress Pixabay Images PHP Code Upload|exploit/unix/webapp/wp_pixabay_images_upload|Required|-|Required|Required|Required
42|WordPress Platform Theme File Upload Vulnerability|exploit/unix/webapp/wp_platform_exec|Required|-|Required|Required|Required
43|Wordpress Work The Flow Upload Vulnerability|exploit/unix/webapp/wp_worktheflow_upload|Required|-|Required|Required|Required
44|WordPress WPshop eCommerce Arbitrary File Upload Vulnerability|exploit/unix/webapp/wp_wpshop_ecommerce_file_upload|Required|-|Required|Required|Required
45|X11 Keyboard Command Injection|exploit/unix/x11/x11_keyboard_exec|Required|-|Required|Required|-
46|Apache ActiveMQ 5.x-5.11.1 Directory Traversal Shell Upload|exploit/windows/http/apache_activemq_traversal_upload|Required|Required|Required|Required|Required
47|Ektron 8.5, 8.7, 9.0 XSLT Transform Remote Code Execution|exploit/windows/http/ektron_xslt_exec_ws|Required|-|Required|Required|Required
48|Kaseya VSA uploader.aspx Arbitrary File Upload|exploit/windows/http/kaseya_uploader|Required|-|Required|Required|-
49|ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability|exploit/windows/http/manageengine_connectionid_write|Required|-|Required|Required|Required
50|Oracle BeeHive 2 voice-servlet prepareAudioToPlay() Arbitrary File Upload|exploit/windows/http/oracle_beehive_prepareaudiotoplay|Required|-|Required|Required|Required
51|Symantec Endpoint Protection Manager Authentication Bypass and Code Execution|exploit/windows/http/sepm_auth_bypass_rce|Required|-|Required|Required|Required
52|Solarwinds Firewall Security Manager 6.6.5 Client Session Handling Vulnerability|exploit/windows/http/solarwinds_fsm_userlogin|Required|-|Required|Required|Required
53|IBM WebSphere RCE Java Deserialization Vulnerability|exploit/windows/misc/ibm_websphere_java_deserialize|Required|-|Required|Required|Required
54|IPass Control Pipe Remote Command Execution|exploit/windows/smb/ipass_pipe_exec|Required|-|Required|Required|-

#### 2016 (58)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apache Continuum Arbitrary Command Execution|exploit/linux/http/apache_continuum_cmd_exec|Required|-|Required|Required|-
2|Apache CouchDB Arbitrary Command Execution|exploit/linux/http/apache_couchdb_cmd_exec|Required|Required|Required|Required|-
3|ATutor 2.2.1 Directory Traversal / Remote Code Execution|exploit/linux/http/atutor_filemanager_traversal|Required|-|Required|Required|Required
4|Centreon Web Useralias Command Execution|exploit/linux/http/centreon_useralias_exec|Required|-|Required|Required|Required
5|Cisco Firepower Management Console 6.0 Post Authentication UserAdd Vulnerability|exploit/linux/http/cisco_firepower_useradd|Required|Required|Required|Required|Required
6|Dlink DIR Routers Unauthenticated HNAP Login Stack Buffer Overflow|exploit/linux/http/dlink_hnap_login_bof|Required|-|Required|Required|-
7|PowerShellEmpire Arbitrary File Upload (Skywalker)|exploit/linux/http/empire_skywalker|Required|-|Required|Required|-
8|Hadoop YARN ResourceManager Unauthenticated Command Execution|exploit/linux/http/hadoop_unauth_exec|Required|-|Required|Required|-
9|IPFire proxy.cgi RCE|exploit/linux/http/ipfire_proxy_exec|Required|Required|Required|Required|-
10|Kaltura Remote PHP Code Execution|exploit/linux/http/kaltura_unserialize_rce|Required|-|Required|Required|Required
11|Nagios XI Chained Remote Code Execution|exploit/linux/http/nagios_xi_chained_rce|Required|-|Required|Required|-
12|Netgear R7000 and R6400 cgi-bin Command Injection|exploit/linux/http/netgear_r7000_cgibin_exec|Required|-|Required|Required|-
13|Netgear Devices Unauthenticated Remote Command Execution|exploit/linux/http/netgear_unauth_exec|Required|-|Required|Required|Required
14|NETGEAR WNR2000v5 (Un)authenticated hidden_lang_avi Stack Buffer Overflow|exploit/linux/http/netgear_wnr2000_rce|Required|Required|Required|Required|-
15|NUUO NVRmini 2 / Crystal / NETGEAR ReadyNAS Surveillance Authenticated Remote Code Execution|exploit/linux/http/nuuo_nvrmini_auth_rce|Required|Required|Required|Required|Required
16|NUUO NVRmini 2 / NETGEAR ReadyNAS Surveillance Unauthenticated Remote Code Execution|exploit/linux/http/nuuo_nvrmini_unauth_rce|Required|-|Required|Required|Required
17|op5 v7.1.9 Configuration Command Execution|exploit/linux/http/op5_config_exec|Required|Required|Required|Required|Required
18|Riverbed SteelCentral NetProfiler/NetExpress Remote Code Execution|exploit/linux/http/riverbed_netprofiler_netexpress_exec|Required|Required|Required|Required|Required
19|Tiki-Wiki CMS Calendar Command Execution|exploit/linux/http/tiki_calendar_exec|Required|Required|Required|Required|Required
20|Trend Micro Smart Protection Server Exec Remote Code Injection|exploit/linux/http/trendmicro_sps_exec|Required|Required|Required|Required|Required
21|TrueOnline / Billion 5200W-T Router Unauthenticated Command Injection|exploit/linux/http/trueonline_billion_5200w_rce|Required|Required|Required|Required|-
22|TrueOnline / ZyXEL P660HN-T v1 Router Unauthenticated Command Injection|exploit/linux/http/trueonline_p660hn_v1_rce|Required|-|Required|Required|-
23|Ubiquiti airOS Arbitrary File Upload|exploit/linux/http/ubiquiti_airos_file_upload|Required|-|Required|Required|-
24|HID discoveryd command_blink_on Unauthenticated RCE|exploit/linux/misc/hid_discoveryd_command_blink_on_unauth_rce|Required|-|Required|Required|-
25|Jenkins CLI HTTP Java Deserialization Vulnerability|exploit/linux/misc/jenkins_ldap_deserialize|Required|-|Required|Required|Required
26|ExaGrid Known SSH Key and Default Password|exploit/linux/ssh/exagrid_known_privkey|Required|-|Required|Required|-
27|VMware VDP Known SSH Key|exploit/linux/ssh/vmware_vdp_known_privkey|Required|-|Required|Required|-
28|ActiveMQ web shell upload|exploit/multi/http/apache_activemq_upload_jsp|Required|Required|Required|Required|-
29|ATutor 2.2.1 SQL Injection / Remote Code Execution|exploit/multi/http/atutor_sqli|Required|-|Required|Required|Required
30|Bassmaster Batch Arbitrary JavaScript Injection Remote Code Execution|exploit/multi/http/bassmaster_js_injection|Required|-|Required|Required|-
31|BuilderEngine Arbitrary File Upload Vulnerability and execution|exploit/multi/http/builderengine_upload_exec|Required|-|Required|Required|Required
32|Jenkins XStream Groovy classpath Deserialization Vulnerability|exploit/multi/http/jenkins_xstream_deserialize|Required|-|Required|Required|Required
33|Magento 2.0.6 Unserialize Remote Code Execution|exploit/multi/http/magento_unserialize|Required|-|Required|Required|Required
34|Metasploit Web UI Static secret_key_base Value|exploit/multi/http/metasploit_static_secret_key_base|Required|-|Required|Required|Required
35|Novell ServiceDesk Authenticated File Upload|exploit/multi/http/novell_servicedesk_rce|Required|Required|Required|Required|-
36|Oracle ATS Arbitrary File Upload|exploit/multi/http/oracle_ats_file_upload|Required|-|Required|Required|-
37|Phoenix Exploit Kit Remote Code Execution|exploit/multi/http/phoenix_exec|Required|-|Required|Required|Required
38|phpMyAdmin Authenticated Remote Code Execution|exploit/multi/http/phpmyadmin_null_termination_exec|Required|Required|Required|Required|Required
39|Ruby on Rails ActionPack Inline ERB Code Execution|exploit/multi/http/rails_actionpack_inline_exec|Required|-|Required|Required|Required
40|Ruby on Rails Dynamic Render File Upload Remote Code Execution|exploit/multi/http/rails_dynamic_render_code_exec|Required|-|Required|Required|-
41|Apache Shiro v1.2.4 Cookie RememberME Deserial RCE|exploit/multi/http/shiro_rememberme_v124_deserialize|Required|-|Required|Required|Required
42|Apache Struts Dynamic Method Invocation Remote Code Execution|exploit/multi/http/struts_dmi_exec|Required|-|Required|Required|Required
43|Apache Struts REST Plugin With Dynamic Method Invocation Remote Code Execution|exploit/multi/http/struts_dmi_rest_exec|Required|-|Required|Required|Required
44|WebNMS Framework Server Arbitrary File Upload|exploit/multi/http/webnms_file_upload|Required|-|Required|Required|Required
45|BMC Server Automation RSCD Agent NSH Remote Command Execution|exploit/multi/misc/bmc_server_automation_rscd_nsh_rce|Required|-|Required|Required|-
46|NodeJS Debugger Command Injection|exploit/multi/misc/nodejs_v8_debugger|Required|-|Required|Required|-
47|pfSense authenticated graph status RCE|exploit/unix/http/pfsense_graph_injection_exec|Required|Required|Required|Required|-
48|SonicWall Global Management System XMLRPC set_time_zone Unauth RCE|exploit/unix/sonicwall/sonicwall_xmlrpc_rce|Required|-|Required|Required|-
49|Drupal CODER Module Remote Command Execution|exploit/unix/webapp/drupal_coder_exec|Required|-|Required|Required|Required
50|Drupal RESTWS Module Remote PHP Code Execution|exploit/unix/webapp/drupal_restws_exec|Required|-|Required|Required|Required
51|SugarCRM REST Unserialize PHP Code Execution|exploit/unix/webapp/sugarcrm_rest_unserialize_exec|Required|-|Required|Required|Required
52|Tiki Wiki Unauthenticated File Upload Vulnerability|exploit/unix/webapp/tikiwiki_upload_exec|Required|-|Required|Required|Required
53|WordPress WP Mobile Detector 3.5 Shell Upload|exploit/unix/webapp/wp_mobile_detector_upload_execute|Required|-|Required|Required|Required
54|Disk Pulse Enterprise Login Buffer Overflow|exploit/windows/http/disk_pulse_enterprise_bof|Required|-|Required|Required|-
55|DiskBoss Enterprise GET Buffer Overflow|exploit/windows/http/diskboss_get_bof|Required|-|Required|Required|-
56|DiskSavvy Enterprise GET Buffer Overflow|exploit/windows/http/disksavvy_get_bof|Required|-|Required|Required|-
57|NETGEAR ProSafe Network Management System 300 Arbitrary File Upload|exploit/windows/http/netgear_nms_rce|Required|-|Required|Required|Required
58|Advantech WebAccess Dashboard Viewer uploadImageCommon Arbitrary File Upload|exploit/windows/scada/advantech_webaccess_dashboard_file_upload|Required|-|Required|Required|Required

#### 2017 (56)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AlienVault OSSIM/USM Remote Code Execution|exploit/linux/http/alienvault_exec|Required|-|Required|Required|Required
2|Crypttech CryptoLog Remote Code Execution|exploit/linux/http/crypttech_cryptolog_login_exec|Required|-|Required|Required|Required
3|DC/OS Marathon UI Docker Exploit|exploit/linux/http/dcos_marathon|Required|-|Required|Required|Required
4|DenyAll Web Application Firewall Remote Code Execution|exploit/linux/http/denyall_waf_exec|Required|-|Required|Required|Required
5|DIR-850L (Un)authenticated OS Command Exec|exploit/linux/http/dlink_dir850l_unauth_exec|Required|-|Required|Required|-
6|dnaLIMS Admin Module Command Execution|exploit/linux/http/dnalims_admin_exec|Required|-|Required|Required|Required
7|Docker Daemon - Unprotected TCP Socket Exploit|exploit/linux/http/docker_daemon_tcp|Required|-|Required|Required|-
8|Github Enterprise Default Session Secret And Deserialization Vulnerability|exploit/linux/http/github_enterprise_secret|Required|-|Required|Required|Required
9|GoAhead Web Server LD_PRELOAD Arbitrary Module Load|exploit/linux/http/goahead_ldpreload|Required|-|Required|Required|-
10|Huawei HG532n Command Injection|exploit/linux/http/huawei_hg532n_cmdinject|Required|-|Required|Required|-
11|IPFire proxy.cgi RCE|exploit/linux/http/ipfire_oinkcode_exec|Required|Required|Required|Required|-
12|Jenkins CLI Deserialization|exploit/linux/http/jenkins_cli_deserialization|Required|-|Required|Required|Required
13|Linksys WVBR0-25 User-Agent Command Execution|exploit/linux/http/linksys_wvbr0_user_agent_exec_noauth|Required|-|Required|Required|-
14|Logsign Remote Command Injection|exploit/linux/http/logsign_exec|Required|-|Required|Required|-
15|Palo Alto Networks readSessionVarsFromFile() Session Corruption|exploit/linux/http/panos_readsessionvars|Required|-|Required|Required|-
16|Rancher Server - Docker Exploit|exploit/linux/http/rancher_server|Required|-|Required|Required|Required
17|Apache Spark Unauthenticated Command Execution|exploit/linux/http/spark_unauth_rce|Required|-|Required|Required|-
18|Supervisor XML-RPC Authenticated Remote Code Execution|exploit/linux/http/supervisor_xmlrpc_exec|Required|-|Required|Required|Required
19|Trend Micro InterScan Messaging Security (Virtual Appliance) Remote Code Execution|exploit/linux/http/trend_micro_imsva_exec|Required|Required|Required|Required|Required
20|Trend Micro InterScan Messaging Security (Virtual Appliance) Remote Code Execution|exploit/linux/http/trendmicro_imsva_widget_exec|Required|-|Required|Required|Required
21|Unitrends UEB http api remote code execution|exploit/linux/http/ueb_api_rce|Required|-|Required|Required|-
22|Western Digital MyCloud multi_uploadify File Upload Vulnerability|exploit/linux/http/wd_mycloud_multiupload_upload|Required|-|Required|Required|-
23|WePresent WiPG-1000 Command Injection|exploit/linux/http/wipg1000_cmd_injection|Required|-|Required|Required|-
24|Xplico Remote Code Execution|exploit/linux/http/xplico_exec|Required|-|Required|Required|-
25|QNAP Transcode Server Command Execution|exploit/linux/misc/qnap_transcode_server|Required|-|Required|Required|-
26|Unitrends UEB bpserverd authentication bypass RCE|exploit/linux/misc/ueb9_bpserverd|Required|-|Required|Required|-
27|Samba is_known_pipename() Arbitrary Module Load|exploit/linux/samba/is_known_pipename|Required|-|Required|Required|-
28|SolarWinds LEM Default SSH Password Remote Code Execution|exploit/linux/ssh/solarwinds_lem_exec|Required|Required|Required|Required|-
29|IBM OpenAdmin Tool SOAP welcomeServer PHP Code Execution|exploit/multi/http/ibm_openadmin_tool_soap_welcomeserver_exec|Required|-|Required|Required|Required
30|Mako Server v2.5, 2.6 OS Command Injection RCE|exploit/multi/http/makoserver_cmd_exec|Required|-|Required|Required|Required
31|October CMS Upload Protection Bypass Code Execution|exploit/multi/http/october_upload_bypass_exec|Required|Required|Required|Required|Required
32|Oracle WebLogic wls-wsat Component Deserialization RCE|exploit/multi/http/oracle_weblogic_wsat_deserialization_rce|Required|-|Required|Required|Required
33|PlaySMS sendfromfile.php Authenticated "Filename" Field Code Execution|exploit/multi/http/playsms_filename_exec|Required|Required|Required|Required|Required
34|PlaySMS import.php Authenticated CSV File Upload Code Execution|exploit/multi/http/playsms_uploadcsv_exec|Required|Required|Required|Required|Required
35|Apache Struts 2 Struts 1 Plugin Showcase OGNL Code Execution|exploit/multi/http/struts2_code_exec_showcase|Required|-|Required|Required|Required
36|Apache Struts Jakarta Multipart Parser OGNL Injection|exploit/multi/http/struts2_content_type_ognl|Required|-|Required|Required|Required
37|Apache Struts 2 REST Plugin XStream RCE|exploit/multi/http/struts2_rest_xstream|Required|-|Required|Required|Required
38|Tomcat RCE via JSP Upload Bypass|exploit/multi/http/tomcat_jsp_upload_bypass|Required|-|Required|Required|Required
39|Trend Micro Threat Discovery Appliance admin_sys_time.cgi Remote Command Execution|exploit/multi/http/trendmicro_threat_discovery_admin_sys_time_cmdi|Required|Required|Required|Required|Required
40|Oracle Weblogic Server Deserialization RCE - RMI UnicastRef|exploit/multi/misc/weblogic_deserialize_unicastref|Required|-|Required|Required|-
41|Cambium ePMP1000 'get_chart' Shell via Command Injection (v3.1-3.5-RC7)|exploit/unix/http/epmp1000_get_chart_cmd_shell|Required|Required|Required|Required|-
42|pfSense authenticated group member RCE|exploit/unix/http/pfsense_group_member_exec|Required|Required|Required|Required|-
43|xdebug Unauthenticated OS Command Execution|exploit/unix/http/xdebug_unauth_exec|Required|-|Required|Required|-
44|Zivif Camera iptest.cgi Blind Remote Command Execution|exploit/unix/http/zivif_ipcheck_exec|Required|-|Required|Required|-
45|Polycom Shell HDX Series Traceroute Command Execution|exploit/unix/misc/polycom_hdx_traceroute_exec|Required|-|Required|Required|-
46|Joomla Component Fields SQLi Remote Code Execution|exploit/unix/webapp/joomla_comfields_sqli_rce|Required|-|Required|Required|Required
47|phpCollab 2.5.1 Unauthenticated File Upload|exploit/unix/webapp/phpcollab_upload_exec|Required|-|Required|Required|Required
48|VICIdial user_authorization Unauthenticated Command Execution|exploit/unix/webapp/vicidial_user_authorization_unauth_cmd_exec|Required|-|Required|Required|Required
49|Disk Pulse Enterprise GET Buffer Overflow|exploit/windows/http/disk_pulse_enterprise_get|Required|-|Required|Required|-
50|DotNetNuke Cookie Deserialization Remote Code Excecution|exploit/windows/http/dnn_cookie_deserialization_rce|Required|-|Required|Required|Required
51|HP Intelligent Management Java Deserialization RCE|exploit/windows/http/hp_imc_java_deserialize|Required|-|Required|Required|Required
52|Octopus Deploy Authenticated Code Execution|exploit/windows/http/octopusdeploy_deploy|Required|-|Required|Required|-
53|Serviio Media Server checkStreamUrl Command Execution|exploit/windows/http/serviio_checkstreamurl_cmd_exec|Required|-|Required|Required|-
54|Trend Micro OfficeScan Remote Code Execution|exploit/windows/http/trendmicro_officescan_widget_exec|Required|-|Required|Required|Required
55|HPE iMC dbman RestartDB Unauthenticated RCE|exploit/windows/misc/hp_imc_dbman_restartdb_unauth_rce|Required|-|Required|Required|-
56|HPE iMC dbman RestoreDBase Unauthenticated RCE|exploit/windows/misc/hp_imc_dbman_restoredbase_unauth_rce|Required|-|Required|Required|-

#### 2018 (31)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AsusWRT LAN Unauthenticated Remote Code Execution|exploit/linux/http/asuswrt_lan_rce|Required|-|Required|Required|-
2|Axis Network Camera .srv to parhand RCE|exploit/linux/http/axis_srv_parhand_rce|Required|-|Required|Required|-
3|Cisco Prime Infrastructure Unauthenticated Remote Code Execution|exploit/linux/http/cisco_prime_inf_rce|Required|-|Required|Required|Required
4|HP VAN SDN Controller Root Command Injection|exploit/linux/http/hp_van_sdn_cmd_inject|Required|-|Required|Required|-
5|IBM QRadar SIEM Unauthenticated Remote Code Execution|exploit/linux/http/ibm_qradar_unauth_rce|Required|-|Required|Required|-
6|Imperva SecureSphere PWS Command Injection|exploit/linux/http/imperva_securesphere_exec|Required|-|Required|Required|-
7|MicroFocus Secure Messaging Gateway Remote Code Execution|exploit/linux/http/microfocus_secure_messaging_gateway|Required|-|Required|Required|Required
8|QNAP Q'Center change_passwd Command Execution|exploit/linux/http/qnap_qcenter_change_passwd_exec|Required|Required|Required|Required|Required
9|Baldr Botnet Panel Shell Upload Exploit|exploit/multi/http/baldr_upload_exec|Required|-|Required|Required|Required
10|ClipBucket beats_uploader Unauthenticated Arbitrary File Upload|exploit/multi/http/clipbucket_fileupload_exec|Required|-|Required|Required|Required
11|Adobe ColdFusion CKEditor unrestricted file upload|exploit/multi/http/coldfusion_ckeditor_file_upload|Required|-|Required|Required|-
12|GitList v0.6.0 Argument Injection Vulnerability|exploit/multi/http/gitlist_arg_injection|Required|-|Required|Required|Required
13|Atlassian Jira Authenticated Upload Code Execution|exploit/multi/http/jira_plugin_upload|Required|Required|Required|Required|Required
14|Navigate CMS Unauthenticated Remote Code Execution|exploit/multi/http/navigate_cms_rce|Required|-|Required|Required|Required
15|NUUO NVRmini upgrade_handle.php Remote Command Execution|exploit/multi/http/nuuo_nvrmini_upgrade_rce|Required|-|Required|Required|-
16|osCommerce Installer Unauthenticated Code Execution|exploit/multi/http/oscommerce_installer_unauth_code_exec|Required|-|Required|Required|-
17|Apache Struts 2 Namespace Redirect OGNL Injection|exploit/multi/http/struts2_namespace_ognl|Required|-|Required|Required|Required
18|Nanopool Claymore Dual Miner APIs RCE|exploit/multi/misc/claymore_dual_miner_remote_manager_rce|Required|-|Required|Required|-
19|Hashicorp Consul Remote Command Execution via Rexec|exploit/multi/misc/consul_rexec_exec|Required|-|Required|Required|Required
20|Hashicorp Consul Remote Command Execution via Services API|exploit/multi/misc/consul_service_exec|Required|-|Required|Required|Required
21|Metasploit msfd Remote Code Execution|exploit/multi/misc/msfd_rce_remote|Required|-|Required|Required|-
22|PHP Laravel Framework token Unserialize Remote Command Execution|exploit/unix/http/laravel_token_unserialize_exec|Required|-|Required|Required|Required
23|Pi-Hole Whitelist OS Command Execution|exploit/unix/http/pihole_whitelist_exec|Required|-|Required|Required|Required
24|Quest KACE Systems Management Command Injection|exploit/unix/http/quest_kace_systems_management_rce|Required|-|Required|Required|-
25|Drupal Drupalgeddon 2 Forms API Property Injection|exploit/unix/webapp/drupal_drupalgeddon2|Required|-|Required|Required|Required
26|blueimp's jQuery (Arbitrary) File Upload|exploit/unix/webapp/jquery_file_upload|Required|-|Required|Required|Required
27|ThinkPHP Multiple PHP Injection RCEs|exploit/unix/webapp/thinkphp_rce|Required|-|Required|Required|Required
28|Apache Tika Header Command Injection|exploit/windows/http/apache_tika_jp2_jscript|Required|-|Required|Required|Required
29|Manage Engine Exchange Reporter Plus Unauthenticated RCE|exploit/windows/http/manageengine_adshacluster_rce|Required|-|Required|Required|Required
30|ManageEngine Applications Manager Remote Code Execution|exploit/windows/http/manageengine_appmanager_exec|Required|-|Required|Required|Required
31|PRTG Network Monitor Authenticated RCE|exploit/windows/http/prtg_authenticated_rce|Required|Required|Required|Required|-

#### 2019 (36)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Cisco UCS Director Unauthenticated Remote Code Execution|exploit/linux/http/cisco_ucs_rce|Required|-|Required|Required|Required
2|Cisco Prime Infrastructure Health Monitor TarArchive Directory Traversal Vulnerability|exploit/linux/http/cpi_tararchive_upload|Required|-|Required|Required|Required
3|DLINK DWL-2600 Authenticated Remote Command Injection|exploit/linux/http/dlink_dwl_2600_command_injection|Required|Required|Required|Required|Required
4|Webmin password_change.cgi Backdoor|exploit/linux/http/webmin_backdoor|Required|-|Required|Required|Required
5|Barco WePresent file_transfer.cgi Command Injection|exploit/linux/http/wepresent_cmd_injection|Required|-|Required|Required|-
6|Zimbra Collaboration Autodiscover Servlet XXE and ProxyServlet SSRF|exploit/linux/http/zimbra_xxe_rce|Required|-|Required|Required|Required
7|AwindInc SNMP Service Command Injection|exploit/linux/snmp/awind_snmp_exec|Required|-|Required|Required|-
8|Cisco UCS Director default scpuser password|exploit/linux/ssh/cisco_ucs_scpuser|Required|Required|Required|Required|-
9|D-Link DIR-859 Unauthenticated Remote Command Execution|exploit/linux/upnp/dlink_dir859_subscribe_exec|Required|-|Required|Required|-
10|Agent Tesla Panel Remote Code Execution|exploit/multi/http/agent_tesla_panel_rce|Required|-|Required|Required|Required
11|Apache Flink JAR Upload Java Code Execution|exploit/multi/http/apache_flink_jar_upload_exec|Required|-|Required|Required|-
12|Cisco Data Center Network Manager Unauthenticated Remote Code Execution|exploit/multi/http/cisco_dcnm_upload_2019|Required|Required|Required|Required|Required
13|GetSimpleCMS Unauthenticated RCE|exploit/multi/http/getsimplecms_unauth_code_exec|Required|-|Required|Required|Required
14|Jenkins ACL Bypass and Metaprogramming RCE|exploit/multi/http/jenkins_metaprogramming|Required|-|Required|Required|Required
15|Liferay Portal Java Unmarshalling via JSONWS RCE|exploit/multi/http/liferay_java_unmarshalling|Required|-|Required|Required|Required
16|PHPStudy Backdoor Remote Code execution|exploit/multi/http/phpstudy_backdoor_rce|Required|-|Required|Required|Required
17|Ruby On Rails DoubleTap Development Mode secret_key_base Vulnerability|exploit/multi/http/rails_double_tap|Required|-|Required|Required|Required
18|Shopware createInstanceFromNamedArguments PHP Object Instantiation RCE|exploit/multi/http/shopware_createinstancefromnamedarguments_rce|Required|Required|Required|Required|Required
19|Apache Solr Remote Code Execution via Velocity Template|exploit/multi/http/solr_velocity_rce|Required|-|Required|Required|-
20|Total.js CMS 12 Widget JavaScript Code Injection|exploit/multi/http/totaljs_cms_widget_exec|Required|Required|Required|Required|Required
21|vBulletin widgetConfig RCE|exploit/multi/http/vbulletin_widgetconfig_rce|Required|-|Required|Required|Required
22|BMC Patrol Agent Privilege Escalation Cmd Execution|exploit/multi/misc/bmc_patrol_cmd_exec|Required|Required|Required|Required|-
23|IBM TM1 / Planning Analytics Unauthenticated Remote Code Execution|exploit/multi/misc/ibm_tm1_unauth_rce|Required|-|Required|Required|-
24|Oracle Weblogic Server Deserialization RCE - AsyncResponseService |exploit/multi/misc/weblogic_deserialize_asyncresponseservice|Required|-|Required|Required|Required
25|PostgreSQL COPY FROM PROGRAM Command Execution|exploit/multi/postgres/postgres_copy_from_program_cmd_exec|Required|Required|Required|Required|-
26|Schneider Electric Pelco Endura NET55XX Encoder|exploit/unix/http/schneider_electric_net55xx_encoder|Required|Required|Required|Required|-
27|Ajenti auth username Command Injection|exploit/unix/webapp/ajenti_auth_username_cmd_injection|Required|-|Required|Required|Required
28|elFinder PHP Connector exiftran Command Injection|exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection|Required|-|Required|Required|Required
29|OpenNetAdmin Ping Command Injection|exploit/unix/webapp/opennetadmin_ping_cmd_injection|Required|-|Required|Required|Required
30|rConfig install Command Execution|exploit/unix/webapp/rconfig_install_cmd_exec|Required|-|Required|Required|Required
31|D-Link Central WiFi Manager CWM(100) RCE|exploit/windows/http/dlink_central_wifimanager_rce|Required|-|Required|Required|Required
32|Kentico CMS Staging SyncServer Unserialize Remote Command Execution|exploit/windows/http/kentico_staging_syncserver|Required|-|Required|Required|Required
33|Telerik UI ASP.NET AJAX RadAsyncUpload Deserialization|exploit/windows/http/telerik_rau_deserialization|Required|-|Required|Required|Required
34|Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability|exploit/windows/http/tomcat_cgi_cmdlineargs|Required|-|Required|Required|Required
35|IBM Websphere Application Server Network Deployment Untrusted Data Deserialization Remote Code Execution|exploit/windows/ibm/ibm_was_dmgr_java_deserialization_rce|Required|-|Required|Required|-
36|Ahsay Backup v7.x-v8.1.1.50 (authenticated) file upload|exploit/windows/misc/ahsay_backup_fileupload|Required|Required|Required|Required|Required

#### 2020 (42)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apache OFBiz XML-RPC Java Deserialization|exploit/linux/http/apache_ofbiz_deserialization|Required|-|Required|Required|Required
2|Artica proxy 4.30.000000 Auth Bypass service-cmds-peform Command Injection|exploit/linux/http/artica_proxy_auth_bypass_service_cmds_peform_command_injection|Required|-|Required|Required|Required
3|Cayin CMS NTP Server RCE|exploit/linux/http/cayin_cms_ntp|Required|Required|Required|Required|Required
4|Cisco UCS Director Cloupia Script RCE|exploit/linux/http/cisco_ucs_cloupia_script_rce|Required|-|Required|Required|Required
5|Geutebruck testaction.cgi Remote Command Execution|exploit/linux/http/geutebruck_testaction_exec|Required|Required|Required|Required|Required
6|IBM Data Risk Manager Unauthenticated Remote Code Execution|exploit/linux/http/ibm_drm_rce|Required|-|Required|Required|Required
7|Klog Server authenticate.php user Unauthenticated Command Injection|exploit/linux/http/klog_server_authenticate_user_unauth_command_injection|Required|-|Required|Required|Required
8|LinuxKI Toolset 6.01 Remote Command Execution|exploit/linux/http/linuxki_rce|Required|-|Required|Required|Required
9|Mida Solutions eFramework ajaxreq.php Command Injection|exploit/linux/http/mida_solutions_eframework_ajaxreq_rce|Required|-|Required|Required|Required
10|MobileIron MDM Hessian-Based Java Deserialization RCE|exploit/linux/http/mobileiron_mdm_hessian_rce|Required|-|Required|Required|Required
11|Netsweeper WebAdmin unixlogin.php Python Code Injection|exploit/linux/http/netsweeper_webadmin_unixlogin|Required|-|Required|Required|Required
12|Pandora FMS Events Remote Command Execution|exploit/linux/http/pandora_fms_events_exec|Required|Required|Required|Required|Required
13|Pulse Secure VPN gzip RCE|exploit/linux/http/pulse_secure_gzip_rce|Required|Required|Required|Required|Required
14|SaltStack Salt REST API Arbitrary Command Execution|exploit/linux/http/saltstack_salt_api_cmd_exec|Required|-|Required|Required|Required
15|TP-Link Cloud Cameras NCXXX Bonjour Command Injection|exploit/linux/http/tp_link_ncxxx_bonjour_command_injection|Required|Required|Required|Required|-
16|Trend Micro Web Security (Virtual Appliance) Remote Code Execution|exploit/linux/http/trendmicro_websecurity_exec|Required|-|Required|Required|-
17|Unraid 6.8.0 Auth Bypass PHP Code Execution|exploit/linux/http/unraid_auth_bypass_exec|Required|-|Required|Required|Required
18|TP-Link Archer A7/C7 Unauthenticated LAN Remote Code Execution|exploit/linux/misc/tplink_archer_a7_c7_lan_rce|Required|-|Required|Required|-
19|IBM Data Risk Manager a3user Default Password|exploit/linux/ssh/ibm_drm_a3user|Required|Required|Required|Required|-
20|Apache NiFi API Remote Code Execution|exploit/multi/http/apache_nifi_processor_rce|Required|-|Required|Required|Required
21|GitLab File Read Remote Code Execution|exploit/multi/http/gitlab_file_read_rce|Required|-|Required|Required|Required
22|Kong Gateway Admin API Remote Code Execution|exploit/multi/http/kong_gateway_admin_api_rce|Required|-|Required|Required|Required
23|MaraCMS Arbitrary PHP File Upload|exploit/multi/http/maracms_upload_exec|Required|Required|Required|Required|Required
24|Micro Focus UCMDB Java Deserialization Unauthenticated Remote Code Execution|exploit/multi/http/microfocus_ucmdb_unauth_deser|Required|-|Required|Required|Required
25|PlaySMS index.php Unauthenticated Template Injection Code Execution|exploit/multi/http/playsms_template_injection|Required|-|Required|Required|Required
26|Apache Struts 2 Forced Multi OGNL Evaluation|exploit/multi/http/struts2_multi_eval_ognl|Required|-|Required|Required|Required
27|vBulletin 5.x /ajax/render/widget_tabbedcontainer_tab_panel PHP remote code execution.|exploit/multi/http/vbulletin_widget_template_rce|Required|-|Required|Required|Required
28|Oracle WebLogic Server Administration Console Handle RCE|exploit/multi/http/weblogic_admin_handle_rce|Required|-|Required|Required|Required
29|WordPress AIT CSV Import Export Unauthenticated Remote Code Execution|exploit/multi/http/wp_ait_csv_rce|Required|-|Required|Required|Required
30|Wordpress Drag and Drop Multi File Uploader RCE|exploit/multi/http/wp_dnd_mul_file_rce|Required|-|Required|Required|Required
31|Inductive Automation Ignition Remote Code Execution|exploit/multi/scada/inductive_ignition_rce|Required|-|Required|Required|-
32|Pi-Hole heisenbergCompensator Blocklist OS Command Execution|exploit/unix/http/pihole_blocklist_exec|Required|-|Required|Required|Required
33|OpenSMTPD MAIL FROM Remote Code Execution|exploit/unix/smtp/opensmtpd_mail_from_rce|Required|-|Required|Required|-
34|OpenMediaVault rpc.php Authenticated PHP Code Injection|exploit/unix/webapp/openmediavault_rpc_rce|Required|Required|Required|Required|Required
35|openSIS Unauthenticated PHP Code Execution|exploit/unix/webapp/opensis_chain_exec|Required|-|Required|Required|Required
36|TrixBox CE endpoint_devicemap.php Authenticated Command Execution|exploit/unix/webapp/trixbox_ce_endpoint_devicemap_rce|Required|Required|Required|Required|-
37|Cayin xPost wayfinder_seqid SQLi to RCE|exploit/windows/http/cayin_xpost_sql_rce|Required|-|Required|Required|Required
38|ManageEngine Desktop Central Java Deserialization|exploit/windows/http/desktopcentral_deserialization|Required|-|Required|Required|Required
39|HPE Systems Insight Manager AMF Deserialization RCE|exploit/windows/http/hpe_sim_76_amf_deserialization|Required|-|Required|Required|Required
40|Plesk/myLittleAdmin ViewState .NET Deserialization|exploit/windows/http/plesk_mylittleadmin_viewstate|Required|-|Required|Required|Required
41|Microsoft SharePoint Server-Side Include and ViewState RCE|exploit/windows/http/sharepoint_ssi_viewstate|Required|-|Required|Required|Required
42|CA Unified Infrastructure Management Nimsoft 7.80 - Remote Buffer Overflow|exploit/windows/nimsoft/nimcontroller_bof|Required|-|Required|Required|-

#### 2021 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Microsoft Exchange Server DlpUtils AddTenantDlpPolicy RCE|exploit/windows/http/exchange_ecp_dlp_policy|Required|-|Required|Required|Required

## Evasion (0)

