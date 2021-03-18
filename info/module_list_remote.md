# Module info

## Stats:
- Total modules: 1924
- Auxiliary 758
	- 758 Normal
- Exploits 1166
	- 34 Manual
	- 2 Low
	- 122 Average
	- 125 Normal
	- 105 Good
	- 163 Great
	- 615 Excellent
- Evasion 0


## Table legend
- `✓` - Option present with default value provided
- `✗` - Option present but no default value
- `-` - Option not present

## Auxiliary (758)

### Normal Ranking (758)

#### 2000 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|UoW pop2d Remote File Retrieval Vulnerability|auxiliary/admin/pop2/uw_fileretrieval|-|-|✗|✓|-
2|Cisco Device HTTP Device Manager Access|auxiliary/scanner/http/cisco_device_manager|-|✓|✗|✓|-

#### 2001 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Cisco IOS HTTP Unauthorized Administrative Access|auxiliary/scanner/http/cisco_ios_auth_bypass|-|-|✗|✓|-

#### 2003 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Solaris KCMS + TTDB Arbitrary File Read|auxiliary/admin/sunrpc/solaris_kcms_readfile|-|-|✗|✓|-
2|Memcached UDP Version Scanner|auxiliary/scanner/memcached/memcached_udp_version|-|-|✗|✓|-

#### 2004 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|IBM DB2 db2rcmd.exe Command Execution Vulnerability|auxiliary/admin/db2/db2rcmd|-|✓|✗|✓|-
2|HP Web JetAdmin 6.5 Server Arbitrary Command Execution|auxiliary/admin/http/hp_web_jetadmin_exec|-|-|✗|✓|-
3|Motorola WR850G v4.03 Credentials|auxiliary/admin/motorola/wr850g_cred|-|-|✗|✓|-

#### 2006 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Cisco VPN Concentrator 3000 FTP Unauthorized Administrative Access|auxiliary/admin/networking/cisco_vpn_3000_ftp_bypass|-|-|✗|✓|-
2|TikiWiki Information Disclosure|auxiliary/admin/tikiwiki/tikidblib|-|-|✗|✓|-
3|RealVNC NULL Authentication Mode Bypass|auxiliary/admin/vnc/realvnc_41_bypass|-|-|✗|✓|-
4|Webmin File Disclosure|auxiliary/admin/webmin/file_disclosure|-|-|✗|✓|-

#### 2007 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|2Wire Cross-Site Request Forgery Password Reset Vulnerability|auxiliary/admin/2wire/xslt_password_reset|-|✗|✗|✓|-
2|Intersil (Boa) HTTPd Basic Authentication Password Reset|auxiliary/admin/http/intersil_pass_reset|-|✓|✗|✓|✓

#### 2008 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|EMC AlphaStor Device Manager Arbitrary Command Execution|auxiliary/admin/emc/alphastor_devicemanager_exec|-|-|✗|✓|-
2|EMC AlphaStor Library Manager Arbitrary Command Execution|auxiliary/admin/emc/alphastor_librarymanager_exec|-|-|✗|✓|-
3|SAP MaxDB cons.exe Remote Command Injection|auxiliary/admin/maxdb/maxdb_cons_exec|-|-|✗|✓|-
4|Microsoft Host Integration Server 2006 Command Execution Vulnerability|auxiliary/admin/ms/ms08_059_his2006|-|-|✗|✓|-

#### 2009 (13)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Tomcat UTF-8 Directory Traversal Vulnerability|auxiliary/admin/http/tomcat_utf8_traversal|-|-|✗|✓|✓
2|TrendMicro Data Loss Prevention 5.5 Directory Traversal|auxiliary/admin/http/trendmicro_dlp_traversal|-|-|✗|✓|-
3|TYPO3 sa-2009-001 Weak Encryption Key File Disclosure|auxiliary/admin/http/typo3_sa_2009_001|-|-|✗|✓|-
4|Typo3 sa-2009-002 File Disclosure|auxiliary/admin/http/typo3_sa_2009_002|-|-|✗|✓|-
5|Oracle Secure Backup exec_qr() Command Injection Vulnerability|auxiliary/admin/oracle/osb_execqr|-|-|✗|✓|-
6|Oracle Secure Backup Authentication Bypass/Command Injection Vulnerability|auxiliary/admin/oracle/osb_execqr2|-|-|✗|✓|-
7|Oracle TNS Listener SID Brute Forcer|auxiliary/admin/oracle/sid_brute|-|-|✗|✓|-
8|Oracle TNS Listener Command Issuer|auxiliary/admin/oracle/tnscmd|-|-|✗|✓|-
9|Motorola Timbuktu Service Detection|auxiliary/scanner/motorola/timbuktu_udp|-|-|✗|✓|-
10|Oracle TNS Listener SID Enumeration|auxiliary/scanner/oracle/sid_enum|-|-|✗|✓|-
11|Oracle TNS Listener Service Version Query|auxiliary/scanner/oracle/tnslsnr_version|-|-|✗|✓|-
12|Scanner for Bleichenbacher Oracle in RSA PKCS #1 v1.5|auxiliary/scanner/ssl/bleichenbacher_oracle|-|-|✗|✓|-
13|NetDecision 4.2 TFTP Directory Traversal|auxiliary/scanner/tftp/netdecision_tftp|-|-|✗|✓|-

#### 2010 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS10-065 Microsoft IIS 5 NTFS Stream Authentication Bypass|auxiliary/admin/http/iis_auth_bypass|-|-|✗|✓|✓
2|Oracle Secure Backup Authentication Bypass/Command Injection Vulnerability|auxiliary/admin/oracle/osb_execqr3|-|-|✗|✓|-
3|Titan FTP XCRC Directory Traversal Information Disclosure|auxiliary/scanner/ftp/titanftp_xcrc_traversal|-|-|✗|✓|-
4|Barracuda Multiple Product "locale" Directory Traversal|auxiliary/scanner/http/barracuda_directory_traversal|-|-|✗|✓|✓
5|Drupal Views Module Users Enumeration|auxiliary/scanner/http/drupal_views_user_enum|-|-|✗|✓|✓

#### 2011 (13)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP Data Protector 6.1 EXEC_CMD Command Execution|auxiliary/admin/hp/hp_data_protector_cmd|-|-|✗|✓|-
2|Zend Server Java Bridge Design Flaw Remote Code Execution|auxiliary/admin/zend/java_bridge|-|-|✗|✓|-
3|CheckPoint Firewall-1 SecuRemote Topology Service Hostname Disclosure|auxiliary/gather/checkpoint_hostname|-|-|✗|✓|-
4|Majordomo2 _list_file_get() Directory Traversal|auxiliary/scanner/http/majordomo2_directory_traversal|-|-|✗|✓|-
5|S40 0.4.2 CMS Directory Traversal Vulnerability|auxiliary/scanner/http/s40_traversal|-|-|✗|✓|✓
6|Squiz Matrix User Enumeration Scanner|auxiliary/scanner/http/squiz_matrix_user_enum|-|-|✗|✓|✓
7|Sybase Easerver 6.3 Directory Traversal|auxiliary/scanner/http/sybase_easerver_traversal|-|-|✗|✓|-
8|Synology Forget Password  User Enumeration Scanner|auxiliary/scanner/http/synology_forget_passwd_user_enum|-|-|✗|✓|✓
9|Yaws Web Server Directory Traversal|auxiliary/scanner/http/yaws_traversal|-|-|✗|✓|-
10|Java RMI Server Insecure Endpoint Code Execution Scanner|auxiliary/scanner/misc/java_rmi_server|-|-|✗|✓|-
11|Modbus Version Scanner|auxiliary/scanner/scada/modbusdetect|-|-|✗|✓|-
12|IpSwitch WhatsUp Gold TFTP Directory Traversal|auxiliary/scanner/tftp/ipswitch_whatsupgold_tftp|-|-|✗|✓|-
13|VMWare Update Manager 4 Directory Traversal|auxiliary/scanner/vmware/vmware_update_manager_traversal|-|-|✗|✓|-

#### 2012 (24)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SAP ConfigServlet OS Command Execution|auxiliary/admin/sap/sap_configservlet_exec_noauth|-|-|✗|✓|✓
2|Schneider Modicon Remote START/STOP Command|auxiliary/admin/scada/modicon_command|-|-|✗|✓|-
3|Schneider Modicon Quantum Password Recovery|auxiliary/admin/scada/modicon_password_recovery|-|✓|✗|✓|-
4|Schneider Modicon Ladder Logic Upload/Download|auxiliary/admin/scada/modicon_stux_transfer|-|-|✗|✓|-
5|Allen-Bradley/Rockwell Automation EtherNet/IP CIP Commands|auxiliary/admin/scada/multi_cip_command|-|-|✗|✓|-
6|General Electric D20 Password Recovery|auxiliary/gather/d20pass|-|-|✓|✓|-
7|DarkComet Server Remote File Download Exploit|auxiliary/gather/darkcomet_filedownloader|-|-|✓|✓|-
8|Drupal OpenID External Entity Injection|auxiliary/gather/drupal_openid_xxe|-|-|✗|✓|✓
9|Network Shutdown Module sort_values Credential Dumper|auxiliary/gather/eaton_nsm_creds|-|-|✗|✓|-
10|XBMC Web Server Directory Traversal|auxiliary/gather/xbmc_traversal|-|✓|✗|✓|-
11|Bitweaver overlay_type Directory Traversal|auxiliary/scanner/http/bitweaver_overlay_type_traversal|-|-|✗|✓|✓
12|ClanSphere 2011.3 Local File Inclusion Vulnerability|auxiliary/scanner/http/clansphere_traversal|-|-|✗|✓|✓
13|ManageEngine DeviceExpert 5.6 ScheduleResultViewer FileName Traversal|auxiliary/scanner/http/manageengine_deviceexpert_traversal|-|-|✗|✓|-
14|ManageEngine SecurityManager Plus 5.5 Directory Traversal|auxiliary/scanner/http/manageengine_securitymanager_traversal|-|-|✗|✓|✓
15|NetDecision NOCVision Server Directory Traversal|auxiliary/scanner/http/netdecision_traversal|-|-|✗|✓|-
16|NFR Agent FSFUI Record Arbitrary Remote File Access|auxiliary/scanner/http/novell_file_reporter_fsfui_fileaccess|-|-|✗|✓|-
17|NFR Agent SRS Record Arbitrary Remote File Access|auxiliary/scanner/http/novell_file_reporter_srs_fileaccess|-|-|✗|✓|-
18|Outlook Web App (OWA) / Client Access Server (CAS) IIS HTTP Internal IP Disclosure|auxiliary/scanner/http/owa_iis_internal_ip|-|-|✗|✓|-
19|Sockso Music Host Server 1.5 Directory Traversal|auxiliary/scanner/http/sockso_traversal|-|-|✗|✓|-
20|WebPageTest Directory Traversal|auxiliary/scanner/http/webpagetest_traversal|-|-|✗|✓|✓
21|MySQL Authentication Bypass Password Dump|auxiliary/scanner/mysql/mysql_authbypass_hashdump|-|✓|✗|✓|-
22|Oracle TNS Listener Checker|auxiliary/scanner/oracle/tnspoison_checker|-|-|✗|✓|-
23|Koyo DirectLogic PLC Password Brute Force Utility|auxiliary/scanner/scada/koyo_login|-|-|✗|✓|-
24|Modbus Unit ID and Station ID Enumerator|auxiliary/scanner/scada/modbus_findunitid|-|-|✗|✓|-

#### 2013 (26)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP Intelligent Management SOM Account Creation|auxiliary/admin/hp/hp_imc_som_create_account|-|✓|✗|✓|-
2|D-Link DIR-600 / DIR-300 Unauthenticated Remote Command Execution|auxiliary/admin/http/dlink_dir_300_600_exec_noauth|-|-|✗|✓|-
3|Linksys E1500/E2500 Remote Command Execution|auxiliary/admin/http/linksys_e1500_e2500_exec|-|✓|✗|✓|-
4|Linksys WRT54GL Remote Command Execution|auxiliary/admin/http/linksys_wrt54gl_exec|-|✓|✗|✓|✓
5|Openbravo ERP XXE Arbitrary File Read|auxiliary/admin/http/openbravo_xxe|-|✓|✗|✓|✓
6|Sophos Web Protection Appliance patience.cgi Directory Traversal|auxiliary/admin/http/sophos_wpa_traversal|-|-|✗|✓|-
7|vBulletin Administrator Account Creation|auxiliary/admin/http/vbulletin_upgrade_admin|-|✓|✗|✓|✓
8|SerComm Device Configuration Dump|auxiliary/admin/misc/sercomm_dump_config|-|-|✗|✓|-
9|GE Proficy Cimplicity WebView substitute.bcl Directory Traversal|auxiliary/admin/scada/ge_proficy_substitute_traversal|-|-|✗|✓|✓
10|ColdFusion 'password.properties' Hash Extraction|auxiliary/gather/coldfusion_pwd_props|-|-|✗|✓|✓
11|HP ProCurve SNAC Domain Controller Credential Dumper|auxiliary/gather/hp_snac_domain_creds|-|-|✗|✓|-
12|Huawei Datacard Information Disclosure Vulnerability|auxiliary/gather/huawei_wifi_info|-|-|✓|✓|-
13|IBM Lotus Notes Sametime User Enumeration|auxiliary/gather/ibm_sametime_enumerate_users|-|-|✗|✓|✓
14|IBM Lotus Sametime Version Enumeration|auxiliary/gather/ibm_sametime_version|-|-|✗|✓|✓
15|vBulletin Password Collector via nodeid SQL Injection|auxiliary/gather/vbulletin_vote_sqli|-|-|✗|✓|✓
16|Canon Printer Wireless Configuration Disclosure|auxiliary/scanner/http/canon_wireless|-|-|✗|✓|-
17|D-Link User-Agent Backdoor Scanner|auxiliary/scanner/http/dlink_user_agent_backdoor|-|-|✗|✓|-
18|SevOne Network Performance Management Application Brute Force Login Utility|auxiliary/scanner/http/sevone_enum|-|-|✗|✓|-
19|Simple Web Server 2.3-RC1 Directory Traversal|auxiliary/scanner/http/simple_webserver_traversal|-|-|✗|✓|-
20|Supermicro Onboard IPMI CGI Vulnerability Scanner|auxiliary/scanner/http/smt_ipmi_cgi_scanner|-|-|✗|✓|-
21|Supermicro Onboard IPMI Static SSL Certificate Scanner|auxiliary/scanner/http/smt_ipmi_static_cert_scanner|-|-|✗|✓|-
22|Supermicro Onboard IPMI url_redirect.cgi Authenticated Directory Traversal|auxiliary/scanner/http/smt_ipmi_url_redirect_traversal|-|✓|✗|✓|-
23|IPMI 2.0 Cipher Zero Authentication Bypass Scanner|auxiliary/scanner/ipmi/ipmi_cipher_zero|-|-|✗|✓|-
24|IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval|auxiliary/scanner/ipmi/ipmi_dumphashes|-|-|✗|✓|-
25|Java JMX Server Insecure Endpoint Code Execution Scanner|auxiliary/scanner/misc/java_jmx_server|-|-|✗|✓|-
26|SerComm Network Device Backdoor Detection|auxiliary/scanner/misc/sercomm_backdoor_scanner|-|-|✗|✓|-

#### 2014 (31)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Allegro Software RomPager 'Misfortune Cookie' (CVE-2014-9222) Authentication Bypass|auxiliary/admin/http/allegro_rompager_auth_bypass|-|-|✗|✓|✓
2|Linksys WRT120N tmUnblock Stack Buffer Overflow|auxiliary/admin/http/linksys_tmunblock_admin_reset_bof|-|-|✗|✓|-
3|ManageEngine Desktop Central Administrator Account Creation|auxiliary/admin/http/manage_engine_dc_create_admin|-|✓|✗|✓|✓
4|ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection|auxiliary/admin/http/manageengine_pmp_privesc|-|✓|✗|✓|✓
5|ManageEngine NetFlow Analyzer Arbitrary File Download|auxiliary/admin/http/netflow_file_download|-|-|✗|✓|✓
6|WordPress custom-contact-forms Plugin SQL Upload|auxiliary/admin/http/wp_custom_contact_forms|-|-|✗|✓|✓
7|Advantech WebAccess DBVisitor.dll ChartThemeConfig SQL Injection|auxiliary/admin/scada/advantech_webaccess_dbvisitor_sqli|-|-|✗|✓|✓
8|Yokogawa BKBCopyD.exe Client|auxiliary/admin/scada/yokogawa_bkbcopyd_client|-|-|✗|✓|-
9|DoliWamp 'jqueryFileTree.php' Traversal Gather Credentials|auxiliary/gather/doliwamp_traversal_creds|-|-|✗|✓|✓
10|EMC CTA v10.0 Unauthenticated XXE Arbitrary File Read|auxiliary/gather/emc_cta_xxe|-|-|✗|✓|✓
11|ManageEngine Eventlog Analyzer Managed Hosts Administrator Credential Disclosure|auxiliary/gather/eventlog_cred_disclosure|-|-|✗|✓|✓
12|Joomla weblinks-categories Unauthenticated SQL Injection Arbitrary File Read|auxiliary/gather/joomla_weblinks_sqli|-|-|✗|✓|✓
13|MantisBT Admin SQL Injection Arbitrary File Read|auxiliary/gather/mantisbt_admin_sqli|-|✓|✗|✓|✓
14|MongoDB NoSQL Collection Enumeration Via Injection|auxiliary/gather/mongodb_js_inject_collection_enum|-|-|✗|✓|✓
15|MyBB Database Fingerprint|auxiliary/gather/mybb_db_fingerprint|-|-|✗|✓|✓
16|BMC / Numara Track-It! Domain Administrator and SQL Server User Password Disclosure|auxiliary/gather/trackit_sql_domain_creds|-|-|✗|✓|-
17|Cisco DLSw Information Disclosure Scanner|auxiliary/scanner/dlsw/dlsw_leak_capture|-|-|✗|✓|-
18|A10 Networks AX Loadbalancer Directory Traversal|auxiliary/scanner/http/a10networks_ax_directory_traversal|-|-|✗|✓|✓
19|Allegro Software RomPager 'Misfortune Cookie' (CVE-2014-9222) Scanner|auxiliary/scanner/http/allegro_rompager_misfortune_cookie|-|-|✗|✓|✓
20|BMC TrackIt! Unauthenticated Arbitrary User Password Change|auxiliary/scanner/http/bmc_trackit_passwd_reset|-|✓|✗|✓|✓
21|Cisco ASA SSL VPN Privilege Escalation Vulnerability|auxiliary/scanner/http/cisco_ssl_vpn_priv_esc|-|✓|✗|✓|-
22|GitLab User Enumeration|auxiliary/scanner/http/gitlab_user_enum|-|-|✗|✓|✓
23|ManageEngine DeviceExpert User Credentials|auxiliary/scanner/http/manageengine_deviceexpert_user_creds|-|-|✗|✓|-
24|Oracle Demantra Database Credentials Leak|auxiliary/scanner/http/oracle_demantra_database_credentials_leak|-|-|✗|✓|-
25|Oracle Demantra Arbitrary File Retrieval with Authentication Bypass|auxiliary/scanner/http/oracle_demantra_file_retrieval|-|-|✗|✓|-
26|Supermicro Onboard IPMI Port 49152 Sensitive File Exposure|auxiliary/scanner/http/smt_ipmi_49152_exposure|-|-|✗|✓|-
27|HTTP SSL/TLS Version Detection (POODLE scanner)|auxiliary/scanner/http/ssl_version|-|-|✗|✓|-
28|ManageEngine Support Center Plus Directory Traversal|auxiliary/scanner/http/support_center_plus_directory_traversal|-|✓|✗|✓|✓
29|WildFly Directory Traversal|auxiliary/scanner/http/wildfly_traversal|-|-|✗|✓|-
30|OpenSSL Server-Side ChangeCipherSpec Injection Scanner|auxiliary/scanner/ssl/openssl_ccs|-|-|✗|✓|-
31|OpenSSL Heartbeat (Heartbleed) Information Leak|auxiliary/scanner/ssl/openssl_heartbleed|-|-|✗|✓|-

#### 2015 (30)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Kaseya VSA Master Administrator Account Creation|auxiliary/admin/http/kaseya_master_admin|-|✓|✗|✓|✓
2|Limesurvey Unauthenticated File Download|auxiliary/admin/http/limesurvey_file_download|-|-|✗|✓|✓
3|ManageEngine Multiple Products Arbitrary Directory Listing|auxiliary/admin/http/manageengine_dir_listing|-|-|✗|✓|✓
4|ManageEngine Multiple Products Arbitrary File Download|auxiliary/admin/http/manageengine_file_download|-|-|✗|✓|✓
5|Netgear Unauthenticated SOAP Password Extractor|auxiliary/admin/http/netgear_soap_password_extractor|-|-|✗|✓|-
6|SysAid Help Desk Administrator Account Creation|auxiliary/admin/http/sysaid_admin_acct|-|✓|✗|✓|✓
7|SysAid Help Desk Arbitrary File Download|auxiliary/admin/http/sysaid_file_download|-|-|✗|✓|✓
8|SysAid Help Desk Database Credentials Disclosure|auxiliary/admin/http/sysaid_sql_creds|-|-|✗|✓|✓
9|WordPress Symposium Plugin SQL Injection|auxiliary/admin/http/wp_symposium_sql_injection|-|-|✗|✓|✓
10|Moxa Device Credential Retrieval|auxiliary/admin/scada/moxa_credentials_recovery|-|-|✗|✓|-
11|PhoenixContact PLC Remote START/STOP Command|auxiliary/admin/scada/phoenix_command|-|-|✗|✗|-
12|Joomla Real Estate Manager Component Error-Based SQL Injection|auxiliary/gather/joomla_com_realestatemanager_sqli|-|-|✗|✓|✓
13|Joomla com_contenthistory Error-Based SQL Injection|auxiliary/gather/joomla_contenthistory_sqli|-|-|✗|✓|✓
14|McAfee ePolicy Orchestrator Authenticated XXE Credentials Exposure|auxiliary/gather/mcafee_epo_xxe|-|✓|✗|✓|✓
15|OpenNMS Authenticated XXE|auxiliary/gather/opennms_xxe|-|✓|✗|✓|✓
16|Solarwinds Orion AccountManagement.asmx GetAccounts Admin Creation|auxiliary/gather/solarwinds_orion_sqli|-|✓|✗|✓|✓
17|WordPress All-in-One Migration Export|auxiliary/gather/wp_all_in_one_migration_export|-|-|✗|✓|✓
18|WordPress Ultimate CSV Importer User Table Extract|auxiliary/gather/wp_ultimate_csv_importer_user_extract|-|-|✗|✓|✓
19|BisonWare BisonFTP Server 3.5 Directory Traversal Information Disclosure|auxiliary/scanner/ftp/bison_ftp_traversal|-|-|✗|✓|-
20|Konica Minolta FTP Utility 1.00 Directory Traversal Information Disclosure|auxiliary/scanner/ftp/konica_ftp_traversal|-|-|✗|✓|-
21|PCMan FTP Server 2.0.7 Directory Traversal Information Disclosure|auxiliary/scanner/ftp/pcman_ftp_traversal|-|-|✗|✓|-
22|Accellion FTA 'statecode' Cookie Arbitrary File Read|auxiliary/scanner/http/accellion_fta_statecode_file_read|-|-|✗|✓|✓
23|Path Traversal in Oracle GlassFish Server Open Source Edition|auxiliary/scanner/http/glassfish_traversal|-|-|✗|✓|-
24|Web-Dorado ECommerce WD for Joomla! search_category_id SQL Injection Scanner|auxiliary/scanner/http/joomla_ecommercewd_sqli_scanner|-|-|✗|✓|✓
25|Gallery WD for Joomla! Unauthenticated SQL Injection Scanner|auxiliary/scanner/http/joomla_gallerywd_sqli_scanner|-|-|✗|✓|✓
26|ManageEngine ServiceDesk Plus Path Traversal|auxiliary/scanner/http/servicedesk_plus_traversal|-|-|✗|✓|✓
27|WordPress CP Multi-View Calendar Unauthenticated SQL Injection Scanner|auxiliary/scanner/http/wordpress_cp_calendar_sqli|-|-|✗|✓|✓
28|WordPress Contus Video Gallery Unauthenticated SQL Injection Scanner|auxiliary/scanner/http/wp_contus_video_gallery_sqli|-|-|✗|✓|✓
29|Redis File Upload|auxiliary/scanner/redis/file_upload|-|-|✗|✓|-
30|Juniper SSH Backdoor Scanner|auxiliary/scanner/ssh/juniper_backdoor|-|-|✗|✓|-

#### 2016 (17)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Joomla Account Creation and Privilege Escalation|auxiliary/admin/http/joomla_registration_privesc|-|✓|✗|✓|✓
2|NETGEAR ProSafe Network Management System 300 Authenticated File Download|auxiliary/admin/http/netgear_auth_download|-|✓|✗|✓|✓
3|NETGEAR WNR2000v5 Administrator Password Recovery|auxiliary/admin/http/netgear_wnr2000_pass_recovery|-|-|✗|✓|-
4|NUUO NVRmini 2 / NETGEAR ReadyNAS Surveillance Default Configuration Load and Administrator Password Reset|auxiliary/admin/http/nuuo_nvrmini_reset|-|-|✗|✓|✓
5|Telpho10 Backup Credentials Dumper|auxiliary/admin/http/telpho10_credential_dump|-|-|✗|✓|-
6|WebNMS Framework Server Credential Disclosure|auxiliary/admin/http/webnms_cred_disclosure|-|-|✗|✓|✓
7|WebNMS Framework Server Arbitrary Text File Download|auxiliary/admin/http/webnms_file_download|-|-|✗|✓|✓
8|C2S DVR Management Password Disclosure|auxiliary/gather/c2s_dvr_password_disclosure|-|-|✗|✓|-
9|Cerberus Helpdesk User Hash Disclosure|auxiliary/gather/cerberus_helpdesk_hash_disclosure|-|-|✗|✓|-
10|JVC/Siemens/Vanderbilt IP-Camera Readfile Password Disclosure|auxiliary/gather/ipcamera_password_disclosure|-|-|✗|✓|-
11|Zabbix toggle_ids SQL Injection|auxiliary/gather/zabbix_toggleids_sqli|-|-|✗|✓|✓
12|ColoradoFTP Server 1.3 Build 8 Directory Traversal Information Disclosure|auxiliary/scanner/ftp/colorado_ftp_traversal|-|✓|✗|✓|-
13|Cisco Firepower Management Console 6.0 Post Auth Report Download Directory Traversal|auxiliary/scanner/http/cisco_firepower_download|-|✓|✗|✓|✓
14|Cisco IKE Information Disclosure|auxiliary/scanner/ike/cisco_ike_benigncertain|-|-|✗|✓|-
15|ClamAV Remote Command Transmitter|auxiliary/scanner/misc/clamav_control|-|-|✗|✓|-
16|Apache Karaf Default Credentials Command Execution|auxiliary/scanner/ssh/apache_karaf_command_execution|-|✓|✗|✓|-
17|Fortinet SSH Backdoor Scanner|auxiliary/scanner/ssh/fortinet_backdoor|-|-|✗|✓|-

#### 2017 (17)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP iLO 4 1.00-2.50 Authentication Bypass Administrator Account Creation|auxiliary/admin/hp/hp_ilo_create_admin_account|-|✓|✗|✓|-
2|MantisBT password reset|auxiliary/admin/http/mantisbt_password_reset|-|-|✗|✓|✓
3|ScadaBR Credentials Dumper|auxiliary/admin/http/scadabr_credential_dump|-|✓|✗|✓|✓
4|TYPO3 News Module SQL Injection|auxiliary/admin/http/typo3_news_module_sqli|-|-|✗|✓|✓
5|MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution|auxiliary/admin/smb/ms17_010_command|-|-|✗|✓|-
6|Advantech WebAccess 8.1 Post Authentication Credential Collector|auxiliary/gather/advantech_webaccess_creds|-|✓|✗|✓|✓
7|QNAP NAS/NVR Administrator Hash Disclosure|auxiliary/gather/qnap_backtrace_admin_hash|-|-|✗|✓|-
8|Easy File Sharing FTP Server 3.6 Directory Traversal|auxiliary/scanner/ftp/easy_file_sharing_ftp|-|-|✗|✓|-
9|Apache Optionsbleed Scanner|auxiliary/scanner/http/apache_optionsbleed|-|-|✗|✓|✓
10|DnaLIMS Directory Traversal|auxiliary/scanner/http/dnalims_file_retrieve|-|-|✗|✓|✓
11|Intel AMT Digest Authentication Bypass Scanner|auxiliary/scanner/http/intel_amt_digest_bypass|-|-|✗|✓|-
12|Kodi 17.0 Local File Inclusion Vulnerability|auxiliary/scanner/http/kodi_traversal|-|-|✗|✓|✓
13|Riverbed SteelHead VCX File Read|auxiliary/scanner/http/riverbed_steelhead_vcx_file_read|-|✓|✗|✓|✓
14|SurgeNews User Credentials|auxiliary/scanner/http/surgenews_user_creds|-|-|✗|✓|-
15|WordPress REST API Content Injection|auxiliary/scanner/http/wordpress_content_injection|-|-|✗|✓|✓
16|Satel Iberia SenNet Data Logger and Electricity Meters Command Injection Vulnerability|auxiliary/scanner/telnet/satel_cmd_exec|-|-|✗|✓|-
17|Open WAN-to-LAN proxy on AT&T routers|auxiliary/scanner/wproxy/att_open_proxy|-|-|✗|✓|-

#### 2018 (17)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|GitStack Unauthenticated REST API Requests|auxiliary/admin/http/gitstack_rest|-|-|✗|✓|-
2|SAP Internet Graphics Server (IGS) XMLCHART XXE|auxiliary/admin/sap/sap_igs_xmlchart_xxe|-|-|✗|✓|-
3|Teradata ODBC SQL Query Module|auxiliary/admin/teradata/teradata_odbc_sql|-|✓|✗|✓|-
4|Dolibarr Gather Credentials via SQL Injection|auxiliary/gather/dolibarr_creds_sqli|-|✓|✗|✓|✓
5|Mikrotik Winbox Arbitrary File Read|auxiliary/gather/mikrotik_winbox_fileread|-|-|✗|✓|-
6|Nuuo Central Management Server User Session Token Bruteforce|auxiliary/gather/nuuo_cms_bruteforce|-|-|✗|✓|-
7|Nuuo Central Management Server Authenticated Arbitrary File Download|auxiliary/gather/nuuo_cms_file_download|-|-|✗|✓|-
8|Etcd Keys API Information Gathering|auxiliary/scanner/etcd/open_key_scanner|-|-|✗|✓|✓
9|Etcd Version Scanner|auxiliary/scanner/etcd/version|-|-|✗|✓|✓
10|Cisco ASA Directory Traversal|auxiliary/scanner/http/cisco_directory_traversal|-|-|✗|✓|✓
11|Dicoogle PACS Web Server Directory Traversal|auxiliary/scanner/http/dicoogle_traversal|-|-|✗|✓|-
12|HTTP SickRage Password Leak|auxiliary/scanner/http/http_sickrage_password_leak|-|-|✗|✓|✓
13|Vulnerable domain identification|auxiliary/scanner/msmail/host_id|-|-|✗|-|-
14|On premise user enumeration|auxiliary/scanner/msmail/onprem_enum|-|-|✗|-|-
15|Eaton Xpert Meter SSH Private Key Exposure Scanner|auxiliary/scanner/ssh/eaton_xpert_backdoor|-|-|✗|✓|-
16|libssh Authentication Bypass Scanner|auxiliary/scanner/ssh/libssh_auth_bypass|-|-|✗|✓|-
17|Teradata ODBC Login Scanner Module|auxiliary/scanner/teradata/teradata_odbc_login|-|-|✗|✓|-

#### 2019 (20)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Supra Smart Cloud TV Remote File Inclusion|auxiliary/admin/http/supra_smart_cloud_tv_rfi|-|-|✗|✓|-
2|WordPress Google Maps Plugin SQL Injection|auxiliary/admin/http/wp_google_maps_sqli|-|-|✗|✓|✓
3|Cisco Data Center Network Manager Unauthenticated File Download|auxiliary/admin/networking/cisco_dcnm_download|-|✓|✗|✓|✓
4|Chrome Debugger Arbitrary File Read / Arbitrary Web Request|auxiliary/gather/chrome_debugger|-|-|✗|✓|-
5|Cisco RV320/RV326 Configuration Disclosure|auxiliary/gather/cisco_rv320_config|-|-|✗|✓|✓
6|IBM BigFix Relay Server Sites and Package Enum|auxiliary/gather/ibm_bigfix_sites_packages_enum|-|-|✗|✓|✓
7|Pulse Secure VPN Arbitrary File Disclosure|auxiliary/gather/pulse_secure_file_disclosure|-|-|✗|✓|-
8|QNAP QTS and Photo Station Local File Inclusion|auxiliary/gather/qnap_lfi|-|-|✗|✓|✓
9|Citrix ADC (NetScaler) Directory Traversal Scanner|auxiliary/scanner/http/citrix_dir_traversal|-|-|✗|✓|✓
10|ES File Explorer Open Port|auxiliary/scanner/http/es_file_explorer_open_port|-|-|✗|✓|-
11|Onion Omega2 Login Brute-Force|auxiliary/scanner/http/onion_omega2_login|-|-|✗|✓|-
12|Spring Cloud Config Server Directory Traversal|auxiliary/scanner/http/springcloud_traversal|-|-|✗|✓|-
13|ThinVNC Directory Traversal|auxiliary/scanner/http/thinvnc_traversal|-|-|✗|✓|-
14|Total.js prior to 3.2.4 Directory Traversal|auxiliary/scanner/http/totaljs_traversal|-|-|✗|✓|✓
15|TVT NVMS-1000 Directory Traversal|auxiliary/scanner/http/tvt_nvms_traversal|-|-|✗|✓|✓
16|WordPress Email Subscribers and Newsletter Hash SQLi Scanner|auxiliary/scanner/http/wp_email_sub_news_sqli|-|-|✗|✓|✓
17|CVE-2019-0708 BlueKeep Microsoft Remote Desktop RCE Check|auxiliary/scanner/rdp/cve_2019_0708_bluekeep|-|-|✗|✓|-
18|URGENT/11 Scanner, Based on Detection Tool by Armis|auxiliary/scanner/vxworks/urgent11_check|-|-|✗|-|-
19|D-Link Central WiFiManager SQL injection|auxiliary/sqli/dlink/dlink_central_wifimanager_sqli|-|-|✗|✓|✓
20|OpenEMR 5.0.1 Patch 6 SQLi Dump|auxiliary/sqli/openemr/openemr_sqli_dump|-|-|✗|✓|✓

#### 2020 (15)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|IBM Data Risk Manager Arbitrary File Download|auxiliary/admin/http/ibm_drm_download|-|-|✗|✓|✓
2|Netgear R6700v3 Unauthenticated LAN Admin Password Reset|auxiliary/admin/http/netgear_r6700_pass_reset|-|-|✗|✓|-
3|LDAP Information Disclosure|auxiliary/gather/ldap_hashdump|-|-|✗|✓|-
4|SaltStack Salt Master Server Root Key Disclosure|auxiliary/gather/saltstack_salt_root_key|-|-|✗|✓|-
5|vBulletin /ajax/api/content_infraction/getIndexableContent nodeid Parameter SQL Injection|auxiliary/gather/vbulletin_getindexablecontent_sqli|-|-|✗|✓|✓
6|VMware vCenter Server vmdir Information Disclosure|auxiliary/gather/vmware_vcenter_vmdir_ldap|-|-|✗|✓|-
7|Apache ZooKeeper Information Disclosure|auxiliary/gather/zookeeper_info_disclosure|-|-|✗|✓|-
8|LimeSurvey Zip Path Traversals|auxiliary/scanner/http/limesurvey_zip_traversals|-|✓|✗|✓|✓
9|Directory Traversal in Spring Cloud Config Server|auxiliary/scanner/http/springcloud_directory_traversal|-|-|✗|✓|✓
10|WordPress ChopSlider3 id SQLi Scanner|auxiliary/scanner/http/wp_chopslider_id_sqli|-|-|✗|✓|✓
11|WordPress Duplicator File Read Vulnerability|auxiliary/scanner/http/wp_duplicator_file_read|-|-|✗|✓|✓
12|WordPress Easy WP SMTP Password Reset|auxiliary/scanner/http/wp_easy_wp_smtp|-|-|✗|✓|✓
13|WordPress Loginizer log SQLi Scanner|auxiliary/scanner/http/wp_loginizer_log_sqli|-|-|✗|✓|✓
14|WordPress Total Upkeep Unauthenticated Backup Downloader|auxiliary/scanner/http/wp_total_upkeep_downloader|-|-|✗|✓|✓
15|Zen Load Balancer Directory Traversal|auxiliary/scanner/http/zenload_balancer_traversal|-|✓|✗|✓|✓

#### 2021 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apache Flink JobManager Traversal|auxiliary/scanner/http/apache_flink_jobmanager_traversal|-|-|✗|✓|-

#### No Disclosure Date (511)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Veeder-Root Automatic Tank Gauge (ATG) Administrative Client|auxiliary/admin/atg/atg_client|-|-|✗|✓|-
2|Veritas Backup Exec Windows Remote File Access|auxiliary/admin/backupexec/dump|-|-|✗|✓|-
3|Veritas Backup Exec Server Registry Access|auxiliary/admin/backupexec/registry|-|-|✗|✓|-
4|Chromecast YouTube Remote Control|auxiliary/admin/chromecast/chromecast_youtube|-|-|✗|✓|-
5|Novell eDirectory DHOST Predictable Session Cookie|auxiliary/admin/edirectory/edirectory_dhost_cookie|-|-|✗|✓|-
6|Novell eDirectory eMBox Unauthenticated File Access|auxiliary/admin/edirectory/edirectory_edirutil|-|-|✗|✓|-
7|Amazon Fire TV YouTube Remote Control|auxiliary/admin/firetv/firetv_youtube|-|-|✗|✓|-
8|Cambium cnPilot r200/r201 Command Execution as 'root'|auxiliary/admin/http/cnpilot_r_cmd_exec|-|-|✗|✓|-
9|Cambium cnPilot r200/r201 File Path Traversal|auxiliary/admin/http/cnpilot_r_fpt|-|-|✗|✓|-
10|ContentKeeper Web Appliance mimencode File Access|auxiliary/admin/http/contentkeeper_fileaccess|-|-|✗|✓|-
11|D-Link DIR 645 Password Extractor|auxiliary/admin/http/dlink_dir_645_password_extractor|-|-|✗|✓|-
12|D-Link DSL 320B Password Extractor|auxiliary/admin/http/dlink_dsl320b_password_extractor|-|-|✗|✓|-
13|Iomega StorCenter Pro NAS Web Authentication Bypass|auxiliary/admin/http/iomega_storcenterpro_sessionid|-|-|✗|✓|-
14|JBoss JMX Console Beanshell Deployer WAR Upload and Deployment|auxiliary/admin/http/jboss_bshdeployer|-|-|✗|✓|✓
15|JBoss JMX Console DeploymentFileRepository WAR Upload and Deployment|auxiliary/admin/http/jboss_deploymentfilerepository|-|-|✗|✓|✓
16|Novell File Reporter Agent Arbitrary File Delete|auxiliary/admin/http/novell_file_reporter_filedelete|-|-|✗|✓|-
17|Tomcat Administration Tool Default Access|auxiliary/admin/http/tomcat_administration|-|-|✗|✓|-
18|TYPO3 sa-2010-020 Remote File Disclosure|auxiliary/admin/http/typo3_sa_2010_020|-|-|✗|✓|-
19|TYPO3 Winstaller Default Encryption Keys|auxiliary/admin/http/typo3_winstaller_default_enc_keys|-|-|✗|✓|-
20|Ulterius Server File Download Vulnerability|auxiliary/admin/http/ulterius_file_download|-|-|✗|✓|-
21|ZyXEL GS1510-16 Password Extractor|auxiliary/admin/http/zyxel_admin_password_extractor|-|-|✗|✓|-
22|Microsoft SQL Server Configuration Enumerator|auxiliary/admin/mssql/mssql_enum|-|-|✗|✓|-
23|Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration|auxiliary/admin/mssql/mssql_enum_domain_accounts|-|-|✗|✓|-
24|Microsoft SQL Server SQLi SUSER_SNAME Windows Domain Account Enumeration|auxiliary/admin/mssql/mssql_enum_domain_accounts_sqli|-|-|✗|✓|-
25|Microsoft SQL Server SUSER_SNAME SQL Logins Enumeration|auxiliary/admin/mssql/mssql_enum_sql_logins|-|-|✗|✓|-
26|Microsoft SQL Server Escalate Db_Owner|auxiliary/admin/mssql/mssql_escalate_dbowner|-|-|✗|✓|-
27|Microsoft SQL Server SQLi Escalate Db_Owner|auxiliary/admin/mssql/mssql_escalate_dbowner_sqli|-|-|✗|✓|-
28|Microsoft SQL Server Escalate EXECUTE AS|auxiliary/admin/mssql/mssql_escalate_execute_as|-|-|✗|✓|-
29|Microsoft SQL Server SQLi Escalate Execute AS|auxiliary/admin/mssql/mssql_escalate_execute_as_sqli|-|-|✗|✓|-
30|Microsoft SQL Server xp_cmdshell Command Execution|auxiliary/admin/mssql/mssql_exec|-|-|✗|✓|-
31|Microsoft SQL Server Find and Sample Data|auxiliary/admin/mssql/mssql_findandsampledata|-|-|✗|✓|-
32|Microsoft SQL Server Interesting Data Finder|auxiliary/admin/mssql/mssql_idf|-|-|✗|✓|-
33|Microsoft SQL Server NTLM Stealer|auxiliary/admin/mssql/mssql_ntlm_stealer|-|-|✗|✓|-
34|Microsoft SQL Server SQLi NTLM Stealer|auxiliary/admin/mssql/mssql_ntlm_stealer_sqli|-|-|✗|✓|-
35|Microsoft SQL Server Generic Query|auxiliary/admin/mssql/mssql_sql|-|-|✗|✓|-
36|MySQL Enumeration Module|auxiliary/admin/mysql/mysql_enum|-|-|✗|✓|-
37|MySQL SQL Generic Query|auxiliary/admin/mysql/mysql_sql|-|-|✗|✓|-
38|NAT-PMP Port Mapper|auxiliary/admin/natpmp/natpmp_map|-|-|✗|✓|-
39|NetBIOS Response Brute Force Spoof (Direct)|auxiliary/admin/netbios/netbios_spoof|-|-|✗|✓|-
40|Cisco ASA Authentication Bypass (EXTRABACON)|auxiliary/admin/networking/cisco_asa_extrabacon|-|-|✗|✓|-
41|TrendMicro OfficeScanNT Listener Traversal Arbitrary File Access|auxiliary/admin/officescan/tmlisten_traversal|-|-|✗|✓|-
42|PostgreSQL Server Generic Query|auxiliary/admin/postgres/postgres_readfile|-|✓|✗|✓|-
43|PostgreSQL Server Generic Query|auxiliary/admin/postgres/postgres_sql|-|✓|✗|✓|-
44|Unitronics PCOM remote START/STOP/RESET command|auxiliary/admin/scada/pcom_command|-|-|✗|✓|-
45|TrendMicro ServerProtect File Access|auxiliary/admin/serverprotect/file|-|-|✗|✓|-
46|SMB File Delete Utility|auxiliary/admin/smb/delete_file|-|-|✗|✓|-
47|SMB File Download Utility|auxiliary/admin/smb/download_file|-|-|✗|✓|-
48|SMB Directory Listing Utility|auxiliary/admin/smb/list_directory|-|-|✗|✓|-
49|PsExec NTDS.dit And SYSTEM Hive Download Utility|auxiliary/admin/smb/psexec_ntdsgrab|-|-|✗|✓|-
50|SMB File Upload Utility|auxiliary/admin/smb/upload_file|-|-|✗|✓|-
51|WebEx Remote Command Execution Utility|auxiliary/admin/smb/webexec_command|-|-|✗|✓|-
52|Apple Airport Extreme Password Extraction (WDBRPC)|auxiliary/admin/vxworks/apple_airport_extreme_password|-|-|✗|✓|-
53|D-Link i2eye Video Conference AutoAnswer (WDBRPC)|auxiliary/admin/vxworks/dlink_i2eye_autoanswer|-|-|✗|✓|-
54|VxWorks WDB Agent Remote Memory Dump|auxiliary/admin/vxworks/wdbrpc_memory_dump|-|-|✗|✓|-
55|VxWorks WDB Agent Remote Reboot|auxiliary/admin/vxworks/wdbrpc_reboot|-|-|✗|✓|-
56|Belkin Wemo-Enabled Crock-Pot Remote Control|auxiliary/admin/wemo/crockpot|-|-|✗|✓|-
57|BNAT Scanner|auxiliary/bnat/bnat_scan|-|-|✗|-|-
58|IEC104 Client Utility|auxiliary/client/iec104/iec104|-|-|✗|✓|-
59|Generic Emailer (SMTP)|auxiliary/client/smtp/emailer|-|-|✗|✓|-
60|Metasploit Web Crawler|auxiliary/crawler/msfcrawler|-|-|✗|✓|-
61|DNS and DNSSEC Fuzzer|auxiliary/fuzzers/dns/dns_fuzzer|-|-|✗|✓|-
62|Simple FTP Fuzzer|auxiliary/fuzzers/ftp/ftp_pre_post|-|-|✗|✓|-
63|HTTP Form Field Fuzzer|auxiliary/fuzzers/http/http_form_field|-|-|✗|✓|-
64|HTTP GET Request URI Fuzzer (Incrementing Lengths)|auxiliary/fuzzers/http/http_get_uri_long|-|-|✗|✓|-
65|HTTP GET Request URI Fuzzer (Fuzzer Strings)|auxiliary/fuzzers/http/http_get_uri_strings|-|-|✗|✓|-
66|NTP Protocol Fuzzer|auxiliary/fuzzers/ntp/ntp_protocol_fuzzer|-|-|✗|✓|-
67|SMB Negotiate SMB2 Dialect Corruption|auxiliary/fuzzers/smb/smb2_negotiate_corrupt|-|-|✗|✓|-
68|SMB Create Pipe Request Fuzzer|auxiliary/fuzzers/smb/smb_create_pipe|-|-|✗|✓|-
69|SMB Create Pipe Request Corruption|auxiliary/fuzzers/smb/smb_create_pipe_corrupt|-|-|✗|✓|-
70|SMB Negotiate Dialect Corruption|auxiliary/fuzzers/smb/smb_negotiate_corrupt|-|-|✗|✓|-
71|SMB NTLMv1 Login Request Corruption|auxiliary/fuzzers/smb/smb_ntlm1_login_corrupt|-|-|✗|✓|-
72|SMB Tree Connect Request Fuzzer|auxiliary/fuzzers/smb/smb_tree_connect|-|-|✗|✓|-
73|SMB Tree Connect Request Corruption|auxiliary/fuzzers/smb/smb_tree_connect_corrupt|-|-|✗|✓|-
74|SMTP Simple Fuzzer|auxiliary/fuzzers/smtp/smtp_fuzzer|-|-|✗|✓|-
75|SSH Key Exchange Init Corruption|auxiliary/fuzzers/ssh/ssh_kexinit_corrupt|-|-|✗|✓|-
76|SSH 1.5 Version Fuzzer|auxiliary/fuzzers/ssh/ssh_version_15|-|-|✗|✓|-
77|SSH 2.0 Version Fuzzer|auxiliary/fuzzers/ssh/ssh_version_2|-|-|✗|✓|-
78|SSH Version Corruption|auxiliary/fuzzers/ssh/ssh_version_corrupt|-|-|✗|✓|-
79|TDS Protocol Login Request Corruption Fuzzer|auxiliary/fuzzers/tds/tds_login_corrupt|-|-|✗|✓|-
80|TDS Protocol Login Request Username Fuzzer|auxiliary/fuzzers/tds/tds_login_username|-|-|✗|✓|-
81|Apache Rave User Information Disclosure|auxiliary/gather/apache_rave_creds|-|-|✗|✓|✓
82|Asterisk Gather Credentials|auxiliary/gather/asterisk_creds|-|✓|✗|✓|-
83|AVTECH 744 DVR Account Information Retrieval|auxiliary/gather/avtech744_dvr_accounts|-|-|✗|✓|-
84|Citrix MetaFrame ICA Published Applications Scanner|auxiliary/gather/citrix_published_applications|-|-|✗|✓|-
85|Citrix MetaFrame ICA Published Applications Bruteforcer|auxiliary/gather/citrix_published_bruteforce|-|-|✗|✓|-
86|Discover External IP via Ifconfig.me|auxiliary/gather/external_ip|-|-|✓|✓|-
87|F5 BigIP Backend Cookie Disclosure|auxiliary/gather/f5_bigip_cookie_disclosure|-|-|✗|✓|✓
88|FortiOS Path Traversal Credential Gatherer|auxiliary/gather/fortios_vpnssl_traversal_creds_leak|-|-|✗|✓|✓
89|HP Operations Manager Perfd Environment Scanner|auxiliary/gather/hp_enum_perfd|-|-|✗|✓|-
90|HTTP SSL Certificate Impersonation|auxiliary/gather/impersonate_ssl|-|-|✗|✓|-
91|Java RMI Registry Interfaces Enumeration|auxiliary/gather/java_rmi_registry|-|-|✗|✓|-
92|Jenkins Domain Credential Recovery|auxiliary/gather/jenkins_cred_recovery|-|-|✗|✓|✓
93|Konica Minolta Password Extractor|auxiliary/gather/konica_minolta_pwd_extract|-|✓|✗|✓|-
94|Lansweeper Credential Collector|auxiliary/gather/lansweeper_collector|-|-|✗|✓|-
95|Memcached Extractor|auxiliary/gather/memcached_extractor|-|-|✗|✓|-
96|NAT-PMP External Address Scanner|auxiliary/gather/natpmp_external_address|-|-|✗|✓|-
97|NETGEAR Administrator Password Disclosure|auxiliary/gather/netgear_password_disclosure|-|-|✗|✓|✓
98|Peplink Balance routers SQLi|auxiliary/gather/peplink_bauth_sqli|-|-|✗|✓|✓
99|Ruby On Rails File Content Disclosure ('doubletap')|auxiliary/gather/rails_doubletap_file_read|-|-|✗|✓|-
100|TeamTalk Gather Credentials|auxiliary/gather/teamtalk_creds|-|✓|✗|✓|-
101|Microsoft Windows Deployment Services Unattend Gatherer|auxiliary/gather/windows_deployment_services_shares|-|-|✗|✓|-
102|Windows Secrets Dump|auxiliary/gather/windows_secrets_dump|-|-|✗|✓|-
103|WordPress W3-Total-Cache Plugin 0.9.2.4 (or before) Username and Hash Extract|auxiliary/gather/wp_w3_total_cache_hash_extract|-|-|✗|✓|✓
104|Xerox Administrator Console Password Extractor|auxiliary/gather/xerox_pwd_extract|-|-|✗|✓|-
105|Xymon Daemon Gather Information|auxiliary/gather/xymon_info|-|-|✗|✓|-
106|Apple Airport ACPP Authentication Scanner|auxiliary/scanner/acpp/login|-|-|✗|✓|-
107|Apple Filing Protocol Login Utility|auxiliary/scanner/afp/afp_login|-|-|✗|✓|-
108|Apple Filing Protocol Info Enumerator|auxiliary/scanner/afp/afp_server_info|-|-|✗|✓|-
109|Energizer DUO Trojan Scanner|auxiliary/scanner/backdoor/energizer_duo_detect|-|-|✗|✓|-
110|CouchDB Enum Utility|auxiliary/scanner/couchdb/couchdb_enum|-|✓|✗|✓|✓
111|CouchDB Login Utility|auxiliary/scanner/couchdb/couchdb_login|-|-|✗|✓|-
112|DB2 Authentication Brute Force Utility|auxiliary/scanner/db2/db2_auth|-|-|✗|✓|-
113|DB2 Probe Utility|auxiliary/scanner/db2/db2_version|-|-|✗|✓|-
114|DB2 Discovery Service Detection|auxiliary/scanner/db2/discovery|-|-|✗|✓|-
115|Endpoint Mapper Service Discovery|auxiliary/scanner/dcerpc/endpoint_mapper|-|-|✗|✓|-
116|Remote Management Interface Discovery|auxiliary/scanner/dcerpc/management|-|-|✗|✓|-
117|DCERPC TCP Service Auditor|auxiliary/scanner/dcerpc/tcp_dcerpc_auditor|-|-|✗|✓|-
118|Microsoft Windows Deployment Services Unattend Retrieval|auxiliary/scanner/dcerpc/windows_deployment_services|-|-|✗|✓|-
119|ARP Sweep Local Network Discovery|auxiliary/scanner/discovery/arp_sweep|-|-|✗|-|-
120|IPv6 Link Local/Node Local Ping Discovery|auxiliary/scanner/discovery/ipv6_multicast_ping|-|-|✗|-|-
121|IPv6 Local Neighbor Discovery|auxiliary/scanner/discovery/ipv6_neighbor|-|-|✗|-|-
122|IPv6 Local Neighbor Discovery Using Router Advertisement|auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement|-|-|✗|-|-
123|UDP Service Prober|auxiliary/scanner/discovery/udp_probe|-|-|✗|-|-
124|UDP Service Sweeper|auxiliary/scanner/discovery/udp_sweep|-|-|✗|-|-
125|ElasticSearch Indices Enumeration Utility|auxiliary/scanner/elasticsearch/indices_enum|-|-|✗|✓|-
126|EMC AlphaStor Device Manager Service|auxiliary/scanner/emc/alphastor_devicemanager|-|-|✗|✓|-
127|EMC AlphaStor Library Manager Service|auxiliary/scanner/emc/alphastor_librarymanager|-|-|✗|✓|-
128|Finger Service User Enumerator|auxiliary/scanner/finger/finger_users|-|-|✗|✓|-
129|Anonymous FTP Access Detection|auxiliary/scanner/ftp/anonymous|-|-|✗|✓|-
130|FTP Authentication Scanner|auxiliary/scanner/ftp/ftp_login|-|-|✗|✓|-
131|FTP Version Scanner|auxiliary/scanner/ftp/ftp_version|-|-|✗|✓|-
132|Gopher gophermap Scanner|auxiliary/scanner/gopher/gopher_gophermap|-|-|✗|✓|-
133|GTP Echo Scanner|auxiliary/scanner/gprs/gtp_echo|-|-|✗|✓|-
134|H.323 Version Scanner|auxiliary/scanner/h323/h323_version|-|-|✗|✓|-
135|Adobe XML External Entity Injection|auxiliary/scanner/http/adobe_xml_inject|-|-|✗|✓|-
136|Advantech WebAccess Login|auxiliary/scanner/http/advantech_webaccess_login|-|-|✗|✓|✓
137|Apache ActiveMQ JSP Files Source Disclosure|auxiliary/scanner/http/apache_activemq_source_disclosure|-|-|✗|✓|✓
138|Apache ActiveMQ Directory Traversal|auxiliary/scanner/http/apache_activemq_traversal|-|-|✗|✓|-
139|Apache "mod_userdir" User Enumeration|auxiliary/scanner/http/apache_userdir_enum|-|-|✗|✓|✓
140|AppleTV AirPlay Login Utility|auxiliary/scanner/http/appletv_login|-|-|✗|✓|-
141|Atlassian Crowd XML Entity Expansion Remote File Access|auxiliary/scanner/http/atlassian_crowd_fileaccess|-|-|✗|✓|✓
142|Apache Axis2 v1.4.1 Local File Inclusion|auxiliary/scanner/http/axis_local_file_include|-|-|✗|✓|-
143|Apache Axis2 Brute Force Utility|auxiliary/scanner/http/axis_login|-|-|✗|✓|-
144|HTTP Backup File Scanner|auxiliary/scanner/http/backup_file|-|-|✗|✓|-
145|BAVision IP Camera Web Server Login|auxiliary/scanner/http/bavision_cam_login|-|-|✗|✓|-
146|Binom3 Web Management Login Scanner, Config and Password File Dump|auxiliary/scanner/http/binom3_login_config_pass_dump|-|-|✗|✓|-
147|HTTP Blind SQL Injection Scanner|auxiliary/scanner/http/blind_sql_query|-|-|✗|✓|-
148|HTTP Directory Brute Force Scanner|auxiliary/scanner/http/brute_dirs|-|-|✗|✓|-
149|Buffalo NAS Login Utility|auxiliary/scanner/http/buffalo_login|-|-|✗|✓|-
150|Inedo BuildMaster Login Scanner|auxiliary/scanner/http/buildmaster_login|-|-|✗|✓|-
151|Chinese Caidao Backdoor Bruteforce|auxiliary/scanner/http/caidao_bruteforce_login|-|-|✗|✓|✓
152|HTTP SSL Certificate Checker|auxiliary/scanner/http/cert|-|-|✗|✓|-
153|Chef Web UI Brute Force Utility|auxiliary/scanner/http/chef_webui_login|-|-|✗|✓|✓
154|Chromecast Web Server Scanner|auxiliary/scanner/http/chromecast_webserver|-|-|✗|✓|-
155|Chromecast Wifi Enumeration|auxiliary/scanner/http/chromecast_wifi|-|-|✗|✓|-
156|Cisco ASA ASDM Bruteforce Login Utility|auxiliary/scanner/http/cisco_asa_asdm|-|✓|✗|✓|-
157|Cisco Firepower Management Console 6.0 Login|auxiliary/scanner/http/cisco_firepower_login|-|-|✗|✓|✓
158|Cisco Ironport Bruteforce Login Utility|auxiliary/scanner/http/cisco_ironport_enum|-|✓|✗|✓|-
159|Cisco Network Access Manager Directory Traversal Vulnerability|auxiliary/scanner/http/cisco_nac_manager_traversal|-|-|✗|✓|-
160|Cisco SSL VPN Bruteforce Login Utility|auxiliary/scanner/http/cisco_ssl_vpn|-|-|✗|✓|-
161|Cambium cnPilot r200/r201 Login Scanner and Config Dump|auxiliary/scanner/http/cnpilot_r_web_login_loot|-|-|✗|✓|-
162|ColdFusion Server Check|auxiliary/scanner/http/coldfusion_locale_traversal|-|-|✗|✓|-
163|ColdFusion Version Scanner|auxiliary/scanner/http/coldfusion_version|-|-|✗|✓|-
164|Concrete5 Member List Enumeration|auxiliary/scanner/http/concrete5_member_list|-|-|✗|✓|-
165|HTTP Copy File Scanner|auxiliary/scanner/http/copy_of_file|-|-|✗|✓|-
166|Web Site Crawler|auxiliary/scanner/http/crawler|-|-|✗|✓|-
167|Dell iDRAC Default Login|auxiliary/scanner/http/dell_idrac|-|-|✗|✓|✓
168|HTTP Directory Listing Scanner|auxiliary/scanner/http/dir_listing|-|-|✗|✓|-
169|HTTP Directory Scanner|auxiliary/scanner/http/dir_scanner|-|-|✗|✓|-
170|MS09-020 IIS6 WebDAV Unicode Auth Bypass Directory Scanner|auxiliary/scanner/http/dir_webdav_unicode_bypass|-|-|✗|✓|-
171|DirectAdmin Web Control Panel Login Utility|auxiliary/scanner/http/directadmin_login|-|-|✗|✓|-
172|D-Link DIR-300A / DIR-320 / DIR-615D HTTP Login Utility|auxiliary/scanner/http/dlink_dir_300_615_http_login|-|-|✗|✓|-
173|D-Link DIR-615H HTTP Login Utility|auxiliary/scanner/http/dlink_dir_615h_http_login|-|-|✗|✓|-
174|D-Link DIR-300B / DIR-600B / DIR-815 / DIR-645 HTTP Login Utility|auxiliary/scanner/http/dlink_dir_session_cgi_http_login|-|-|✗|✓|-
175|Docker Server Version Scanner|auxiliary/scanner/http/docker_version|-|-|✗|✓|-
176|Dolibarr ERP/CRM Login Utility|auxiliary/scanner/http/dolibarr_login|-|-|✗|✓|✓
177|Ektron CMS400.NET Default Password Scanner|auxiliary/scanner/http/ektron_cms400net|-|-|✗|✓|-
178|ElasticSearch Snapshot API Directory Traversal|auxiliary/scanner/http/elasticsearch_traversal|-|-|✗|✓|-
179|Cambium ePMP 1000 Dump Device Config|auxiliary/scanner/http/epmp1000_dump_config|-|✓|✗|✓|-
180|Cambium ePMP 1000 'ping' Password Hash Extractor (up to v2.5)|auxiliary/scanner/http/epmp1000_dump_hashes|-|✓|✗|✓|-
181|Cambium ePMP 1000 'get_chart' Command Injection (v3.1-3.5-RC7)|auxiliary/scanner/http/epmp1000_get_chart_cmd_exec|-|✓|✗|✓|-
182|Cambium ePMP 1000 'ping' Command Injection (up to v2.5)|auxiliary/scanner/http/epmp1000_ping_cmd_exec|-|✓|✗|✓|-
183|Cambium ePMP 1000 Account Password Reset|auxiliary/scanner/http/epmp1000_reset_pass|-|✓|✗|✓|-
184|Cambium ePMP 1000 Login Scanner|auxiliary/scanner/http/epmp1000_web_login|-|-|✗|✓|-
185|HTTP Error Based SQL Injection Scanner|auxiliary/scanner/http/error_sql_injection|-|-|✗|✓|-
186|EtherPAD Duo Login Bruteforce Utility|auxiliary/scanner/http/etherpad_duo_login|-|-|✗|✓|-
187|F5 BigIP HTTP Virtual Server Scanner|auxiliary/scanner/http/f5_bigip_virtual_server|-|-|✗|-|-
188|F5 Networks Devices Management Interface Scanner|auxiliary/scanner/http/f5_mgmt_scanner|-|-|✗|✓|-
189|HTTP File Same Name Directory Scanner|auxiliary/scanner/http/file_same_name_dir|-|-|✗|✓|-
190|HTTP Interesting File Scanner|auxiliary/scanner/http/files_dir|-|-|✗|✓|-
191|FortiMail Unauthenticated Login Bypass Scanner|auxiliary/scanner/http/fortimail_login_bypass_detection|-|-|✗|✓|✓
192|Fortinet SSL VPN Bruteforce Login Utility|auxiliary/scanner/http/fortinet_ssl_vpn|-|-|✗|✓|-
193|FrontPage .pwd File Credential Dump|auxiliary/scanner/http/frontpage_credential_dump|-|-|✗|✓|✓
194|Carlo Gavazzi Energy Meters - Login Brute Force, Extract Info and Dump Plant Database|auxiliary/scanner/http/gavazzi_em_login_loot|-|✓|✗|✓|-
195|HTTP Git Scanner|auxiliary/scanner/http/git_scanner|-|-|✗|✓|✓
196|GitLab Login Utility|auxiliary/scanner/http/gitlab_login|-|✓|✗|✓|✓
197|GlassFish Brute Force Utility|auxiliary/scanner/http/glassfish_login|-|✓|✗|✓|-
198|Embedthis GoAhead Embedded Web Server Directory Traversal|auxiliary/scanner/http/goahead_traversal|-|-|✗|✓|-
199|Novell Groupwise Agents HTTP Directory Traversal|auxiliary/scanner/http/groupwise_agents_http_traversal|-|-|✗|✓|-
200|HTTP Host Header Injection Detection|auxiliary/scanner/http/host_header_injection|-|-|✗|✓|-
201|HP Intelligent Management BIMS DownloadServlet Directory Traversal|auxiliary/scanner/http/hp_imc_bims_downloadservlet_traversal|-|-|✗|✓|✓
202|HP Intelligent Management FaultDownloadServlet Directory Traversal|auxiliary/scanner/http/hp_imc_faultdownloadservlet_traversal|-|-|✗|✓|✓
203|HP Intelligent Management IctDownloadServlet Directory Traversal|auxiliary/scanner/http/hp_imc_ictdownloadservlet_traversal|-|-|✗|✓|✓
204|HP Intelligent Management ReportImgServlt Directory Traversal|auxiliary/scanner/http/hp_imc_reportimgservlt_traversal|-|-|✗|✓|✓
205|HP Intelligent Management SOM FileDownloadServlet Arbitrary Download|auxiliary/scanner/http/hp_imc_som_file_download|-|-|✗|✓|✓
206|HP SiteScope SOAP Call getFileInternal Remote File Access|auxiliary/scanner/http/hp_sitescope_getfileinternal_fileaccess|-|-|✗|✓|✓
207|HP SiteScope SOAP Call getSiteScopeConfiguration Configuration Access|auxiliary/scanner/http/hp_sitescope_getsitescopeconfiguration|-|-|✗|✓|✓
208|HP SiteScope SOAP Call loadFileContent Remote File Access|auxiliary/scanner/http/hp_sitescope_loadfilecontent_fileaccess|-|-|✗|✓|✓
209|HP System Management Homepage Login Utility|auxiliary/scanner/http/hp_sys_mgmt_login|-|-|✗|✓|-
210|HTTP Header Detection|auxiliary/scanner/http/http_header|-|-|✗|✓|✓
211|HTTP Strict Transport Security (HSTS) Detection|auxiliary/scanner/http/http_hsts|-|-|✗|✓|-
212|HTTP Login Utility|auxiliary/scanner/http/http_login|-|-|✗|✓|-
213|HTTP Writable Path PUT/DELETE File Access|auxiliary/scanner/http/http_put|-|-|✗|✓|-
214|Generic HTTP Directory Traversal Utility|auxiliary/scanner/http/http_traversal|-|-|✗|✓|-
215|HTTP Version Detection|auxiliary/scanner/http/http_version|-|-|✗|✓|-
216|Httpdasm Directory Traversal|auxiliary/scanner/http/httpdasm_directory_traversal|-|-|✗|✓|✓
217|Microsoft IIS HTTP Internal IP Disclosure|auxiliary/scanner/http/iis_internal_ip|-|-|✗|✓|-
218|Microsoft IIS shortname vulnerability scanner|auxiliary/scanner/http/iis_shortname_scanner|-|-|✗|✓|-
219|InfluxDB Enum Utility|auxiliary/scanner/http/influxdb_enum|-|✓|✗|✓|✓
220|InfoVista VistaPortal Application Bruteforce Login Utility|auxiliary/scanner/http/infovista_enum|-|-|✗|✓|✓
221|IP Board Login Auxiliary Module|auxiliary/scanner/http/ipboard_login|-|-|✗|✓|✓
222|JBoss Status Servlet Information Gathering|auxiliary/scanner/http/jboss_status|-|-|✗|✓|✓
223|JBoss Vulnerability Scanner|auxiliary/scanner/http/jboss_vulnscan|-|-|✗|✓|-
224|Jenkins-CI Unauthenticated Script-Console Scanner|auxiliary/scanner/http/jenkins_command|-|-|✗|✓|✓
225|Jenkins-CI Enumeration|auxiliary/scanner/http/jenkins_enum|-|-|✗|✓|✓
226|Jenkins-CI Login Utility|auxiliary/scanner/http/jenkins_login|-|-|✗|✓|-
227|Joomla Bruteforce Login Utility|auxiliary/scanner/http/joomla_bruteforce_login|-|-|✗|✓|-
228|Joomla Page Scanner|auxiliary/scanner/http/joomla_pages|-|-|✗|✓|✓
229|Joomla Plugins Scanner|auxiliary/scanner/http/joomla_plugins|-|-|✗|✓|✓
230|Joomla Version Scanner|auxiliary/scanner/http/joomla_version|-|-|✗|✓|✓
231|Jupyter Login Utility|auxiliary/scanner/http/jupyter_login|-|-|✗|✓|✓
232|Linknat Vos Manager Traversal|auxiliary/scanner/http/linknat_vos_traversal|-|-|✗|✓|✓
233|Linksys E1500 Directory Traversal Vulnerability|auxiliary/scanner/http/linksys_e1500_traversal|-|✓|✗|✓|-
234|HTTP Microsoft SQL Injection Table XSS Infection|auxiliary/scanner/http/lucky_punch|-|-|✗|✓|-
235|ManageEngine Desktop Central Login Utility|auxiliary/scanner/http/manageengine_desktop_central_login|-|-|✗|✓|-
236|MediaWiki SVG XML Entity Expansion Remote File Access|auxiliary/scanner/http/mediawiki_svg_fileaccess|-|-|✗|✓|✓
237|Meteocontrol WEBlog Password Extractor|auxiliary/scanner/http/meteocontrol_weblog_extractadmin|-|-|✗|✓|-
238|Apache HTTPD mod_negotiation Filename Bruter|auxiliary/scanner/http/mod_negotiation_brute|-|-|✗|✓|-
239|Apache HTTPD mod_negotiation Scanner|auxiliary/scanner/http/mod_negotiation_scanner|-|-|✗|✓|-
240|MS09-020 IIS6 WebDAV Unicode Authentication Bypass|auxiliary/scanner/http/ms09_020_webdav_unicode_bypass|-|-|✗|✓|-
241|MS15-034 HTTP Protocol Stack Request Handling HTTP.SYS Memory Information Disclosure|auxiliary/scanner/http/ms15_034_http_sys_memory_dump|-|-|✗|✓|-
242|Western Digital MyBook Live Login Utility|auxiliary/scanner/http/mybook_live_login|-|-|✗|✓|-
243|Netgear SPH200D Directory Traversal Vulnerability|auxiliary/scanner/http/netgear_sph200d_traversal|-|✓|✗|✓|-
244|Novell Zenworks Mobile Device Managment Admin Credentials|auxiliary/scanner/http/novell_mdm_creds|-|-|✗|✓|✓
245|Host Information Enumeration via NTLM Authentication|auxiliary/scanner/http/ntlm_info_enumeration|-|-|✗|✓|-
246|Octopus Deploy Login Utility|auxiliary/scanner/http/octopusdeploy_login|-|-|✗|✓|✓
247|HTTP Open Proxy Detection|auxiliary/scanner/http/open_proxy|-|-|✗|✓|-
248|OpenMind Message-OS Portal Login Brute Force Utility|auxiliary/scanner/http/openmind_messageos_login|-|✓|✗|✓|✓
249|HTTP Options Detection|auxiliary/scanner/http/options|-|-|✗|✓|-
250|Oracle ILO Manager Login Brute Force Utility|auxiliary/scanner/http/oracle_ilom_login|-|-|✗|✓|-
251|OWA Exchange Web Services (EWS) Login Scanner|auxiliary/scanner/http/owa_ews_login|-|-|✗|✓|-
252|PhpMyAdmin Login Scanner|auxiliary/scanner/http/phpmyadmin_login|-|✓|✗|✓|✓
253|PocketPAD Login Bruteforce Force Utility|auxiliary/scanner/http/pocketpad_login|-|-|✗|✓|-
254|HTTP Previous Directory File Scanner|auxiliary/scanner/http/prev_dir_same_name_file|-|-|✗|✓|-
255|Radware AppDirector Bruteforce Login Utility|auxiliary/scanner/http/radware_appdirector_enum|-|✓|✗|✓|-
256|Ruby on Rails JSON Processor YAML Deserialization Scanner|auxiliary/scanner/http/rails_json_yaml_scanner|-|-|✗|✓|✓
257|Ruby On Rails Attributes Mass Assignment Scanner|auxiliary/scanner/http/rails_mass_assignment|-|-|✗|✓|-
258|Ruby on Rails XML Processor YAML Deserialization Scanner|auxiliary/scanner/http/rails_xml_yaml_scanner|-|-|✗|✓|-
259|HTTP File Extension Scanner|auxiliary/scanner/http/replace_ext|-|-|✗|✓|-
260|Apache Reverse Proxy Bypass Vulnerability Scanner|auxiliary/scanner/http/rewrite_proxy_bypass|-|-|✗|✓|-
261|RFCode Reader Web Interface Login / Bruteforce Utility|auxiliary/scanner/http/rfcode_reader_enum|-|-|✗|✓|-
262|RIPS Scanner Directory Traversal|auxiliary/scanner/http/rips_traversal|-|-|✗|✓|✓
263|HTTP Robots.txt Content Scanner|auxiliary/scanner/http/robots_txt|-|-|✗|✓|-
264|SAP BusinessObjects User Bruteforcer|auxiliary/scanner/http/sap_businessobjects_user_brute|-|-|✗|✓|-
265|SAP BusinessObjects Web User Bruteforcer|auxiliary/scanner/http/sap_businessobjects_user_brute_web|-|-|✗|✓|-
266|SAP BusinessObjects User Enumeration|auxiliary/scanner/http/sap_businessobjects_user_enum|-|-|✗|✓|-
267|SAP BusinessObjects Version Detection|auxiliary/scanner/http/sap_businessobjects_version_enum|-|-|✗|✓|-
268|HTTP Page Scraper|auxiliary/scanner/http/scraper|-|-|✗|✓|-
269|Sentry Switched CDU Bruteforce Login Utility|auxiliary/scanner/http/sentry_cdu_enum|-|✓|✗|✓|-
270|HTTP SOAP Verb/Noun Brute Force Scanner|auxiliary/scanner/http/soap_xml|-|-|✗|✓|-
271|Splunk Web Interface Login Utility|auxiliary/scanner/http/splunk_web_login|-|-|✗|✓|-
272|HTTP SSL Certificate Information|auxiliary/scanner/http/ssl|-|-|✗|✓|-
273|HTTP Subversion Scanner|auxiliary/scanner/http/svn_scanner|-|-|✗|✓|-
274|SVN wc.db Scanner|auxiliary/scanner/http/svn_wcdb_scanner|-|-|✗|✓|-
275|Symantec Web Gateway Login Utility|auxiliary/scanner/http/symantec_web_gateway_login|-|-|✗|✓|-
276|Titan FTP Administrative Password Disclosure|auxiliary/scanner/http/titan_ftp_admin_pwd|-|-|✗|✓|-
277|HTTP HTML Title Tag Content Grabber|auxiliary/scanner/http/title|-|-|✗|✓|✓
278|Apache Tomcat User Enumeration|auxiliary/scanner/http/tomcat_enum|-|-|✗|✓|✓
279|Tomcat Application Manager Login Utility|auxiliary/scanner/http/tomcat_mgr_login|-|-|✗|✓|✓
280|TP-Link Wireless Lite N Access Point Directory Traversal Vulnerability|auxiliary/scanner/http/tplink_traversal_noauth|-|-|✗|✓|-
281|HTTP Cross-Site Tracing Detection|auxiliary/scanner/http/trace|-|-|✗|✓|-
282|HTTP trace.axd Content Scanner|auxiliary/scanner/http/trace_axd|-|-|✗|✓|-
283|Typo3 Login Bruteforcer|auxiliary/scanner/http/typo3_bruteforce|-|-|✗|✓|✓
284|V-CMS Login Utility|auxiliary/scanner/http/vcms_login|-|-|✗|✓|✓
285|HTTP Verb Authentication Bypass Scanner|auxiliary/scanner/http/verb_auth_bypass|-|-|✗|✓|✓
286|WANGKONGBAO CNS-1000 and 1100 UTM Directory Traversal|auxiliary/scanner/http/wangkongbao_traversal|-|-|✗|✓|-
287|HTTP WebDAV Internal IP Scanner|auxiliary/scanner/http/webdav_internal_ip|-|-|✗|✓|-
288|HTTP WebDAV Scanner|auxiliary/scanner/http/webdav_scanner|-|-|✗|✓|-
289|HTTP WebDAV Website Content Scanner|auxiliary/scanner/http/webdav_website_content|-|-|✗|✓|-
290|WordPress XMLRPC GHOST Vulnerability Scanner|auxiliary/scanner/http/wordpress_ghost_scanner|-|-|✗|✓|✓
291|WordPress Brute Force and User Enumeration Utility|auxiliary/scanner/http/wordpress_login_enum|-|-|✗|✓|✓
292|Wordpress XML-RPC system.multicall Credential Collector|auxiliary/scanner/http/wordpress_multicall_creds|-|-|✗|✓|✓
293|Wordpress Pingback Locator|auxiliary/scanner/http/wordpress_pingback_access|-|-|✗|✓|✓
294|Wordpress Scanner|auxiliary/scanner/http/wordpress_scanner|-|-|✗|✓|✓
295|Wordpress XML-RPC Username/Password Login Scanner|auxiliary/scanner/http/wordpress_xmlrpc_login|-|-|✗|✓|✓
296|WordPress DukaPress Plugin File Read Vulnerability|auxiliary/scanner/http/wp_dukapress_file_read|-|-|✗|✓|✓
297|WordPress GI-Media Library Plugin Directory Traversal Vulnerability|auxiliary/scanner/http/wp_gimedia_library_file_read|-|-|✗|✓|✓
298|WordPress Mobile Pack Information Disclosure Vulnerability|auxiliary/scanner/http/wp_mobile_pack_info_disclosure|-|-|✗|✓|✓
299|WordPress Mobile Edition File Read Vulnerability|auxiliary/scanner/http/wp_mobileedition_file_read|-|-|✗|✓|✓
300|WordPress Simple Backup File Read Vulnerability|auxiliary/scanner/http/wp_simple_backup_file_read|-|-|✗|✓|✓
301|HTTP Blind XPATH 1.0 Injector|auxiliary/scanner/http/xpath|-|-|✗|✓|-
302|Zabbix Server Brute Force Utility|auxiliary/scanner/http/zabbix_login|-|-|✗|✓|✓
303|Novell ZENworks Asset Management 7.5 Remote File Access|auxiliary/scanner/http/zenworks_assetmanagement_fileaccess|-|-|✗|✓|-
304|Novell ZENworks Asset Management 7.5 Configuration Access|auxiliary/scanner/http/zenworks_assetmanagement_getconfig|-|-|✗|✓|-
305|IMAP4 Banner Grabber|auxiliary/scanner/imap/imap_version|-|-|✗|✓|-
306|IPID Sequence Scanner|auxiliary/scanner/ip/ipidseq|-|-|✗|✓|-
307|IPMI Information Discovery|auxiliary/scanner/ipmi/ipmi_version|-|-|✗|✓|-
308|Gather Kademlia Server Information|auxiliary/scanner/kademlia/server_info|-|-|✗|✓|-
309|LLMNR Query|auxiliary/scanner/llmnr/query|-|-|✓|✓|-
310|Lotus Domino Password Hash Collector|auxiliary/scanner/lotus/lotus_domino_hashes|-|-|✗|✓|-
311|Lotus Domino Brute Force Utility|auxiliary/scanner/lotus/lotus_domino_login|-|-|✗|✓|-
312|Lotus Domino Version|auxiliary/scanner/lotus/lotus_domino_version|-|-|✗|✓|-
313|mDNS Query|auxiliary/scanner/mdns/query|-|-|✓|✓|-
314|CCTV DVR Login Scanning Utility|auxiliary/scanner/misc/cctv_dvr_login|-|-|✗|✓|-
315|Identify Cisco Smart Install endpoints|auxiliary/scanner/misc/cisco_smart_install|-|-|✗|✓|-
316|Dahua DVR Auth Bypass Scanner|auxiliary/scanner/misc/dahua_dvr_auth_bypass|-|-|✗|✓|-
317|Multiple DVR Manufacturers Configuration Disclosure|auxiliary/scanner/misc/dvr_config_disclosure|-|-|✗|✓|-
318|EasyCafe Server Remote File Access|auxiliary/scanner/misc/easycafe_server_fileaccess|-|-|✗|✓|-
319|Borland InterBase Services Manager Information|auxiliary/scanner/misc/ib_service_mgr_info|-|-|✗|✓|-
320|Identify Queue Manager Name and MQ Version|auxiliary/scanner/misc/ibm_mq_enum|-|-|✗|-|-
321|OKI Printer Default Login Credential Scanner|auxiliary/scanner/misc/oki_scanner|-|-|✗|-|-
322|Poison Ivy Command and Control Scanner|auxiliary/scanner/misc/poisonivy_control_scanner|-|-|✗|-|-
323|Ray Sharp DVR Password Retriever|auxiliary/scanner/misc/raysharp_dvr_passwords|-|-|✗|✓|-
324|Rosewill RXS-3211 IP Camera Password Retriever|auxiliary/scanner/misc/rosewill_rxs3211_passwords|-|-|✗|✓|-
325|SunRPC Portmap Program Enumerator|auxiliary/scanner/misc/sunrpc_portmapper|-|-|✗|✓|-
326|Novell ZENworks Configuration Management Preboot Service Remote File Access|auxiliary/scanner/misc/zenworks_preboot_fileaccess|-|-|✗|✓|-
327|MongoDB Login Utility|auxiliary/scanner/mongodb/mongodb_login|-|-|✗|✓|-
328|MQTT Authentication Scanner|auxiliary/scanner/mqtt/connect|-|-|✗|✓|-
329|Metasploit RPC Interface Login Utility|auxiliary/scanner/msf/msf_rpc_login|-|✓|✗|✓|-
330|Metasploit Web Interface Login Utility|auxiliary/scanner/msf/msf_web_login|-|-|✗|✓|-
331|MSSQL Password Hashdump|auxiliary/scanner/mssql/mssql_hashdump|-|-|✗|✓|-
332|MSSQL Login Utility|auxiliary/scanner/mssql/mssql_login|-|-|✗|✓|-
333|MSSQL Ping Utility|auxiliary/scanner/mssql/mssql_ping|-|-|✗|-|-
334|MSSQL Schema Dump|auxiliary/scanner/mssql/mssql_schemadump|-|-|✗|✓|-
335|MYSQL Password Hashdump|auxiliary/scanner/mysql/mysql_hashdump|-|-|✗|✓|-
336|MySQL Login Utility|auxiliary/scanner/mysql/mysql_login|-|-|✗|✓|-
337|MYSQL Schema Dump|auxiliary/scanner/mysql/mysql_schemadump|-|-|✗|✓|-
338|MySQL Server Version Enumeration|auxiliary/scanner/mysql/mysql_version|-|-|✗|✓|-
339|NAT-PMP External Port Scanner|auxiliary/scanner/natpmp/natpmp_portscan|-|-|✗|✓|-
340|Nessus NTP Login Utility|auxiliary/scanner/nessus/nessus_ntp_login|-|-|✗|✓|-
341|Nessus RPC Interface Login Utility|auxiliary/scanner/nessus/nessus_rest_login|-|-|✗|✓|✓
342|Nessus XMLRPC Interface Login Utility|auxiliary/scanner/nessus/nessus_xmlrpc_login|-|-|✗|✓|-
343|Nessus XMLRPC Interface Ping Utility|auxiliary/scanner/nessus/nessus_xmlrpc_ping|-|-|✗|✓|-
344|NetBIOS Information Discovery|auxiliary/scanner/netbios/nbname|-|-|✗|✓|-
345|NeXpose API Interface Login Utility|auxiliary/scanner/nexpose/nexpose_api_login|-|-|✗|✓|-
346|NFS Mount Scanner|auxiliary/scanner/nfs/nfsmount|-|-|✗|✓|-
347|NNTP Login Utility|auxiliary/scanner/nntp/nntp_login|-|-|✗|✓|-
348|NTP "NAK to the Future"|auxiliary/scanner/ntp/ntp_nak_to_the_future|-|-|✗|✓|-
349|OpenVAS gsad Web Interface Login Utility|auxiliary/scanner/openvas/openvas_gsad_login|-|-|✗|✓|-
350|OpenVAS OMP Login Utility|auxiliary/scanner/openvas/openvas_omp_login|-|-|✗|✓|-
351|OpenVAS OTP Login Utility|auxiliary/scanner/openvas/openvas_otp_login|-|-|✗|✓|-
352|Oracle Enterprise Manager Control SID Discovery|auxiliary/scanner/oracle/emc_sid|-|-|✗|✓|-
353|Oracle iSQL*Plus Login Utility|auxiliary/scanner/oracle/isqlplus_login|-|-|✗|✓|-
354|Oracle RDBMS Login Utility|auxiliary/scanner/oracle/oracle_login|-|-|✗|-|-
355|Oracle TNS Listener SID Bruteforce|auxiliary/scanner/oracle/sid_brute|-|-|✗|✓|-
356|Oracle Application Server Spy Servlet SID Enumeration|auxiliary/scanner/oracle/spy_sid|-|-|✗|✓|-
357|Oracle XML DB SID Discovery|auxiliary/scanner/oracle/xdb_sid|-|-|✗|✓|-
358|Oracle XML DB SID Discovery via Brute Force|auxiliary/scanner/oracle/xdb_sid_brute|-|-|✗|✓|-
359|PcAnywhere Login Scanner|auxiliary/scanner/pcanywhere/pcanywhere_login|-|-|✗|✓|-
360|PcAnywhere TCP Service Discovery|auxiliary/scanner/pcanywhere/pcanywhere_tcp|-|-|✗|✓|-
361|PcAnywhere UDP Service Discovery|auxiliary/scanner/pcanywhere/pcanywhere_udp|-|-|✗|✓|-
362|POP3 Login Utility|auxiliary/scanner/pop3/pop3_login|-|-|✗|✓|-
363|POP3 Banner Grabber|auxiliary/scanner/pop3/pop3_version|-|-|✗|✓|-
364|TCP ACK Firewall Scanner|auxiliary/scanner/portscan/ack|-|-|✗|-|-
365|TCP SYN Port Scanner|auxiliary/scanner/portscan/syn|-|-|✗|-|-
366|TCP Port Scanner|auxiliary/scanner/portscan/tcp|-|-|✗|-|-
367|TCP "XMas" Port Scanner|auxiliary/scanner/portscan/xmas|-|-|✗|-|-
368|PostgreSQL Database Name Command Line Flag Injection|auxiliary/scanner/postgres/postgres_dbname_flag_injection|-|-|✗|✓|-
369|Postgres Password Hashdump|auxiliary/scanner/postgres/postgres_hashdump|-|✓|✗|✓|-
370|PostgreSQL Login Utility|auxiliary/scanner/postgres/postgres_login|-|-|✗|✓|-
371|Postgres Schema Dump|auxiliary/scanner/postgres/postgres_schemadump|-|✓|✗|✓|-
372|PostgreSQL Version Probe|auxiliary/scanner/postgres/postgres_version|-|✓|✗|✓|-
373|Canon IR-Adv Password Extractor|auxiliary/scanner/printer/canon_iradv_pwd_extract|-|✓|✗|✓|-
374|Printer File Deletion Scanner|auxiliary/scanner/printer/printer_delete_file|-|-|✗|✓|-
375|Printer File Download Scanner|auxiliary/scanner/printer/printer_download_file|-|-|✗|✓|-
376|Printer Environment Variables Scanner|auxiliary/scanner/printer/printer_env_vars|-|-|✗|✓|-
377|Printer Directory Listing Scanner|auxiliary/scanner/printer/printer_list_dir|-|-|✗|✓|-
378|Printer Volume Listing Scanner|auxiliary/scanner/printer/printer_list_volumes|-|-|✗|✓|-
379|Printer Ready Message Scanner|auxiliary/scanner/printer/printer_ready_message|-|-|✗|✓|-
380|Printer File Upload Scanner|auxiliary/scanner/printer/printer_upload_file|-|-|✗|✓|-
381|Printer Version Information Scanner|auxiliary/scanner/printer/printer_version_info|-|-|✗|✓|-
382|Gather Quake Server Information|auxiliary/scanner/quake/server_info|-|-|✗|✓|-
383|MS12-020 Microsoft Remote Desktop Checker|auxiliary/scanner/rdp/ms12_020_check|-|-|✗|✓|-
384|Identify endpoints speaking the Remote Desktop Protocol (RDP)|auxiliary/scanner/rdp/rdp_scanner|-|-|✗|✓|-
385|Redis Login Utility|auxiliary/scanner/redis/redis_login|-|-|✗|✓|-
386|Redis Command Execute Scanner|auxiliary/scanner/redis/redis_server|-|-|✗|✓|-
387|Rogue Gateway Detection: Receiver|auxiliary/scanner/rogue/rogue_recv|-|-|✗|✓|-
388|rexec Authentication Scanner|auxiliary/scanner/rservices/rexec_login|-|-|✗|✓|-
389|rlogin Authentication Scanner|auxiliary/scanner/rservices/rlogin_login|-|-|✗|✓|-
390|rsh Authentication Scanner|auxiliary/scanner/rservices/rsh_login|-|-|✗|✓|-
391|List Rsync Modules|auxiliary/scanner/rsync/modules_list|-|-|✗|✓|-
392|SAP CTC Service Verb Tampering User Management|auxiliary/scanner/sap/sap_ctc_verb_tampering_user_mgmt|-|✓|✗|✓|-
393|SAP Host Agent Information Disclosure|auxiliary/scanner/sap/sap_hostctrl_getcomputersystem|-|-|✗|✓|-
394|SAP ICF /sap/public/info Service Sensitive Information Gathering|auxiliary/scanner/sap/sap_icf_public_info|-|-|✗|✓|✓
395|SAP URL Scanner|auxiliary/scanner/sap/sap_icm_urlscan|-|-|✗|✓|-
396|SAP Management Console ABAP Syslog Disclosure|auxiliary/scanner/sap/sap_mgmt_con_abaplog|-|-|✗|✓|-
397|SAP Management Console Brute Force|auxiliary/scanner/sap/sap_mgmt_con_brute_login|-|-|✗|✓|-
398|SAP Management Console Extract Users|auxiliary/scanner/sap/sap_mgmt_con_extractusers|-|-|✗|✓|-
399|SAP Management Console Get Access Points|auxiliary/scanner/sap/sap_mgmt_con_getaccesspoints|-|-|✗|✓|-
400|SAP Management Console getEnvironment|auxiliary/scanner/sap/sap_mgmt_con_getenv|-|-|✗|✓|-
401|SAP Management Console Get Logfile|auxiliary/scanner/sap/sap_mgmt_con_getlogfiles|-|-|✗|✓|-
402|SAP Management Console GetProcessList|auxiliary/scanner/sap/sap_mgmt_con_getprocesslist|-|-|✗|✓|-
403|SAP Management Console Get Process Parameters|auxiliary/scanner/sap/sap_mgmt_con_getprocessparameter|-|-|✗|✓|-
404|SAP Management Console Instance Properties|auxiliary/scanner/sap/sap_mgmt_con_instanceproperties|-|-|✗|✓|-
405|SAP Management Console List Config Files|auxiliary/scanner/sap/sap_mgmt_con_listconfigfiles|-|-|✗|✓|-
406|SAP Management Console List Logfiles|auxiliary/scanner/sap/sap_mgmt_con_listlogfiles|-|-|✗|✓|-
407|SAP Management Console getStartProfile|auxiliary/scanner/sap/sap_mgmt_con_startprofile|-|-|✗|✓|-
408|SAP Management Console Version Detection|auxiliary/scanner/sap/sap_mgmt_con_version|-|-|✗|✓|-
409|SAPRouter Admin Request|auxiliary/scanner/sap/sap_router_info_request|-|-|✗|✓|-
410|SAP Service Discovery|auxiliary/scanner/sap/sap_service_discovery|-|-|✗|-|-
411|SAP /sap/bc/soap/rfc SOAP Service BAPI_USER_CREATE1 Function User Creation|auxiliary/scanner/sap/sap_soap_bapi_user_create1|-|✓|✗|✓|-
412|SAP SOAP Service RFC_PING Login Brute Forcer|auxiliary/scanner/sap/sap_soap_rfc_brute_login|-|-|✗|✓|✓
413|SAP /sap/bc/soap/rfc SOAP Service SXPG_CALL_SYSTEM Function Command Injection|auxiliary/scanner/sap/sap_soap_rfc_dbmcli_sxpg_call_system_command_exec|-|✓|✗|✓|-
414|SAP /sap/bc/soap/rfc SOAP Service SXPG_COMMAND_EXEC Function Command Injection|auxiliary/scanner/sap/sap_soap_rfc_dbmcli_sxpg_command_exec|-|✓|✗|✓|-
415|SAP SOAP RFC EPS_GET_DIRECTORY_LISTING Directories Information Disclosure|auxiliary/scanner/sap/sap_soap_rfc_eps_get_directory_listing|-|✓|✗|✓|-
416|SAP SOAP RFC PFL_CHECK_OS_FILE_EXISTENCE File Existence Check|auxiliary/scanner/sap/sap_soap_rfc_pfl_check_os_file_existence|-|✓|✗|✓|-
417|SAP /sap/bc/soap/rfc SOAP Service RFC_PING Function Service Discovery|auxiliary/scanner/sap/sap_soap_rfc_ping|-|✓|✗|✓|-
418|SAP /sap/bc/soap/rfc SOAP Service RFC_READ_TABLE Function Dump Data|auxiliary/scanner/sap/sap_soap_rfc_read_table|-|✓|✗|✓|-
419|SAP SOAP RFC RZL_READ_DIR_LOCAL Directory Contents Listing|auxiliary/scanner/sap/sap_soap_rfc_rzl_read_dir|-|✓|✗|✓|-
420|SAP /sap/bc/soap/rfc SOAP Service SUSR_RFC_USER_INTERFACE Function User Creation|auxiliary/scanner/sap/sap_soap_rfc_susr_rfc_user_interface|-|✓|✗|✓|-
421|SAP /sap/bc/soap/rfc SOAP Service SXPG_CALL_SYSTEM Function Command Execution|auxiliary/scanner/sap/sap_soap_rfc_sxpg_call_system_exec|-|✓|✗|✓|-
422|SAP SOAP RFC SXPG_COMMAND_EXECUTE|auxiliary/scanner/sap/sap_soap_rfc_sxpg_command_exec|-|✓|✗|✓|-
423|SAP /sap/bc/soap/rfc SOAP Service RFC_SYSTEM_INFO Function Sensitive Information Gathering|auxiliary/scanner/sap/sap_soap_rfc_system_info|-|✓|✗|✓|-
424|SAP /sap/bc/soap/rfc SOAP Service TH_SAPREL Function Information Disclosure|auxiliary/scanner/sap/sap_soap_th_saprel_disclosure|-|✓|✗|✓|-
425|SAP Web GUI Login Brute Forcer|auxiliary/scanner/sap/sap_web_gui_brute_login|-|-|✗|✓|✓
426|Digi ADDP Remote Reboot Initiator|auxiliary/scanner/scada/digi_addp_reboot|-|✓|✗|✓|-
427|Digi ADDP Information Discovery|auxiliary/scanner/scada/digi_addp_version|-|✓|✗|✓|-
428|Digi RealPort Serial Server Port Scanner|auxiliary/scanner/scada/digi_realport_serialport_scan|-|-|✗|✓|-
429|Digi RealPort Serial Server Version|auxiliary/scanner/scada/digi_realport_version|-|-|✗|✓|-
430|Indusoft WebStudio NTWebServer Remote File Access|auxiliary/scanner/scada/indusoft_ntwebserver_fileaccess|-|-|✗|✓|-
431|Modbus Banner Grabbing|auxiliary/scanner/scada/modbus_banner_grabbing|-|-|✗|✓|-
432|Moxa UDP Device Discovery|auxiliary/scanner/scada/moxa_discover|-|-|✗|✓|-
433|Unitronics PCOM Client|auxiliary/scanner/scada/pcomclient|-|-|✗|✓|-
434|Sielco Sistemi Winlog Remote File Access|auxiliary/scanner/scada/sielco_winlog_fileaccess|-|-|✗|✓|-
435|SIP Username Enumerator (UDP)|auxiliary/scanner/sip/enumerator|-|-|✗|✓|-
436|SIP Username Enumerator (TCP)|auxiliary/scanner/sip/enumerator_tcp|-|-|✗|✓|-
437|SIP Endpoint Scanner (UDP)|auxiliary/scanner/sip/options|-|-|✗|✓|-
438|SIP Endpoint Scanner (TCP)|auxiliary/scanner/sip/options_tcp|-|-|✗|✓|-
439|SIPDroid Extension Grabber|auxiliary/scanner/sip/sipdroid_ext_enum|-|-|✗|✗|-
440|SMB Session Pipe Auditor|auxiliary/scanner/smb/pipe_auditor|-|-|✗|-|-
441|SMB Session Pipe DCERPC Auditor|auxiliary/scanner/smb/pipe_dcerpc_auditor|-|-|✗|-|-
442|Microsoft Windows Authenticated Logged In Users Enumeration|auxiliary/scanner/smb/psexec_loggedin_users|-|-|✗|✓|-
443|SMB Group Policy Preference Saved Passwords Enumeration|auxiliary/scanner/smb/smb_enum_gpp|-|-|✗|✓|-
444|SMB Share Enumeration|auxiliary/scanner/smb/smb_enumshares|-|-|✗|-|-
445|SMB User Enumeration (SAM EnumUsers)|auxiliary/scanner/smb/smb_enumusers|-|-|✗|-|-
446|SMB Domain User Enumeration|auxiliary/scanner/smb/smb_enumusers_domain|-|-|✗|-|-
447|SMB Login Check Scanner|auxiliary/scanner/smb/smb_login|-|-|✗|✓|-
448|SMB SID User Enumeration (LookupSid)|auxiliary/scanner/smb/smb_lookupsid|-|-|✗|-|-
449|MS17-010 SMB RCE Detection|auxiliary/scanner/smb/smb_ms17_010|-|-|✗|✓|-
450|Samba _netr_ServerPasswordSet Uninitialized Credential State|auxiliary/scanner/smb/smb_uninit_cred|-|-|✗|-|-
451|SMB Version Detection|auxiliary/scanner/smb/smb_version|-|-|✗|-|-
452|SMTP User Enumeration Utility|auxiliary/scanner/smtp/smtp_enum|-|-|✗|✓|-
453|SMTP NTLM Domain Extraction|auxiliary/scanner/smtp/smtp_ntlm_domain|-|-|✗|✓|-
454|SMTP Open Relay Detection|auxiliary/scanner/smtp/smtp_relay|-|-|✗|✓|-
455|SMTP Banner Grabber|auxiliary/scanner/smtp/smtp_version|-|-|✗|✓|-
456|AIX SNMP Scanner Auxiliary Module|auxiliary/scanner/snmp/aix_version|-|-|✗|✓|-
457|Arris DG950A Cable Modem Wifi Enumeration|auxiliary/scanner/snmp/arris_dg950|-|-|✗|✓|-
458|Brocade Password Hash Enumeration|auxiliary/scanner/snmp/brocade_enumhash|-|-|✗|✓|-
459|Cisco IOS SNMP Configuration Grabber (TFTP)|auxiliary/scanner/snmp/cisco_config_tftp|-|-|✗|✓|-
460|Cambium cnPilot r200/r201 SNMP Enumeration|auxiliary/scanner/snmp/cnpilot_r_snmp_loot|-|-|✗|✓|-
461|Cambium ePMP 1000 SNMP Enumeration|auxiliary/scanner/snmp/epmp1000_snmp_loot|-|-|✗|✓|-
462|Netopia 3347 Cable Modem Wifi Enumeration|auxiliary/scanner/snmp/netopia_enum|-|-|✗|✓|-
463|ARRIS / Motorola SBG6580 Cable Modem SNMP Enumeration Module|auxiliary/scanner/snmp/sbg6580_enum|-|-|✗|✓|-
464|SNMP Enumeration Module|auxiliary/scanner/snmp/snmp_enum|-|-|✗|✓|-
465|HP LaserJet Printer SNMP Enumeration|auxiliary/scanner/snmp/snmp_enum_hp_laserjet|-|-|✗|✓|-
466|SNMP Windows SMB Share Enumeration|auxiliary/scanner/snmp/snmp_enumshares|-|-|✗|✓|-
467|SNMP Windows Username Enumeration|auxiliary/scanner/snmp/snmp_enumusers|-|-|✗|✓|-
468|SNMP Community Login Scanner|auxiliary/scanner/snmp/snmp_login|-|-|✗|✓|-
469|Ubee DDW3611b Cable Modem Wifi Enumeration|auxiliary/scanner/snmp/ubee_ddw3611|-|-|✗|✓|-
470|Xerox WorkCentre User Enumeration (SNMP)|auxiliary/scanner/snmp/xerox_workcentre_enumusers|-|-|✗|✓|-
471|Kippo SSH Honeypot Detector|auxiliary/scanner/ssh/detect_kippo|-|-|✗|✓|-
472|Apache Karaf Login Utility|auxiliary/scanner/ssh/karaf_login|-|-|✗|✓|-
473|SSH Username Enumeration|auxiliary/scanner/ssh/ssh_enumusers|-|-|✗|✓|-
474|SSH Login Check Scanner|auxiliary/scanner/ssh/ssh_login|-|-|✗|✓|-
475|SSH Version Scanner|auxiliary/scanner/ssh/ssh_version|-|-|✗|✓|-
476|Gather Steam Server Information|auxiliary/scanner/steam/server_info|-|-|✗|✓|-
477|Brocade Enable Login Check Scanner|auxiliary/scanner/telnet/brocade_enable_login|-|-|✗|✓|-
478|Lantronix Telnet Password Recovery|auxiliary/scanner/telnet/lantronix_telnet_password|-|-|✗|✓|-
479|Lantronix Telnet Service Banner Detection|auxiliary/scanner/telnet/lantronix_telnet_version|-|-|✗|✓|-
480|Telnet Service Encryption Key ID Overflow Detection|auxiliary/scanner/telnet/telnet_encrypt_overflow|-|-|✗|✓|-
481|Telnet Login Check Scanner|auxiliary/scanner/telnet/telnet_login|-|-|✗|✓|-
482|RuggedCom Telnet Password Generator|auxiliary/scanner/telnet/telnet_ruggedcom|-|✓|✗|✓|-
483|Telnet Service Banner Detection|auxiliary/scanner/telnet/telnet_version|-|-|✗|✓|-
484|TFTP Brute Forcer|auxiliary/scanner/tftp/tftpbrute|-|-|✗|✓|-
485|Ubiquiti Discovery Scanner|auxiliary/scanner/ubiquiti/ubiquiti_discover|-|-|✗|✓|-
486|UPnP SSDP M-SEARCH Information Discovery|auxiliary/scanner/upnp/ssdp_msearch|-|-|✗|✓|-
487|Varnish Cache CLI Login Utility|auxiliary/scanner/varnish/varnish_cli_login|-|-|✗|✓|-
488|VMWare ESX/ESXi Fingerprint Scanner|auxiliary/scanner/vmware/esx_fingerprint|-|-|✗|✓|-
489|VMWare Authentication Daemon Login Scanner|auxiliary/scanner/vmware/vmauthd_login|-|-|✗|✓|-
490|VMWare Authentication Daemon Version Scanner|auxiliary/scanner/vmware/vmauthd_version|-|-|✗|✓|-
491|VMWare Enumerate Permissions|auxiliary/scanner/vmware/vmware_enum_permissions|-|✓|✗|✓|-
492|VMWare Enumerate Active Sessions|auxiliary/scanner/vmware/vmware_enum_sessions|-|✓|✗|✓|-
493|VMWare Enumerate User Accounts|auxiliary/scanner/vmware/vmware_enum_users|-|✓|✗|✓|-
494|VMWare Enumerate Virtual Machines|auxiliary/scanner/vmware/vmware_enum_vms|-|✓|✗|✓|-
495|VMWare Enumerate Host Details|auxiliary/scanner/vmware/vmware_host_details|-|✓|✗|✓|-
496|VMWare Web Login Scanner|auxiliary/scanner/vmware/vmware_http_login|-|-|✗|✓|-
497|VMWare Screenshot Stealer|auxiliary/scanner/vmware/vmware_screenshot_stealer|-|✓|✗|✓|-
498|VMware Server Directory Traversal Vulnerability|auxiliary/scanner/vmware/vmware_server_dir_trav|-|-|✗|✓|-
499|Apple Remote Desktop Root Vulnerability|auxiliary/scanner/vnc/ard_root_pw|-|-|✗|✓|-
500|VNC Authentication Scanner|auxiliary/scanner/vnc/vnc_login|-|-|✗|✓|-
501|VNC Authentication None Detection|auxiliary/scanner/vnc/vnc_none_auth|-|-|✗|✓|-
502|VxWorks WDB Agent Boot Parameter Scanner|auxiliary/scanner/vxworks/wdbrpc_bootline|-|-|✗|✓|-
503|VxWorks WDB Agent Version Scanner|auxiliary/scanner/vxworks/wdbrpc_version|-|-|✗|✓|-
504|WinRM Authentication Method Detection|auxiliary/scanner/winrm/winrm_auth_methods|-|-|✗|✓|-
505|WinRM Login Utility|auxiliary/scanner/winrm/winrm_login|-|-|✗|✓|-
506|WS-Discovery Information Discovery|auxiliary/scanner/wsdd/wsdd_query|-|-|✓|✓|-
507|X11 No-Auth Scanner|auxiliary/scanner/x11/open_x11|-|-|✗|✓|-
508|HTTP Client MS Credential Relayer|auxiliary/server/http_ntlmrelay|-|-|✗|✓|-
509|Asterisk Manager Login Utility|auxiliary/voip/asterisk_login|-|-|✗|✓|-
510|Viproy CUCDM IP Phone XML Services - Call Forwarding Tool|auxiliary/voip/cisco_cucdm_call_forward|-|-|✗|✓|✓
511|Viproy CUCDM IP Phone XML Services - Speed Dial Attack Tool|auxiliary/voip/cisco_cucdm_speed_dials|-|-|✗|✓|✓

## Exploits (1166)

### Manual Ranking (34)

#### 1999 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Microsoft Windows Authenticated User Code Execution|exploit/windows/smb/psexec|✓|✗|✗|✓|-

#### 2007 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Alcatel-Lucent OmniPCX Enterprise masterCGI Arbitrary Command Execution|exploit/linux/http/alcatel_omnipcx_mastercgi_exec|✓|-|✗|✓|-
2|MS07-029 Microsoft DNS RPC Service extractQuotedChar() Overflow (SMB)|exploit/windows/smb/ms07_029_msdns_zonename|✓|-|✗|✓|-

#### 2008 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Generic PHP Code Evaluation|exploit/unix/webapp/php_eval|✓|-|✗|✓|-
2|Trixbox langChoice PHP Local File Inclusion|exploit/unix/webapp/trixbox_langchoice|✓|-|✗|✓|-

#### 2012 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|D-Link DIR-605L Captcha Handling Buffer Overflow|exploit/linux/http/dlink_dir605l_captcha_bof|✓|-|✗|✓|-
2|FreePBX 2.10.0 / 2.9.0 callmenum Remote Code Execution|exploit/unix/http/freepbx_callmenum|✓|-|✗|✓|-
3|MoinMoin twikidraw Action Traversal File Upload|exploit/unix/webapp/moinmoin_twikidraw|✓|-|✗|✓|✓

#### 2013 (8)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Astium Remote Code Execution|exploit/linux/http/astium_sqli_upload|✓|-|✗|✓|✓
2|Linksys WRT54GL apply.cgi Command Execution|exploit/linux/http/linksys_wrt54gl_apply_exec|✗|✓|✗|✓|-
3|Netgear DGN2200B pppoe.cgi Remote Command Execution|exploit/linux/http/netgear_dgn2200b_pppoe_exec|✗|✓|✗|✓|-
4|NETGEAR ReadyNAS Perl Code Evaluation|exploit/linux/http/netgear_readynas_exec|✓|-|✗|✓|-
5|Raidsonic NAS Devices Unauthenticated Remote Command Execution|exploit/linux/http/raidsonic_nas_ib5220_exec_noauth|✓|-|✗|✓|-
6|GLPI install.php Remote Command Execution|exploit/multi/http/glpi_install_rce|✓|-|✗|✓|✓
7|HP SiteScope Remote Code Execution|exploit/windows/http/hp_sitescope_runomagentcommand|✓|-|✗|✓|✓
8|Intrasrv 1.0 Buffer Overflow|exploit/windows/http/intrasrv_bof|✓|-|✗|✓|-

#### 2014 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Kloxo SQL Injection and Remote Code Execution|exploit/linux/http/kloxo_sqli|✓|-|✗|✓|✓
2|Apache Struts ClassLoader Manipulation Remote Code Execution|exploit/multi/http/struts_code_exec_classloader|✗|-|✗|✓|✓
3|Vtiger Install Unauthenticated Remote Command Execution|exploit/multi/http/vtiger_install_rce|✓|-|✗|✓|✓
4|HybridAuth install.php PHP Code Execution|exploit/unix/webapp/hybridauth_install_php_exec|✓|-|✗|✓|✓
5|Cogent DataHub Command Injection|exploit/windows/http/cogent_datahub_command|✓|-|✗|✓|-

#### 2015 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Generic Web Application DLL Injection|exploit/windows/http/generic_http_dll_injection|✗|-|✗|✓|✓
2|ManageEngine OpManager Remote Code Execution|exploit/windows/http/manage_engine_opmanager_rce|✓|-|✗|✓|-
3|ManageEngine EventLog Analyzer Remote Code Execution|exploit/windows/misc/manageengine_eventlog_analyzer_rce|✓|✓|✗|✓|-

#### 2016 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apache Jetspeed Arbitrary File Upload|exploit/multi/http/apache_jetspeed_file_upload|✗|-|✗|✓|-
2|PHPMailer Sendmail Argument Injection|exploit/multi/http/phpmailer_arg_injection|✗|-|✗|✓|✓
3|Oracle Weblogic Server Deserialization RCE - MarshalledObject|exploit/multi/misc/weblogic_deserialize_marshalledobject|✗|-|✗|✓|-

#### 2017 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Microsoft IIS WebDav ScStoragePathFromUrl Overflow|exploit/windows/iis/iis_webdav_scstoragepathfromurl|✓|-|✗|✓|✓

#### 2018 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Nagios XI Chained Remote Code Execution|exploit/linux/http/nagios_xi_chained_rce_2_electric_boogaloo|✓|-|✗|✓|-
2|Snap Creek Duplicator WordPress plugin code injection|exploit/multi/php/wp_duplicator_code_inject|✓|-|✗|✓|✓
3|Nuuo Central Management Server Authenticated Arbitrary File Upload|exploit/windows/nuuo/nuuo_cms_fu|✓|-|✗|✓|-
4|WebExec Authenticated User Code Execution|exploit/windows/smb/webexec|✓|✗|✗|✓|-

#### 2020 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|vBulletin /ajax/api/content_infraction/getIndexableContent nodeid Parameter SQL Injection|exploit/multi/http/vbulletin_getindexablecontent|✓|-|✗|✓|✓
2|WordPress InfiniteWP Client Authentication Bypass|exploit/unix/webapp/wp_infinitewp_auth_bypass|✓|✓|✗|✓|✓


### Low Ranking (2)

#### 2004 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS04-007 Microsoft ASN.1 Library Bitstring Heap Overflow|exploit/windows/smb/ms04_007_killbill|✓|-|✗|✓|-

#### 2013 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Sami FTP Server LIST Command Buffer Overflow|exploit/windows/ftp/sami_ftpd_list|✓|-|✗|✓|-


### Average Ranking (122)

#### 1988 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Morris Worm sendmail Debug Mode Shell Escape|exploit/unix/smtp/morris_sendmail_debug|✓|-|✗|✓|-

#### 1998 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|War-FTPD 1.65 Password Overflow|exploit/windows/ftp/warftpd_165_pass|✓|-|✗|✓|-
2|War-FTPD 1.65 Username Overflow|exploit/windows/ftp/warftpd_165_user|✓|-|✗|✓|-

#### 2000 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|GAMSoft TelSrv 1.5 Username Buffer Overflow|exploit/windows/telnet/gamsoft_telsrv_username|✗|-|✗|✓|-

#### 2001 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|WinVNC Web Server GET Overflow|exploit/windows/vnc/winvnc_http_get|✗|-|✗|✓|-

#### 2002 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Webster HTTP Server GET Buffer Overflow|exploit/windows/http/webster_http|✗|-|✗|✓|-
2|TFTPD32 Long Filename Buffer Overflow|exploit/windows/tftp/tftpd32_long_filename|✓|-|✗|✓|-

#### 2003 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Samba 2.2.2 - 2.2.6 nttrans Buffer Overflow|exploit/multi/samba/nttrans|✓|-|✗|✓|-
2|Kerio Firewall 2.1.4 Authentication Packet Overflow|exploit/windows/firewall/kerio_auth|✗|-|✗|✓|-
3|Alt-N WebAdmin USER Buffer Overflow|exploit/windows/http/altn_webadmin|✓|-|✗|✓|-
4|IA WebMail 3.x Buffer Overflow|exploit/windows/http/ia_webmail|✓|-|✗|✓|-

#### 2004 (14)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Subversion Date Svnserve|exploit/multi/svn/svnserve_date|✓|-|✗|✓|-
2|AppleFileServer LoginExt PathName Overflow|exploit/osx/afp/loginext|✓|-|✗|✓|-
3|WebSTAR FTP Server USER Overflow|exploit/osx/ftp/webstar_ftp_user|✓|-|✗|✓|-
4|Veritas Backup Exec Name Service Overflow|exploit/windows/backupexec/name_service|✗|-|✗|✓|-
5|CA BrightStor Discovery Service Stack Buffer Overflow|exploit/windows/brightstor/discovery_udp|✗|-|✗|✓|-
6|Sasser Worm avserve FTP PORT Buffer Overflow|exploit/windows/ftp/sasser_ftpd_port|✗|-|✗|✓|-
7|Minishare 1.4.1 Buffer Overflow|exploit/windows/http/minishare_get_overflow|✓|-|✗|✓|-
8|PSO Proxy v0.91 Stack Buffer Overflow|exploit/windows/http/psoproxy91_overflow|✓|-|✗|✓|-
9|SHOUTcast DNAS/win32 1.9.4 File Request Format String Overflow|exploit/windows/http/shoutcast_format|✓|-|✗|✓|-
10|IMail IMAP4D Delete Overflow|exploit/windows/imap/imail_delete|✓|-|✗|✓|-
11|Mercury/32 v4.01a IMAP RENAME Buffer Overflow|exploit/windows/imap/mercury_rename|✓|-|✗|✓|-
12|IMail LDAP Service Buffer Overflow|exploit/windows/ldap/imail_thc|✗|-|✗|✓|-
13|CCProxy Telnet Proxy Ping Overflow|exploit/windows/proxy/ccproxy_telnet_ping|✓|-|✗|✓|-
14|YPOPS 0.6 Buffer Overflow|exploit/windows/smtp/ypops_overflow1|✓|-|✗|✓|-

#### 2005 (20)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Berlios GPSD Format String Vulnerability|exploit/linux/http/gpsd_format_string|✓|-|✗|✓|-
2|Arkeia Backup Client Type 77 Overflow (Mac OS X)|exploit/osx/arkeia/type77|✓|-|✗|✓|-
3|CA BrightStor Discovery Service TCP Overflow|exploit/windows/brightstor/discovery_tcp|✗|-|✗|✓|-
4|CA BrightStor ARCserve License Service GCR NETWORK Buffer Overflow|exploit/windows/brightstor/license_gcr|✗|-|✗|✓|-
5|CA BrightStor Agent for Microsoft SQL Overflow|exploit/windows/brightstor/sql_agent|✗|-|✗|✓|-
6|CA BrightStor Universal Agent Overflow|exploit/windows/brightstor/universal_agent|✓|-|✗|✓|-
7|3Com 3CDaemon 2.0 FTP Username Overflow|exploit/windows/ftp/3cdaemon_ftp_user|✓|-|✗|✓|-
8|freeFTPd 1.0 Username Overflow|exploit/windows/ftp/freeftpd_user|✓|-|✗|✓|-
9|CA iTechnology iGateway Debug Mode Buffer Overflow|exploit/windows/http/ca_igateway_debug|✓|-|✗|✓|-
10|Sybase EAServer 5.2 Remote Stack Buffer Overflow|exploit/windows/http/sybase_easerver|✓|-|✗|✓|-
11|TrackerCam PHP Argument Buffer Overflow|exploit/windows/http/trackercam_phparg_overflow|✗|-|✗|✓|-
12|Novell NetMail IMAP STATUS Buffer Overflow|exploit/windows/imap/novell_netmail_status|✓|-|✗|✓|-
13|Computer Associates License Client GETCONFIG Overflow|exploit/windows/license/calicclnt_getconfig|✓|-|✗|✓|-
14|SentinelLM UDP Buffer Overflow|exploit/windows/license/sentinel_lm7_udp|✓|-|✗|✓|-
15|Hummingbird Connectivity 10 SP5 LPD Buffer Overflow|exploit/windows/lpd/hummingbird_exceed|✓|-|✗|✓|-
16|BakBone NetVault Remote Heap Overflow|exploit/windows/misc/bakbone_netvault_heap|✓|-|✗|✓|-
17|Mercury/32 PH Server Module Buffer Overflow|exploit/windows/misc/mercury_phonebook|✗|-|✗|✓|-
18|SoftiaCom WMailserver 1.0 Buffer Overflow|exploit/windows/smtp/wmailserver|✗|-|✗|✓|-
19|GoodTech Telnet Server Buffer Overflow|exploit/windows/telnet/goodtech_telnet|✗|-|✗|✓|-
20|FutureSoft TFTP Server 2000 Transfer-Mode Overflow|exploit/windows/tftp/futuresoft_transfermode|✓|-|✗|✓|-

#### 2006 (25)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|PeerCast URL Handling Buffer Overflow|exploit/linux/http/peercast_url|✓|-|✗|✓|-
2|CA BrightStor ARCserve Message Engine Heap Overflow|exploit/windows/brightstor/message_engine_heap|✓|-|✗|✓|-
3|CA BrightStor ARCserve Tape Engine Buffer Overflow|exploit/windows/brightstor/tape_engine|✗|-|✗|✓|-
4|Cesar FTP 0.99g MKD Command Buffer Overflow|exploit/windows/ftp/cesarftp_mkd|✗|-|✗|✓|-
5|Easy File Sharing FTP Server 2.0 PASS Overflow|exploit/windows/ftp/easyfilesharing_pass|✗|-|✗|✓|-
6|FileCopa FTP Server Pre 18 Jul Version|exploit/windows/ftp/filecopa_list_overflow|✗|-|✗|✓|-
7|Texas Imperial Software WFTPD 3.23 SIZE Overflow|exploit/windows/ftp/wftpd_size|✗|-|✗|✓|-
8|Ipswitch WS_FTP Server 5.05 XMD5 Overflow|exploit/windows/ftp/wsftp_server_505_xmd5|✗|-|✗|✓|-
9|McAfee ePolicy Orchestrator / ProtectionPilot Overflow|exploit/windows/http/mcafee_epolicy_source|✓|-|✗|✓|-
10|Novell Messenger Server 2.0 Accept-Language Overflow|exploit/windows/http/novell_messenger_acceptlang|✓|-|✗|✓|-
11|PeerCast URL Handling Buffer Overflow|exploit/windows/http/peercast_url|✓|-|✗|✓|-
12|Private Wire Gateway Buffer Overflow|exploit/windows/http/privatewire_gateway|✗|-|✗|✓|-
13|SHTTPD URI-Encoded POST Request Overflow|exploit/windows/http/shttpd_post|✓|-|✗|✓|-
14|Mercur v5.0 IMAP SP3 SELECT Buffer Overflow|exploit/windows/imap/mercur_imap_select_overflow|✗|-|✗|✓|-
15|Mercur Messaging 2005 IMAP Login Buffer Overflow|exploit/windows/imap/mercur_login|✗|-|✗|✓|-
16|Novell NetMail IMAP APPEND Buffer Overflow|exploit/windows/imap/novell_netmail_append|✓|-|✗|✓|-
17|Novell NetMail IMAP SUBSCRIBE Buffer Overflow|exploit/windows/imap/novell_netmail_subscribe|✓|-|✗|✓|-
18|Bomberclone 0.11.6 Buffer Overflow|exploit/windows/misc/bomberclone_overflow|✓|-|✗|✓|-
19|eIQNetworks ESA License Manager LICMGR_ADDLICENSE Overflow|exploit/windows/misc/eiqnetworks_esa|✓|-|✗|✓|-
20|eIQNetworks ESA Topology DELETEDEVICE Overflow|exploit/windows/misc/eiqnetworks_esa_topology|✓|-|✗|✓|-
21|Omni-NFS Server Buffer Overflow|exploit/windows/nfs/xlink_nfsd|✓|-|✗|✓|-
22|Novell NetMail NMAP STOR Buffer Overflow|exploit/windows/novell/nmap_stor|✓|-|✗|✓|-
23|MS06-025 Microsoft RRAS Service Overflow|exploit/windows/smb/ms06_025_rras|✓|-|✗|✓|-
24|FreeFTPd 1.0.10 Key Exchange Algorithm String Buffer Overflow|exploit/windows/ssh/freeftpd_key_exchange|✗|-|✗|✓|-
25|FreeSSHd 1.0.9 Key Exchange Algorithm String Buffer Overflow|exploit/windows/ssh/freesshd_key_exchange|✗|-|✗|✓|-

#### 2007 (22)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|PHP 4 unserialize() ZVAL Reference Counter Overflow (Cookie)|exploit/multi/php/php_unserialize_zval_cookie|✓|-|✗|✓|-
2|Novell NetWare LSASS CIFS.NLM Driver Stack Buffer Overflow|exploit/netware/smb/lsass_cifs|✓|-|✗|✓|-
3|Samba lsa_io_trans_names Heap Overflow|exploit/osx/samba/lsa_transnames_heap|✓|-|✗|✓|-
4|Samba lsa_io_trans_names Heap Overflow|exploit/solaris/samba/lsa_transnames_heap|✗|-|✗|✓|-
5|CA BrightStor ARCserve for Laptops and Desktops LGServer Buffer Overflow|exploit/windows/brightstor/lgserver|✓|-|✗|✓|-
6|CA BrightStor ARCserve for Laptops and Desktops LGServer Multiple Commands Buffer Overflow|exploit/windows/brightstor/lgserver_multi|✓|-|✗|✓|-
7|CA BrightStor ARCserve for Laptops and Desktops LGServer Buffer Overflow|exploit/windows/brightstor/lgserver_rxrlogin|✗|-|✗|✓|-
8|CA BrightStor ARCserve for Laptops and Desktops LGServer rxsSetDataGrowthScheduleAndFilter Buffer Overflow|exploit/windows/brightstor/lgserver_rxssetdatagrowthscheduleandfilter|✓|-|✗|✓|-
9|CA BrightStor ARCserve for Laptops and Desktops LGServer Buffer Overflow|exploit/windows/brightstor/lgserver_rxsuselicenseini|✗|-|✗|✓|-
10|CA BrightStor ArcServe Media Service Stack Buffer Overflow|exploit/windows/brightstor/mediasrv_sunrpc|✗|-|✗|✓|-
11|CA BrightStor ARCserve Message Engine Buffer Overflow|exploit/windows/brightstor/message_engine|✗|-|✗|✓|-
12|Xitami 2.5c2 Web Server If-Modified-Since Overflow|exploit/windows/http/xitami_if_mod_since|✗|-|✗|✓|-
13|Ipswitch IMail IMAP SEARCH Buffer Overflow|exploit/windows/imap/ipswitch_search|✗|-|✗|✓|-
14|Novell NetMail IMAP AUTHENTICATE Buffer Overflow|exploit/windows/imap/novell_netmail_auth|✓|-|✗|✓|-
15|Borland Interbase Create-Request Buffer Overflow|exploit/windows/misc/borland_interbase|✓|-|✗|✓|-
16|Firebird Relational Database isc_attach_database() Buffer Overflow|exploit/windows/misc/fb_isc_attach_database|✗|-|✗|✓|-
17|Firebird Relational Database isc_create_database() Buffer Overflow|exploit/windows/misc/fb_isc_create_database|✗|-|✗|✓|-
18|Firebird Relational Database SVC_attach() Buffer Overflow|exploit/windows/misc/fb_svc_attach|✗|-|✗|✓|-
19|HP OpenView Operations OVTrace Buffer Overflow|exploit/windows/misc/hp_ovtrace|✓|-|✗|✓|-
20|LANDesk Management Suite 8.7 Alert Service Buffer Overflow|exploit/windows/misc/landesk_aolnsrvr|✗|-|✗|✓|-
21|TinyIdentD 2.2 Stack Buffer Overflow|exploit/windows/misc/tiny_identd_overflow|✓|-|✗|✓|-
22|Windows RSH Daemon Buffer Overflow|exploit/windows/misc/windows_rsh|✗|-|✗|✓|-

#### 2008 (12)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|XTACACSD report() Buffer Overflow|exploit/freebsd/tacacs/xtacacsd_report|✓|-|✗|✓|-
2|Computer Associates Alert Notification Buffer Overflow|exploit/windows/brightstor/etrust_itm_alert|✗|-|✗|✓|-
3|Alt-N SecurityGateway username Buffer Overflow|exploit/windows/http/altn_securitygateway|✓|-|✗|✓|-
4|Streamcast HTTP User-Agent Buffer Overflow|exploit/windows/http/steamcast_useragent|✗|-|✗|✓|-
5|IBM Lotus Domino Web Server Accept-Language Stack Buffer Overflow|exploit/windows/lotus/domino_http_accept_language|✓|-|✗|✓|-
6|IBM Lotus Domino Sametime STMux.exe Stack Buffer Overflow|exploit/windows/lotus/domino_sametime_stmux|✗|-|✗|✓|-
7|Asus Dpcproxy Buffer Overflow|exploit/windows/misc/asus_dpcproxy_overflow|✓|-|✗|✓|-
8|BigAnt Server 2.2 Buffer Overflow|exploit/windows/misc/bigant_server|✗|-|✗|✓|-
9|Borland CaliberRM StarTeam Multicast Service Buffer Overflow|exploit/windows/misc/borland_starteam|✗|-|✗|✓|-
10|DoubleTake/HP StorageWorks Storage Mirroring Service Authentication Overflow|exploit/windows/misc/doubletake|✗|-|✗|✓|-
11|MySQL yaSSL SSL Hello Message Buffer Overflow|exploit/windows/mysql/mysql_yassl_hello|✗|-|✗|✓|-
12|OpenTFTP SP 1.4 Error Packet Overflow|exploit/windows/tftp/opentftp_error_code|✗|-|✗|✓|-

#### 2009 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Belkin Bulldog Plus Web Service Buffer Overflow|exploit/windows/http/belkin_bulldog|✓|-|✗|✓|-
2|Hewlett-Packard Power Manager Administration Buffer Overflow|exploit/windows/http/hp_power_manager_login|✓|-|✗|✓|-
3|SafeNet SoftRemote IKE Service Buffer Overflow|exploit/windows/vpn/safenet_ike_11|✗|-|✗|✓|-

#### 2010 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MacOS X EvoCam HTTP GET Buffer Overflow|exploit/osx/http/evocam_webserver|✗|-|✗|✓|-
2|CA BrightStor ARCserve Message Engine 0x72 Buffer Overflow|exploit/windows/brightstor/message_engine_72|✓|-|✗|✓|-
3|CA BrightStor ARCserve Tape Engine 0x8A Buffer Overflow|exploit/windows/brightstor/tape_engine_0x8a|✓|-|✗|✓|-

#### 2011 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|NetSupport Manager Agent Remote Buffer Overflow|exploit/linux/misc/netsupport_manager_agent|✓|-|✗|✓|-
2|CTEK SkyRouter 4200 and 4300 Command Execution|exploit/unix/http/ctek_skyrouter|✓|-|✗|✓|-
3|GoldenFTP PASS Stack Buffer Overflow|exploit/windows/ftp/goldenftp_pass_bof|✓|-|✗|✓|-
4|ManageEngine Applications Manager Authenticated Code Execution|exploit/windows/http/manageengine_apps_mngr|✓|✓|✗|✓|-
5|Siemens FactoryLink vrn.exe Opcode 9 Buffer Overflow|exploit/windows/scada/factorylink_vrn_09|✓|-|✗|✓|-

#### 2012 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SAP NetWeaver HostControl Command Injection|exploit/windows/http/sap_host_control_cmd_exec|✓|-|✗|✓|-
2|HP Diagnostics Server magentservice.exe Overflow|exploit/windows/misc/hp_magentservice|✓|-|✗|✓|-

#### 2013 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Kimai v0.9.2 'db_restore.php' SQL Injection|exploit/unix/webapp/kimai_sqli|✓|-|✗|✓|✓

#### 2014 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Yokogawa CENTUM CS 3000 BKHOdeq.exe Buffer Overflow|exploit/windows/scada/yokogawa_bkhodeq_bof|✓|-|✗|✓|-

#### 2017 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|WordPress PHPMailer Host Header Command Injection|exploit/unix/webapp/wp_phpmailer_host_header|✓|✓|✗|✓|✓
2|Microsoft Windows RRAS Service MIBEntryGet Overflow|exploit/windows/smb/smb_rras_erraticgopher|✓|-|✗|✓|-

#### 2020 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|F5 BIG-IP TMUI Directory Traversal and File Upload RCE|exploit/linux/http/f5_bigip_tmui_rce|✗|-|✗|✓|✓


### Normal Ranking (125)

#### 1988 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Morris Worm fingerd Stack Buffer Overflow|exploit/bsd/finger/morris_fingerd_bof|✓|-|✗|✓|-

#### 2000 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|LPRng use_syslog Remote Format String Vulnerability|exploit/linux/misc/lprng_format_string|✓|-|✗|✓|-

#### 2002 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS02-065 Microsoft IIS MDAC msadcs.dll RDS DataStub Content-Type Overflow|exploit/windows/iis/ms02_065_msadc|✓|-|✗|✓|-

#### 2003 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Sambar 6 Search Results Buffer Overflow|exploit/windows/http/sambar6_search_results|✓|-|✗|✓|-

#### 2004 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Net-SNMPd Write Access SNMP-EXTEND-MIB arbitrary code execution|exploit/linux/snmp/net_snmpd_rw_access|✗|-|✗|✓|-
2|Ability Server 2.34 STOR Command Stack Buffer Overflow|exploit/windows/ftp/ability_server_stor|✓|✓|✗|✓|-
3|Serv-U FTP Server Buffer Overflow|exploit/windows/ftp/servu_chmod|✗|-|✗|✓|-

#### 2005 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Computer Associates License Server GETCONFIG Overflow|exploit/windows/license/calicserv_getconfig|✓|-|✗|✓|-

#### 2006 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Cyrus IMAPD pop3d popsubfolders USER Buffer Overflow|exploit/linux/pop3/cyrus_pop3d_popsubfolders|✓|-|✗|✓|-
2|PHP Remote File Include Generic Code Execution|exploit/unix/webapp/php_include|✓|-|✗|✓|-
3|KarjaSoft Sami FTP Server v2.0.2 USER Overflow|exploit/windows/ftp/sami_ftpd_user|✓|-|✗|✓|-

#### 2007 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Mercury/32 4.01 IMAP LOGIN SEH Buffer Overflow|exploit/windows/imap/mercury_login|✓|-|✗|✓|-

#### 2008 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Symantec Altiris DS SQL Injection|exploit/windows/misc/altiris_ds_sqli|✓|-|✗|✓|-
2|CitectSCADA/CitectFacilities ODBC Buffer Overflow|exploit/windows/scada/citect_scada_odbc|✓|-|✗|✓|-
3|TFTP Server for Windows 1.4 ST WRQ Buffer Overflow|exploit/windows/tftp/tftpserver_wrq_bof|✗|-|✗|✓|-

#### 2009 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP OpenView Network Node Manager Toolbar.exe CGI Cookie Handling Buffer Overflow|exploit/windows/http/hp_nnm_toolbar_02|✓|-|✗|✓|-

#### 2010 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|JBoss Seam 2 File Upload and Execute|exploit/multi/http/jboss_seam_upload_exec|✓|-|✗|✓|✓
2|Amlibweb NetOpacs webquery.dll Stack Buffer Overflow|exploit/windows/http/amlibweb_webquerydll_app|✓|-|✗|✓|-
3|HP Data Protector DtbClsLogin Buffer Overflow|exploit/windows/misc/hp_dataprotector_dtbclslogin|✓|-|✗|✓|-
4|NetTransport Download Manager 2.90.510 Buffer Overflow|exploit/windows/misc/nettransport|✓|-|✗|✓|-
5|Novell ZENworks Configuration Management Preboot Service 0x21 Buffer Overflow|exploit/windows/novell/zenworks_preboot_op21_bof|✓|-|✗|✓|-
6|Novell ZENworks Configuration Management Preboot Service 0x06 Buffer Overflow|exploit/windows/novell/zenworks_preboot_op6_bof|✓|-|✗|✓|-

#### 2011 (17)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|BisonWare BisonFTP Server Buffer Overflow|exploit/windows/ftp/bison_ftp_bof|✓|-|✗|✓|-
2|HP OpenView NNM nnmRptConfig nameParams Buffer Overflow|exploit/windows/http/hp_nnm_nnmrptconfig_nameparams|✓|-|✗|✓|-
3|HP OpenView NNM nnmRptConfig.exe schdParams Buffer Overflow|exploit/windows/http/hp_nnm_nnmrptconfig_schdparams|✓|-|✗|✓|-
4|HP OpenView Network Node Manager ov.dll _OVBuildPath Buffer Overflow|exploit/windows/http/hp_nnm_ovbuildpath_textfile|✓|-|✗|✓|-
5|HP Power Manager 'formExportDataLogs' Buffer Overflow|exploit/windows/http/hp_power_manager_filename|✓|-|✗|✓|-
6|Avaya WinPMD UniteHostRouter Buffer Overflow|exploit/windows/misc/avaya_winpmd_unihostrouter|✗|-|✗|✓|-
7|Avid Media Composer 5.5 - Avid Phonetic Indexer Buffer Overflow|exploit/windows/misc/avidphoneticindexer|✓|-|✗|✓|-
8|Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020000 Buffer Overflow|exploit/windows/misc/citrix_streamprocess_data_msg|✓|-|✗|✓|-
9|Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020004 Buffer Overflow|exploit/windows/misc/citrix_streamprocess_get_boot_record_request|✓|-|✗|✓|-
10|Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020002 Buffer Overflow|exploit/windows/misc/citrix_streamprocess_get_footer|✓|-|✗|✓|-
11|Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020006 Buffer Overflow|exploit/windows/misc/citrix_streamprocess_get_objects|✓|-|✗|✓|-
12|Enterasys NetSight nssyslogd.exe Buffer Overflow|exploit/windows/misc/enterasys_netsight_syslog_bof|✗|-|✗|✓|-
13|SCADA 3S CoDeSys CmpWebServer Stack Buffer Overflow|exploit/windows/scada/codesys_web_server|✓|-|✗|✓|-
14|Siemens FactoryLink 8 CSService Logging Path Param Buffer Overflow|exploit/windows/scada/factorylink_csservice|✓|-|✗|✓|-
15|7-Technologies IGSS 9 IGSSdataServer .RMS Rename Buffer Overflow|exploit/windows/scada/igss9_igssdataserver_rename|✓|-|✗|✓|-
16|Procyon Core Server HMI Coreservice.exe Stack Buffer Overflow|exploit/windows/scada/procyon_core_server|✓|-|✗|✓|-
17|NJStar Communicator 3.00 MiniSMTP Buffer Overflow|exploit/windows/smtp/njstar_smtp_bof|✗|-|✗|✓|-

#### 2012 (23)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP System Management Anonymous Access Code Execution|exploit/linux/http/hp_system_management|✗|-|✗|✓|-
2|Novell eDirectory 8 Buffer Overflow|exploit/linux/misc/novell_edirectory_ncp_bof|✓|-|✗|✓|-
3|Samba SetInformationPolicy AuditEventsInfo Heap Overflow|exploit/linux/samba/setinfopolicy_heap|✗|-|✗|✓|-
4|phpMyAdmin 3.5.2.2 server_sync.php Backdoor|exploit/multi/http/phpmyadmin_3522_backdoor|✓|-|✗|✓|-
5|EMC Networker Format String|exploit/windows/emc/networker_format_string|✗|-|✗|✓|-
6|Free Float FTP Server USER Command Buffer Overflow|exploit/windows/ftp/freefloatftp_user|✓|-|✗|✓|-
7|Ricoh DC DL-10 SR10 FTP USER Command Buffer Overflow|exploit/windows/ftp/ricoh_dl_bof|✓|-|✗|✓|-
8|NetDecision 4.5.1 HTTP Server Buffer Overflow|exploit/windows/http/netdecision_http_bof|✓|-|✗|✓|-
9|PHP apache_request_headers Function Buffer Overflow|exploit/windows/http/php_apache_request_headers_bof|✓|-|✗|✓|✓
10|RabidHamster R4 Log Entry sprintf() Buffer Overflow|exploit/windows/http/rabidhamster_r4_log|✓|-|✗|✓|-
11|Simple Web Server Connection Header Buffer Overflow|exploit/windows/http/sws_connection_bof|✓|-|✗|✓|-
12|FlexNet License Server Manager lmgrd Buffer Overflow|exploit/windows/license/flexnet_lmgrd_bof|✗|-|✗|✓|-
13|ALLMediaServer 0.8 Buffer Overflow|exploit/windows/misc/allmediaserver_bof|✗|-|✗|✓|-
14|GIMP script-fu Server Buffer Overflow|exploit/windows/misc/gimp_script_fu|✗|-|✗|✓|-
15|HP Data Protector Create New Folder Buffer Overflow|exploit/windows/misc/hp_dataprotector_new_folder|✗|✓|✗|✓|-
16|HP Intelligent Management Center UAM Buffer Overflow|exploit/windows/misc/hp_imc_uam|✓|-|✗|✓|-
17|IBM Cognos tm1admsd.exe Overflow|exploit/windows/misc/ibm_cognos_tm1admsd_bof|✓|-|✗|✓|-
18|Poison Ivy Server Buffer Overflow|exploit/windows/misc/poisonivy_bof|✗|-|✗|✓|-
19|SAP NetWeaver Dispatcher DiagTraceR3Info Buffer Overflow|exploit/windows/misc/sap_netweaver_dispatcher|✗|-|✗|✓|-
20|Novell ZENworks Configuration Management Preboot Service 0x4c Buffer Overflow|exploit/windows/novell/zenworks_preboot_op4c_bof|✗|-|✗|✓|-
21|Novell ZENworks Configuration Management Preboot Service 0x6c Buffer Overflow|exploit/windows/novell/zenworks_preboot_op6c_bof|✗|-|✗|✓|-
22|Sielco Sistemi Winlog Buffer Overflow 2.07.14 - 2.07.16|exploit/windows/scada/winlog_runtime_2|✓|-|✗|✓|-
23|Sysax 5.53 SSH Username Buffer Overflow|exploit/windows/ssh/sysax_ssh_username|✗|-|✗|✓|-

#### 2013 (18)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|D-Link authentication.cgi Buffer Overflow|exploit/linux/http/dlink_authentication_cgi_bof|✓|-|✗|✓|-
2|D-Link hedwig.cgi Buffer Overflow in Cookie Header|exploit/linux/http/dlink_hedwig_cgi_bof|✓|-|✗|✓|-
3|D-Link Devices UPnP SOAP Command Execution|exploit/linux/http/dlink_upnp_exec_noauth|✗|-|✗|✓|-
4|HP StorageWorks P4000 Virtual SAN Appliance Login Buffer Overflow|exploit/linux/misc/hp_vsa_login_bof|✓|-|✗|✓|-
5|MiniUPnPd 1.0 Stack Buffer Overflow Remote Code Execution|exploit/linux/upnp/miniupnpd_soap_bof|✗|-|✗|✓|-
6|FTP JCL Execution|exploit/mainframe/ftp/ftp_jcl_creds|✓|-|✗|✓|-
7|Portable UPnP SDK unique_service_name() Remote Code Execution|exploit/multi/upnp/libupnp_ssdp_overflow|✓|-|✗|✓|-
8|Polycom Command Shell Authorization Bypass|exploit/unix/misc/polycom_hdx_auth_bypass|✓|-|✗|✓|-
9|WordPress Plugin Google Document Embedder Arbitrary File Disclosure|exploit/unix/webapp/wp_google_document_embedder_exec|✓|-|✗|✓|✓
10|freeFTPd PASS Command Buffer Overflow|exploit/windows/ftp/freeftpd_pass|✓|✓|✗|✓|-
11|PCMAN FTP Server Post-Authentication STOR Command Stack Buffer Overflow|exploit/windows/ftp/pcman_stor|✓|-|✗|✓|-
12|Cogent DataHub HTTP Server Buffer Overflow|exploit/windows/http/cogent_datahub_request_headers_bof|✓|-|✗|✓|-
13|Ultra Mini HTTPD Stack Buffer Overflow|exploit/windows/http/ultraminihttp_bof|✗|-|✗|✓|-
14|BigAnt Server 2 SCH And DUPF Buffer Overflow|exploit/windows/misc/bigant_server_sch_dupf_bof|✗|-|✗|✓|-
15|Firebird Relational Database CNCT Group Number Buffer Overflow|exploit/windows/misc/fb_cnct_group|✗|-|✗|✓|-
16|HP Data Protector Cell Request Service Buffer Overflow|exploit/windows/misc/hp_dataprotector_crs|✓|-|✗|-|-
17|HP LoadRunner magentproc.exe Overflow|exploit/windows/misc/hp_loadrunner_magentproc|✓|-|✗|✓|-
18|Lianja SQL 1.0.0RC5.1 db_netserver Stack Buffer Overflow|exploit/windows/misc/lianja_db_net|✗|-|✗|✓|-

#### 2014 (14)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Belkin Play N750 login.cgi Buffer Overflow|exploit/linux/http/belkin_login_bof|✓|-|✗|✓|-
2|D-Link info.cgi POST Request Buffer Overflow|exploit/linux/http/dlink_dspw215_info_cgi_bof|✓|-|✗|✓|-
3|D-Link HNAP Request Remote Buffer Overflow|exploit/linux/http/dlink_hnap_bof|✓|-|✗|✓|-
4|Arris VAP2500 tools_command.php Command Execution|exploit/linux/http/vap2500_tools_command_exec|✓|-|✗|✓|-
5|Hikvision DVR RTSP Request Remote Code Execution|exploit/linux/misc/hikvision_rtsp_bof|✗|-|✗|✓|-
6|HP Network Node Manager I PMD Buffer Overflow|exploit/linux/misc/hp_nnmi_pmd_bof|✓|-|✗|✓|-
7|Netcore Router Udp 53413 Backdoor|exploit/linux/misc/netcore_udp_53413_backdoor|✗|-|✗|✓|-
8|Qmail SMTP Bash Environment Variable Injection (Shellshock)|exploit/unix/smtp/qmail_bash_env_exec|✓|-|✗|✓|-
9|Easy File Management Web Server Stack Buffer Overflow|exploit/windows/http/efs_fmws_userid_bof|✓|-|✗|✓|✓
10|Ericom AccessNow Server Buffer Overflow|exploit/windows/http/ericom_access_now_bof|✓|-|✗|✓|-
11|Achat Unicode SEH Buffer Overflow|exploit/windows/misc/achat_bof|✓|-|✗|✓|-
12|Yokogawa CENTUM CS 3000 BKBCopyD.exe Buffer Overflow|exploit/windows/scada/yokogawa_bkbcopyd_bof|✓|-|✗|✓|-
13|Yokogawa CS3000 BKESimmgr.exe Buffer Overflow|exploit/windows/scada/yokogawa_bkesimmgr_bof|✓|-|✗|✓|-
14|Yokogawa CS3000 BKFSim_vhfd.exe Buffer Overflow|exploit/windows/scada/yokogawa_bkfsim_vhfd|✓|-|✗|✓|-

#### 2015 (10)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Airties login-cgi Buffer Overflow|exploit/linux/http/airties_login_cgi_bof|✓|-|✗|✓|-
2|D-Link Cookie Command Execution|exploit/linux/http/dlink_dspw110_cookie_noauth_exec|✗|-|✗|✓|-
3|D-Link Devices HNAP SOAPAction-Header Command Execution|exploit/linux/http/dlink_hnap_header_exec_noauth|✗|-|✗|✓|-
4|D-Link/TRENDnet NCC Service Command Injection|exploit/linux/http/multi_ncc_ping_exec|✗|-|✗|✓|✓
5|Realtek SDK Miniigd UPnP SOAP Command Execution|exploit/linux/http/realtek_miniigd_upnp_exec_noauth|✗|-|✗|✓|-
6|Seagate Business NAS Unauthenticated Remote Command Execution|exploit/linux/http/seagate_nas_php_exec_noauth|✓|-|✗|✓|✓
7|OpenNMS Java Object Unserialization Remote Code Execution|exploit/linux/misc/opennms_java_serialize|✗|-|✗|✓|-
8|Apache James Server 2.3.2 Insecure User Creation Arbitrary File Write|exploit/linux/smtp/apache_james_exec|✗|✓|✗|✓|-
9|Konica Minolta FTP Utility 1.00 Post Auth CWD Command SEH Overflow|exploit/windows/ftp/kmftp_utility_cwd|✓|-|✗|✓|-
10|PCMAN FTP Server Buffer Overflow - PUT Command|exploit/windows/ftp/pcman_put|✓|-|✗|✓|-

#### 2016 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Zyxel/Eir D1000 DSL Modem NewNTPServer Command Injection Over TR-064|exploit/linux/http/tr064_ntpserver_cmdinject|✗|-|✗|✓|-
2|Poison Ivy 2.1.x C2 Buffer Overflow|exploit/windows/misc/poisonivy_21x_bof|✓|-|✗|✓|-

#### 2017 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP Jetdirect Path Traversal Arbitrary Code Execution|exploit/linux/misc/hp_jetdirect_path_traversal|✓|-|✗|✓|-
2|Quest Privilege Manager pmmasterd Buffer Overflow|exploit/linux/misc/quest_pmmasterd_bof|✗|-|✗|✓|-
3|Easy Chat Server User Registeration Buffer Overflow (SEH)|exploit/windows/http/easychatserver_seh|✓|-|✗|✓|-
4|Geutebrueck GCore - GCoreServer.exe Buffer Overflow RCE|exploit/windows/http/geutebrueck_gcore_x64_rce_bo|✓|-|✗|✓|-
5|Gh0st Client buffer Overflow|exploit/windows/misc/gh0st|✓|-|✗|✓|-
6|PlugX Controller Stack Buffer Overflow|exploit/windows/misc/plugx|✗|-|✗|✓|-

#### 2018 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Cisco RV320 and RV325 Unauthenticated Remote Code Execution|exploit/linux/http/cisco_rv32x_rce|✓|-|✗|✓|-
2|Nuuo Central Management Authenticated SQL Server SQLi|exploit/windows/nuuo/nuuo_cms_sqli|✓|-|✗|✓|-
3|Delta Electronics Delta Industrial Automation COMMGR 1.08 Stack Buffer Overflow|exploit/windows/scada/delta_ia_commgr_bof|✓|-|✗|✓|-

#### 2019 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|OpenMRS Java Deserialization RCE|exploit/multi/http/openmrs_deserialization|✓|-|✗|✓|✓
2|PHP-FPM Underflow RCE|exploit/multi/http/php_fpm_rce|✗|-|✗|✓|✓
3|Drupal RESTful Web Services unserialize() RCE|exploit/unix/webapp/drupal_restws_unserialize|✗|-|✗|✓|✓
4|File Sharing Wizard - POST SEH Overflow|exploit/windows/http/file_sharing_wizard_seh|✓|-|✗|✓|-

#### 2020 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SpamTitan Unauthenticated RCE|exploit/freebsd/webapp/spamtitan_unauth_rce|✗|-|✗|✓|✓
2|AnyDesk GUI Format String Write|exploit/linux/misc/cve_2020_13160_anydesk|✗|-|✗|✓|-
3|WordPress File Manager Unauthenticated Remote Code Execution|exploit/multi/http/wp_file_manager_rce|✓|-|✗|✓|✓
4|WebLogic Server Deserialization RCE BadAttributeValueExpException ExtComp|exploit/multi/misc/weblogic_deserialize_badattr_extcomp|✗|-|✗|✓|-
5|WebLogic Server Deserialization RCE - BadAttributeValueExpException|exploit/multi/misc/weblogic_deserialize_badattrval|✗|-|✗|✓|-
6|Veeam ONE Agent .NET Deserialization|exploit/windows/misc/veeam_one_agent_deserialization|✗|-|✗|✓|-


### Good Ranking (105)

#### 2000 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|UoW IMAP Server LSUB Buffer Overflow|exploit/linux/imap/imap_uw_lsub|✓|-|✗|✓|-
2|MS00-094 Microsoft IIS Phone Book Service Overflow|exploit/windows/isapi/ms00_094_pbserver|✗|-|✗|✓|-

#### 2001 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|NTP Daemon readvar Buffer Overflow|exploit/multi/ntp/ntp_overflow|✗|-|✗|✓|-
2|MS01-023 Microsoft IIS 5.0 Printer Host Header Overflow|exploit/windows/iis/ms01_023_printer|✓|-|✗|✓|-
3|MS01-033 Microsoft IIS 5.0 IDQ Path Overflow|exploit/windows/iis/ms01_033_idq|✗|-|✗|✓|-
4|Network Associates PGP KeyServer 7 LDAP Buffer Overflow|exploit/windows/ldap/pgp_keyserver7|✓|-|✗|✓|-
5|Oracle 8i TNS Listener (ARGUMENTS) Buffer Overflow|exploit/windows/oracle/tns_arguments|✗|-|✗|✓|-

#### 2002 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apache Win32 Chunked Encoding|exploit/windows/http/apache_chunked|✗|-|✗|✓|-
2|MS02-018 Microsoft IIS 4.0 .HTR Path Overflow|exploit/windows/iis/ms02_018_htr|✗|-|✗|✓|-
3|MS02-039 Microsoft SQL Server Resolution Overflow|exploit/windows/mssql/ms02_039_slammer|✓|-|✗|✓|-
4|MS02-056 Microsoft SQL Server Hello Overflow|exploit/windows/mssql/ms02_056_hello|✓|-|✗|✓|-
5|Oracle 8i TNS Listener SERVICE_NAME Buffer Overflow|exploit/windows/oracle/tns_service_name|✗|-|✗|✓|-

#### 2003 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS03-022 Microsoft IIS ISAPI nsiislog.dll ISAPI POST Overflow|exploit/windows/isapi/ms03_022_nsiislog_post|✗|-|✗|✓|-
2|MS03-051 Microsoft IIS ISAPI FrontPage fp30reg.dll Chunked Overflow|exploit/windows/isapi/ms03_051_fp30reg_chunked|✗|-|✗|✓|-
3|NIPrint LPD Request Overflow|exploit/windows/lpd/niprint|✗|-|✗|✓|-
4|MS03-049 Microsoft Workstation Service NetAddAlternateComputerName Overflow|exploit/windows/smb/ms03_049_netapi|✓|-|✗|✓|-
5|MS03-046 Exchange 2000 XEXCH50 Heap Overflow|exploit/windows/smtp/ms03_046_exchange2000_xexch50|✓|-|✗|✓|-

#### 2004 (7)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Unreal Tournament 2004 "secure" Overflow (Linux)|exploit/linux/games/ut2004_secure|✓|-|✗|✓|-
2|BolinTech Dream FTP Server 1.02 Format String|exploit/windows/ftp/dreamftp_format|✓|-|✗|✓|-
3|Serv-U FTPD MDTM Overflow|exploit/windows/ftp/servu_mdtm|✗|-|✗|✓|-
4|Unreal Tournament 2004 "secure" Overflow (Win32)|exploit/windows/games/ut2004_secure|✓|-|✗|✓|-
5|Microsoft IIS ISAPI w3who.dll Query String Overflow|exploit/windows/isapi/w3who_query|✓|-|✗|✓|-
6|MS04-011 Microsoft LSASS Service DsRolerUpgradeDownlevelServer Overflow|exploit/windows/smb/ms04_011_lsass|✓|-|✗|✓|-
7|MS04-031 Microsoft NetDDE Service Overflow|exploit/windows/smb/ms04_031_netdde|✓|-|✗|✓|-

#### 2005 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Snort Back Orifice Pre-Preprocessor Buffer Overflow|exploit/linux/ids/snortbopre|✓|-|✗|✓|-
2|GLD (Greylisting Daemon) Postfix Buffer Overflow|exploit/linux/misc/gld_postfix|✓|-|✗|✓|-
3|Arkeia Backup Client Type 77 Overflow (Win32)|exploit/windows/arkeia/type77|✗|-|✗|✓|-
4|MaxDB WebDBM GET Buffer Overflow|exploit/windows/http/maxdb_webdbm_get_overflow|✗|-|✗|✓|-
5|Microsoft IIS ISAPI RSA WebAgent Redirect Overflow|exploit/windows/isapi/rsa_webagent_redirect|✗|-|✗|✓|-
6|MS05-039 Microsoft Plug and Play Service Overflow|exploit/windows/smb/ms05_039_pnp|✗|-|✗|✓|-

#### 2006 (7)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Symantec Remote Management Buffer Overflow|exploit/windows/antivirus/symantec_rtvscan|✓|-|✗|✓|-
2|MaxDB WebDBM Database Parameter Overflow|exploit/windows/http/maxdb_webdbm_database|✗|-|✗|✓|-
3|Qbik WinGate WWW Proxy Server URL Processing Overflow|exploit/windows/proxy/qbik_wingate_wwwproxy|✓|-|✗|✓|-
4|MS06-025 Microsoft RRAS Service RASMAN Registry Overflow|exploit/windows/smb/ms06_025_rasmans_reg|✓|-|✗|✓|-
5|MS06-040 Microsoft Server Service NetpwPathCanonicalize Overflow|exploit/windows/smb/ms06_040_netapi|✓|-|✗|✓|-
6|MS06-066 Microsoft Services nwapi32.dll Module Exploit|exploit/windows/smb/ms06_066_nwapi|✓|-|✗|✓|-
7|MS06-066 Microsoft Services nwwks.dll Module Exploit|exploit/windows/smb/ms06_066_nwwks|✓|-|✗|✓|-

#### 2007 (15)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Borland InterBase INET_connect() Buffer Overflow|exploit/linux/misc/ib_inet_connect|✓|-|✗|✓|-
2|Borland InterBase jrd8_create_database() Buffer Overflow|exploit/linux/misc/ib_jrd8_create_database|✓|-|✗|✓|-
3|Borland InterBase open_marker_file() Buffer Overflow|exploit/linux/misc/ib_open_marker_file|✓|-|✗|✓|-
4|Borland InterBase PWD_db_aliased() Buffer Overflow|exploit/linux/misc/ib_pwd_db_aliased|✓|-|✗|✓|-
5|Samba lsa_io_trans_names Heap Overflow|exploit/linux/samba/lsa_transnames_heap|✗|-|✗|✓|-
6|Trend Micro ServerProtect 5.58 Buffer Overflow|exploit/windows/antivirus/trendmicro_serverprotect|✓|-|✗|✓|-
7|Trend Micro ServerProtect 5.58 CreateBinding() Buffer Overflow|exploit/windows/antivirus/trendmicro_serverprotect_createbinding|✓|-|✗|✓|-
8|Trend Micro ServerProtect 5.58 EarthAgent.EXE Buffer Overflow|exploit/windows/antivirus/trendmicro_serverprotect_earthagent|✓|-|✗|✓|-
9|IBM TPM for OS Deployment 5.1.0.x rembo.exe Buffer Overflow|exploit/windows/http/ibm_tpmfosd_overflow|✗|-|✗|✓|-
10|IBM Tivoli Storage Manager Express CAD Service Buffer Overflow|exploit/windows/http/ibm_tsm_cad_header|✓|-|✗|✓|-
11|Trend Micro OfficeScan Remote Stack Buffer Overflow|exploit/windows/http/trendmicro_officescan|✓|-|✗|✓|-
12|Borland InterBase isc_attach_database() Buffer Overflow|exploit/windows/misc/ib_isc_attach_database|✗|-|✗|✓|-
13|Borland InterBase isc_create_database() Buffer Overflow|exploit/windows/misc/ib_isc_create_database|✗|-|✗|✓|-
14|Borland InterBase SVC_attach() Buffer Overflow|exploit/windows/misc/ib_svc_attach|✗|-|✗|✓|-
15|D-Link TFTP 1.0 Long Filename Buffer Overflow|exploit/windows/tftp/dlink_long_filename|✗|-|✗|✓|-

#### 2008 (7)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MySQL yaSSL SSL Hello Message Buffer Overflow|exploit/linux/mysql/mysql_yassl_hello|✓|-|✗|✓|-
2|HP OpenView NNM 7.53, 7.51 OVAS.EXE Pre-Authentication Stack Buffer Overflow|exploit/windows/http/hp_nnm_ovas|✓|-|✗|✓|-
3|Now SMS/MMS Gateway Buffer Overflow|exploit/windows/http/nowsms|✓|-|✗|✓|-
4|SAP SAPLPD 6.28 Buffer Overflow|exploit/windows/lpd/saplpd|✓|-|✗|✓|-
5|WinComLPD Buffer Overflow|exploit/windows/lpd/wincomlpd_admin|✓|-|✗|✓|-
6|MS09-004 Microsoft SQL Server sp_replwritetovarbin Memory Corruption|exploit/windows/mssql/ms09_004_sp_replwritetovarbin|✓|-|✗|✓|-
7|Quick FTP Pro 2.1 Transfer-Mode Overflow|exploit/windows/tftp/quick_tftp_pro_mode|✗|-|✗|✓|-

#### 2009 (9)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|NetWare 6.5 SunRPC Portmapper CALLIT Stack Buffer Overflow|exploit/netware/sunrpc/pkernel_callit|✓|-|✗|✓|-
2|Symantec Alert Management System Intel Alert Originator Service Buffer Overflow|exploit/windows/antivirus/symantec_iao|✗|-|✗|✓|-
3|Xlink FTP Server Buffer Overflow|exploit/windows/ftp/xlink_server|✓|-|✗|✓|-
4|BEA WebLogic JSESSIONID Cookie Value Overflow|exploit/windows/http/bea_weblogic_jsessionid|✗|-|✗|✓|-
5|Rhinosoft Serv-U Session Cookie Buffer Overflow|exploit/windows/http/servu_session_cookie|✗|-|✗|✓|-
6|Bopup Communications Server Buffer Overflow|exploit/windows/misc/bopup_comm|✓|-|✗|✓|-
7|IBM Tivoli Storage Manager Express CAD Service Buffer Overflow|exploit/windows/misc/ibm_tsm_cad_ping|✓|-|✗|✓|-
8|Oracle Secure Backup NDMP_CONNECT_CLIENT_AUTH Buffer Overflow|exploit/windows/oracle/osb_ndmp_auth|✓|-|✗|✓|-
9|MS09-050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference|exploit/windows/smb/ms09_050_smb2_negotiate_func_index|✓|-|✗|✓|-

#### 2010 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MySQL yaSSL CertDecoder::GetName Buffer Overflow|exploit/linux/mysql/mysql_yassl_getname|✓|-|✗|✓|-
2|Samba chain_reply Memory Corruption (Linux x86)|exploit/linux/samba/chain_reply|✗|-|✗|✓|-
3|Java Debug Wire Protocol Remote Code Execution|exploit/multi/misc/java_jdwp_debugger|✗|-|✗|✓|-
4|Kolibri HTTP Server HEAD Buffer Overflow|exploit/windows/http/kolibri_http|✗|-|✗|✓|-
5|AgentX++ Master AgentX::receive_agentx Stack Buffer Overflow|exploit/windows/misc/agentxpp_receive_agentx|✓|-|✗|✓|-

#### 2011 (7)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|IBM Tivoli Endpoint Manager POST Query Buffer Overflow|exploit/windows/http/ibm_tivoli_endpoint_bof|✓|-|✗|✓|-
2|Blue Coat Authentication and Authorization Agent (BCAAA) 5 Buffer Overflow|exploit/windows/misc/bcaaa_bof|✓|-|✗|✓|-
3|Citrix Provisioning Services 5.6 streamprocess.exe Buffer Overflow|exploit/windows/misc/citrix_streamprocess|✓|-|✗|✓|-
4|HP OmniInet.exe Opcode 20 Buffer Overflow|exploit/windows/misc/hp_omniinet_4|✓|-|✗|✓|-
5|TrendMicro Control Manger CmdProcessor.exe Stack Buffer Overflow|exploit/windows/misc/trendmicro_cmdprocessor_addtask|✓|-|✗|✓|-
6|Iconics GENESIS32 Integer Overflow Version 9.21.201.01|exploit/windows/scada/iconics_genbroker|✓|-|✗|✓|-
7|7-Technologies IGSS IGSSdataServer.exe Stack Buffer Overflow|exploit/windows/scada/igss9_igssdataserver_listall|✓|-|✗|✓|-

#### 2012 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Zenoss 3 showDaemonXMLConfig Command Execution|exploit/linux/http/zenoss_showdaemonxmlconfig_exec|✓|✓|✗|✓|-
2|HP SiteScope Remote Code Execution|exploit/multi/http/hp_sitescope_uploadfileshandler|✗|-|✗|✓|✓
3|Netwin SurgeFTP Remote Command Execution|exploit/multi/http/netwin_surgeftp_exec|✓|✓|✗|✓|-
4|Splunk Custom App Remote Code Execution|exploit/multi/http/splunk_upload_app_exec|✓|✓|✗|✓|-
5|Xerox Multifunction Printers (MFP) "Patch" DLM Vulnerability|exploit/unix/misc/xerox_mfp|✓|-|✗|✓|-
6|ComSndFTP v1.3.7 Beta USER Format String (Write4) Vulnerability|exploit/windows/ftp/comsnd_ftpd_fmtstr|✓|-|✗|✓|-

#### 2013 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Supermicro Onboard IPMI close_window.cgi Buffer Overflow|exploit/linux/http/smt_ipmi_close_window_bof|✓|-|✗|✓|-
2|Jenkins-CI Script-Console Java Execution|exploit/multi/http/jenkins_script_console|✗|-|✗|✓|✓

#### 2014 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SolidWorks Workgroup PDM 2014 pdmwService.exe Arbitrary File Write|exploit/windows/misc/solidworks_workgroup_pdmwservice_file_write|✓|-|✗|✓|-

#### 2015 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SixApart MovableType Storable Perl Code Execution|exploit/unix/webapp/sixapart_movabletype_storable_exec|✓|-|✗|✓|✓
2|HP SiteScope DNS Tool Command Injection|exploit/windows/http/hp_sitescope_dns_tool|✗|-|✗|✓|✓

#### 2016 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|PostgreSQL CREATE LANGUAGE Execution|exploit/multi/postgres/postgres_createlang|✓|✓|✗|✓|-

#### 2017 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Samsung SRN-1670D Web Viewer Version 1.0.0.193 Arbitrary File Read and Upload|exploit/linux/http/samsung_srv_1670d_upload_exec|✓|-|✗|✓|-
2|MediaWiki SyntaxHighlight extension option injection vulnerability|exploit/multi/http/mediawiki_syntaxhighlight|✓|-|✗|✓|✓
3|OrientDB 2.2.x Remote Code Execution|exploit/multi/http/orientdb_exec|✗|✓|✗|✓|✓
4|Commvault Communications Service (cvd) Command Injection|exploit/windows/misc/commvault_cmd_exec|✓|-|✗|✓|-
5|Advantech WebAccess Webvrpcs Service Opcode 80061 Stack Buffer Overflow|exploit/windows/scada/advantech_webaccess_webvrpcs_bof|✓|-|✗|✓|-

#### 2018 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|php imap_open Remote Code Execution|exploit/linux/http/php_imap_open_rce|✗|-|✗|✓|✓
2|Redis Replication Code Execution|exploit/linux/redis/redis_replication_cmd_exec|✓|-|✗|✓|-
3|phpMyAdmin Authenticated Remote Code Execution|exploit/multi/http/phpmyadmin_lfi_rce|✓|✓|✗|✓|✓

#### 2019 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Cisco RV110W/RV130(W)/RV215W Routers Management Interface Remote Command Execution|exploit/linux/http/cve_2019_1663_cisco_rmi_rce|✗|-|✗|✓|-
2|Nostromo Directory Traversal Remote Command Execution|exploit/multi/http/nostromo_code_exec|✓|-|✗|✓|-

#### 2020 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Rconfig 3.x Chained Remote Code Execution|exploit/linux/http/rconfig_ajaxarchivefiles_rce|✓|-|✗|✓|✓
2|WordPress Simple File List Unauthenticated Remote Code Execution|exploit/multi/http/wp_simple_file_list_rce|✓|-|✗|✓|✓
3|Pi-Hole DHCP MAC OS Command Execution|exploit/unix/http/pihole_dhcp_mac_exec|✓|-|✗|✓|✓


### Great Ranking (163)

#### 2000 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|WU-FTPD SITE EXEC/INDEX Format String Vulnerability|exploit/multi/ftp/wuftpd_site_exec_format|✓|-|✗|✓|-

#### 2002 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|RealServer Describe Buffer Overflow|exploit/multi/realserver/describe|✓|-|✗|✓|-
2|Solaris dtspcd Heap Overflow|exploit/solaris/dtspcd/heap_noir|✓|-|✗|✓|-
3|Savant 3.1 Web Server Overflow|exploit/windows/http/savant_31_overflow|✗|-|✗|✓|-

#### 2003 (13)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Samba trans2open Overflow (*BSD x86)|exploit/freebsd/samba/trans2open|✓|-|✗|✓|-
2|Poptop Negative Read Overflow|exploit/linux/pptp/poptop_negative_read|✓|-|✗|✓|-
3|Samba trans2open Overflow (Linux x86)|exploit/linux/samba/trans2open|✓|-|✗|✓|-
4|Samba trans2open Overflow (Mac OS X PPC)|exploit/osx/samba/trans2open|✓|-|✗|✓|-
5|Samba trans2open Overflow (Solaris SPARC)|exploit/solaris/samba/trans2open|✗|-|✗|✓|-
6|MS03-026 Microsoft RPC DCOM Interface Overflow|exploit/windows/dcerpc/ms03_026_dcom|✓|-|✗|✓|-
7|Oracle 9i XDB FTP PASS Overflow (win32)|exploit/windows/ftp/oracle9i_xdb_ftp_pass|✓|-|✗|✓|-
8|Oracle 9i XDB FTP UNLOCK Overflow (win32)|exploit/windows/ftp/oracle9i_xdb_ftp_unlock|✓|✓|✗|✓|-
9|BadBlue 2.5 EXT.dll Buffer Overflow|exploit/windows/http/badblue_ext_overflow|✓|-|✗|✓|-
10|MDaemon WorldClient form2raw.cgi Stack Buffer Overflow|exploit/windows/http/mdaemon_worldclient_form2raw|✗|-|✗|✓|-
11|Oracle 9i XDB HTTP PASS Overflow (win32)|exploit/windows/http/oracle9i_xdb_pass|✓|-|✗|✓|-
12|MS03-007 Microsoft IIS 5.0 WebDAV ntdll.dll Path Overflow|exploit/windows/iis/ms03_007_ntdll_webdav|✓|-|✗|✓|-
13|Seattle Lab Mail 5.5 POP3 Buffer Overflow|exploit/windows/pop3/seattlelab_pass|✓|-|✗|✓|-

#### 2004 (10)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Mercantec SoftCart CGI Overflow|exploit/bsdi/softcart/mercantec_softcart|✓|-|✗|✓|-
2|ISS PAM.dll ICQ Parser Buffer Overflow|exploit/windows/firewall/blackice_pam_icq|✗|-|✗|✓|-
3|WS-FTP Server 5.03 MKD Overflow|exploit/windows/ftp/wsftp_server_503_mkd|✓|-|✗|✓|-
4|Medal of Honor Allied Assault getinfo Stack Buffer Overflow|exploit/windows/games/mohaa_getinfo|✓|-|✗|✓|-
5|Icecast Header Overwrite|exploit/windows/http/icecast_header|✓|-|✗|✓|-
6|Ipswitch WhatsUp Gold 8.03 Buffer Overflow|exploit/windows/http/ipswitch_wug_maincfgret|✓|✓|✗|✓|-
7|Mdaemon 8.0.3 IMAPD CRAM-MD5 Authentication Overflow|exploit/windows/imap/mdaemon_cram_md5|✓|-|✗|✓|-
8|ShixxNOTE 6.net Font Field Overflow|exploit/windows/misc/shixxnote_font|✓|-|✗|✓|-
9|Proxy-Pro Professional GateKeeper 4.7 GET Request Overflow|exploit/windows/proxy/proxypro_http_get|✓|-|✗|✓|-
10|MS04-045 Microsoft WINS Service Memory Overwrite|exploit/windows/wins/ms04_045_wins|✓|-|✗|✓|-

#### 2005 (11)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Linksys WRT54 Access Point apply.cgi Buffer Overflow|exploit/linux/http/linksys_apply_cgi|✗|-|✓|✓|-
2|Veritas Backup Exec Windows Remote Agent Overflow|exploit/windows/backupexec/remote_agent|✗|-|✗|✓|-
3|GlobalSCAPE Secure FTP Server Input Overflow|exploit/windows/ftp/globalscapeftp_input|✓|-|✗|✓|-
4|NetTerm NetFTPD USER Buffer Overflow|exploit/windows/ftp/netterm_netftpd_user|✗|-|✗|✓|-
5|SlimFTPd LIST Concatenation Overflow|exploit/windows/ftp/slimftpd_list_concat|✓|-|✗|✓|-
6|eDirectory 8.7.3 iMonitor Remote Stack Buffer Overflow|exploit/windows/http/edirectory_imonitor|✓|-|✗|✓|-
7|MailEnable Authorization Header Buffer Overflow|exploit/windows/http/mailenable_auth_header|✓|-|✗|✓|-
8|Qualcomm WorldMail 3.0 IMAPD LIST Buffer Overflow|exploit/windows/imap/eudora_list|✓|-|✗|✓|-
9|MailEnable IMAPD (1.54) STATUS Request Buffer Overflow|exploit/windows/imap/mailenable_status|✗|-|✗|✓|-
10|MailEnable IMAPD W3C Logging Buffer Overflow|exploit/windows/imap/mailenable_w3c_select|✓|-|✗|✓|-
11|Blue Coat WinProxy Host Header Overflow|exploit/windows/proxy/bluecoat_winproxy_host|✓|-|✗|✓|-

#### 2006 (10)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|ProFTPD 1.2 - 1.3.0 sreplace Buffer Overflow (Linux)|exploit/linux/ftp/proftp_sreplace|✓|-|✗|✓|-
2|Apache Module mod_rewrite LDAP Protocol Buffer Overflow|exploit/windows/http/apache_mod_rewrite_ldap|✓|-|✗|✓|-
3|Novell eDirectory NDS Server Host Header Overflow|exploit/windows/http/edirectory_host|✓|-|✗|✓|-
4|NaviCOPA 2.0.1 URL Handling Buffer Overflow|exploit/windows/http/navicopa_get_overflow|✓|-|✗|✓|-
5|MailEnable IMAPD (2.34/2.35) Login Request Buffer Overflow|exploit/windows/imap/mailenable_login|✗|-|✗|✓|-
6|AIM Triton 1.0.4 CSeq Buffer Overflow|exploit/windows/sip/aim_triton_cseq|✓|-|✗|✓|-
7|SIPfoundry sipXezPhone 0.35a CSeq Field Overflow|exploit/windows/sip/sipxezphone_cseq|✓|-|✗|✓|-
8|SIPfoundry sipXphone 2.6.0.27 CSeq Buffer Overflow|exploit/windows/sip/sipxphone_cseq|✓|-|✗|✓|-
9|TFTPDWIN v0.4.2 Long Filename Buffer Overflow|exploit/windows/tftp/tftpdwin_long_filename|✓|-|✗|✓|-
10|3CTftpSvc TFTP Long Mode Buffer Overflow|exploit/windows/tftp/threectftpsvc_long_mode|✓|-|✗|✓|-

#### 2007 (8)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|CA BrightStor HSM Buffer Overflow|exploit/windows/brightstor/hsmserver|✓|-|✗|✓|-
2|MS07-029 Microsoft DNS RPC Service extractQuotedChar() Overflow (TCP)|exploit/windows/dcerpc/ms07_029_msdns_zonename|✓|-|✗|✓|-
3|Apache mod_jk 1.2.20 Buffer Overflow|exploit/windows/http/apache_modjk_overflow|✓|-|✗|✓|-
4|BadBlue 2.72b PassThru Buffer Overflow|exploit/windows/http/badblue_passthru|✗|-|✗|✓|-
5|EFS Easy Chat Server Authentication Request Handling Buffer Overflow|exploit/windows/http/efs_easychatserver_username|✓|-|✗|✓|-
6|HP OpenView Network Node Manager OpenView5.exe CGI Buffer Overflow|exploit/windows/http/hp_nnm_openview5|✓|-|✗|✓|-
7|SAP DB 7.4 WebTools Buffer Overflow|exploit/windows/http/sapdb_webtools|✓|-|✗|✓|-
8|Mercury Mail SMTP AUTH CRAM-MD5 Buffer Overflow|exploit/windows/smtp/mercury_cram_md5|✓|-|✗|✓|-

#### 2008 (9)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Sun Solaris sadmind adm_build_path() Buffer Overflow|exploit/solaris/sunrpc/sadmind_adm_build_path|✗|-|✗|✓|-
2|EMC AlphaStor Agent Buffer Overflow|exploit/windows/emc/alphastor_agent|✓|-|✗|✓|-
3|Racer v0.5.3 Beta 5 Buffer Overflow|exploit/windows/games/racer_503beta5|✗|-|✗|✓|-
4|Oracle Weblogic Apache Connector POST Request Buffer Overflow|exploit/windows/http/bea_weblogic_post_bof|✓|-|✗|✓|✓
5|BEA Weblogic Transfer-Encoding Buffer Overflow|exploit/windows/http/bea_weblogic_transfer_encoding|✓|-|✗|✓|-
6|MDaemon 9.6.4 IMAPD FETCH Buffer Overflow|exploit/windows/imap/mdaemon_fetch|✓|-|✗|✓|-
7|BigAnt Server 2.50 SP1 Buffer Overflow|exploit/windows/misc/bigant_server_250|✗|-|✗|✓|-
8|DATAC RealWin SCADA Server Buffer Overflow|exploit/windows/scada/realwin|✓|-|✗|✓|-
9|MS08-067 Microsoft Server Service Relative Path Stack Corruption|exploit/windows/smb/ms08_067_netapi|✓|-|✗|✓|-

#### 2009 (22)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow|exploit/aix/rpc_cmsd_opcode21|✓|-|✗|✓|-
2|ToolTalk rpc.ttdbserverd _tt_internal_realpath Buffer Overflow (AIX)|exploit/aix/rpc_ttdbserverd_realpath|✗|-|✗|✓|-
3|Open Flash Chart v2 Arbitrary File Upload|exploit/unix/webapp/open_flash_chart_upload_exec|✓|-|✗|✓|✓
4|HTTPDX tolog() Function Format String Vulnerability|exploit/windows/ftp/httpdx_tolog_format|✓|✓|✗|✓|-
5|MS09-053 Microsoft IIS FTP Server NLST Response Overflow|exploit/windows/ftp/ms09_053_ftpd_nlst|✗|-|✗|✓|-
6|Vermillion FTP Daemon PORT Command Memory Corruption|exploit/windows/ftp/vermillion_ftpd_port|✓|-|✗|✓|-
7|Free Download Manager Remote Control Server Buffer Overflow|exploit/windows/http/fdm_auth_header|✓|-|✗|✓|-
8|HP OpenView Network Node Manager ovalarm.exe CGI Buffer Overflow|exploit/windows/http/hp_nnm_ovalarm_lang|✗|-|✗|✓|-
9|HP OpenView Network Node Manager OvWebHelp.exe CGI Buffer Overflow|exploit/windows/http/hp_nnm_ovwebhelp|✓|-|✗|✓|-
10|HP OpenView Network Node Manager Snmp.exe CGI Buffer Overflow|exploit/windows/http/hp_nnm_snmp|✓|-|✗|✓|-
11|HP OpenView Network Node Manager Toolbar.exe CGI Buffer Overflow|exploit/windows/http/hp_nnm_toolbar_01|✓|-|✗|✓|-
12|HTTPDX h_handlepeer() Function Buffer Overflow|exploit/windows/http/httpdx_handlepeer|✗|-|✗|✓|-
13|HTTPDX tolog() Function Format String Vulnerability|exploit/windows/http/httpdx_tolog_format|✓|-|✗|✓|-
14|InterSystems Cache UtilConfigHome.csp Argument Buffer Overflow|exploit/windows/http/intersystems_cache|✓|-|✗|✓|-
15|BigAnt Server 2.52 USV Buffer Overflow|exploit/windows/misc/bigant_server_usv|✓|-|✗|✓|-
16|HP OmniInet.exe MSG_PROTOCOL Buffer Overflow|exploit/windows/misc/hp_omniinet_1|✓|-|✗|✓|-
17|HP OmniInet.exe MSG_PROTOCOL Buffer Overflow|exploit/windows/misc/hp_omniinet_2|✓|-|✗|✓|-
18|IBM Tivoli Storage Manager Express RCA Service Buffer Overflow|exploit/windows/misc/ibm_tsm_rca_dicugetidentify|✓|-|✗|✓|-
19|SAP Business One License Manager 2005 Buffer Overflow|exploit/windows/misc/sap_2005_license|✓|-|✗|✓|-
20|Oracle 10gR2 TNS Listener AUTH_SESSKEY Buffer Overflow|exploit/windows/oracle/tns_auth_sesskey|✓|-|✗|✓|-
21|Novell NetIdentity Agent XTIERRPCPIPE Named Pipe Buffer Overflow|exploit/windows/smb/netidentity_xtierrpcpipe|✓|✓|✗|✓|-
22|Timbuktu PlughNTCommand Named Pipe Buffer Overflow|exploit/windows/smb/timbuktu_plughntcommand_bof|✓|-|✗|✓|-

#### 2010 (24)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (FreeBSD)|exploit/freebsd/ftp/proftp_telnet_iac|✓|-|✗|✓|-
2|ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (Linux)|exploit/linux/ftp/proftp_telnet_iac|✓|-|✗|✓|-
3|FreeNAS exec_raw.php Arbitrary Command Execution|exploit/multi/http/freenas_exec_raw|✓|-|✗|✓|-
4|Sun Java System Web Server WebDAV OPTIONS Buffer Overflow|exploit/multi/http/sun_jsws_dav_options|✗|-|✗|✓|-
5|Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow|exploit/multi/misc/wireshark_lwres_getaddrbyname|✓|-|✗|✓|-
6|Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow (loop)|exploit/multi/misc/wireshark_lwres_getaddrbyname_loop|✗|-|✓|✓|-
7|EasyFTP Server CWD Command Stack Buffer Overflow|exploit/windows/ftp/easyftp_cwd_fixret|✗|-|✗|✓|-
8|EasyFTP Server LIST Command Stack Buffer Overflow|exploit/windows/ftp/easyftp_list_fixret|✓|-|✗|✓|-
9|EasyFTP Server MKD Command Stack Buffer Overflow|exploit/windows/ftp/easyftp_mkd_fixret|✗|-|✗|✓|-
10|EasyFTP Server list.html path Stack Buffer Overflow|exploit/windows/http/easyftp_list|✓|✓|✗|✓|-
11|HP OpenView Network Node Manager getnnmdata.exe (Hostname) CGI Buffer Overflow|exploit/windows/http/hp_nnm_getnnmdata_hostname|✗|-|✗|✓|-
12|HP OpenView Network Node Manager getnnmdata.exe (ICount) CGI Buffer Overflow|exploit/windows/http/hp_nnm_getnnmdata_icount|✗|-|✗|✓|-
13|HP OpenView Network Node Manager getnnmdata.exe (MaxAge) CGI Buffer Overflow|exploit/windows/http/hp_nnm_getnnmdata_maxage|✗|-|✗|✓|-
14|HP OpenView Network Node Manager ovwebsnmpsrv.exe main Buffer Overflow|exploit/windows/http/hp_nnm_ovwebsnmpsrv_main|✗|-|✗|✓|-
15|HP OpenView Network Node Manager ovwebsnmpsrv.exe ovutil Buffer Overflow|exploit/windows/http/hp_nnm_ovwebsnmpsrv_ovutil|✗|-|✗|✓|-
16|HP OpenView Network Node Manager ovwebsnmpsrv.exe Unrecognized Option Buffer Overflow|exploit/windows/http/hp_nnm_ovwebsnmpsrv_uro|✗|-|✗|✓|-
17|HP OpenView Network Node Manager snmpviewer.exe Buffer Overflow|exploit/windows/http/hp_nnm_snmpviewer_actapp|✗|-|✗|✓|-
18|HP OpenView Network Node Manager execvp_nc Buffer Overflow|exploit/windows/http/hp_nnm_webappmon_execvp|✓|-|✗|✓|-
19|HP NNM CGI webappmon.exe OvJavaLocale Buffer Overflow|exploit/windows/http/hp_nnm_webappmon_ovjavalocale|✓|-|✗|✓|-
20|Race River Integard Home/Pro LoginAdmin Password Stack Buffer Overflow|exploit/windows/http/integard_password_bof|✓|-|✗|✓|-
21|Windows Media Services ConnectFunnel Stack Buffer Overflow|exploit/windows/mmsp/ms10_025_wmss_connect_funnel|✓|-|✗|✓|-
22|DATAC RealWin SCADA Server SCPC_INITIALIZE Buffer Overflow|exploit/windows/scada/realwin_scpc_initialize|✓|-|✗|✓|-
23|DATAC RealWin SCADA Server SCPC_INITIALIZE_RF Buffer Overflow|exploit/windows/scada/realwin_scpc_initialize_rf|✓|-|✗|✓|-
24|DATAC RealWin SCADA Server SCPC_TXTEVENT Buffer Overflow|exploit/windows/scada/realwin_scpc_txtevent|✓|-|✗|✓|-

#### 2011 (9)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|FreeBSD Telnet Service Encryption Key ID Buffer Overflow|exploit/freebsd/telnet/telnet_encrypt_keyid|✓|-|✗|✓|-
2|Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow|exploit/linux/telnet/telnet_encrypt_keyid|✓|-|✗|✓|-
3|Zend Server Java Bridge Arbitrary Java Code Execution|exploit/multi/misc/zend_java_bridge|✗|-|✗|✓|-
4|EMC Replication Manager Command Execution|exploit/windows/emc/replication_manager_exec|✓|-|✗|✓|-
5|HP OmniInet.exe Opcode 27 Buffer Overflow|exploit/windows/misc/hp_omniinet_3|✓|-|✗|✓|-
6|DATAC RealWin SCADA Server 2 On_FC_CONNECT_FCS_a_FILE Buffer Overflow|exploit/windows/scada/realwin_on_fc_binfile_a|✓|-|✗|✓|-
7|RealWin SCADA Server DATAC Login Buffer Overflow|exploit/windows/scada/realwin_on_fcs_login|✓|-|✗|✓|-
8|Sunway Forcecontrol SNMP NetDBServer.exe Opcode 0x57|exploit/windows/scada/sunway_force_control_netdbsrv|✓|-|✗|✓|-
9|Sielco Sistemi Winlog Buffer Overflow|exploit/windows/scada/winlog_runtime|✓|-|✗|✓|-

#### 2012 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SAP SOAP RFC SXPG_COMMAND_EXECUTE Remote Command Execution|exploit/multi/sap/sap_soap_rfc_sxpg_command_exec|✗|✓|✗|✓|-
2|Nagios3 history.cgi Host Command Execution|exploit/unix/webapp/nagios3_history_cgi|✓|✓|✗|✓|✓
3|Turbo FTP Server 1.30.823 PORT Overflow|exploit/windows/ftp/turboftp_port|✓|-|✗|✓|-
4|SAP ConfigServlet Remote Code Execution|exploit/windows/http/sap_configservlet_exec_noauth|✓|-|✗|✓|✓
5|NFR Agent FSFUI Record File Upload RCE|exploit/windows/novell/file_reporter_fsfui_upload|✓|-|✗|✓|-

#### 2013 (16)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|OpenPLI Webif Arbitrary Command Execution|exploit/linux/http/dreambox_openpli_shell|✓|-|✗|✓|-
2|Nginx HTTP Server 1.3.9-1.4.0 Chunked Encoding Stack Buffer Overflow|exploit/linux/http/nginx_chunked_size|✗|-|✗|✓|-
3|SerComm Device Remote Code Execution|exploit/linux/misc/sercomm_exec|✗|-|✗|✓|-
4|Adobe ColdFusion RDS Authentication Bypass|exploit/multi/http/coldfusion_rds_auth_bypass|✗|-|✗|✓|-
5|HP SiteScope issueSiebelCmd Remote Code Execution|exploit/multi/http/hp_sitescope_issuesiebelcmd|✗|-|✗|✓|✓
6|NAS4Free Arbitrary Remote Code Execution|exploit/multi/http/nas4free_php_exec|✓|✓|✗|✓|-
7|Rocket Servergraph Admin Center fileRequestor Remote Code Execution|exploit/multi/http/rocket_servergraph_file_requestor_rce|✗|-|✗|✓|-
8|Apache Struts includeParams Remote Code Execution|exploit/multi/http/struts_include_params|✗|-|✗|✓|✓
9|STUNSHELL Web Shell Remote PHP Code Execution|exploit/multi/http/stunshell_eval|✓|-|✗|✓|✓
10|STUNSHELL Web Shell Remote Code Execution|exploit/multi/http/stunshell_exec|✗|-|✗|✓|✓
11|v0pCr3w Web Shell Remote Code Execution|exploit/multi/http/v0pcr3w_exec|✗|-|✗|✓|✓
12|Novell ZENworks Configuration Management Remote Execution|exploit/multi/http/zenworks_control_center_upload|✗|-|✗|✓|-
13|Ra1NX PHP Bot PubCall Authentication Bypass Remote Code Execution|exploit/multi/misc/ra1nx_pubcall_exec|✗|-|✗|✓|-
14|SAP SOAP RFC SXPG_CALL_SYSTEM Remote Command Execution|exploit/multi/sap/sap_soap_rfc_sxpg_call_system_exec|✗|✓|✗|✓|-
15|Carberp Web Panel C2 Backdoor Remote PHP Code Execution|exploit/unix/webapp/carberp_backdoor_exec|✓|-|✗|✓|✓
16|HP Intelligent Management Center Arbitrary File Upload|exploit/windows/http/hp_imc_mibfileupload|✓|-|✗|✓|✓

#### 2014 (6)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MantisBT XmlImportExport Plugin PHP Code Injection Vulnerability|exploit/multi/http/mantisbt_php_exec|✓|✓|✗|✓|✓
2|Oracle Forms and Reports Remote Code Execution|exploit/multi/http/oracle_reports_rce|✗|-|✗|✓|-
3|HP Data Protector EXEC_INTEGUTIL Remote Code Execution|exploit/multi/misc/hp_data_protector_exec_integutil|✗|-|✗|✓|-
4|HP Client Automation Command Injection|exploit/multi/misc/persistent_hpca_radexec_exec|✗|-|✗|✓|-
5|HP AutoPass License Server File Upload|exploit/windows/http/hp_autopass_license_traversal|✗|-|✗|✓|✓
6|HP Data Protector Backup Client Service Directory Traversal|exploit/windows/misc/hp_dataprotector_traversal|✓|-|✗|✓|-

#### 2015 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|D-Link DCS-931L File Upload|exploit/linux/http/dlink_dcs931l_upload|✓|✓|✗|✓|-
2|Western Digital Arkeia Remote Code Execution|exploit/multi/misc/arkeia_agent_exec|✗|-|✗|✓|-
3|VNC Keyboard Remote Code Execution|exploit/multi/vnc/vnc_keyboard_exec|✗|-|✗|✓|-

#### 2016 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|D-Link DSL-2750B OS Command Injection|exploit/linux/http/dlink_dsl2750b_exec_noauth|✗|-|✗|✓|-

#### 2017 (8)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Disk Sorter Enterprise GET Buffer Overflow|exploit/windows/http/disksorter_bof|✓|-|✗|✓|-
2|Dup Scout Enterprise Login Buffer Overflow|exploit/windows/http/dup_scout_enterprise_login_bof|✓|-|✗|✓|-
3|Dup Scout Enterprise GET Buffer Overflow|exploit/windows/http/dupscts_bof|✓|-|✗|✓|-
4|Sync Breeze Enterprise GET Buffer Overflow|exploit/windows/http/syncbreeze_bof|✓|-|✗|✓|-
5|VX Search Enterprise GET Buffer Overflow|exploit/windows/http/vxsrchs_bof|✓|-|✗|✓|-
6|Disk Savvy Enterprise v10.4.18|exploit/windows/misc/disk_savvy_adm|✓|-|✗|✓|-
7|RDP DOUBLEPULSAR Remote Code Execution|exploit/windows/rdp/rdp_doublepulsar_rce|✗|-|✗|✓|-
8|SMB DOUBLEPULSAR Remote Code Execution|exploit/windows/smb/smb_doublepulsar_rce|✗|-|✗|✓|-

#### 2018 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|VyOS restricted-shell Escape and Privilege Escalation|exploit/linux/ssh/vyos_restricted_shell_privesc|✓|✓|✗|✓|-
2|GitStack Unsanitized Argument RCE|exploit/windows/http/gitstack_rce|✓|-|✗|✓|-
3|CloudMe Sync v1.10.9|exploit/windows/misc/cloudme_sync|✓|-|✗|✓|-

#### 2020 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Aerospike Database UDF Lua Code Execution|exploit/linux/misc/aerospike_database_udf_cmd_exec|✗|-|✗|✓|-


### Excellent Ranking (615)

#### 1993 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Generic Web Application Unix Command Execution|exploit/unix/webapp/generic_exec|✓|-|✗|✓|-

#### 1994 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Solaris ypupdated Command Execution|exploit/solaris/sunrpc/ypupdated_exec|✓|-|✗|✓|-

#### 1998 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|MS99-025 Microsoft IIS MDAC msadcs.dll RDS Arbitrary Remote Command Execution|exploit/windows/iis/msadc|✓|-|✗|✓|-

#### 1999 (5)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Matt Wright guestbook.pl Arbitrary Command Execution|exploit/unix/webapp/guestbook_ssi_exec|✓|-|✗|✓|-
2|PsExec via Current User Token|exploit/windows/local/current_user_psexec|✓|-|✗|-|-
3|Powershell Remoting Remote Command Execution|exploit/windows/local/powershell_remoting|✓|-|✗|-|-
4|Windows Management Instrumentation (WMI) Remote Command Execution|exploit/windows/local/wmi|✓|-|✗|-|-
5|Microsoft SQL Server Clr Stored Procedure Payload Execution|exploit/windows/mssql/mssql_clr_payload|✓|-|✗|✓|-

#### 2000 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|RedHat Piranha Virtual Server Package passwd.php3 Arbitrary Command Execution|exploit/linux/http/piranha_passwd_exec|✓|✓|✗|✓|-
2|Microsoft SQL Server Payload Execution|exploit/windows/mssql/mssql_payload|✓|-|✗|✓|-
3|Microsoft SQL Server Payload Execution via SQL Injection|exploit/windows/mssql/mssql_payload_sqli|✓|-|✗|✓|-

#### 2001 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Irix LPD tagprinter Command Execution|exploit/irix/lpd/tagprinter_exec|✓|-|✗|✓|-
2|HP OpenView OmniBack II Command Execution|exploit/multi/misc/openview_omniback_exec|✗|-|✗|✓|-
3|Solaris LPD Command Execution|exploit/solaris/lpd/sendmail_exec|✓|-|✗|✓|-
4|MS01-026 Microsoft IIS/PWS CGI Filename Double Decode Command Execution|exploit/windows/iis/ms01_026_dbldecode|✓|-|✗|✓|-

#### 2002 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|HP-UX LPD Command Execution|exploit/hpux/lpd/cleanup_exec|✓|-|✗|✓|-
2|Solaris in.telnetd TTYPROMPT Buffer Overflow|exploit/solaris/telnet/ttyprompt|✓|✓|✗|✓|-
3|DistCC Daemon Command Execution|exploit/unix/misc/distcc_exec|✓|-|✗|✓|-

#### 2003 (2)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Solaris sadmind Command Execution|exploit/solaris/sunrpc/sadmind_exec|✓|-|✗|✓|-
2|QuickTime Streaming Server parse_xml.cgi Remote Execution|exploit/unix/webapp/qtss_parse_xml_exec|✓|-|✗|✓|-

#### 2004 (3)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|phpBB viewtopic.php Arbitrary Code Execution|exploit/unix/webapp/phpbb_highlight|✓|-|✗|✓|-
2|TWiki Search Function Arbitrary Command Execution|exploit/unix/webapp/twiki_search|✓|-|✗|✓|-
3|Microsoft IIS WebDAV Write Access Code Execution|exploit/windows/iis/iis_webdav_upload_asp|✓|-|✗|✓|-

#### 2005 (11)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AWStats configdir Remote Command Execution|exploit/unix/webapp/awstats_configdir_exec|✓|-|✗|✓|-
2|Barracuda IMG.PL Remote Command Execution|exploit/unix/webapp/barracuda_img_exec|✓|-|✗|✓|-
3|Cacti graph_view.php Remote Command Execution|exploit/unix/webapp/cacti_graphimage_exec|✓|-|✗|✓|-
4|Google Appliance ProxyStyleSheet Command Execution|exploit/unix/webapp/google_proxystylesheet_exec|✓|-|✗|✓|-
5|HP Openview connectedNodes.ovpl Remote Command Execution|exploit/unix/webapp/openview_connectednodes_exec|✓|-|✗|✓|-
6|vBulletin misc.php Template Name Arbitrary Code Execution|exploit/unix/webapp/php_vbulletin_template|✓|-|✗|✓|-
7|PHP XML-RPC Arbitrary Code Execution|exploit/unix/webapp/php_xmlrpc_eval|✓|-|✗|✓|-
8|Simple PHP Blog Remote Command Execution|exploit/unix/webapp/sphpblog_file_upload|✓|-|✗|✓|-
9|TWiki History TWikiUsers rev Parameter Command Execution|exploit/unix/webapp/twiki_history|✓|-|✗|✓|-
10|WordPress cache_lastpostdate Arbitrary Code Execution|exploit/unix/webapp/wp_lastpost_exec|✓|-|✗|✓|-
11|Lyris ListManager MSDE Weak sa Password|exploit/windows/mssql/lyris_listmanager_weak_pass|✓|-|✗|✓|-

#### 2006 (4)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|SpamAssassin spamd Remote Command Execution|exploit/unix/misc/spamassassin_exec|✓|-|✗|✓|-
2|AWStats migrate Remote Command Execution|exploit/unix/webapp/awstats_migrate_exec|✓|-|✗|✓|-
3|PAJAX Remote Command Execution|exploit/unix/webapp/pajax_remote_exec|✓|-|✗|✓|-
4|TikiWiki jhot Remote Command Execution|exploit/unix/webapp/tikiwiki_jhot_exec|✓|-|✗|✓|-

#### 2007 (9)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apple iOS Default SSH Password Vulnerability|exploit/apple_ios/ssh/cydia_default_ssh|✓|-|✗|✓|-
2|HPLIP hpssd.py From Address Arbitrary Command Execution|exploit/linux/misc/hplip_hpssd_exec|✓|-|✗|✓|-
3|PostgreSQL for Linux Payload Execution|exploit/linux/postgres/postgres_payload|✗|✓|✗|✓|-
4|JBoss DeploymentFileRepository WAR Deployment (via JMXInvokerServlet)|exploit/multi/http/jboss_invoke_deploy|✓|-|✗|✓|✓
5|Samba "username map script" Command Execution|exploit/multi/samba/usermap_script|✓|-|✗|✓|-
6|Sun Solaris Telnet Remote Authentication Bypass Vulnerability|exploit/solaris/telnet/fuser|✓|✓|✗|✓|-
7|ClamAV Milter Blackhole-Mode Remote Code Execution|exploit/unix/smtp/clamav_milter_blackhole|✓|-|✗|✓|-
8|TikiWiki tiki-graph_formula Remote PHP Code Execution|exploit/unix/webapp/tikiwiki_graph_formula_exec|✓|-|✗|✓|-
9|Oracle Job Scheduler Named Pipe Command Execution|exploit/windows/oracle/extjob|✓|-|✗|✓|-

#### 2008 (9)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Mantis manage_proj_page PHP Code Execution|exploit/multi/http/mantisbt_manage_proj_page_rce|✓|✓|✗|✓|✓
2|Openfire Admin Console Authentication Bypass|exploit/multi/http/openfire_auth_bypass|✗|-|✗|✓|✓
3|phpScheduleIt PHP reserve.php start_date Parameter Arbitrary Code Injection|exploit/multi/http/phpscheduleit_start_date|✓|-|✗|✓|-
4|AWStats Totals multisort Remote Command Execution|exploit/unix/webapp/awstatstotals_multisort|✓|-|✗|✓|-
5|BASE base_qry_common Remote File Include|exploit/unix/webapp/base_qry_common|✓|-|✗|✓|-
6|Coppermine Photo Gallery picEditor.php Command Execution|exploit/unix/webapp/coppermine_piceditor|✓|-|✗|✓|-
7|Mambo Cache_Lite Class mosConfig_absolute_path Remote File Include|exploit/unix/webapp/mambo_cache_lite|✓|-|✗|✓|-
8|Timbuktu Pro Directory Traversal/File Upload|exploit/windows/motorola/timbuktu_fileupload|✓|-|✗|✓|-
9|MS09-004 Microsoft SQL Server sp_replwritetovarbin Memory Corruption via SQL Injection|exploit/windows/mssql/ms09_004_sp_replwritetovarbin_sqli|✓|-|✗|✓|-

#### 2009 (20)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|DD-WRT HTTP Daemon Arbitrary Command Execution|exploit/linux/http/ddwrt_cgibin_exec|✓|-|✗|✓|-
2|Zabbix Server Arbitrary Command Execution|exploit/linux/misc/zabbix_server_exec|✓|-|✗|✓|-
3|NETGEAR TelnetEnable|exploit/linux/telnet/netgear_telnetenable|✓|-|✗|✓|-
4|Apache Tomcat Manager Application Deployer Authenticated Code Execution|exploit/multi/http/tomcat_mgr_deploy|✓|-|✗|✓|-
5|Apache Tomcat Manager Authenticated Upload Code Execution|exploit/multi/http/tomcat_mgr_upload|✗|-|✗|✓|✓
6|PHP IRC Bot pbot eval() Remote Code Execution|exploit/multi/misc/pbot_exec|✓|-|✗|✓|-
7|Oracle MySQL UDF Payload Execution|exploit/multi/mysql/mysql_udf_payload|✗|-|✗|✓|-
8|Wyse Rapport Hagent Fake Hserver Command Execution|exploit/multi/wyse/hagent_untrusted_hsdata|✗|-|✗|✓|-
9|ContentKeeper Web Remote Command Execution|exploit/unix/http/contentkeeperweb_mimencode|✓|-|✗|✓|-
10|Zabbix Agent net.tcp.listen Command Injection|exploit/unix/misc/zabbix_agent_exec|✓|-|✗|✓|-
11|Dogfood CRM spell.php Remote Command Execution|exploit/unix/webapp/dogfood_spell_exec|✓|-|✗|✓|-
12|Joomla 1.5.12 TinyBrowser File Upload Code Execution|exploit/unix/webapp/joomla_tinybrowser|✓|-|✗|✓|-
13|Nagios3 statuswml.cgi Ping Command Execution|exploit/unix/webapp/nagios3_statuswml_ping|✓|✓|✗|✓|-
14|osCommerce 2.2 Arbitrary PHP Code Execution|exploit/unix/webapp/oscommerce_filemanager|✓|-|✗|✓|-
15|PhpMyAdmin Config File Code Injection|exploit/unix/webapp/phpmyadmin_config|✓|-|✗|✓|-
16|Symantec System Center Alert Management System (xfr.exe) Arbitrary Command Execution|exploit/windows/antivirus/ams_xfr|✓|-|✗|✓|-
17|Adobe RoboHelp Server 8 Arbitrary File Upload and Execute|exploit/windows/http/adobe_robohelper_authbypass|✓|-|✗|✓|-
18|ColdFusion 8.0.1 Arbitrary File Upload and Execute|exploit/windows/http/coldfusion_fckeditor|✓|-|✗|✓|-
19|IBM System Director Agent DLL Injection|exploit/windows/misc/ibm_director_cim_dllinject|✓|-|✗|✓|-
20|PostgreSQL for Microsoft Windows Payload Execution|exploit/windows/postgres/postgres_payload|✗|✓|✗|✓|-

#### 2010 (23)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AjaXplorer checkInstall.php Remote Command Execution|exploit/multi/http/ajaxplorer_checkinstall_exec|✓|-|✗|✓|✓
2|Axis2 / SAP BusinessObjects Authenticated Code Execution (via SOAP)|exploit/multi/http/axis2_deployer|✗|✓|✗|✓|-
3|JBoss JMX Console Beanshell Deployer WAR Upload and Deployment|exploit/multi/http/jboss_bshdeployer|✓|-|✗|✓|✓
4|JBoss Java Class DeploymentFileRepository WAR Deployment|exploit/multi/http/jboss_deploymentfilerepository|✓|-|✗|✓|✓
5|Pandora FMS v3.1 Auth Bypass and Arbitrary File Upload Vulnerability|exploit/multi/http/pandora_upload_exec|✓|-|✗|✓|✓
6|ProcessMaker Plugin Upload|exploit/multi/http/processmaker_plugin_upload|✓|✓|✗|✓|-
7|ProFTPD-1.3.3c Backdoor Command Execution|exploit/unix/ftp/proftpd_133c_backdoor|✓|-|✗|✓|-
8|UnrealIRCD 3.2.8.1 Backdoor Command Execution|exploit/unix/irc/unreal_ircd_3281_backdoor|✓|-|✗|✓|-
9|Exim4 string_format Function Heap Buffer Overflow|exploit/unix/smtp/exim4_string_format|✓|-|✗|✓|-
10|CakePHP Cache Corruption Code Execution|exploit/unix/webapp/cakephp_cache_corruption|✓|-|✗|✓|-
11|Citrix Access Gateway Command Execution|exploit/unix/webapp/citrix_access_gateway_exec|✓|-|✗|✓|-
12|Mitel Audio and Web Conferencing Command Injection|exploit/unix/webapp/mitel_awc_exec|✓|-|✗|✓|-
13|Redmine SCM Repository Arbitrary Command Execution|exploit/unix/webapp/redmine_scm_exec|✓|-|✗|✓|-
14|Symantec System Center Alert Management System (hndlrsvc.exe) Arbitrary Command Execution|exploit/windows/antivirus/ams_hndlrsvc|✓|-|✗|✓|-
15|Energizer DUO USB Battery Charger Arucer.dll Trojan Code Execution|exploit/windows/backdoor/energizer_duo_payload|✓|-|✗|✓|-
16|Novell iManager getMultiPartParameters Arbitrary File Upload|exploit/windows/http/novell_imanager_upload|✓|-|✗|✓|-
17|Oracle BeeHive 2 voice-servlet processEvaluation() Vulnerability|exploit/windows/http/oracle_beehive_evaluation|✓|-|✗|✓|✓
18|Oracle Secure Backup Authentication Bypass/Command Injection Vulnerability|exploit/windows/http/osb_uname_jlist|✓|-|✗|✓|-
19|Novell ZENworks Configuration Management Remote Execution|exploit/windows/http/zenworks_uploadservlet|✗|-|✗|✓|-
20|HP Mercury LoadRunner Agent magentproc.exe Remote Command Execution|exploit/windows/misc/hp_loadrunner_magentproc_cmdexec|✓|-|✗|✓|-
21|MS10-104 Microsoft Office SharePoint Server 2007 Remote Code Execution|exploit/windows/misc/ms10_104_sharepoint|✓|-|✗|✓|-
22|MS10-061 Microsoft Print Spooler Service Impersonation Vulnerability|exploit/windows/smb/ms10_061_spoolss|✓|-|✗|✓|-
23|Freesshd Authentication Bypass|exploit/windows/ssh/freesshd_authbypass|✗|-|✗|✓|-

#### 2011 (33)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|V-CMS PHP File Upload and Execute|exploit/linux/http/vcms_upload|✗|-|✗|✓|✓
2|WeBid converter.php Remote PHP Code Injection|exploit/linux/http/webid_converter|✓|-|✗|✓|✓
3|Accellion FTA MPIPE2 Command Execution|exploit/linux/misc/accellion_fta_mpipe2|✓|-|✗|✓|-
4|HP Data Protector 6 EXEC_CMD Remote Code Execution|exploit/linux/misc/hp_data_protector_cmd_exec|✓|-|✗|✓|-
5|Family Connections less.php Remote Command Execution|exploit/multi/http/familycms_less_exec|✓|-|✗|✓|-
6|LotusCMS 3.0 eval() Remote Command Execution|exploit/multi/http/lcms_php_exec|✓|-|✗|✓|-
7|Log1 CMS writeInfo() PHP Code Injection|exploit/multi/http/log1cms_ajax_create_folder|✓|-|✗|✓|✓
8|phpLDAPadmin query_engine Remote PHP Code Injection|exploit/multi/http/phpldapadmin_query_engine|✓|-|✗|✓|-
9|Plone and Zope XMLTools Remote Command Execution|exploit/multi/http/plone_popen2|✓|-|✗|✓|-
10|PmWiki pagelist.php Remote PHP Code Injection Exploit|exploit/multi/http/pmwiki_pagelist|✓|-|✗|✓|-
11|Snortreport nmap.php/nbtscan.php Remote Command Execution|exploit/multi/http/snortreport_exec|✓|-|✗|✓|-
12|Splunk Search Remote Code Execution|exploit/multi/http/splunk_mappy_exec|✓|✓|✗|✓|-
13|Spreecommerce 0.60.1 Arbitrary Command Execution|exploit/multi/http/spree_search_exec|✓|-|✗|✓|-
14|Spreecommerce Arbitrary Command Execution|exploit/multi/http/spree_searchlogic_exec|✓|-|✗|✓|-
15|Apache Struts ParametersInterceptor Remote Code Execution|exploit/multi/http/struts_code_exec_parameters|✗|-|✗|✓|✓
16|Traq admincp/common.php Remote Code Execution|exploit/multi/http/traq_plugin_exec|✓|-|✗|✓|-
17|HP StorageWorks P4000 Virtual SAN Appliance Command Execution|exploit/multi/misc/hp_vsa_exec|✓|-|✗|✓|-
18|VSFTPD v2.3.4 Backdoor Command Execution|exploit/unix/ftp/vsftpd_234_backdoor|✓|-|✗|✓|-
19|LifeSize Room Command Injection|exploit/unix/http/lifesize_room|✓|-|✗|✓|-
20|myBB 1.6.4 Backdoor Arbitrary Command Execution|exploit/unix/webapp/mybb_backdoor|✓|-|✗|✓|-
21|QuickShare File Server 1.2.1 Directory Traversal Vulnerability|exploit/windows/ftp/quickshare_traversal_write|✓|-|✗|✓|-
22|CA Arcserve D2D GWT RPC Credential Information Disclosure|exploit/windows/http/ca_arcserve_rpc_authbypass|✓|-|✗|✓|-
23|CA Total Defense Suite reGenerateReports Stored Procedure SQL Injection|exploit/windows/http/ca_totaldefense_regeneratereports|✓|-|✗|✓|-
24|HP Managed Printing Administration jobAcct Remote Command Execution|exploit/windows/http/hp_mpa_job_acct|✓|-|✗|✓|-
25|HP OpenView Performance Insight Server Backdoor Account Code Execution|exploit/windows/http/hp_openview_insight_backdoor|✓|✓|✗|✓|-
26|Solarwinds Storage Manager 5.1.0 SQL Injection|exploit/windows/http/solarwinds_storage_manager_sql|✓|-|✗|✓|-
27|Novell ZENworks Asset Management Remote Execution|exploit/windows/http/zenworks_assetmgmt_uploadservlet|✓|-|✗|✓|-
28|HP Data Protector 6.10/6.11/6.20 Install Service|exploit/windows/misc/hp_dataprotector_install_service|✓|-|✗|✓|-
29|Oracle Database Client System Analyzer Arbitrary File Upload|exploit/windows/oracle/client_system_analyzer_upload|✓|-|✗|✓|-
30|7-Technologies IGSS 9 Data Server/Collector Packet Handling Vulnerabilities|exploit/windows/scada/igss9_misc|✓|-|✗|✓|-
31|Interactive Graphical SCADA System Remote Command Injection|exploit/windows/scada/igss_exec_17|✓|-|✗|✓|-
32|InduSoft Web Studio Arbitrary Upload Remote Code Execution|exploit/windows/scada/indusoft_webstudio_exec|✓|-|✗|✓|-
33|Measuresoft ScadaPro Remote Command Execution|exploit/windows/scada/scadapro_cmdexe|✓|-|✗|✓|-

#### 2012 (70)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Dolibarr ERP/CRM Post-Auth OS Command Injection|exploit/linux/http/dolibarr_cmd_exec|✓|✓|✗|✓|✓
2|E-Mail Security Virtual Appliance learn-msg.cgi Command Injection|exploit/linux/http/esva_exec|✓|-|✗|✓|-
3|Openfiler v2.x NetworkCard Command Execution|exploit/linux/http/openfiler_networkcard_exec|✓|✓|✗|✓|-
4|Symantec Web Gateway 5.0.2.8 ipchange.php Command Injection|exploit/linux/http/symantec_web_gateway_exec|✓|-|✗|✓|-
5|Symantec Web Gateway 5.0.2.8 Arbitrary PHP File Upload Vulnerability|exploit/linux/http/symantec_web_gateway_file_upload|✓|-|✗|✓|-
6|Symantec Web Gateway 5.0.2.8 relfile File Inclusion Vulnerability|exploit/linux/http/symantec_web_gateway_lfi|✓|-|✗|✓|-
7|Symantec Web Gateway 5.0.2.18 pbcontrol.php Command Injection|exploit/linux/http/symantec_web_gateway_pbcontrol|✓|-|✗|✓|✓
8|WAN Emulator v2.3 Command Execution|exploit/linux/http/wanem_exec|✓|-|✗|✓|-
9|WebCalendar 1.2.4 Pre-Auth Remote Code Injection|exploit/linux/http/webcalendar_settings_exec|✓|-|✗|✓|✓
10|ZEN Load Balancer Filelog Command Execution|exploit/linux/http/zen_load_balancer_exec|✓|✓|✗|✓|-
11|F5 BIG-IP SSH Private Key Exposure|exploit/linux/ssh/f5_bigip_known_privkey|✓|-|✗|✓|-
12|Symantec Messaging Gateway 9.5 Default SSH Password Vulnerability|exploit/linux/ssh/symantec_smg_ssh|✓|-|✗|✓|-
13|appRain CMF Arbitrary PHP File Upload Vulnerability|exploit/multi/http/apprain_upload_exec|✓|-|✗|✓|✓
14|Auxilium RateMyPet Arbitrary File Upload Vulnerability|exploit/multi/http/auxilium_upload_exec|✗|-|✗|✓|✓
15|CuteFlow v2.11.2 Arbitrary File Upload Vulnerability|exploit/multi/http/cuteflow_upload_exec|✓|-|✗|✓|✓
16|Network Shutdown Module (sort_values) Remote PHP Code Injection|exploit/multi/http/eaton_nsm_code_exec|✗|-|✗|✓|-
17|eXtplorer v2.1 Arbitrary File Upload Vulnerability|exploit/multi/http/extplorer_upload_exec|✓|✓|✗|✓|✓
18|Gitorious Arbitrary Command Execution|exploit/multi/http/gitorious_graph|✓|-|✗|✓|-
19|Horde 3.3.12 Backdoor Arbitrary PHP Code Execution|exploit/multi/http/horde_href_backdoor|✓|-|✗|✓|-
20|ManageEngine Security Manager Plus 5.5 Build 5505 SQL Injection|exploit/multi/http/manageengine_search_sqli|✓|-|✗|✓|-
21|Th3 MMA mma.php Backdoor Arbitrary File Upload|exploit/multi/http/mma_backdoor_upload|✓|-|✗|✓|✓
22|MobileCartly 1.0 Arbitrary File Creation Vulnerability|exploit/multi/http/mobilecartly_upload_exec|✗|-|✗|✓|✓
23|Mutiny Remote Command Execution|exploit/multi/http/mutiny_subnetmask_exec|✗|✓|✗|✓|✓
24|OP5 license.php Remote Command Execution|exploit/multi/http/op5_license|✓|-|✗|✓|-
25|OP5 welcome Remote Command Execution|exploit/multi/http/op5_welcome|✓|-|✗|✓|-
26|PHP CGI Argument Injection|exploit/multi/http/php_cgi_arg_injection|✓|-|✗|✓|-
27|PHP Volunteer Management System v1.0.2 Arbitrary File Upload Vulnerability|exploit/multi/http/php_volunteer_upload_exec|✓|✓|✗|✓|✓
28|PhpTax pfilez Parameter Exec Remote Code Injection|exploit/multi/http/phptax_exec|✓|-|✗|✓|✓
29|PolarBear CMS PHP File Upload Vulnerability|exploit/multi/http/polarcms_upload_exec|✗|-|✗|✓|✓
30|Sflog! CMS 1.0 Arbitrary File Upload Vulnerability|exploit/multi/http/sflog_upload_exec|✗|✓|✗|✓|✓
31|SonicWALL GMS 6 Arbitrary File Upload|exploit/multi/http/sonicwall_gms_upload|✗|-|✗|✓|✓
32|Apache Struts 2 Developer Mode OGNL Execution|exploit/multi/http/struts_dev_mode|✓|-|✗|✓|✓
33|TestLink v1.9.3 Arbitrary File Upload Vulnerability|exploit/multi/http/testlink_upload_exec|✓|-|✗|✓|✓
34|vBSEO proc_deutf() Remote PHP Code Injection|exploit/multi/http/vbseo_proc_deutf|✓|-|✗|✓|-
35|WebPageTest Arbitrary PHP File Upload|exploit/multi/http/webpagetest_upload_exec|✓|-|✗|✓|✓
36|Zemra Botnet CnC Web Panel Remote Code Execution|exploit/multi/http/zemra_panel_rce|✗|-|✗|✓|✓
37|Adobe IndesignServer 5.5 SOAP Server Arbitrary Script Execution|exploit/multi/misc/indesign_server_soap|✗|-|✗|✓|-
38|QNX qconn Command Execution|exploit/qnx/qconn/qconn_exec|✓|-|✗|✓|-
39|Tectia SSH USERAUTH Change Request Password Reset Vulnerability|exploit/unix/ssh/tectia_passwd_changereq|✓|✓|✗|✓|-
40|Basilic 1.5.14 diff.php Arbitrary Command Execution|exploit/unix/webapp/basilic_diff_exec|✓|-|✗|✓|✓
41|EGallery PHP File Upload Vulnerability|exploit/unix/webapp/egallery_upload_exec|✓|-|✗|✓|✓
42|Foswiki MAKETEXT Remote Command Execution|exploit/unix/webapp/foswiki_maketext|✓|-|✗|✓|✓
43|Invision IP.Board unserialize() PHP Code Execution|exploit/unix/webapp/invision_pboard_unserialize_exec|✓|-|✗|✓|✓
44|Joomla Component JCE File Upload Remote Code Execution|exploit/unix/webapp/joomla_comjce_imgmanager|✓|-|✗|✓|✓
45|Narcissus Image Configuration Passthru Vulnerability|exploit/unix/webapp/narcissus_backend_exec|✓|-|✗|✓|✓
46|Project Pier Arbitrary File Upload Vulnerability|exploit/unix/webapp/projectpier_upload_exec|✗|-|✗|✓|✓
47|SPIP connect Parameter PHP Injection|exploit/unix/webapp/spip_connect_exec|✓|-|✗|✓|✓
48|Tiki Wiki unserialize() PHP Code Execution|exploit/unix/webapp/tikiwiki_unserialize_exec|✓|-|✗|✓|✓
49|TWiki MAKETEXT Remote Command Execution|exploit/unix/webapp/twiki_maketext|✓|-|✗|✓|✓
50|WordPress Plugin Advanced Custom Fields Remote File Inclusion|exploit/unix/webapp/wp_advanced_custom_fields_exec|✓|-|✗|✓|✓
51|WordPress Asset-Manager PHP File Upload Vulnerability|exploit/unix/webapp/wp_asset_manager_upload_exec|✓|-|✗|✓|✓
52|WordPress Plugin Foxypress uploadify.php Arbitrary Code Execution|exploit/unix/webapp/wp_foxypress_upload|✓|-|✗|✓|✓
53|Wordpress Front-end Editor File Upload|exploit/unix/webapp/wp_frontend_editor_file_upload|✓|-|✗|✓|✓
54|WordPress WP-Property PHP File Upload Vulnerability|exploit/unix/webapp/wp_property_upload_exec|✓|-|✗|✓|✓
55|Wordpress Reflex Gallery Upload Vulnerability|exploit/unix/webapp/wp_reflexgallery_file_upload|✓|-|✗|✓|✓
56|XODA 0.4.5 Arbitrary PHP File Upload Vulnerability|exploit/unix/webapp/xoda_file_upload|✓|-|✗|✓|✓
57|FreeFloat FTP Server Arbitrary File Upload|exploit/windows/ftp/freefloatftp_wbem|✓|-|✗|✓|-
58|Open-FTPD 1.2 Arbitrary File Upload|exploit/windows/ftp/open_ftpd_wbem|✓|-|✗|✓|-
59|Avaya IP Office Customer Call Reporter ImageUpload.ashx Remote Command Execution|exploit/windows/http/avaya_ccr_imageupload_exec|✓|-|✗|✓|✓
60|Cyclope Employee Surveillance Solution v6 SQL Injection|exploit/windows/http/cyclope_ess_sqli|✓|-|✗|✓|✓
61|Ektron 8.02 XSLT Transform Remote Code Execution|exploit/windows/http/ektron_xslt_exec|✓|-|✗|✓|✓
62|EZHomeTech EzServer Stack Buffer Overflow Vulnerability|exploit/windows/http/ezserver_http|✓|-|✗|✓|-
63|LANDesk Lenovo ThinkManagement Console Remote Command Execution|exploit/windows/http/landesk_thinkmanagement_upload_asp|✓|-|✗|✓|-
64|Oracle Business Transaction Management FlashTunnelService Remote Code Execution|exploit/windows/http/oracle_btm_writetofile|✗|-|✗|✓|-
65|Dell SonicWALL (Plixer) Scrutinizer 9 SQL Injection|exploit/windows/http/sonicwall_scrutinizer_sqli|✓|-|✗|✓|✓
66|Umbraco CMS Remote Command Execution|exploit/windows/http/umbraco_upload_aspx|✓|-|✗|✓|✓
67|XAMPP WebDAV PHP Upload|exploit/windows/http/xampp_webdav_upload_php|✓|✓|✗|✓|-
68|Authenticated WMI Exec via Powershell|exploit/windows/local/ps_wmi_exec|✓|-|✗|-|-
69|Plixer Scrutinizer NetFlow and sFlow Analyzer 9 Default MySQL Credential|exploit/windows/mysql/scrutinizer_upload_exec|✓|✓|✗|-|✓
70|NetIQ Privileged User Manager 2.3.1 ldapagnt_eval() Remote Perl Code Execution|exploit/windows/novell/netiq_pum_eval|✓|-|✗|✓|-

#### 2013 (80)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Red Hat CloudForms Management Engine 5.1 agent/linuxpkgs Path Traversal|exploit/linux/http/cfme_manageiq_evm_upload_exec|✓|-|✗|✓|✓
2|D-Link Devices Unauthenticated Remote Command Execution|exploit/linux/http/dlink_command_php_exec_noauth|✓|-|✗|✓|-
3|D-Link DIR-645 / DIR-815 diagnostic.php Command Execution|exploit/linux/http/dlink_diagnostic_exec_noauth|✗|-|✗|✓|-
4|D-Link Devices Unauthenticated Remote Command Execution|exploit/linux/http/dlink_dir300_exec_telnet|✓|✓|✗|✓|-
5|D-Link DIR615h OS Command Injection|exploit/linux/http/dlink_dir615_up_exec|✗|✓|✗|✓|-
6|F5 iControl Remote Root Command Execution|exploit/linux/http/f5_icontrol_exec|✓|✓|✗|✓|✓
7|Foreman (Red Hat OpenStack/Satellite) bookmarks/create Code Injection|exploit/linux/http/foreman_openstack_satellite_code_exec|✓|✓|✗|✓|✓
8|GroundWork monarch_scan.cgi OS Command Injection|exploit/linux/http/groundwork_monarch_cmd_exec|✓|✓|✗|✓|-
9|Linksys E1500/E2500 apply.cgi Remote Command Injection|exploit/linux/http/linksys_e1500_apply_exec|✗|✓|✗|✓|-
10|Linksys Devices pingstr Remote Command Injection|exploit/linux/http/linksys_wrt110_cmd_exec|✓|✓|✗|✓|-
11|Mutiny 5 Arbitrary File Upload|exploit/linux/http/mutiny_frontend_upload|✓|✓|✗|✓|✓
12|Netgear DGN1000 Setup.cgi Unauthenticated RCE|exploit/linux/http/netgear_dgn1000_setup_unauth_exec|✓|-|✗|✓|-
13|Netgear DGN1000B setup.cgi Remote Command Execution|exploit/linux/http/netgear_dgn1000b_setup_exec|✗|✓|✗|✓|-
14|PineApp Mail-SeCure ldapsyncnow.php Arbitrary Command Execution|exploit/linux/http/pineapp_ldapsyncnow_exec|✓|-|✗|✓|-
15|PineApp Mail-SeCure livelog.html Arbitrary Command Execution|exploit/linux/http/pineapp_livelog_exec|✓|-|✗|✓|-
16|PineApp Mail-SeCure test_li_connection.php Arbitrary Command Execution|exploit/linux/http/pineapp_test_li_conn_exec|✓|-|✗|✓|-
17|Sophos Web Protection Appliance sblistpack Arbitrary Command Execution|exploit/linux/http/sophos_wpa_sblistpack_exec|✓|-|✗|✓|-
18|Synology DiskStation Manager SLICEUPLOAD Remote Command Execution|exploit/linux/http/synology_dsm_sliceupload_exec_noauth|✓|-|✗|✓|-
19|Zabbix 2.0.8 SQL Injection and Remote Code Execution|exploit/linux/http/zabbix_sqli|✓|-|✗|✓|✓
20|Nagios Remote Plugin Executor Arbitrary Command Execution|exploit/linux/misc/nagios_nrpe_arguments|✓|-|✗|✓|-
21|Exim and Dovecot Insecure Configuration Command Injection|exploit/linux/smtp/exim4_dovecot_exec|✓|-|✗|✓|-
22|D-Link Unauthenticated UPnP M-SEARCH Multicast Command Injection|exploit/linux/upnp/dlink_upnp_msearch_exec|✗|-|✗|✓|-
23|ElasticSearch Dynamic Script Arbitrary Java Execution|exploit/multi/elasticsearch/script_mvel_rce|✓|-|✗|✓|✓
24|Apache Roller OGNL Injection|exploit/multi/http/apache_roller_ognl_injection|✓|-|✗|✓|✓
25|Cisco Prime Data Center Network Manager Arbitrary File Upload|exploit/multi/http/cisco_dcnm_upload|✓|-|✗|✓|✓
26|GestioIP Remote Command Execution|exploit/multi/http/gestioip_exec|✓|-|✗|✓|✓
27|Gitlab-shell Code Execution|exploit/multi/http/gitlab_shell_exec|✗|✓|✗|✓|✓
28|Glossword v1.8.8 - 1.8.12 Arbitrary File Upload Vulnerability|exploit/multi/http/glossword_upload_exec|✓|✓|✗|✓|✓
29|HP System Management Homepage JustGetSNMPQueue Command Injection|exploit/multi/http/hp_sys_mgmt_exec|✓|-|✗|✓|-
30|VMware Hyperic HQ Groovy Script-Console Java Execution|exploit/multi/http/hyperic_hq_script_console|✓|✓|✗|✓|✓
31|ISPConfig Authenticated Arbitrary PHP Code Execution|exploit/multi/http/ispconfig_php_exec|✓|✓|✗|✓|✓
32|Kordil EDMS v2.2.60rc3 Unauthenticated Arbitrary File Upload Vulnerability|exploit/multi/http/kordil_edms_upload_exec|✓|-|✗|✓|✓
33|Movable Type 4.2x, 4.3x Web Upgrade Remote Code Execution|exploit/multi/http/movabletype_upgrade_exec|✓|-|✗|✓|✓
34|OpenMediaVault Cron Remote Command Execution|exploit/multi/http/openmediavault_cmd_exec|✓|✓|✗|✓|-
35|OpenX Backdoor PHP Code Execution|exploit/multi/http/openx_backdoor_php|✓|-|✗|✓|✓
36|phpMyAdmin Authenticated Remote Code Execution via preg_replace()|exploit/multi/http/phpmyadmin_preg_replace|✓|✓|✗|✓|✓
37|ProcessMaker Open Source Authenticated PHP Code Execution|exploit/multi/http/processmaker_exec|✓|✓|✗|✓|-
38|Ruby on Rails JSON Processor YAML Deserialization Code Execution|exploit/multi/http/rails_json_yaml_code_exec|✓|-|✗|✓|✓
39|Ruby on Rails XML Processor YAML Deserialization Code Execution|exploit/multi/http/rails_xml_yaml_code_exec|✓|-|✗|✓|-
40|Apache Struts 2 DefaultActionMapper Prefixes OGNL Code Execution|exploit/multi/http/struts_default_action_mapper|✓|-|✗|✓|✓
41|Idera Up.Time Monitoring Station 7.0 post2file.php Arbitrary File Upload|exploit/multi/http/uptime_file_upload_1|✓|-|✗|✓|✓
42|Idera Up.Time Monitoring Station 7.4 post2file.php Arbitrary File Upload|exploit/multi/http/uptime_file_upload_2|✓|✓|✗|✓|-
43|vTigerCRM v5.4.0/v5.3.0 Authenticated Remote Code Execution|exploit/multi/http/vtiger_php_exec|✓|✓|✗|✓|✓
44|vTiger CRM SOAP AddEmailAttachment Arbitrary File Upload|exploit/multi/http/vtiger_soap_upload|✓|-|✗|✓|✓
45|Zabbix Authenticated Remote Command Execution|exploit/multi/http/zabbix_script_exec|✓|✓|✗|✓|✓
46|Western Digital Arkeia Remote Code Execution|exploit/unix/webapp/arkeia_upload_exec|✓|-|✗|✓|✓
47|ClipBucket Remote Code Execution|exploit/unix/webapp/clipbucket_upload_exec|✓|-|✗|✓|✓
48|DataLife Engine preview.php PHP Code Injection|exploit/unix/webapp/datalife_preview_exec|✓|-|✗|✓|✓
49|FlashChat Arbitrary File Upload|exploit/unix/webapp/flashchat_upload_exec|✓|-|✗|✓|✓
50|Graphite Web Unsafe Pickle Handling|exploit/unix/webapp/graphite_pickle_exec|✓|-|✗|✓|✓
51|Havalite CMS Arbitary File Upload Vulnerability|exploit/unix/webapp/havalite_upload_exec|✗|-|✗|✓|✓
52|Horde Framework Unserialize PHP Code Execution|exploit/unix/webapp/horde_unserialize_exec|✓|-|✗|✓|✓
53|InstantCMS 1.6 Remote PHP Code Execution|exploit/unix/webapp/instantcms_exec|✓|-|✗|✓|✓
54|LibrettoCMS File Manager Arbitary File Upload Vulnerability|exploit/unix/webapp/libretto_upload_exec|✗|-|✗|✓|✓
55|OpenEMR PHP File Upload Vulnerability|exploit/unix/webapp/openemr_upload_exec|✓|-|✗|✓|✓
56|PHP-Charts v1.0 PHP Code Execution Vulnerability|exploit/unix/webapp/php_charts_exec|✓|-|✗|✓|✓
57|Squash YAML Code Execution|exploit/unix/webapp/squash_yaml_exec|✓|-|✗|✓|✓
58|vBulletin index.php/ajax/api/reputation/vote nodeid Parameter SQL Injection|exploit/unix/webapp/vbulletin_vote_sqli_exec|✓|-|✗|✓|✓
59|VICIdial Manager Send OS Command Injection|exploit/unix/webapp/vicidial_manager_send_cmd_exec|✓|✓|✗|✓|-
60|WebTester 5.x Command Execution|exploit/unix/webapp/webtester_exec|✓|-|✗|✓|✓
61|WordPress OptimizePress Theme File Upload Vulnerability|exploit/unix/webapp/wp_optimizepress_upload|✓|-|✗|✓|✓
62|WordPress W3 Total Cache PHP Code Execution|exploit/unix/webapp/wp_total_cache_exec|✓|-|✗|✓|✓
63|ZeroShell Remote Code Execution|exploit/unix/webapp/zeroshell_exec|✓|-|✗|✓|✓
64|Zimbra Collaboration Server LFI|exploit/unix/webapp/zimbra_lfi|✓|-|✗|✓|✓
65|ZoneMinder Video Server packageControl Command Execution|exploit/unix/webapp/zoneminder_packagecontrol_exec|✓|✓|✗|✓|✓
66|EMC AlphaStor Device Manager Opcode 0x75 Command Injection|exploit/windows/emc/alphastor_device_manager_exec|✓|-|✗|✓|-
67|ManageEngine Desktop Central AgentLogUpload Arbitrary File Upload|exploit/windows/http/desktopcentral_file_upload|✓|-|✗|✓|-
68|HP Intelligent Management Center BIMS UploadServlet Directory Traversal|exploit/windows/http/hp_imc_bims_upload|✓|-|✗|✓|-
69|HP LoadRunner EmulationAdmin Web Service Directory Traversal|exploit/windows/http/hp_loadrunner_copyfiletoserver|✓|-|✗|✓|-
70|HP ProCurve Manager SNAC UpdateCertificatesServlet File Upload|exploit/windows/http/hp_pcm_snac_update_certificates|✓|-|✗|✓|-
71|HP ProCurve Manager SNAC UpdateDomainControllerServlet File Upload|exploit/windows/http/hp_pcm_snac_update_domain|✓|-|✗|✓|-
72|Kaseya uploadImage Arbitrary File Upload|exploit/windows/http/kaseya_uploadimage_file_upload|✓|-|✗|✓|-
73|MiniWeb (Build 300) Arbitrary File Upload|exploit/windows/http/miniweb_upload_wbem|✓|-|✗|✓|-
74|Novell Zenworks Mobile Managment MDM.php Local File Inclusion Vulnerability|exploit/windows/http/novell_mdm_lfi|✓|-|✗|✓|✓
75|Oracle Endeca Server Remote Command Execution|exploit/windows/http/oracle_endeca_exec|✓|-|✗|✓|✓
76|VMware vCenter Chargeback Manager ImageUploadServlet Arbitrary File Upload|exploit/windows/http/vmware_vcenter_chargeback_upload|✓|-|✗|✓|-
77|BigAnt Server DUPF Command Arbitrary File Upload|exploit/windows/misc/bigant_server_dupf_upload|✓|-|✗|✓|-
78|Nvidia Mental Ray Satellite Service Arbitrary DLL Injection|exploit/windows/misc/nvidia_mental_ray|✓|-|✗|✓|-
79|ABB MicroSCADA wserver.exe Remote Code Execution|exploit/windows/scada/abb_wserver_exec|✓|-|✗|✓|-
80|SCADA 3S CoDeSys Gateway Server Directory Traversal|exploit/windows/scada/codesys_gateway_server_traversal|✓|-|✗|✓|-

#### 2014 (55)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AlienVault OSSIM SQL Injection and Remote Code Execution|exploit/linux/http/alienvault_sqli_exec|✓|-|✗|✓|✓
2|Centreon SQL and Command Injection|exploit/linux/http/centreon_sqli_exec|✓|-|✗|✓|✓
3|Fritz!Box Webcm Unauthenticated Command Injection|exploit/linux/http/fritzbox_echo_exec|✗|-|✗|✓|-
4|Gitlist Unauthenticated Remote Command Execution|exploit/linux/http/gitlist_exec|✓|-|✗|✓|✓
5|IPFire Bash Environment Variable Injection (Shellshock)|exploit/linux/http/ipfire_bashbug_exec|✓|✓|✗|✓|-
6|LifeSize UVC Authenticated RCE via Ping|exploit/linux/http/lifesize_uvc_ping_rce|✓|✓|✗|✓|✓
7|Linksys E-Series TheMoon Remote Command Injection|exploit/linux/http/linksys_themoon_exec|✗|-|✗|✓|-
8|Pandora FMS Remote Code Execution|exploit/linux/http/pandora_fms_exec|✓|-|✗|✓|✓
9|Pandora FMS Default Credential / SQLi Remote Code Execution|exploit/linux/http/pandora_fms_sqli|✓|-|✗|✓|✓
10|Railo Remote File Include|exploit/linux/http/railo_cfml_rfi|✓|-|✗|✓|✓
11|AlienVault OSSIM av-centerd Command Injection|exploit/linux/ids/alienvault_centerd_soap_exec|✓|-|✗|✓|-
12|Loadbalancer.org Enterprise VA SSH Private Key Exposure|exploit/linux/ssh/loadbalancerorg_enterprise_known_privkey|✓|-|✗|✓|-
13|Quantum DXi V1000 SSH Private Key Exposure|exploit/linux/ssh/quantum_dxi_known_privkey|✓|-|✗|✓|-
14|Quantum vmPRO Backdoor Command|exploit/linux/ssh/quantum_vmpro_backdoor|✓|✓|✗|✓|-
15|Belkin Wemo UPnP Remote Code Execution|exploit/linux/upnp/belkin_wemo_upnp_exec|✗|-|✗|✓|-
16|Pure-FTPd External Authentication Bash Environment Variable Code Injection (Shellshock)|exploit/multi/ftp/pureftpd_bash_env_exec|✗|-|✗|✓|-
17|Dexter (CasinoLoader) SQL Injection|exploit/multi/http/dexter_casinoloader_exec|✓|-|✗|✓|✓
18|Drupal HTTP Parameter Key/Value SQL Injection|exploit/multi/http/drupal_drupageddon|✗|-|✗|✓|✓
19|ManageEngine Eventlog Analyzer Arbitrary File Upload|exploit/multi/http/eventlog_file_upload|✓|-|✗|✓|-
20|ManageEngine Desktop Central / Password Manager LinkViewFetchServlet.dat SQL Injection|exploit/multi/http/manage_engine_dc_pmp_sqli|✓|-|✗|✓|-
21|ManageEngine Multiple Products Authenticated File Upload|exploit/multi/http/manageengine_auth_upload|✓|✓|✗|✓|-
22|MediaWiki Thumb.php Remote Command Execution|exploit/multi/http/mediawiki_thumb|✓|-|✗|✓|✓
23|ManageEngine OpManager and Social IT Arbitrary File Upload|exploit/multi/http/opmanager_socialit_file_upload|✓|-|✗|✓|-
24|Phpwiki Ploticus Remote Code Execution|exploit/multi/http/phpwiki_ploticus_exec|✗|-|✗|✓|✓
25|SolarWinds Storage Manager Authentication Bypass|exploit/multi/http/solarwinds_store_manager_auth_filter|✓|-|✗|✓|-
26|Dell SonicWALL Scrutinizer 11.01 methodDetail SQL Injection|exploit/multi/http/sonicwall_scrutinizer_methoddetail_sqli|✓|✓|✗|✓|✓
27|Visual Mining NetCharts Server Remote Code Execution|exploit/multi/http/visual_mining_netcharts_upload|✓|-|✗|✓|-
28|Zpanel Remote Unauthenticated RCE|exploit/multi/http/zpanel_information_disclosure_rce|✗|-|✗|✓|✓
29|Dell KACE K1000 File Upload|exploit/unix/http/dell_kace_k1000_upload|✓|-|✗|✓|-
30|TWiki Debugenableplugins Remote Code Execution|exploit/unix/http/twiki_debug_plugins|✓|-|✗|✓|✓
31|VMTurbo Operations Manager vmtadmin.cgi Remote Command Execution|exploit/unix/http/vmturbo_vmtadmin_exec_noauth|✗|-|✗|✓|-
32|Array Networks vAPV and vxAG Private Key Privilege Escalation Code Execution|exploit/unix/ssh/array_vxag_vapv_privkey_privesc|✓|✓|✗|✓|-
33|ActualAnalyzer 'ant' Cookie Command Execution|exploit/unix/webapp/actualanalyzer_ant_cookie_exec|✓|✓|✗|✓|✓
34|FreePBX config.php Remote Code Execution|exploit/unix/webapp/freepbx_config_exec|✓|-|✗|✓|✓
35|Joomla Akeeba Kickstart Unserialize Remote Code Execution|exploit/unix/webapp/joomla_akeeba_unserialize|✓|-|✗|✓|✓
36|ProjectSend Arbitrary File Upload|exploit/unix/webapp/projectsend_upload_exec|✓|-|✗|✓|✓
37|SePortal SQLi Remote Code Execution|exploit/unix/webapp/seportal_sqli_exec|✓|✓|✗|✓|✓
38|Simple E-Document Arbitrary File Upload|exploit/unix/webapp/simple_e_document_upload_exec|✓|-|✗|✓|✓
39|SkyBlueCanvas CMS Remote Code Execution|exploit/unix/webapp/skybluecanvas_exec|✓|-|✗|✓|✓
40|Wordpress Creative Contact Form Upload Vulnerability|exploit/unix/webapp/wp_creativecontactform_file_upload|✓|-|✗|✓|✓
41|Wordpress Download Manager (download-manager) Unauthenticated File Upload|exploit/unix/webapp/wp_downloadmanager_upload|✓|-|✗|✓|✓
42|Wordpress InfusionSoft Upload Vulnerability|exploit/unix/webapp/wp_infusionsoft_upload|✓|-|✗|✓|✓
43|WordPress RevSlider File Upload and Execute Vulnerability|exploit/unix/webapp/wp_revslider_upload_execute|✓|-|✗|✓|✓
44|WordPress WP Symposium 14.11 Shell Upload|exploit/unix/webapp/wp_symposium_shell_upload|✓|-|✗|✓|✓
45|Wordpress MailPoet Newsletters (wysija-newsletters) Unauthenticated File Upload|exploit/unix/webapp/wp_wysija_newsletters_upload|✓|-|✗|✓|✓
46|Symantec Endpoint Protection Manager /servlet/ConsoleServlet Remote Command Execution|exploit/windows/antivirus/symantec_endpoint_manager_rce|✓|-|✗|✓|✓
47|Symantec Workspace Streaming ManagementAgentServer.putFile XMLRPC Request Arbitrary File Upload|exploit/windows/antivirus/symantec_workspace_streaming_exec|✓|-|✗|✓|-
48|ManageEngine Desktop Central StatusUpdate Arbitrary File Upload|exploit/windows/http/desktopcentral_statusupdate_upload|✓|-|✗|✓|-
49|Lexmark MarkVision Enterprise Arbitrary File Upload|exploit/windows/http/lexmark_markvision_gfd_upload|✓|-|✗|✓|✓
50|Oracle Event Processing FileUploadServlet Arbitrary File Upload|exploit/windows/http/oracle_event_processing_upload|✓|-|✗|✓|-
51|Rejetto HttpFileServer Remote Command Execution|exploit/windows/http/rejetto_hfs_exec|✓|-|✗|✓|✓
52|Numara / BMC Track-It! FileStorageService Arbitrary File Upload|exploit/windows/http/trackit_file_upload|✓|-|✗|✓|✓
53|HP Data Protector 8.10 Remote Command Execution|exploit/windows/misc/hp_dataprotector_cmd_exec|✓|-|✗|✓|-
54|HP Data Protector Backup Client Service Remote Code Execution|exploit/windows/misc/hp_dataprotector_exec_bar|✗|-|✗|✓|-
55|GE Proficy CIMPLICITY gefebt.exe Remote Code Execution|exploit/windows/scada/ge_proficy_cimplicity_gefebt|✓|-|✗|✓|✓

#### 2015 (54)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Watchguard XCS Remote Command Execution|exploit/freebsd/http/watchguard_cmd_exec|✓|✓|✗|✓|✓
2|Accellion FTA getStatus verify_oauth_token Command Execution|exploit/linux/http/accellion_fta_getstatus_oauth|✓|-|✗|✓|-
3|Advantech Switch Bash Environment Variable Code Injection (Shellshock)|exploit/linux/http/advantech_switch_bash_env_exec|✓|-|✗|✓|-
4|D-Link DCS-930L Authenticated Remote Command Execution|exploit/linux/http/dlink_dcs_930l_authenticated_remote_command_execution|✓|✓|✗|✓|-
5|F5 iControl iCall::Script Root Command Execution|exploit/linux/http/f5_icall_cmd|✓|✓|✗|✓|✓
6|GoAutoDial 3.3 Authentication Bypass / Command Injection|exploit/linux/http/goautodial_3_rce_command_injection|✓|-|✗|✓|✓
7|MVPower DVR Shell Unauthenticated Command Execution|exploit/linux/http/mvpower_dvr_shell_exec|✓|-|✗|✓|-
8|Hak5 WiFi Pineapple Preconfiguration Command Injection|exploit/linux/http/pineapple_bypass_cmdinject|✓|-|✓|✓|✓
9|Hak5 WiFi Pineapple Preconfiguration Command Injection|exploit/linux/http/pineapple_preconfig_cmdinject|✓|✓|✓|✓|✓
10|TP-Link SC2020n Authenticated Telnet Injection|exploit/linux/http/tp_link_sc2020n_authenticated_telnet_injection|✓|✓|✗|✓|-
11|ASUS infosvr Auth Bypass Command Execution|exploit/linux/misc/asus_infosvr_auth_bypass_exec|✓|-|✗|✓|-
12|Jenkins CLI RMI Java Deserialization Vulnerability|exploit/linux/misc/jenkins_java_deserialize|✓|-|✗|✓|✓
13|Ceragon FibeAir IP-10 SSH Private Key Exposure|exploit/linux/ssh/ceragon_fibeair_known_privkey|✓|-|✗|✓|-
14|ElasticSearch Search Groovy Sandbox Bypass|exploit/multi/elasticsearch/search_groovy_script|✓|-|✗|✓|✓
15|China Chopper Caidao PHP Backdoor Code Execution|exploit/multi/http/caidao_php_backdoor_exec|✓|✓|✗|✓|✓
16|Atlassian HipChat for Jira Plugin Velocity Template Injection|exploit/multi/http/jira_hipchat_template|✗|-|✗|✓|✓
17|Joomla HTTP Header Unauthenticated Remote Code Execution|exploit/multi/http/joomla_http_header_rce|✓|-|✗|✓|✓
18|ManageEngine ServiceDesk Plus Arbitrary File Upload|exploit/multi/http/manageengine_sd_uploader|✓|-|✗|✓|-
19|PHP Utility Belt Remote Code Execution|exploit/multi/http/php_utility_belt_rce|✓|-|✗|✓|✓
20|phpFileManager 0.9.8 Remote Code Execution|exploit/multi/http/phpfilemanager_rce|✗|-|✗|✓|✓
21|PHPMoAdmin 1.1.2 Remote Code Execution|exploit/multi/http/phpmoadmin_exec|✓|-|✗|✓|✓
22|Ruby on Rails Web Console (v2) Whitelist Bypass Code Execution|exploit/multi/http/rails_web_console_v2_code_exec|✓|-|✗|✓|✓
23|Simple Backdoor Shell Remote Code Execution|exploit/multi/http/simple_backdoors_exec|✗|-|✗|✓|✓
24|SysAid Help Desk 'rdslogs' Arbitrary File Upload|exploit/multi/http/sysaid_rdslogs_file_upload|✓|-|✗|✓|✓
25|vBulletin 5.1.2 Unserialize Code Execution|exploit/multi/http/vbulletin_unserialize|✓|-|✗|✓|✓
26|Werkzeug Debug Shell Command Execution|exploit/multi/http/werkzeug_debug_rce|✓|-|✗|✓|✓
27|Novell ZENworks Configuration Management Arbitrary File Upload|exploit/multi/http/zenworks_configuration_management_upload|✓|-|✗|✓|✓
28|Legend Perl IRC Bot Remote Code Execution|exploit/multi/misc/legend_bot_exec|✓|-|✗|✓|-
29|TeamCity Agent XML-RPC Command Execution|exploit/multi/misc/teamcity_agent_xmlrpc_exec|✗|-|✗|✓|-
30|w3tw0rk / Pitbul IRC Bot  Remote Code Execution|exploit/multi/misc/w3tw0rk_exec|✓|-|✗|✓|-
31|Oracle Weblogic Server Deserialization RCE - Raw Object|exploit/multi/misc/weblogic_deserialize_rawobject|✗|-|✗|✓|-
32|Xdh / LinuxNet Perlbot / fBot IRC Bot Remote Code Execution|exploit/multi/misc/xdh_x_exec|✓|-|✗|✓|-
33|ProFTPD 1.3.5 Mod_Copy Command Execution|exploit/unix/ftp/proftpd_modcopy_exec|✓|-|✗|✓|✓
34|Cambium ePMP1000 'ping' Shell via Command Injection (up to v2.5)|exploit/unix/http/epmp1000_ping_cmd_shell|✓|✓|✗|✓|-
35|Joomla Content History SQLi Remote Code Execution|exploit/unix/webapp/joomla_contenthistory_sqli_rce|✓|-|✗|✓|✓
36|Maarch LetterBox Unrestricted File Upload|exploit/unix/webapp/maarch_letterbox_file_upload|✓|-|✗|✓|✓
37|WordPress WP EasyCart Unrestricted File Upload|exploit/unix/webapp/wp_easycart_unrestricted_file_upload|✓|-|✗|✓|✓
38|WordPress Holding Pattern Theme Arbitrary File Upload|exploit/unix/webapp/wp_holding_pattern_file_upload|✓|-|✗|✓|✓
39|Wordpress InBoundio Marketing PHP Upload Vulnerability|exploit/unix/webapp/wp_inboundio_marketing_file_upload|✓|-|✗|✓|✓
40|Wordpress N-Media Website Contact Form Upload Vulnerability|exploit/unix/webapp/wp_nmediawebsite_file_upload|✓|-|✗|✓|✓
41|WordPress Pixabay Images PHP Code Upload|exploit/unix/webapp/wp_pixabay_images_upload|✓|-|✗|✓|✓
42|WordPress Platform Theme File Upload Vulnerability|exploit/unix/webapp/wp_platform_exec|✓|-|✗|✓|✓
43|Wordpress Work The Flow Upload Vulnerability|exploit/unix/webapp/wp_worktheflow_upload|✓|-|✗|✓|✓
44|WordPress WPshop eCommerce Arbitrary File Upload Vulnerability|exploit/unix/webapp/wp_wpshop_ecommerce_file_upload|✓|-|✗|✓|✓
45|X11 Keyboard Command Injection|exploit/unix/x11/x11_keyboard_exec|✗|-|✗|✓|-
46|Apache ActiveMQ 5.x-5.11.1 Directory Traversal Shell Upload|exploit/windows/http/apache_activemq_traversal_upload|✓|✓|✗|✓|✓
47|Ektron 8.5, 8.7, 9.0 XSLT Transform Remote Code Execution|exploit/windows/http/ektron_xslt_exec_ws|✓|-|✗|✓|✓
48|Kaseya VSA uploader.aspx Arbitrary File Upload|exploit/windows/http/kaseya_uploader|✓|-|✗|✓|-
49|ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability|exploit/windows/http/manageengine_connectionid_write|✓|-|✗|✓|✓
50|Oracle BeeHive 2 voice-servlet prepareAudioToPlay() Arbitrary File Upload|exploit/windows/http/oracle_beehive_prepareaudiotoplay|✓|-|✗|✓|✓
51|Symantec Endpoint Protection Manager Authentication Bypass and Code Execution|exploit/windows/http/sepm_auth_bypass_rce|✓|-|✗|✓|✓
52|Solarwinds Firewall Security Manager 6.6.5 Client Session Handling Vulnerability|exploit/windows/http/solarwinds_fsm_userlogin|✓|-|✗|✓|✓
53|IBM WebSphere RCE Java Deserialization Vulnerability|exploit/windows/misc/ibm_websphere_java_deserialize|✓|-|✗|✓|✓
54|IPass Control Pipe Remote Command Execution|exploit/windows/smb/ipass_pipe_exec|✗|-|✗|✓|-

#### 2016 (58)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apache Continuum Arbitrary Command Execution|exploit/linux/http/apache_continuum_cmd_exec|✓|-|✗|✓|-
2|Apache CouchDB Arbitrary Command Execution|exploit/linux/http/apache_couchdb_cmd_exec|✓|-|✗|✓|-
3|ATutor 2.2.1 Directory Traversal / Remote Code Execution|exploit/linux/http/atutor_filemanager_traversal|✓|-|✗|✓|✓
4|Centreon Web Useralias Command Execution|exploit/linux/http/centreon_useralias_exec|✓|-|✗|✓|✓
5|Cisco Firepower Management Console 6.0 Post Authentication UserAdd Vulnerability|exploit/linux/http/cisco_firepower_useradd|✓|✓|✗|✓|✓
6|Dlink DIR Routers Unauthenticated HNAP Login Stack Buffer Overflow|exploit/linux/http/dlink_hnap_login_bof|✗|-|✗|✓|-
7|PowerShellEmpire Arbitrary File Upload (Skywalker)|exploit/linux/http/empire_skywalker|✗|-|✗|✓|-
8|Hadoop YARN ResourceManager Unauthenticated Command Execution|exploit/linux/http/hadoop_unauth_exec|✓|-|✗|✓|-
9|IPFire proxy.cgi RCE|exploit/linux/http/ipfire_proxy_exec|✓|✓|✗|✓|-
10|Kaltura Remote PHP Code Execution|exploit/linux/http/kaltura_unserialize_rce|✓|-|✗|✓|✓
11|Nagios XI Chained Remote Code Execution|exploit/linux/http/nagios_xi_chained_rce|✓|-|✗|✓|-
12|Netgear R7000 and R6400 cgi-bin Command Injection|exploit/linux/http/netgear_r7000_cgibin_exec|✓|-|✗|✓|-
13|Netgear Devices Unauthenticated Remote Command Execution|exploit/linux/http/netgear_unauth_exec|✓|-|✗|✓|✓
14|NETGEAR WNR2000v5 (Un)authenticated hidden_lang_avi Stack Buffer Overflow|exploit/linux/http/netgear_wnr2000_rce|✓|✓|✗|✓|-
15|NUUO NVRmini 2 / Crystal / NETGEAR ReadyNAS Surveillance Authenticated Remote Code Execution|exploit/linux/http/nuuo_nvrmini_auth_rce|✓|✓|✗|✓|✓
16|NUUO NVRmini 2 / NETGEAR ReadyNAS Surveillance Unauthenticated Remote Code Execution|exploit/linux/http/nuuo_nvrmini_unauth_rce|✓|-|✗|✓|✓
17|op5 v7.1.9 Configuration Command Execution|exploit/linux/http/op5_config_exec|✓|✓|✗|✓|✓
18|Riverbed SteelCentral NetProfiler/NetExpress Remote Code Execution|exploit/linux/http/riverbed_netprofiler_netexpress_exec|✓|✓|✗|✓|✓
19|Tiki-Wiki CMS Calendar Command Execution|exploit/linux/http/tiki_calendar_exec|✓|✓|✗|✓|✓
20|Trend Micro Smart Protection Server Exec Remote Code Injection|exploit/linux/http/trendmicro_sps_exec|✓|✓|✗|✓|✓
21|TrueOnline / Billion 5200W-T Router Unauthenticated Command Injection|exploit/linux/http/trueonline_billion_5200w_rce|✓|✓|✗|✓|-
22|TrueOnline / ZyXEL P660HN-T v1 Router Unauthenticated Command Injection|exploit/linux/http/trueonline_p660hn_v1_rce|✓|-|✗|✓|-
23|Ubiquiti airOS Arbitrary File Upload|exploit/linux/http/ubiquiti_airos_file_upload|✓|-|✗|✓|-
24|HID discoveryd command_blink_on Unauthenticated RCE|exploit/linux/misc/hid_discoveryd_command_blink_on_unauth_rce|✓|-|✗|✓|-
25|Jenkins CLI HTTP Java Deserialization Vulnerability|exploit/linux/misc/jenkins_ldap_deserialize|✓|-|✗|✓|✓
26|ExaGrid Known SSH Key and Default Password|exploit/linux/ssh/exagrid_known_privkey|✓|-|✗|✓|-
27|VMware VDP Known SSH Key|exploit/linux/ssh/vmware_vdp_known_privkey|✓|-|✗|✓|-
28|ActiveMQ web shell upload|exploit/multi/http/apache_activemq_upload_jsp|✗|✓|✗|✓|-
29|ATutor 2.2.1 SQL Injection / Remote Code Execution|exploit/multi/http/atutor_sqli|✓|-|✗|✓|✓
30|Bassmaster Batch Arbitrary JavaScript Injection Remote Code Execution|exploit/multi/http/bassmaster_js_injection|✓|-|✗|✓|-
31|BuilderEngine Arbitrary File Upload Vulnerability and execution|exploit/multi/http/builderengine_upload_exec|✓|-|✗|✓|✓
32|Jenkins XStream Groovy classpath Deserialization Vulnerability|exploit/multi/http/jenkins_xstream_deserialize|✗|-|✗|✓|✓
33|Magento 2.0.6 Unserialize Remote Code Execution|exploit/multi/http/magento_unserialize|✓|-|✗|✓|✓
34|Metasploit Web UI Static secret_key_base Value|exploit/multi/http/metasploit_static_secret_key_base|✓|-|✗|✓|✓
35|Novell ServiceDesk Authenticated File Upload|exploit/multi/http/novell_servicedesk_rce|✓|✓|✗|✓|-
36|Oracle ATS Arbitrary File Upload|exploit/multi/http/oracle_ats_file_upload|✗|-|✗|✓|-
37|Phoenix Exploit Kit Remote Code Execution|exploit/multi/http/phoenix_exec|✓|-|✗|✓|✓
38|phpMyAdmin Authenticated Remote Code Execution|exploit/multi/http/phpmyadmin_null_termination_exec|✓|✓|✗|✓|✓
39|Ruby on Rails ActionPack Inline ERB Code Execution|exploit/multi/http/rails_actionpack_inline_exec|✓|-|✗|✓|✓
40|Ruby on Rails Dynamic Render File Upload Remote Code Execution|exploit/multi/http/rails_dynamic_render_code_exec|✓|-|✗|✓|-
41|Apache Shiro v1.2.4 Cookie RememberME Deserial RCE|exploit/multi/http/shiro_rememberme_v124_deserialize|✗|-|✗|✓|✓
42|Apache Struts Dynamic Method Invocation Remote Code Execution|exploit/multi/http/struts_dmi_exec|✗|-|✗|✓|✓
43|Apache Struts REST Plugin With Dynamic Method Invocation Remote Code Execution|exploit/multi/http/struts_dmi_rest_exec|✗|-|✗|✓|✓
44|WebNMS Framework Server Arbitrary File Upload|exploit/multi/http/webnms_file_upload|✓|-|✗|✓|✓
45|BMC Server Automation RSCD Agent NSH Remote Command Execution|exploit/multi/misc/bmc_server_automation_rscd_nsh_rce|✓|-|✗|✓|-
46|NodeJS Debugger Command Injection|exploit/multi/misc/nodejs_v8_debugger|✓|-|✗|✓|-
47|pfSense authenticated graph status RCE|exploit/unix/http/pfsense_graph_injection_exec|✓|✓|✗|✓|-
48|SonicWall Global Management System XMLRPC set_time_zone Unauth RCE|exploit/unix/sonicwall/sonicwall_xmlrpc_rce|✓|-|✗|✓|-
49|Drupal CODER Module Remote Command Execution|exploit/unix/webapp/drupal_coder_exec|✓|-|✗|✓|✓
50|Drupal RESTWS Module Remote PHP Code Execution|exploit/unix/webapp/drupal_restws_exec|✓|-|✗|✓|✓
51|SugarCRM REST Unserialize PHP Code Execution|exploit/unix/webapp/sugarcrm_rest_unserialize_exec|✓|-|✗|✓|✓
52|Tiki Wiki Unauthenticated File Upload Vulnerability|exploit/unix/webapp/tikiwiki_upload_exec|✓|-|✗|✓|✓
53|WordPress WP Mobile Detector 3.5 Shell Upload|exploit/unix/webapp/wp_mobile_detector_upload_execute|✓|-|✗|✓|✓
54|Disk Pulse Enterprise Login Buffer Overflow|exploit/windows/http/disk_pulse_enterprise_bof|✓|-|✗|✓|-
55|DiskBoss Enterprise GET Buffer Overflow|exploit/windows/http/diskboss_get_bof|✓|-|✗|✓|-
56|DiskSavvy Enterprise GET Buffer Overflow|exploit/windows/http/disksavvy_get_bof|✓|-|✗|✓|-
57|NETGEAR ProSafe Network Management System 300 Arbitrary File Upload|exploit/windows/http/netgear_nms_rce|✓|-|✗|✓|✓
58|Advantech WebAccess Dashboard Viewer uploadImageCommon Arbitrary File Upload|exploit/windows/scada/advantech_webaccess_dashboard_file_upload|✓|-|✗|✓|✓

#### 2017 (56)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AlienVault OSSIM/USM Remote Code Execution|exploit/linux/http/alienvault_exec|✓|-|✗|✓|✓
2|Crypttech CryptoLog Remote Code Execution|exploit/linux/http/crypttech_cryptolog_login_exec|✓|-|✗|✓|✓
3|DC/OS Marathon UI Docker Exploit|exploit/linux/http/dcos_marathon|✓|-|✗|✓|✓
4|DenyAll Web Application Firewall Remote Code Execution|exploit/linux/http/denyall_waf_exec|✓|-|✗|✓|✓
5|DIR-850L (Un)authenticated OS Command Exec|exploit/linux/http/dlink_dir850l_unauth_exec|✓|-|✗|✓|-
6|dnaLIMS Admin Module Command Execution|exploit/linux/http/dnalims_admin_exec|✓|-|✗|✓|✓
7|Docker Daemon - Unprotected TCP Socket Exploit|exploit/linux/http/docker_daemon_tcp|✗|-|✗|✓|-
8|Github Enterprise Default Session Secret And Deserialization Vulnerability|exploit/linux/http/github_enterprise_secret|✓|-|✗|✓|✓
9|GoAhead Web Server LD_PRELOAD Arbitrary Module Load|exploit/linux/http/goahead_ldpreload|✓|-|✗|✓|-
10|Huawei HG532n Command Injection|exploit/linux/http/huawei_hg532n_cmdinject|✓|-|✗|✓|-
11|IPFire proxy.cgi RCE|exploit/linux/http/ipfire_oinkcode_exec|✓|✓|✗|✓|-
12|Jenkins CLI Deserialization|exploit/linux/http/jenkins_cli_deserialization|✓|-|✗|✓|✓
13|Linksys WVBR0-25 User-Agent Command Execution|exploit/linux/http/linksys_wvbr0_user_agent_exec_noauth|✓|-|✗|✓|-
14|Logsign Remote Command Injection|exploit/linux/http/logsign_exec|✓|-|✗|✓|-
15|Palo Alto Networks readSessionVarsFromFile() Session Corruption|exploit/linux/http/panos_readsessionvars|✓|-|✗|✓|-
16|Rancher Server - Docker Exploit|exploit/linux/http/rancher_server|✓|-|✗|✓|✓
17|Apache Spark Unauthenticated Command Execution|exploit/linux/http/spark_unauth_rce|✓|-|✗|✓|-
18|Supervisor XML-RPC Authenticated Remote Code Execution|exploit/linux/http/supervisor_xmlrpc_exec|✓|-|✗|✓|✓
19|Trend Micro InterScan Messaging Security (Virtual Appliance) Remote Code Execution|exploit/linux/http/trend_micro_imsva_exec|✓|✓|✗|✓|✓
20|Trend Micro InterScan Messaging Security (Virtual Appliance) Remote Code Execution|exploit/linux/http/trendmicro_imsva_widget_exec|✓|-|✗|✓|✓
21|Unitrends UEB http api remote code execution|exploit/linux/http/ueb_api_rce|✗|-|✗|✓|-
22|Western Digital MyCloud multi_uploadify File Upload Vulnerability|exploit/linux/http/wd_mycloud_multiupload_upload|✓|-|✗|✓|-
23|WePresent WiPG-1000 Command Injection|exploit/linux/http/wipg1000_cmd_injection|✓|-|✗|✓|-
24|Xplico Remote Code Execution|exploit/linux/http/xplico_exec|✓|-|✗|✓|-
25|QNAP Transcode Server Command Execution|exploit/linux/misc/qnap_transcode_server|✓|-|✗|✓|-
26|Unitrends UEB bpserverd authentication bypass RCE|exploit/linux/misc/ueb9_bpserverd|✓|-|✗|✓|-
27|Samba is_known_pipename() Arbitrary Module Load|exploit/linux/samba/is_known_pipename|✓|-|✗|✓|-
28|SolarWinds LEM Default SSH Password Remote Code Execution|exploit/linux/ssh/solarwinds_lem_exec|✓|✓|✗|✓|-
29|IBM OpenAdmin Tool SOAP welcomeServer PHP Code Execution|exploit/multi/http/ibm_openadmin_tool_soap_welcomeserver_exec|✓|-|✗|✓|✓
30|Mako Server v2.5, 2.6 OS Command Injection RCE|exploit/multi/http/makoserver_cmd_exec|✓|-|✗|✓|✓
31|October CMS Upload Protection Bypass Code Execution|exploit/multi/http/october_upload_bypass_exec|✓|✓|✗|✓|✓
32|Oracle WebLogic wls-wsat Component Deserialization RCE|exploit/multi/http/oracle_weblogic_wsat_deserialization_rce|✗|-|✗|✓|✓
33|PlaySMS sendfromfile.php Authenticated "Filename" Field Code Execution|exploit/multi/http/playsms_filename_exec|✓|✓|✗|✓|✓
34|PlaySMS import.php Authenticated CSV File Upload Code Execution|exploit/multi/http/playsms_uploadcsv_exec|✓|✓|✗|✓|✓
35|Apache Struts 2 Struts 1 Plugin Showcase OGNL Code Execution|exploit/multi/http/struts2_code_exec_showcase|✓|-|✗|✓|✓
36|Apache Struts Jakarta Multipart Parser OGNL Injection|exploit/multi/http/struts2_content_type_ognl|✓|-|✗|✓|✓
37|Apache Struts 2 REST Plugin XStream RCE|exploit/multi/http/struts2_rest_xstream|✗|-|✗|✓|✓
38|Tomcat RCE via JSP Upload Bypass|exploit/multi/http/tomcat_jsp_upload_bypass|✓|-|✗|✓|✓
39|Trend Micro Threat Discovery Appliance admin_sys_time.cgi Remote Command Execution|exploit/multi/http/trendmicro_threat_discovery_admin_sys_time_cmdi|✓|✓|✗|✓|✓
40|Oracle Weblogic Server Deserialization RCE - RMI UnicastRef|exploit/multi/misc/weblogic_deserialize_unicastref|✗|-|✗|✓|-
41|Cambium ePMP1000 'get_chart' Shell via Command Injection (v3.1-3.5-RC7)|exploit/unix/http/epmp1000_get_chart_cmd_shell|✓|✓|✗|✓|-
42|pfSense authenticated group member RCE|exploit/unix/http/pfsense_group_member_exec|✓|✓|✗|✓|-
43|xdebug Unauthenticated OS Command Execution|exploit/unix/http/xdebug_unauth_exec|✓|-|✗|✓|-
44|Zivif Camera iptest.cgi Blind Remote Command Execution|exploit/unix/http/zivif_ipcheck_exec|✓|-|✗|✓|-
45|Polycom Shell HDX Series Traceroute Command Execution|exploit/unix/misc/polycom_hdx_traceroute_exec|✓|-|✗|✓|-
46|Joomla Component Fields SQLi Remote Code Execution|exploit/unix/webapp/joomla_comfields_sqli_rce|✓|-|✗|✓|✓
47|phpCollab 2.5.1 Unauthenticated File Upload|exploit/unix/webapp/phpcollab_upload_exec|✓|-|✗|✓|✓
48|VICIdial user_authorization Unauthenticated Command Execution|exploit/unix/webapp/vicidial_user_authorization_unauth_cmd_exec|✓|-|✗|✓|✓
49|Disk Pulse Enterprise GET Buffer Overflow|exploit/windows/http/disk_pulse_enterprise_get|✓|-|✗|✓|-
50|DotNetNuke Cookie Deserialization Remote Code Excecution|exploit/windows/http/dnn_cookie_deserialization_rce|✓|-|✗|✓|✓
51|HP Intelligent Management Java Deserialization RCE|exploit/windows/http/hp_imc_java_deserialize|✓|-|✗|✓|✓
52|Octopus Deploy Authenticated Code Execution|exploit/windows/http/octopusdeploy_deploy|✓|-|✗|✓|-
53|Serviio Media Server checkStreamUrl Command Execution|exploit/windows/http/serviio_checkstreamurl_cmd_exec|✓|-|✗|✓|-
54|Trend Micro OfficeScan Remote Code Execution|exploit/windows/http/trendmicro_officescan_widget_exec|✓|-|✗|✓|✓
55|HPE iMC dbman RestartDB Unauthenticated RCE|exploit/windows/misc/hp_imc_dbman_restartdb_unauth_rce|✓|-|✗|✓|-
56|HPE iMC dbman RestoreDBase Unauthenticated RCE|exploit/windows/misc/hp_imc_dbman_restoredbase_unauth_rce|✓|-|✗|✓|-

#### 2018 (31)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|AsusWRT LAN Unauthenticated Remote Code Execution|exploit/linux/http/asuswrt_lan_rce|✓|-|✗|✓|-
2|Axis Network Camera .srv to parhand RCE|exploit/linux/http/axis_srv_parhand_rce|✗|-|✗|✓|-
3|Cisco Prime Infrastructure Unauthenticated Remote Code Execution|exploit/linux/http/cisco_prime_inf_rce|✓|-|✗|✓|✓
4|HP VAN SDN Controller Root Command Injection|exploit/linux/http/hp_van_sdn_cmd_inject|✗|-|✗|✓|-
5|IBM QRadar SIEM Unauthenticated Remote Code Execution|exploit/linux/http/ibm_qradar_unauth_rce|✓|-|✗|✓|-
6|Imperva SecureSphere PWS Command Injection|exploit/linux/http/imperva_securesphere_exec|✓|-|✗|✓|-
7|MicroFocus Secure Messaging Gateway Remote Code Execution|exploit/linux/http/microfocus_secure_messaging_gateway|✓|-|✗|✓|✓
8|QNAP Q'Center change_passwd Command Execution|exploit/linux/http/qnap_qcenter_change_passwd_exec|✓|✓|✗|✓|✓
9|Baldr Botnet Panel Shell Upload Exploit|exploit/multi/http/baldr_upload_exec|✗|-|✗|✓|✓
10|ClipBucket beats_uploader Unauthenticated Arbitrary File Upload|exploit/multi/http/clipbucket_fileupload_exec|✓|-|✗|✓|✓
11|Adobe ColdFusion CKEditor unrestricted file upload|exploit/multi/http/coldfusion_ckeditor_file_upload|✓|-|✗|✓|-
12|GitList v0.6.0 Argument Injection Vulnerability|exploit/multi/http/gitlist_arg_injection|✓|-|✗|✓|✓
13|Atlassian Jira Authenticated Upload Code Execution|exploit/multi/http/jira_plugin_upload|✓|✓|✗|✓|✓
14|Navigate CMS Unauthenticated Remote Code Execution|exploit/multi/http/navigate_cms_rce|✓|-|✗|✓|✓
15|NUUO NVRmini upgrade_handle.php Remote Command Execution|exploit/multi/http/nuuo_nvrmini_upgrade_rce|✓|-|✗|✓|-
16|osCommerce Installer Unauthenticated Code Execution|exploit/multi/http/oscommerce_installer_unauth_code_exec|✓|-|✗|✓|-
17|Apache Struts 2 Namespace Redirect OGNL Injection|exploit/multi/http/struts2_namespace_ognl|✓|-|✗|✓|✓
18|Nanopool Claymore Dual Miner APIs RCE|exploit/multi/misc/claymore_dual_miner_remote_manager_rce|✓|-|✗|✓|-
19|Hashicorp Consul Remote Command Execution via Rexec|exploit/multi/misc/consul_rexec_exec|✓|-|✗|✓|✓
20|Hashicorp Consul Remote Command Execution via Services API|exploit/multi/misc/consul_service_exec|✗|-|✗|✓|✓
21|Metasploit msfd Remote Code Execution|exploit/multi/misc/msfd_rce_remote|✓|-|✗|✓|-
22|PHP Laravel Framework token Unserialize Remote Command Execution|exploit/unix/http/laravel_token_unserialize_exec|✓|-|✗|✓|✓
23|Pi-Hole Whitelist OS Command Execution|exploit/unix/http/pihole_whitelist_exec|✓|-|✗|✓|✓
24|Quest KACE Systems Management Command Injection|exploit/unix/http/quest_kace_systems_management_rce|✓|-|✗|✓|-
25|Drupal Drupalgeddon 2 Forms API Property Injection|exploit/unix/webapp/drupal_drupalgeddon2|✓|-|✗|✓|✓
26|blueimp's jQuery (Arbitrary) File Upload|exploit/unix/webapp/jquery_file_upload|✗|-|✗|✓|✓
27|ThinkPHP Multiple PHP Injection RCEs|exploit/unix/webapp/thinkphp_rce|✗|-|✗|✓|✓
28|Apache Tika Header Command Injection|exploit/windows/http/apache_tika_jp2_jscript|✓|-|✗|✓|✓
29|Manage Engine Exchange Reporter Plus Unauthenticated RCE|exploit/windows/http/manageengine_adshacluster_rce|✓|-|✗|✓|✓
30|ManageEngine Applications Manager Remote Code Execution|exploit/windows/http/manageengine_appmanager_exec|✓|-|✗|✓|✓
31|PRTG Network Monitor Authenticated RCE|exploit/windows/http/prtg_authenticated_rce|✓|✓|✗|✓|-

#### 2019 (36)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Cisco UCS Director Unauthenticated Remote Code Execution|exploit/linux/http/cisco_ucs_rce|✓|-|✗|✓|✓
2|Cisco Prime Infrastructure Health Monitor TarArchive Directory Traversal Vulnerability|exploit/linux/http/cpi_tararchive_upload|✓|-|✗|✓|✓
3|DLINK DWL-2600 Authenticated Remote Command Injection|exploit/linux/http/dlink_dwl_2600_command_injection|✗|✓|✗|✓|✓
4|Webmin password_change.cgi Backdoor|exploit/linux/http/webmin_backdoor|✓|-|✗|✓|✓
5|Barco WePresent file_transfer.cgi Command Injection|exploit/linux/http/wepresent_cmd_injection|✗|-|✗|✓|-
6|Zimbra Collaboration Autodiscover Servlet XXE and ProxyServlet SSRF|exploit/linux/http/zimbra_xxe_rce|✓|-|✗|✓|✓
7|AwindInc SNMP Service Command Injection|exploit/linux/snmp/awind_snmp_exec|✗|-|✗|✓|-
8|Cisco UCS Director default scpuser password|exploit/linux/ssh/cisco_ucs_scpuser|✓|✓|✗|✓|-
9|D-Link DIR-859 Unauthenticated Remote Command Execution|exploit/linux/upnp/dlink_dir859_subscribe_exec|✓|-|✗|✓|-
10|Agent Tesla Panel Remote Code Execution|exploit/multi/http/agent_tesla_panel_rce|✓|-|✗|✓|✓
11|Apache Flink JAR Upload Java Code Execution|exploit/multi/http/apache_flink_jar_upload_exec|✓|-|✗|✓|-
12|Cisco Data Center Network Manager Unauthenticated Remote Code Execution|exploit/multi/http/cisco_dcnm_upload_2019|✓|✓|✗|✓|✓
13|GetSimpleCMS Unauthenticated RCE|exploit/multi/http/getsimplecms_unauth_code_exec|✓|-|✗|✓|✓
14|Jenkins ACL Bypass and Metaprogramming RCE|exploit/multi/http/jenkins_metaprogramming|✗|-|✗|✓|✓
15|Liferay Portal Java Unmarshalling via JSONWS RCE|exploit/multi/http/liferay_java_unmarshalling|✓|-|✗|✓|✓
16|PHPStudy Backdoor Remote Code execution|exploit/multi/http/phpstudy_backdoor_rce|✓|-|✗|✓|✓
17|Ruby On Rails DoubleTap Development Mode secret_key_base Vulnerability|exploit/multi/http/rails_double_tap|✓|-|✗|✓|✓
18|Shopware createInstanceFromNamedArguments PHP Object Instantiation RCE|exploit/multi/http/shopware_createinstancefromnamedarguments_rce|✓|✓|✗|✓|✓
19|Apache Solr Remote Code Execution via Velocity Template|exploit/multi/http/solr_velocity_rce|✗|-|✗|✓|-
20|Total.js CMS 12 Widget JavaScript Code Injection|exploit/multi/http/totaljs_cms_widget_exec|✗|✓|✗|✓|✓
21|vBulletin widgetConfig RCE|exploit/multi/http/vbulletin_widgetconfig_rce|✗|-|✗|✓|✓
22|BMC Patrol Agent Privilege Escalation Cmd Execution|exploit/multi/misc/bmc_patrol_cmd_exec|✗|✓|✗|✓|-
23|IBM TM1 / Planning Analytics Unauthenticated Remote Code Execution|exploit/multi/misc/ibm_tm1_unauth_rce|✗|-|✗|✓|-
24|Oracle Weblogic Server Deserialization RCE - AsyncResponseService |exploit/multi/misc/weblogic_deserialize_asyncresponseservice|✗|-|✗|✓|✓
25|PostgreSQL COPY FROM PROGRAM Command Execution|exploit/multi/postgres/postgres_copy_from_program_cmd_exec|✓|✓|✗|✓|-
26|Schneider Electric Pelco Endura NET55XX Encoder|exploit/unix/http/schneider_electric_net55xx_encoder|✓|✓|✗|✓|-
27|Ajenti auth username Command Injection|exploit/unix/webapp/ajenti_auth_username_cmd_injection|✓|-|✗|✓|✓
28|elFinder PHP Connector exiftran Command Injection|exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection|✓|-|✗|✓|✓
29|OpenNetAdmin Ping Command Injection|exploit/unix/webapp/opennetadmin_ping_cmd_injection|✓|-|✗|✓|✓
30|rConfig install Command Execution|exploit/unix/webapp/rconfig_install_cmd_exec|✓|-|✗|✓|✓
31|D-Link Central WiFi Manager CWM(100) RCE|exploit/windows/http/dlink_central_wifimanager_rce|✓|-|✗|✓|✓
32|Kentico CMS Staging SyncServer Unserialize Remote Command Execution|exploit/windows/http/kentico_staging_syncserver|✓|-|✗|✓|✓
33|Telerik UI ASP.NET AJAX RadAsyncUpload Deserialization|exploit/windows/http/telerik_rau_deserialization|✓|-|✗|✓|✓
34|Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability|exploit/windows/http/tomcat_cgi_cmdlineargs|✓|-|✗|✓|✓
35|IBM Websphere Application Server Network Deployment Untrusted Data Deserialization Remote Code Execution|exploit/windows/ibm/ibm_was_dmgr_java_deserialization_rce|✗|-|✗|✓|-
36|Ahsay Backup v7.x-v8.1.1.50 (authenticated) file upload|exploit/windows/misc/ahsay_backup_fileupload|✗|✓|✗|✓|✓

#### 2020 (42)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Apache OFBiz XML-RPC Java Deserialization|exploit/linux/http/apache_ofbiz_deserialization|✗|-|✗|✓|✓
2|Artica proxy 4.30.000000 Auth Bypass service-cmds-peform Command Injection|exploit/linux/http/artica_proxy_auth_bypass_service_cmds_peform_command_injection|✗|-|✗|✓|✓
3|Cayin CMS NTP Server RCE|exploit/linux/http/cayin_cms_ntp|✓|✓|✗|✓|✓
4|Cisco UCS Director Cloupia Script RCE|exploit/linux/http/cisco_ucs_cloupia_script_rce|✗|-|✗|✓|✓
5|Geutebruck testaction.cgi Remote Command Execution|exploit/linux/http/geutebruck_testaction_exec|✓|✓|✗|✓|✓
6|IBM Data Risk Manager Unauthenticated Remote Code Execution|exploit/linux/http/ibm_drm_rce|✓|-|✗|✓|✓
7|Klog Server authenticate.php user Unauthenticated Command Injection|exploit/linux/http/klog_server_authenticate_user_unauth_command_injection|✗|-|✗|✓|✓
8|LinuxKI Toolset 6.01 Remote Command Execution|exploit/linux/http/linuxki_rce|✓|-|✗|✓|✓
9|Mida Solutions eFramework ajaxreq.php Command Injection|exploit/linux/http/mida_solutions_eframework_ajaxreq_rce|✗|-|✗|✓|✓
10|MobileIron MDM Hessian-Based Java Deserialization RCE|exploit/linux/http/mobileiron_mdm_hessian_rce|✗|-|✗|✓|✓
11|Netsweeper WebAdmin unixlogin.php Python Code Injection|exploit/linux/http/netsweeper_webadmin_unixlogin|✓|-|✗|✓|✓
12|Pandora FMS Events Remote Command Execution|exploit/linux/http/pandora_fms_events_exec|✗|✓|✗|✓|✓
13|Pulse Secure VPN gzip RCE|exploit/linux/http/pulse_secure_gzip_rce|✗|✓|✗|✓|✓
14|SaltStack Salt REST API Arbitrary Command Execution|exploit/linux/http/saltstack_salt_api_cmd_exec|✗|-|✗|✓|✓
15|TP-Link Cloud Cameras NCXXX Bonjour Command Injection|exploit/linux/http/tp_link_ncxxx_bonjour_command_injection|✗|✓|✗|✓|-
16|Trend Micro Web Security (Virtual Appliance) Remote Code Execution|exploit/linux/http/trendmicro_websecurity_exec|✓|-|✗|✓|-
17|Unraid 6.8.0 Auth Bypass PHP Code Execution|exploit/linux/http/unraid_auth_bypass_exec|✓|-|✗|✓|✓
18|TP-Link Archer A7/C7 Unauthenticated LAN Remote Code Execution|exploit/linux/misc/tplink_archer_a7_c7_lan_rce|✓|-|✗|✓|-
19|IBM Data Risk Manager a3user Default Password|exploit/linux/ssh/ibm_drm_a3user|✓|✓|✗|✓|-
20|Apache NiFi API Remote Code Execution|exploit/multi/http/apache_nifi_processor_rce|✗|-|✗|✓|✓
21|GitLab File Read Remote Code Execution|exploit/multi/http/gitlab_file_read_rce|✓|-|✗|✓|✓
22|Kong Gateway Admin API Remote Code Execution|exploit/multi/http/kong_gateway_admin_api_rce|✓|-|✗|✓|✓
23|MaraCMS Arbitrary PHP File Upload|exploit/multi/http/maracms_upload_exec|✗|✓|✗|✓|✓
24|Micro Focus UCMDB Java Deserialization Unauthenticated Remote Code Execution|exploit/multi/http/microfocus_ucmdb_unauth_deser|✗|-|✗|✓|✓
25|PlaySMS index.php Unauthenticated Template Injection Code Execution|exploit/multi/http/playsms_template_injection|✓|-|✗|✓|✓
26|Apache Struts 2 Forced Multi OGNL Evaluation|exploit/multi/http/struts2_multi_eval_ognl|✗|-|✗|✓|✓
27|vBulletin 5.x /ajax/render/widget_tabbedcontainer_tab_panel PHP remote code execution.|exploit/multi/http/vbulletin_widget_template_rce|✗|-|✗|✓|✓
28|Oracle WebLogic Server Administration Console Handle RCE|exploit/multi/http/weblogic_admin_handle_rce|✗|-|✗|✓|✓
29|WordPress AIT CSV Import Export Unauthenticated Remote Code Execution|exploit/multi/http/wp_ait_csv_rce|✓|-|✗|✓|✓
30|Wordpress Drag and Drop Multi File Uploader RCE|exploit/multi/http/wp_dnd_mul_file_rce|✓|-|✗|✓|✓
31|Inductive Automation Ignition Remote Code Execution|exploit/multi/scada/inductive_ignition_rce|✓|-|✗|✓|-
32|Pi-Hole heisenbergCompensator Blocklist OS Command Execution|exploit/unix/http/pihole_blocklist_exec|✓|-|✗|✓|✓
33|OpenSMTPD MAIL FROM Remote Code Execution|exploit/unix/smtp/opensmtpd_mail_from_rce|✓|-|✗|✓|-
34|OpenMediaVault rpc.php Authenticated PHP Code Injection|exploit/unix/webapp/openmediavault_rpc_rce|✓|✓|✗|✓|✓
35|openSIS Unauthenticated PHP Code Execution|exploit/unix/webapp/opensis_chain_exec|✓|-|✗|✓|✓
36|TrixBox CE endpoint_devicemap.php Authenticated Command Execution|exploit/unix/webapp/trixbox_ce_endpoint_devicemap_rce|✓|✓|✗|✓|-
37|Cayin xPost wayfinder_seqid SQLi to RCE|exploit/windows/http/cayin_xpost_sql_rce|✓|-|✗|✓|✓
38|ManageEngine Desktop Central Java Deserialization|exploit/windows/http/desktopcentral_deserialization|✗|-|✗|✓|✓
39|HPE Systems Insight Manager AMF Deserialization RCE|exploit/windows/http/hpe_sim_76_amf_deserialization|✗|-|✗|✓|✓
40|Plesk/myLittleAdmin ViewState .NET Deserialization|exploit/windows/http/plesk_mylittleadmin_viewstate|✗|-|✗|✓|✓
41|Microsoft SharePoint Server-Side Include and ViewState RCE|exploit/windows/http/sharepoint_ssi_viewstate|✗|-|✗|✓|✓
42|CA Unified Infrastructure Management Nimsoft 7.80 - Remote Buffer Overflow|exploit/windows/nimsoft/nimcontroller_bof|✓|-|✗|✓|-

#### 2021 (1)

| # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
1|Microsoft Exchange Server DlpUtils AddTenantDlpPolicy RCE|exploit/windows/http/exchange_ecp_dlp_policy|✓|-|✗|✓|✓

## Evasion (0)

