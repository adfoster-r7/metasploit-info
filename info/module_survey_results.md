# A survey of module options to identify modules which only require target, port, credentials, or URL paths
## Session required 

 | # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
| 1 | Eaton Xpert Meter SSH Private Key Exposure Scanner | auxiliary/scanner/ssh/eaton_xpert_backdoor | - | - | Required | - |
| 2 | Fortinet SSH Backdoor Scanner | auxiliary/scanner/ssh/fortinet_backdoor | - | - | Required | - |
| 3 | libssh Authentication Bypass Scanner | auxiliary/scanner/ssh/libssh_auth_bypass | - | - | Required | - |
| 4 | SSH Login Check Scanner | auxiliary/scanner/ssh/ssh_login | - | - | Required | - |
| 5 | SSH Public Key Login Scanner | auxiliary/scanner/ssh/ssh_login_pubkey | - | - | Required | - |


## No session required

| # | Module Name | Module Path | Target | Credentials | Port | URL |
| :---: | :--- | :--- | :----: | :----: | :----: | :---: |
| 1 | ibstat $PATH Privilege Escalation | exploit/aix/local/ibstat_path | Required | - | - | - |
| 2 | Xorg X11 Server Local Privilege Escalation | exploit/aix/local/xorg_x11_server | Required | - | - | - |
| 3 | Adobe Reader for Android addJavascriptInterface Exploit | exploit/android/fileformat/adobe_reader_pdf_js_interface | Required | - | - | - |
| 4 | Android Binder Use-After-Free Exploit | exploit/android/local/binder_uaf | Required | - | - | - |
| 5 | Android 'Towelroot' Futex Requeue Kernel Exploit | exploit/android/local/futex_requeue | Required | - | - | - |
| 6 | Android Janus APK Signature bypass | exploit/android/local/janus | Required | - | - | - |
| 7 | Android get_user/put_user Exploit | exploit/android/local/put_user_vroot | Required | - | - | - |
| 8 | Apple iOS Default SSH Password Vulnerability | exploit/apple_ios/ssh/cydia_default_ssh | Required | - | Required | - |
| 9 | System V Derived /bin/login Extraneous Arguments Buffer Overflow | exploit/dialup/multi/login/manyargs | Required | - | - | - |
| 10 | Firefox Exec Shellcode from Privileged Javascript Shell | exploit/firefox/local/exec_shellcode | Required | - | - | - |
| 11 | FreeBSD Intel SYSRET Privilege Escalation | exploit/freebsd/local/intel_sysret_priv_esc | Required | - | - | - |
| 12 | FreeBSD ip6_setpktopt Use-After-Free Privilege Escalation | exploit/freebsd/local/ip6_setpktopt_uaf_priv_esc | Required | - | - | - |
| 13 | FreeBSD 9 Address Space Manipulation Privilege Escalation | exploit/freebsd/local/mmap | Required | - | - | - |
| 14 | FreeBSD rtld execl() Privilege Escalation | exploit/freebsd/local/rtld_execl_priv_esc | Required | - | - | - |
| 15 | Watchguard XCS FixCorruptMail Local Privilege Escalation | exploit/freebsd/local/watchguard_fix_corrupt_mail | Required | - | - | - |
| 16 | XTACACSD report() Buffer Overflow | exploit/freebsd/tacacs/xtacacsd_report | Required | - | Required | - |
| 17 | Unreal Tournament 2004 "secure" Overflow (Linux) | exploit/linux/games/ut2004_secure | Required | - | Required | - |
| 18 | Snort Back Orifice Pre-Preprocessor Buffer Overflow | exploit/linux/ids/snortbopre | Required | - | Required | - |
| 19 | ABRT raceabrt Privilege Escalation | exploit/linux/local/abrt_raceabrt_priv_esc | Required | - | - | - |
| 20 | ABRT sosreport Privilege Escalation | exploit/linux/local/abrt_sosreport_priv_esc | Required | - | - | - |
| 21 | AF_PACKET chocobo_root Privilege Escalation | exploit/linux/local/af_packet_chocobo_root_priv_esc | Required | - | - | - |
| 22 | AF_PACKET packet_set_ring Privilege Escalation | exploit/linux/local/af_packet_packet_set_ring_priv_esc | Required | - | - | - |
| 23 | Apport / ABRT chroot Privilege Escalation | exploit/linux/local/apport_abrt_chroot_priv_esc | Required | - | - | - |
| 24 | APT Package Manager Persistence | exploit/linux/local/apt_package_manager_persistence | Required | - | - | - |
| 25 | AddressSanitizer (ASan) SUID Executable Privilege Escalation | exploit/linux/local/asan_suid_executable_priv_esc | Required | - | - | - |
| 26 | Autostart Desktop Item Persistence | exploit/linux/local/autostart_persistence | Required | - | - | - |
| 27 | Bash Profile Persistence | exploit/linux/local/bash_profile_persistence | Required | - | - | - |
| 28 | blueman set_dhcp_handler D-Bus Privilege Escalation | exploit/linux/local/blueman_set_dhcp_handler_dbus_priv_esc | Required | - | - | - |
| 29 | Linux BPF doubleput UAF Privilege Escalation | exploit/linux/local/bpf_priv_esc | Required | - | - | - |
| 30 | Linux BPF Sign Extension Local Privilege Escalation | exploit/linux/local/bpf_sign_extension_priv_esc | Required | - | - | - |
| 31 | Cisco Prime Infrastructure Runrshell Privilege Escalation | exploit/linux/local/cpi_runrshell_priv_esc | Required | - | - | - |
| 32 | Cron Persistence | exploit/linux/local/cron_persistence | Required | - | - | - |
| 33 | Desktop Linux Password Stealer and Privilege Escalation | exploit/linux/local/desktop_privilege_escalation | Required | - | - | - |
| 34 | Diamorphine Rootkit Signal Privilege Escalation | exploit/linux/local/diamorphine_rootkit_signal_priv_esc | Required | - | - | - |
| 35 | Docker Daemon Privilege Escalation | exploit/linux/local/docker_daemon_privilege_escalation | Required | - | - | - |
| 36 | Docker Privileged Container Escape | exploit/linux/local/docker_privileged_container_escape | Required | - | - | - |
| 37 | Exim 4.87 - 4.91 Local Privilege Escalation | exploit/linux/local/exim4_deliver_message_priv_esc | Required | - | - | - |
| 38 | glibc LD_AUDIT Arbitrary DSO Load Privilege Escalation | exploit/linux/local/glibc_ld_audit_dso_load_priv_esc | Required | - | - | - |
| 39 | glibc '$ORIGIN' Expansion Privilege Escalation | exploit/linux/local/glibc_origin_expansion_priv_esc | Required | - | - | - |
| 40 | glibc 'realpath()' Privilege Escalation | exploit/linux/local/glibc_realpath_priv_esc | Required | - | - | - |
| 41 | HP System Management Homepage Local Privilege Escalation | exploit/linux/local/hp_smhstart | Required | - | - | - |
| 42 | HP Performance Monitoring xglance Priv Esc | exploit/linux/local/hp_xglance_priv_esc | Required | - | - | - |
| 43 | Juju-run Agent Privilege Escalation | exploit/linux/local/juju_run_agent_priv_esc | Required | - | - | - |
| 44 | Kloxo Local Privilege Escalation | exploit/linux/local/kloxo_lxsuexec | Required | - | - | - |
| 45 | ktsuss suid Privilege Escalation | exploit/linux/local/ktsuss_suid_priv_esc | Required | - | - | - |
| 46 | lastore-daemon D-Bus Privilege Escalation | exploit/linux/local/lastore_daemon_dbus_priv_esc | Required | - | - | - |
| 47 | Libuser roothelper Privilege Escalation | exploit/linux/local/libuser_roothelper_priv_esc | Required | - | - | - |
| 48 | Linux Nested User Namespace idmap Limit Local Privilege Escalation | exploit/linux/local/nested_namespace_idmap_limit_priv_esc | Required | - | - | - |
| 49 | Linux Kernel 4.6.3 Netfilter Privilege Escalation | exploit/linux/local/netfilter_priv_esc_ipv4 | Required | - | - | - |
| 50 | Network Manager VPNC Username Privilege Escalation | exploit/linux/local/network_manager_vpnc_username_priv_esc | Required | - | - | - |
| 51 | Debian/Ubuntu ntfs-3g Local Privilege Escalation | exploit/linux/local/ntfs3g_priv_esc | Required | - | - | - |
| 52 | Micro Focus (HPE) Data Protector SUID Privilege Escalation | exploit/linux/local/omniresolve_suid_priv_esc | Required | - | - | - |
| 53 | Overlayfs Privilege Escalation | exploit/linux/local/overlayfs_priv_esc | Required | - | - | - |
| 54 | Linux PolicyKit Race Condition Privilege Escalation | exploit/linux/local/pkexec | Required | - | - | - |
| 55 | ptrace Sudo Token Privilege Escalation | exploit/linux/local/ptrace_sudo_token_priv_esc | Required | - | - | - |
| 56 | Linux Polkit pkexec helper PTRACE_TRACEME local root exploit | exploit/linux/local/ptrace_traceme_pkexec_helper | Required | - | - | - |
| 57 | rc.local Persistence | exploit/linux/local/rc_local_persistence | Required | - | - | - |
| 58 | Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation | exploit/linux/local/rds_atomic_free_op_null_pointer_deref_priv_esc | Required | - | - | - |
| 59 | Reliable Datagram Sockets (RDS) rds_page_copy_user Privilege Escalation | exploit/linux/local/rds_rds_page_copy_user_priv_esc | Required | - | - | - |
| 60 | Linux Kernel recvmmsg Privilege Escalation | exploit/linux/local/recvmmsg_priv_esc | Required | - | - | - |
| 61 | Reptile Rootkit reptile_cmd Privilege Escalation | exploit/linux/local/reptile_rootkit_reptile_cmd_priv_esc | Required | - | - | - |
| 62 | Service Persistence | exploit/linux/local/service_persistence | Required | - | - | - |
| 63 | Serv-U FTP Server prepareinstallation Privilege Escalation | exploit/linux/local/servu_ftp_server_prepareinstallation_priv_esc | Required | - | - | - |
| 64 | Linux Kernel Sendpage Local Privilege Escalation | exploit/linux/local/sock_sendpage | Required | - | - | - |
| 65 | Sophos Web Protection Appliance clear_keys.pl Local Privilege Escalation | exploit/linux/local/sophos_wpa_clear_keys | Required | - | - | - |
| 66 | Login to Another User with Su on Linux / Unix Systems | exploit/linux/local/su_login | Required | Required | - | - |
| 67 | Sudo Heap-Based Buffer Overflow | exploit/linux/local/sudo_baron_samedit | Required | - | - | - |
| 68 | SystemTap MODPROBE_OPTIONS Privilege Escalation | exploit/linux/local/systemtap_modprobe_options_priv_esc | Required | - | - | - |
| 69 | Linux udev Netlink Local Privilege Escalation | exploit/linux/local/udev_netlink | Required | - | - | - |
| 70 | Unitrends Enterprise Backup bpserverd Privilege Escalation | exploit/linux/local/ueb_bpserverd_privesc | Required | - | - | - |
| 71 | Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation | exploit/linux/local/ufo_privilege_escalation | Required | - | - | - |
| 72 | VMware Workstation ALSA Config File Local Privilege Escalation | exploit/linux/local/vmware_alsa_config | Required | - | - | - |
| 73 | VMWare Setuid vmware-mount Unsafe popen(3) | exploit/linux/local/vmware_mount | Required | - | - | - |
| 74 | Yum Package Manager Persistence | exploit/linux/local/yum_package_manager_persistence | Required | - | - | - |
| 75 | ZPanel zsudo Local Privilege Escalation Exploit | exploit/linux/local/zpanel_zsudo | Required | - | - | - |
| 76 | Accellion FTA MPIPE2 Command Execution | exploit/linux/misc/accellion_fta_mpipe2 | Required | - | Required | - |
| 77 | ASUS infosvr Auth Bypass Command Execution | exploit/linux/misc/asus_infosvr_auth_bypass_exec | Required | - | Required | - |
| 78 | AnyDesk GUI Format String Write | exploit/linux/misc/cve_2020_13160_anydesk | Required | - | Required | - |
| 79 | HP Network Node Manager I PMD Buffer Overflow | exploit/linux/misc/hp_nnmi_pmd_bof | Required | - | Required | - |
| 80 | PostgreSQL for Linux Payload Execution | exploit/linux/postgres/postgres_payload | Required | Required | Required | - |
| 81 | Ceragon FibeAir IP-10 SSH Private Key Exposure | exploit/linux/ssh/ceragon_fibeair_known_privkey | Required | - | Required | - |
| 82 | Cisco UCS Director default scpuser password | exploit/linux/ssh/cisco_ucs_scpuser | Required | Required | Required | - |
| 83 | ExaGrid Known SSH Key and Default Password | exploit/linux/ssh/exagrid_known_privkey | Required | - | Required | - |
| 84 | F5 BIG-IP SSH Private Key Exposure | exploit/linux/ssh/f5_bigip_known_privkey | Required | - | Required | - |
| 85 | IBM Data Risk Manager a3user Default Password | exploit/linux/ssh/ibm_drm_a3user | Required | Required | Required | - |
| 86 | Loadbalancer.org Enterprise VA SSH Private Key Exposure | exploit/linux/ssh/loadbalancerorg_enterprise_known_privkey | Required | - | Required | - |
| 87 | Mercurial Custom hg-ssh Wrapper Remote Code Exec | exploit/linux/ssh/mercurial_ssh_exec | Required | Required | Required | - |
| 88 | Quantum DXi V1000 SSH Private Key Exposure | exploit/linux/ssh/quantum_dxi_known_privkey | Required | - | Required | - |
| 89 | Quantum vmPRO Backdoor Command | exploit/linux/ssh/quantum_vmpro_backdoor | Required | Required | Required | - |
| 90 | SolarWinds LEM Default SSH Password Remote Code Execution | exploit/linux/ssh/solarwinds_lem_exec | Required | Required | Required | - |
| 91 | Symantec Messaging Gateway 9.5 Default SSH Password Vulnerability | exploit/linux/ssh/symantec_smg_ssh | Required | - | Required | - |
| 92 | VMware VDP Known SSH Key | exploit/linux/ssh/vmware_vdp_known_privkey | Required | - | Required | - |
| 93 | VyOS restricted-shell Escape and Privilege Escalation | exploit/linux/ssh/vyos_restricted_shell_privesc | Required | Required | Required | - |
| 94 | Adobe U3D CLODProgressiveMeshDeclaration Array Overrun | exploit/multi/fileformat/adobe_u3d_meshcont | Required | - | - | - |
| 95 | PEAR Archive_Tar 1.4.10 Arbitrary File Write | exploit/multi/fileformat/archive_tar_arb_file_write | Required | - | - | - |
| 96 | Evince CBT File Command Injection | exploit/multi/fileformat/evince_cbt_cmd_injection | Required | - | - | - |
| 97 | Javascript Injection for Eval-based Unpackers | exploit/multi/fileformat/js_unpacker_eval_injection | Required | - | - | - |
| 98 | LibreOffice Macro Python Code Execution | exploit/multi/fileformat/libreoffice_logo_exec | Required | - | - | - |
| 99 | Maple Maplet File Creation and Command Execution | exploit/multi/fileformat/maple_maplet | Required | - | - | - |
| 100 | Nodejs js-yaml load() Code Execution | exploit/multi/fileformat/nodejs_js_yaml_load_code_exec | Required | - | - | - |
| 101 | Microsoft Office Word Malicious Macro Execution | exploit/multi/fileformat/office_word_macro | Required | - | - | - |
| 102 | PeaZip Zip Processing Command Injection | exploit/multi/fileformat/peazip_command_injection | Required | - | - | - |
| 103 | JSON Swagger CodeGen Parameter Injector | exploit/multi/fileformat/swagger_param_inject | Required | - | - | - |
| 104 | Generic Zip Slip Traversal Vulnerability | exploit/multi/fileformat/zip_slip | Required | - | - | - |
| 105 | Steamed Hams | exploit/multi/hams/steamed | Required | - | - | - |
| 106 | Generic Payload Handler | exploit/multi/handler | Required | - | - | - |
| 107 | Allwinner 3.4 Legacy Kernel Local Privilege Escalation | exploit/multi/local/allwinner_backdoor | Required | - | - | - |
| 108 | MagniComp SysInfo mcsiwrapper Privilege Escalation | exploit/multi/local/magnicomp_sysinfo_mcsiwrapper_priv_esc | Required | - | - | - |
| 109 | Xorg X11 Server SUID logfile Privilege Escalation | exploit/multi/local/xorg_x11_suid_server | Required | - | - | - |
| 110 | Xorg X11 Server SUID modulepath Privilege Escalation | exploit/multi/local/xorg_x11_suid_server_modulepath | Required | - | - | - |
| 111 | Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow | exploit/multi/misc/wireshark_lwres_getaddrbyname | Required | - | Required | - |
| 112 | Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow (loop) | exploit/multi/misc/wireshark_lwres_getaddrbyname_loop | Required | - | Required | - |
| 113 | NTP Daemon readvar Buffer Overflow | exploit/multi/ntp/ntp_overflow | Required | - | Required | - |
| 114 | Portable UPnP SDK unique_service_name() Remote Code Execution | exploit/multi/upnp/libupnp_ssdp_overflow | Required | - | Required | - |
| 115 | NetWare 6.5 SunRPC Portmapper CALLIT Stack Buffer Overflow | exploit/netware/sunrpc/pkernel_callit | Required | - | Required | - |
| 116 | OpenBSD Dynamic Loader chpass Privilege Escalation | exploit/openbsd/local/dynamic_loader_chpass_privesc | Required | - | - | - |
| 117 | macOS cfprefsd Arbitrary File Write Local Privilege Escalation | exploit/osx/local/cfprefsd_race_condition | Required | - | - | - |
| 118 | Apple OS X DYLD_PRINT_TO_FILE Privilege Escalation | exploit/osx/local/dyld_print_to_file_root | Required | - | - | - |
| 119 | Mac OS X Feedback Assistant Race Condition | exploit/osx/local/feedback_assistant_root | Required | - | - | - |
| 120 | Mac OS X IOKit Keyboard Driver Root Privilege Escalation | exploit/osx/local/iokit_keyboard_root | Required | - | - | - |
| 121 | Mac OS X libxpc MITM Privilege Escalation | exploit/osx/local/libxpc_mitm_ssudo | Required | - | - | - |
| 122 | Mac OS X NFS Mount Privilege Escalation Exploit | exploit/osx/local/nfs_mount_root | Required | - | - | - |
| 123 | Mac OS X Persistent Payload Installer | exploit/osx/local/persistence | Required | - | - | - |
| 124 | Mac OS X Root Privilege Escalation | exploit/osx/local/root_no_password | Required | - | - | - |
| 125 | Apple OS X Rootpipe Privilege Escalation | exploit/osx/local/rootpipe | Required | - | - | - |
| 126 | Apple OS X Entitlements Rootpipe Privilege Escalation | exploit/osx/local/rootpipe_entitlements | Required | - | - | - |
| 127 | Mac OS X 10.9.5 / 10.10.5 - rsh/libmalloc Privilege Escalation | exploit/osx/local/rsh_libmalloc | Required | - | - | - |
| 128 | Setuid Tunnelblick Privilege Escalation | exploit/osx/local/setuid_tunnelblick | Required | - | - | - |
| 129 | Viscosity setuid-set ViscosityHelper Privilege Escalation | exploit/osx/local/setuid_viscosity | Required | - | - | - |
| 130 | Mac OS X Sudo Password Bypass | exploit/osx/local/sudo_password_bypass | Required | - | - | - |
| 131 | Mac OS X TimeMachine (tmdiagnose) Command Injection Privilege Escalation | exploit/osx/local/timemachine_cmd_injection | Required | - | - | - |
| 132 | Mac OS X "tpwn" Privilege Escalation | exploit/osx/local/tpwn | Required | - | - | - |
| 133 | OS X VMWare Fusion Privilege Escalation via Bash Environment Code Injection (Shellshock) | exploit/osx/local/vmware_bash_function_root | Required | - | - | - |
| 134 | VMware Fusion USB Arbitrator Setuid Privilege Escalation | exploit/osx/local/vmware_fusion_lpe | Required | - | - | - |
| 135 | Mac OS X mDNSResponder UPnP Location Overflow | exploit/osx/mdns/upnp_location | Required | - | Required | - |
| 136 | ifwatchd Privilege Escalation | exploit/qnx/local/ifwatchd_priv_esc | Required | - | - | - |
| 137 | Solaris 'EXTREMEPARR' dtappgather Privilege Escalation | exploit/solaris/local/extremeparr_dtappgather_priv_esc | Required | - | - | - |
| 138 | Solaris libnspr NSPR_LOG_FILE Privilege Escalation | exploit/solaris/local/libnspr_nspr_log_file_priv_esc | Required | - | - | - |
| 139 | Solaris RSH Stack Clash Privilege Escalation | exploit/solaris/local/rsh_stack_clash_priv_esc | Required | - | - | - |
| 140 | Solaris xscreensaver log Privilege Escalation | exploit/solaris/local/xscreensaver_log_priv_esc | Required | - | - | - |
| 141 | Oracle Solaris SunSSH PAM parse_user_name() Buffer Overflow | exploit/solaris/ssh/pam_username_bof | Required | - | Required | - |
| 142 | Dhclient Bash Environment Variable Injection (Shellshock) | exploit/unix/dhcp/bash_environment | Required | - | - | - |
| 143 | DHCP Client Command Injection (DynoRoot) | exploit/unix/dhcp/rhel_dhcp_client_command_injection | Required | - | - | - |
| 144 | Ghostscript Type Confusion Arbitrary Command Execution | exploit/unix/fileformat/ghostscript_type_confusion | Required | - | - | - |
| 145 | ImageMagick Delegate Arbitrary Command Execution | exploit/unix/fileformat/imagemagick_delegate | Required | - | - | - |
| 146 | Metasploit Libnotify Plugin Arbitrary Command Execution | exploit/unix/fileformat/metasploit_libnotify_cmd_injection | Required | - | - | - |
| 147 | Rapid7 Metasploit Framework msfvenom APK Template Command Injection | exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection | Required | - | - | - |
| 148 | at(1) Persistence | exploit/unix/local/at_persistence | Required | - | - | - |
| 149 | Chkrootkit Local Privilege Escalation | exploit/unix/local/chkrootkit | Required | - | - | - |
| 150 | Emacs movemail Privilege Escalation | exploit/unix/local/emacs_movemail | Required | - | - | - |
| 151 | Exim "perl_startup" Privilege Escalation | exploit/unix/local/exim_perl_startup | Required | - | - | - |
| 152 | NetBSD mail.local Privilege Escalation | exploit/unix/local/netbsd_mail_local | Required | - | - | - |
| 153 | Setuid Nmap Exploit | exploit/unix/local/setuid_nmap | Required | - | - | - |
| 154 | Arista restricted shell escape (with privesc) | exploit/unix/ssh/arista_tacplus_shell | Required | - | Required | - |
| 155 | Array Networks vAPV and vxAG Private Key Privilege Escalation Code Execution | exploit/unix/ssh/array_vxag_vapv_privkey_privesc | Required | Required | Required | - |
| 156 | A-PDF WAV to MP3 v1.0.0 Buffer Overflow | exploit/windows/fileformat/a_pdf_wav_to_mp3 | Required | - | - | - |
| 157 | ABBS Audio Media Player .LST Buffer Overflow | exploit/windows/fileformat/abbs_amp_lst | Required | - | - | - |
| 158 | ACDSee FotoSlate PLP File id Parameter Overflow | exploit/windows/fileformat/acdsee_fotoslate_string | Required | - | - | - |
| 159 | ACDSee XPM File Section Buffer Overflow | exploit/windows/fileformat/acdsee_xpm | Required | - | - | - |
| 160 | ActiveFax (ActFax) 4.3 Client Importer Buffer Overflow | exploit/windows/fileformat/actfax_import_users_bof | Required | - | - | - |
| 161 | activePDF WebGrabber ActiveX Control Buffer Overflow | exploit/windows/fileformat/activepdf_webgrabber | Required | - | - | - |
| 162 | Adobe Collab.collectEmailInfo() Buffer Overflow | exploit/windows/fileformat/adobe_collectemailinfo | Required | - | - | - |
| 163 | Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow | exploit/windows/fileformat/adobe_cooltype_sing | Required | - | - | - |
| 164 | Adobe Flash Player "Button" Remote Code Execution | exploit/windows/fileformat/adobe_flashplayer_button | Required | - | - | - |
| 165 | Adobe Flash Player "newfunction" Invalid Pointer Use | exploit/windows/fileformat/adobe_flashplayer_newfunction | Required | - | - | - |
| 166 | Adobe FlateDecode Stream Predictor 02 Integer Overflow | exploit/windows/fileformat/adobe_flatedecode_predictor02 | Required | - | - | - |
| 167 | Adobe Collab.getIcon() Buffer Overflow | exploit/windows/fileformat/adobe_geticon | Required | - | - | - |
| 168 | Adobe Illustrator CS4 v14.0.0 | exploit/windows/fileformat/adobe_illustrator_v14_eps | Required | - | - | - |
| 169 | Adobe JBIG2Decode Memory Corruption | exploit/windows/fileformat/adobe_jbig2decode | Required | - | - | - |
| 170 | Adobe Acrobat Bundled LibTIFF Integer Overflow | exploit/windows/fileformat/adobe_libtiff | Required | - | - | - |
| 171 | Adobe Doc.media.newPlayer Use After Free Vulnerability | exploit/windows/fileformat/adobe_media_newplayer | Required | - | - | - |
| 172 | Adobe PDF Embedded EXE Social Engineering | exploit/windows/fileformat/adobe_pdf_embedded_exe | Required | - | - | - |
| 173 | Adobe PDF Escape EXE Social Engineering (No JavaScript) | exploit/windows/fileformat/adobe_pdf_embedded_exe_nojs | Required | - | - | - |
| 174 | Adobe Reader U3D Memory Corruption Vulnerability | exploit/windows/fileformat/adobe_reader_u3d | Required | - | - | - |
| 175 | Adobe Reader ToolButton Use After Free | exploit/windows/fileformat/adobe_toolbutton | Required | - | - | - |
| 176 | Adobe U3D CLODProgressiveMeshDeclaration Array Overrun | exploit/windows/fileformat/adobe_u3d_meshdecl | Required | - | - | - |
| 177 | Adobe util.printf() Buffer Overflow | exploit/windows/fileformat/adobe_utilprintf | Required | - | - | - |
| 178 | ALLPlayer M3U Buffer Overflow | exploit/windows/fileformat/allplayer_m3u_bof | Required | - | - | - |
| 179 | Altap Salamander 2.5 PE Viewer Buffer Overflow | exploit/windows/fileformat/altap_salamander_pdb | Required | - | - | - |
| 180 | AOL Desktop 9.6 RTX Buffer Overflow | exploit/windows/fileformat/aol_desktop_linktag | Required | - | - | - |
| 181 | AOL 9.5 Phobos.Playlist Import() Stack-based Buffer Overflow | exploit/windows/fileformat/aol_phobos_bof | Required | - | - | - |
| 182 | Apple QuickTime PICT PnSize Buffer Overflow | exploit/windows/fileformat/apple_quicktime_pnsize | Required | - | - | - |
| 183 | Apple Quicktime 7 Invalid Atom Length Buffer Overflow | exploit/windows/fileformat/apple_quicktime_rdrf | Required | - | - | - |
| 184 | Apple QuickTime TeXML Style Element Stack Buffer Overflow | exploit/windows/fileformat/apple_quicktime_texml | Required | - | - | - |
| 185 | AudioCoder .M3U Buffer Overflow | exploit/windows/fileformat/audio_coder_m3u | Required | - | - | - |
| 186 | Audio Workstation 6.4.2.4.3 pls Buffer Overflow | exploit/windows/fileformat/audio_wkstn_pls | Required | - | - | - |
| 187 | Audiotran 1.4.1 (PLS File) Stack Buffer Overflow | exploit/windows/fileformat/audiotran_pls | Required | - | - | - |
| 188 | Audiotran PLS File Stack Buffer Overflow | exploit/windows/fileformat/audiotran_pls_1424 | Required | - | - | - |
| 189 | Aviosoft Digital TV Player Professional 1.0 Stack Buffer Overflow | exploit/windows/fileformat/aviosoft_plf_buf | Required | - | - | - |
| 190 | BACnet OPC Client Buffer Overflow | exploit/windows/fileformat/bacnet_csv | Required | - | - | - |
| 191 | Beetel Connection Manager NetConfig.ini Buffer Overflow | exploit/windows/fileformat/beetel_netconfig_ini_bof | Required | - | - | - |
| 192 | BlazeVideo HDTV Player Pro v6.6 Filename Handling Vulnerability | exploit/windows/fileformat/blazedvd_hdtv_bof | Required | - | - | - |
| 193 | BlazeDVD 6.1 PLF Buffer Overflow | exploit/windows/fileformat/blazedvd_plf | Required | - | - | - |
| 194 | Boxoft WAV to MP3 Converter v1.1 Buffer Overflow | exploit/windows/fileformat/boxoft_wav_to_mp3 | Required | - | - | - |
| 195 | BulletProof FTP Client BPS Buffer Overflow | exploit/windows/fileformat/bpftp_client_bps_bof | Required | - | - | - |
| 196 | BS.Player 2.57 Buffer Overflow (Unicode SEH) | exploit/windows/fileformat/bsplayer_m3u | Required | - | - | - |
| 197 | CA Antivirus Engine CAB Buffer Overflow | exploit/windows/fileformat/ca_cab | Required | - | - | - |
| 198 | Cain and Abel RDP Buffer Overflow | exploit/windows/fileformat/cain_abel_4918_rdp | Required | - | - | - |
| 199 | CCMPlayer 1.5 m3u Playlist Stack Based Buffer Overflow | exploit/windows/fileformat/ccmplayer_m3u_bof | Required | - | - | - |
| 200 | Chasys Draw IES Buffer Overflow | exploit/windows/fileformat/chasys_draw_ies_bmp_bof | Required | - | - | - |
| 201 | Cool PDF Image Stream Buffer Overflow | exploit/windows/fileformat/coolpdf_image_stream_bof | Required | - | - | - |
| 202 | Corel PDF Fusion Stack Buffer Overflow | exploit/windows/fileformat/corelpdf_fusion_bof | Required | - | - | - |
| 203 | Csound hetro File Handling Stack Buffer Overflow | exploit/windows/fileformat/csound_getnum_bof | Required | - | - | - |
| 204 | GlobalSCAPE CuteZIP Stack Buffer Overflow | exploit/windows/fileformat/cutezip_bof | Required | - | - | - |
| 205 | LNK Code Execution Vulnerability | exploit/windows/fileformat/cve_2017_8464_lnk_rce | Required | - | - | - |
| 206 | CyberLink LabelPrint 2.5 Stack Buffer Overflow | exploit/windows/fileformat/cyberlink_lpp_bof | Required | - | - | - |
| 207 | CyberLink Power2Go name Attribute (p2g) Stack Buffer Overflow Exploit | exploit/windows/fileformat/cyberlink_p2g_bof | Required | - | - | - |
| 208 | Cytel Studio 9.0 (CY3 File) Stack Buffer Overflow | exploit/windows/fileformat/cytel_studio_cy3 | Required | - | - | - |
| 209 | AstonSoft DeepBurner (DBR File) Path Buffer Overflow | exploit/windows/fileformat/deepburner_path | Required | - | - | - |
| 210 | Destiny Media Player 1.61 PLS M3U Buffer Overflow | exploit/windows/fileformat/destinymediaplayer16 | Required | - | - | - |
| 211 | Digital Music Pad Version 8.2.3.3.4 Stack Buffer Overflow | exploit/windows/fileformat/digital_music_pad_pls | Required | - | - | - |
| 212 | DJ Studio Pro 5.1 .pls Stack Buffer Overflow | exploit/windows/fileformat/djstudio_pls_bof | Required | - | - | - |
| 213 | DjVu DjVu_ActiveX_MSOffice.dll ActiveX ComponentBuffer Overflow | exploit/windows/fileformat/djvu_imageurl | Required | - | - | - |
| 214 | Documalis Free PDF Editor and Scanner JPEG Stack Buffer Overflow | exploit/windows/fileformat/documalis_pdf_editor_and_scanner | Required | - | - | - |
| 215 | Dup Scout Enterprise v10.4.16 - Import Command Buffer Overflow | exploit/windows/fileformat/dupscout_xml | Required | - | - | - |
| 216 | DVD X Player 5.5 .plf PlayList Buffer Overflow | exploit/windows/fileformat/dvdx_plf_bof | Required | - | - | - |
| 217 | Easy CD-DA Recorder PLS Buffer Overflow | exploit/windows/fileformat/easycdda_pls_bof | Required | - | - | - |
| 218 | EMC ApplicationXtender (KeyWorks) ActiveX Control Buffer Overflow | exploit/windows/fileformat/emc_appextender_keyworks | Required | - | - | - |
| 219 | ERS Viewer 2011 ERS File Handling Buffer Overflow | exploit/windows/fileformat/erdas_er_viewer_bof | Required | - | - | - |
| 220 | ERS Viewer 2013 ERS File Handling Buffer Overflow | exploit/windows/fileformat/erdas_er_viewer_rf_report_error | Required | - | - | - |
| 221 | eSignal and eSignal Pro File Parsing Buffer Overflow in QUO | exploit/windows/fileformat/esignal_styletemplate_bof | Required | - | - | - |
| 222 | CA eTrust PestPatrol ActiveX Control Buffer Overflow | exploit/windows/fileformat/etrust_pestscan | Required | - | - | - |
| 223 | eZip Wizard 3.0 Stack Buffer Overflow | exploit/windows/fileformat/ezip_wizard_bof | Required | - | - | - |
| 224 | Fat Player Media Player 0.6b0 Buffer Overflow | exploit/windows/fileformat/fatplayer_wav | Required | - | - | - |
| 225 | Free Download Manager Torrent Parsing Buffer Overflow | exploit/windows/fileformat/fdm_torrent | Required | - | - | - |
| 226 | FeedDemon Stack Buffer Overflow | exploit/windows/fileformat/feeddemon_opml | Required | - | - | - |
| 227 | Foxit PDF Reader 4.2 Javascript File Write | exploit/windows/fileformat/foxit_reader_filewrite | Required | - | - | - |
| 228 | Foxit Reader 3.0 Open Execute Action Stack Based Buffer Overflow | exploit/windows/fileformat/foxit_reader_launch | Required | - | - | - |
| 229 | Foxit PDF Reader Pointer Overwrite UAF | exploit/windows/fileformat/foxit_reader_uaf | Required | - | - | - |
| 230 | Foxit PDF Reader v4.1.1 Title Stack Buffer Overflow | exploit/windows/fileformat/foxit_title_bof | Required | - | - | - |
| 231 | Free MP3 CD Ripper 1.1 WAV File Stack Buffer Overflow | exploit/windows/fileformat/free_mp3_ripper_wav | Required | - | - | - |
| 232 | gAlan 0.2.1 Buffer Overflow | exploit/windows/fileformat/galan_fileformat_bof | Required | - | - | - |
| 233 | GSM SIM Editor 5.15 Buffer Overflow | exploit/windows/fileformat/gsm_sim | Required | - | - | - |
| 234 | GTA SA-MP server.cfg Buffer Overflow | exploit/windows/fileformat/gta_samp | Required | - | - | - |
| 235 | HTML Help Workshop 4.74 (hhp Project File) Buffer Overflow | exploit/windows/fileformat/hhw_hhp_compiledfile_bof | Required | - | - | - |
| 236 | HTML Help Workshop 4.74 (hhp Project File) Buffer Overflow | exploit/windows/fileformat/hhw_hhp_contentfile_bof | Required | - | - | - |
| 237 | HTML Help Workshop 4.74 (hhp Project File) Buffer Overflow | exploit/windows/fileformat/hhw_hhp_indexfile_bof | Required | - | - | - |
| 238 | Heroes of Might and Magic III .h3m Map file Buffer Overflow | exploit/windows/fileformat/homm3_h3m | Required | - | - | - |
| 239 | HT-MP3Player 1.0 HT3 File Parsing Buffer Overflow | exploit/windows/fileformat/ht_mp3player_ht3_bof | Required | - | - | - |
| 240 | IBM Forms Viewer Unicode Buffer Overflow | exploit/windows/fileformat/ibm_forms_viewer_fontname | Required | - | - | - |
| 241 | IBM Personal Communications iSeries Access WorkStation 5.9 Profile | exploit/windows/fileformat/ibm_pcm_ws | Required | - | - | - |
| 242 | IcoFX Stack Buffer Overflow | exploit/windows/fileformat/icofx_bof | Required | - | - | - |
| 243 | PointDev IDEAL Migration Buffer Overflow | exploit/windows/fileformat/ideal_migration_ipj | Required | - | - | - |
| 244 | i-FTP Schedule Buffer Overflow | exploit/windows/fileformat/iftp_schedule_bof | Required | - | - | - |
| 245 | Irfanview JPEG2000 jp2 Stack Buffer Overflow | exploit/windows/fileformat/irfanview_jpeg2000_bof | Required | - | - | - |
| 246 | Lattice Semiconductor ispVM System XCF File Handling Overflow | exploit/windows/fileformat/ispvm_xcf_ispxcf | Required | - | - | - |
| 247 | KingView Log File Parsing Buffer Overflow | exploit/windows/fileformat/kingview_kingmess_kvl | Required | - | - | - |
| 248 | Lattice Semiconductor PAC-Designer 6.21 Symbol Value Buffer Overflow | exploit/windows/fileformat/lattice_pac_bof | Required | - | - | - |
| 249 | Lotus Notes 8.0.x - 8.5.2 FP2 - Autonomy Keyview (.lzh Attachment) | exploit/windows/fileformat/lotusnotes_lzh | Required | - | - | - |
| 250 | Magix Musik Maker 16 .mmm Stack Buffer Overflow | exploit/windows/fileformat/magix_musikmaker_16_mmm | Required | - | - | - |
| 251 | McAfee Remediation Client ActiveX Control Buffer Overflow | exploit/windows/fileformat/mcafee_hercules_deletesnapshot | Required | - | - | - |
| 252 | MediaCoder .M3U Buffer Overflow | exploit/windows/fileformat/mediacoder_m3u | Required | - | - | - |
| 253 | Media Jukebox 8.0.400 Buffer Overflow (SEH) | exploit/windows/fileformat/mediajukebox | Required | - | - | - |
| 254 | MicroP 0.1.1.1600 (MPPL File) Stack Buffer Overflow | exploit/windows/fileformat/microp_mppl | Required | - | - | - |
| 255 | Microsoft Windows Contact File Format Arbitary Code Execution | exploit/windows/fileformat/microsoft_windows_contact | Required | - | - | - |
| 256 | Millenium MP3 Studio 2.0 (PLS File) Stack Buffer Overflow | exploit/windows/fileformat/millenium_mp3_pls | Required | - | - | - |
| 257 | Mini-Stream RM-MP3 Converter v3.1.2.1 PLS File Stack Buffer Overflow | exploit/windows/fileformat/mini_stream_pls_bof | Required | - | - | - |
| 258 | MJM Core Player 2011 .s3m Stack Buffer Overflow | exploit/windows/fileformat/mjm_coreplayer2011_s3m | Required | - | - | - |
| 259 | MJM QuickPlayer 1.00 Beta 60a / QuickPlayer 2010 .s3m Stack Buffer Overflow | exploit/windows/fileformat/mjm_quickplayer_s3m | Required | - | - | - |
| 260 | MOXA MediaDBPlayback ActiveX Control Buffer Overflow | exploit/windows/fileformat/moxa_mediadbplayback | Required | - | - | - |
| 261 | MPlayer Lite M3U Buffer Overflow | exploit/windows/fileformat/mplayer_m3u_bof | Required | - | - | - |
| 262 | MPlayer SAMI Subtitle File Buffer Overflow | exploit/windows/fileformat/mplayer_sami_bof | Required | - | - | - |
| 263 | MS09-067 Microsoft Excel Malformed FEATHEADER Record Vulnerability | exploit/windows/fileformat/ms09_067_excel_featheader | Required | - | - | - |
| 264 | MS10-004 Microsoft PowerPoint Viewer TextBytesAtom Stack Buffer Overflow | exploit/windows/fileformat/ms10_004_textbytesatom | Required | - | - | - |
| 265 | MS11-038 Microsoft Office Excel Malformed OBJ Record Handling Overflow | exploit/windows/fileformat/ms10_038_excel_obj_bof | Required | - | - | - |
| 266 | MS10-087 Microsoft Word RTF pFragments Stack Buffer Overflow (File Format) | exploit/windows/fileformat/ms10_087_rtf_pfragments_bof | Required | - | - | - |
| 267 | MS11-006 Microsoft Windows CreateSizedDIBSECTION Stack Buffer Overflow | exploit/windows/fileformat/ms11_006_createsizeddibsection | Required | - | - | - |
| 268 | MS11-021 Microsoft Office 2007 Excel .xlb Buffer Overflow | exploit/windows/fileformat/ms11_021_xlb_bof | Required | - | - | - |
| 269 | MS12-027 MSCOMCTL ActiveX Buffer Overflow | exploit/windows/fileformat/ms12_027_mscomctl_bof | Required | - | - | - |
| 270 | MS14-017 Microsoft Word RTF Object Confusion | exploit/windows/fileformat/ms14_017_rtf | Required | - | - | - |
| 271 | MS14-060 Microsoft Windows OLE Package Manager Code Execution | exploit/windows/fileformat/ms14_060_sandworm | Required | - | - | - |
| 272 | MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python | exploit/windows/fileformat/ms14_064_packager_python | Required | - | - | - |
| 273 | MS14-064 Microsoft Windows OLE Package Manager Code Execution | exploit/windows/fileformat/ms14_064_packager_run_as_admin | Required | - | - | - |
| 274 | Microsoft Windows Shell LNK Code Execution | exploit/windows/fileformat/ms15_020_shortcut_icon_dllloader | Required | - | - | - |
| 275 | Microsoft Visual Basic VBP Buffer Overflow | exploit/windows/fileformat/ms_visual_basic_vbp | Required | - | - | - |
| 276 | MS13-096 Microsoft Tagged Image File Format (TIFF) Integer Overflow | exploit/windows/fileformat/mswin_tiff_overflow | Required | - | - | - |
| 277 | Microsoft Works 7 WkImgSrv.dll WKsPictureInterface() ActiveX Code Execution | exploit/windows/fileformat/msworks_wkspictureinterface | Required | - | - | - |
| 278 | Steinberg MyMP3Player 3.0 Buffer Overflow | exploit/windows/fileformat/mymp3player_m3u | Required | - | - | - |
| 279 | NetOp Remote Control Client 9.5 Buffer Overflow | exploit/windows/fileformat/netop | Required | - | - | - |
| 280 | Nuance PDF Reader v6.0 Launch Stack Buffer Overflow | exploit/windows/fileformat/nuance_pdf_launch_overflow | Required | - | - | - |
| 281 | Office OLE Multiple DLL Side Loading Vulnerabilities | exploit/windows/fileformat/office_ole_multiple_dll_hijack | Required | - | - | - |
| 282 | OpenOffice OLE Importer DocumentSummaryInformation Stream Handling Overflow | exploit/windows/fileformat/openoffice_ole | Required | - | - | - |
| 283 | Orbit Downloader URL Unicode Conversion Overflow | exploit/windows/fileformat/orbit_download_failed_bof | Required | - | - | - |
| 284 | Orbital Viewer ORB File Parsing Buffer Overflow | exploit/windows/fileformat/orbital_viewer_orb | Required | - | - | - |
| 285 | VMWare OVF Tools Format String Vulnerability | exploit/windows/fileformat/ovf_format_string | Required | - | - | - |
| 286 | ProShow Gold v4.0.2549 (PSH File) Stack Buffer Overflow | exploit/windows/fileformat/proshow_cellimage_bof | Required | - | - | - |
| 287 | Photodex ProShow Producer 5.0.3256 load File Handling Buffer Overflow | exploit/windows/fileformat/proshow_load_bof | Required | - | - | - |
| 288 | Publish-It PUI Buffer Overflow (SEH) | exploit/windows/fileformat/publishit_pui | Required | - | - | - |
| 289 | Real Networks Netzip Classic 7.5.1 86 File Parsing Buffer Overflow Vulnerability | exploit/windows/fileformat/real_networks_netzip_bof | Required | - | - | - |
| 290 | RealPlayer RealMedia File Handling Buffer Overflow | exploit/windows/fileformat/real_player_url_property_bof | Required | - | - | - |
| 291 | RealNetworks RealPlayer Version Attribute Buffer Overflow | exploit/windows/fileformat/realplayer_ver_attribute_bof | Required | - | - | - |
| 292 | SafeNet SoftRemote GROUPNAME Buffer Overflow | exploit/windows/fileformat/safenet_softremote_groupname | Required | - | - | - |
| 293 | SasCam Webcam Server v.2.6.5 Get() Method Buffer Overflow | exploit/windows/fileformat/sascam_get | Required | - | - | - |
| 294 | ScadaTEC ScadaPhone Stack Buffer Overflow | exploit/windows/fileformat/scadaphone_zip | Required | - | - | - |
| 295 | Shadow Stream Recorder 3.0.1.7 Buffer Overflow | exploit/windows/fileformat/shadow_stream_recorder_bof | Required | - | - | - |
| 296 | PDF Shaper Buffer Overflow | exploit/windows/fileformat/shaper_pdf_bof | Required | - | - | - |
| 297 | S.O.M.P.L 1.0 Player Buffer Overflow | exploit/windows/fileformat/somplplayer_m3u | Required | - | - | - |
| 298 | Subtitle Processor 7.7.1 .M3U SEH Unicode Buffer Overflow | exploit/windows/fileformat/subtitle_processor_m3u_bof | Required | - | - | - |
| 299 | Sync Breeze Enterprise 9.5.16 - Import Command Buffer Overflow | exploit/windows/fileformat/syncbreeze_xml | Required | - | - | - |
| 300 | TFM MMPlayer (m3u/ppl File) Buffer Overflow | exploit/windows/fileformat/tfm_mmplayer_m3u_ppl_bof | Required | - | - | - |
| 301 | Total Video Player 1.3.1 (Settings.ini) - SEH Buffer Overflow | exploit/windows/fileformat/total_video_player_ini_bof | Required | - | - | - |
| 302 | TugZip 3.5 Zip File Parsing Buffer Overflow Vulnerability | exploit/windows/fileformat/tugzip | Required | - | - | - |
| 303 | UltraISO CCD File Parsing Buffer Overflow | exploit/windows/fileformat/ultraiso_ccd | Required | - | - | - |
| 304 | UltraISO CUE File Parsing Buffer Overflow | exploit/windows/fileformat/ultraiso_cue | Required | - | - | - |
| 305 | URSoft W32Dasm Disassembler Function Buffer Overflow | exploit/windows/fileformat/ursoft_w32dasm | Required | - | - | - |
| 306 | VariCAD 2010-2.05 EN (DWB File) Stack Buffer Overflow | exploit/windows/fileformat/varicad_dwb | Required | - | - | - |
| 307 | VideoCharge Studio Buffer Overflow (SEH) | exploit/windows/fileformat/videocharge_studio | Required | - | - | - |
| 308 | VideoLAN VLC TiVo Buffer Overflow | exploit/windows/fileformat/videolan_tivo | Required | - | - | - |
| 309 | VeryTools Video Spirit Pro | exploit/windows/fileformat/videospirit_visprj | Required | - | - | - |
| 310 | Microsoft Office Visio VISIODWG.DLL DXF File Handling Vulnerability | exploit/windows/fileformat/visio_dxf_bof | Required | - | - | - |
| 311 | VisiWave VWR File Parsing Vulnerability | exploit/windows/fileformat/visiwave_vwr_type | Required | - | - | - |
| 312 | VLC Media Player MKV Use After Free | exploit/windows/fileformat/vlc_mkv | Required | - | - | - |
| 313 | VideoLAN VLC ModPlug ReadS3M Stack Buffer Overflow | exploit/windows/fileformat/vlc_modplug_s3m | Required | - | - | - |
| 314 | VLC Media Player RealText Subtitle Overflow | exploit/windows/fileformat/vlc_realtext | Required | - | - | - |
| 315 | VideoLAN Client (VLC) Win32 smb:// URI Buffer Overflow | exploit/windows/fileformat/vlc_smb_uri | Required | - | - | - |
| 316 | VideoLAN VLC MKV Memory Corruption | exploit/windows/fileformat/vlc_webm | Required | - | - | - |
| 317 | VUPlayer CUE Buffer Overflow | exploit/windows/fileformat/vuplayer_cue | Required | - | - | - |
| 318 | VUPlayer M3U Buffer Overflow | exploit/windows/fileformat/vuplayer_m3u | Required | - | - | - |
| 319 | Watermark Master Buffer Overflow (SEH) | exploit/windows/fileformat/watermark_master | Required | - | - | - |
| 320 | Winamp MAKI Buffer Overflow | exploit/windows/fileformat/winamp_maki_bof | Required | - | - | - |
| 321 | RARLAB WinRAR ACE Format Input Validation Remote Code Execution | exploit/windows/fileformat/winrar_ace | Required | - | - | - |
| 322 | WinRAR Filename Spoofing | exploit/windows/fileformat/winrar_name_spoofing | Required | - | - | - |
| 323 | Wireshark wiretap/mpeg.c Stack Buffer Overflow | exploit/windows/fileformat/wireshark_mpeg_overflow | Required | - | - | - |
| 324 | Wireshark packet-dect.c Stack Buffer Overflow (local) | exploit/windows/fileformat/wireshark_packet_dect | Required | - | - | - |
| 325 | WM Downloader 3.1.2.2 Buffer Overflow | exploit/windows/fileformat/wm_downloader_m3u | Required | - | - | - |
| 326 | Xenorate 2.50 (.xpl) Universal Local Buffer Overflow (SEH) | exploit/windows/fileformat/xenorate_xpl_bof | Required | - | - | - |
| 327 | Xion Audio Player 1.0.126 Unicode Stack Buffer Overflow | exploit/windows/fileformat/xion_m3u_sehbof | Required | - | - | - |
| 328 | xRadio 0.95b Buffer Overflow | exploit/windows/fileformat/xradio_xrl_sehbof | Required | - | - | - |
| 329 | Zahir Enterprise Plus 6 Stack Buffer Overflow | exploit/windows/fileformat/zahir_enterprise_plus_csv | Required | - | - | - |
| 330 | Zinf Audio Player 2.2.1 (PLS File) Stack Buffer Overflow | exploit/windows/fileformat/zinfaudioplayer221_pls | Required | - | - | - |
| 331 | ISS PAM.dll ICQ Parser Buffer Overflow | exploit/windows/firewall/blackice_pam_icq | Required | - | Required | - |
| 332 | Medal of Honor Allied Assault getinfo Stack Buffer Overflow | exploit/windows/games/mohaa_getinfo | Required | - | Required | - |
| 333 | Racer v0.5.3 Beta 5 Buffer Overflow | exploit/windows/games/racer_503beta5 | Required | - | Required | - |
| 334 | Unreal Tournament 2004 "secure" Overflow (Win32) | exploit/windows/games/ut2004_secure | Required | - | Required | - |
| 335 | SentinelLM UDP Buffer Overflow | exploit/windows/license/sentinel_lm7_udp | Required | - | Required | - |
| 336 | AdobeCollabSync Buffer Overflow Adobe Reader X Sandbox Bypass | exploit/windows/local/adobe_sandbox_adobecollabsync | Required | - | - | - |
| 337 | Agnitum Outpost Internet Security Local Privilege Escalation | exploit/windows/local/agnitum_outpost_acs | Required | - | - | - |
| 338 | Microsoft Windows ALPC Task Scheduler Local Privilege Elevation | exploit/windows/local/alpc_taskscheduler | Required | - | - | - |
| 339 | Windows AlwaysInstallElevated MSI | exploit/windows/local/always_install_elevated | Required | - | - | - |
| 340 | Cisco AnyConnect Privilege Escalations (CVE-2020-3153 and CVE-2020-3433) | exploit/windows/local/anyconnect_lpe | Required | - | - | - |
| 341 | AppLocker Execution Prevention Bypass | exploit/windows/local/applocker_bypass | Required | - | - | - |
| 342 | AppXSvc Hard Link Privilege Escalation | exploit/windows/local/appxsvc_hard_link_privesc | Required | - | - | - |
| 343 | Windows Escalate UAC Execute RunAs | exploit/windows/local/ask | Required | - | - | - |
| 344 | SYSTEM token impersonation through NTLM bits authentication on missing WinRM Service. | exploit/windows/local/bits_ntlm_token_impersonation | Required | - | - | - |
| 345 | MS14-062 Microsoft Bluetooth Personal Area Networking (BthPan.sys) Privilege Escalation | exploit/windows/local/bthpan | Required | - | - | - |
| 346 | Windows Escalate UAC Protection Bypass | exploit/windows/local/bypassuac | Required | - | - | - |
| 347 | Windows Escalate UAC Protection Bypass (Via COM Handler Hijack) | exploit/windows/local/bypassuac_comhijack | Required | - | - | - |
| 348 | Windows Escalate UAC Protection Bypass (Via dot net profiler) | exploit/windows/local/bypassuac_dotnet_profiler | Required | - | - | - |
| 349 | Windows Escalate UAC Protection Bypass (Via Eventvwr Registry Key) | exploit/windows/local/bypassuac_eventvwr | Required | - | - | - |
| 350 | Windows UAC Protection Bypass (Via FodHelper Registry Key) | exploit/windows/local/bypassuac_fodhelper | Required | - | - | - |
| 351 | Windows Escalate UAC Protection Bypass (In Memory Injection) | exploit/windows/local/bypassuac_injection | Required | - | - | - |
| 352 | Windows Escalate UAC Protection Bypass (In Memory Injection) abusing WinSXS | exploit/windows/local/bypassuac_injection_winsxs | Required | - | - | - |
| 353 | Windows Escalate UAC Protection Bypass (Via Shell Open Registry Key) | exploit/windows/local/bypassuac_sdclt | Required | - | - | - |
| 354 | Windows Escalate UAC Protection Bypass (Via SilentCleanup) | exploit/windows/local/bypassuac_silentcleanup | Required | - | - | - |
| 355 | Windows UAC Protection Bypass (Via Slui File Handler Hijack) | exploit/windows/local/bypassuac_sluihijack | Required | - | - | - |
| 356 | Windows Escalate UAC Protection Bypass (ScriptHost Vulnerability) | exploit/windows/local/bypassuac_vbs | Required | - | - | - |
| 357 | Windows 10 UAC Protection Bypass Via Windows Store (WSReset.exe) | exploit/windows/local/bypassuac_windows_store_filesys | Required | - | - | - |
| 358 | Windows 10 UAC Protection Bypass Via Windows Store (WSReset.exe) and Registry | exploit/windows/local/bypassuac_windows_store_reg | Required | - | - | - |
| 359 | Windows Capcom.sys Kernel Execution Exploit (x64 only) | exploit/windows/local/capcom_sys_exec | Required | - | - | - |
| 360 | Microsoft UPnP Local Privilege Elevation Vulnerability | exploit/windows/local/comahawk | Required | - | - | - |
| 361 | PsExec via Current User Token | exploit/windows/local/current_user_psexec | Required | - | - | - |
| 362 | LNK Code Execution Vulnerability | exploit/windows/local/cve_2017_8464_lnk_lpe | Required | - | - | - |
| 363 | Windows NtUserSetWindowFNID Win32k User Callback | exploit/windows/local/cve_2018_8453_win32k_priv_esc | Required | - | - | - |
| 364 | Microsoft Windows Uninitialized Variable Local Privilege Elevation | exploit/windows/local/cve_2019_1458_wizardopium | Required | - | - | - |
| 365 | Service Tracing Privilege Elevation Vulnerability | exploit/windows/local/cve_2020_0668_service_tracing | Required | - | - | - |
| 366 | Background Intelligent Transfer Service Arbitrary File Move Privilege Elevation Vulnerability | exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move | Required | - | - | - |
| 367 | SMBv3 Compression Buffer Overflow | exploit/windows/local/cve_2020_0796_smbghost | Required | - | - | - |
| 368 | Microsoft Spooler Local Privilege Elevation Vulnerability | exploit/windows/local/cve_2020_1048_printerdemon | Required | - | - | - |
| 369 | Microsoft Windows DrawIconEx OOB Write Local Privilege Elevation | exploit/windows/local/cve_2020_1054_drawiconex_lpe | Required | - | - | - |
| 370 | Windows Update Orchestrator unchecked ScheduleWork call | exploit/windows/local/cve_2020_1313_system_orchestrator | Required | - | - | - |
| 371 | Microsoft Spooler Local Privilege Elevation Vulnerability | exploit/windows/local/cve_2020_1337_printerdemon | Required | - | - | - |
| 372 | CVE-2020-1170 Cloud Filter Arbitrary File Creation EOP | exploit/windows/local/cve_2020_17136 | Required | - | - | - |
| 373 | DnsAdmin ServerLevelPluginDll Feature Abuse Privilege Escalation | exploit/windows/local/dnsadmin_serverlevelplugindll | Required | - | - | - |
| 374 | Docker-Credential-Wincred.exe Privilege Escalation | exploit/windows/local/docker_credential_wincred | Required | - | - | - |
| 375 | Druva inSync inSyncCPHwnet64.exe RPC Type 5 Privilege Escalation | exploit/windows/local/druva_insync_insynccphwnet64_rcp_type_5_priv_esc | Required | - | - | - |
| 376 | GOG GalaxyClientService Privilege Escalation | exploit/windows/local/gog_galaxyclientservice_privesc | Required | - | - | - |
| 377 | IKE and AuthIP IPsec Keyring Modules Service (IKEEXT) Missing DLL | exploit/windows/local/ikeext_service | Required | - | - | - |
| 378 | iPass Mobile Client Service Privilege Escalation | exploit/windows/local/ipass_launch_app | Required | - | - | - |
| 379 | Lenovo System Update Privilege Escalation | exploit/windows/local/lenovo_systemupdate | Required | - | - | - |
| 380 | Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability | exploit/windows/local/mov_ss | Required | - | - | - |
| 381 | MQAC.sys Arbitrary Write Privilege Escalation | exploit/windows/local/mqac_write | Required | - | - | - |
| 382 | Windows SYSTEM Escalation via KiTrap0D | exploit/windows/local/ms10_015_kitrap0d | Required | - | - | - |
| 383 | Windows Escalate Task Scheduler XML Privilege Escalation | exploit/windows/local/ms10_092_schelevator | Required | - | - | - |
| 384 | MS11-080 AfdJoinLeaf Privilege Escalation | exploit/windows/local/ms11_080_afdjoinleaf | Required | - | - | - |
| 385 | Windows NTUserMessageCall Win32k Kernel Pool Overflow (Schlamperei) | exploit/windows/local/ms13_053_schlamperei | Required | - | - | - |
| 386 | Windows TrackPopupMenuEx Win32k NULL Page | exploit/windows/local/ms13_081_track_popup_menu | Required | - | - | - |
| 387 | MS14-009 .NET Deployment Service IE Sandbox Escape | exploit/windows/local/ms14_009_ie_dfsvc | Required | - | - | - |
| 388 | Windows TrackPopupMenu Win32k NULL Pointer Dereference | exploit/windows/local/ms14_058_track_popup_menu | Required | - | - | - |
| 389 | MS14-070 Windows tcpip!SetAddrOptions NULL Pointer Dereference | exploit/windows/local/ms14_070_tcpip_ioctl | Required | - | - | - |
| 390 | MS15-004 Microsoft Remote Desktop Services Web Proxy IE Sandbox Escape | exploit/windows/local/ms15_004_tswbproxy | Required | - | - | - |
| 391 | Windows ClientCopyImage Win32k Exploit | exploit/windows/local/ms15_051_client_copy_image | Required | - | - | - |
| 392 | MS15-078 Microsoft Windows Font Driver Buffer Overflow | exploit/windows/local/ms15_078_atmfd_bof | Required | - | - | - |
| 393 | Windows WMI Receive Notification Exploit | exploit/windows/local/ms16_014_wmi_recv_notif | Required | - | - | - |
| 394 | MS16-016 mrxdav.sys WebDav Local Privilege Escalation | exploit/windows/local/ms16_016_webdav | Required | - | - | - |
| 395 | MS16-032 Secondary Logon Handle Privilege Escalation | exploit/windows/local/ms16_032_secondary_logon_handle_privesc | Required | - | - | - |
| 396 | Windows Net-NTLMv2 Reflection DCOM/RPC | exploit/windows/local/ms16_075_reflection | Required | - | - | - |
| 397 | Windows Net-NTLMv2 Reflection DCOM/RPC (Juicy) | exploit/windows/local/ms16_075_reflection_juicy | Required | - | - | - |
| 398 | Windows SetImeInfoEx Win32k NULL Pointer Dereference | exploit/windows/local/ms18_8120_win32k_privesc | Required | - | - | - |
| 399 | MS14-002 Microsoft Windows ndproxy.sys Local Privilege Escalation | exploit/windows/local/ms_ndproxy | Required | - | - | - |
| 400 | Novell Client 2 SP3 nicm.sys Local Privilege Escalation | exploit/windows/local/novell_client_nicm | Required | - | - | - |
| 401 | Novell Client 4.91 SP4 nwfs.sys Local Privilege Escalation | exploit/windows/local/novell_client_nwfs | Required | - | - | - |
| 402 | MS15-001 Microsoft Windows NtApphelpCacheControl Improper Authorization Check | exploit/windows/local/ntapphelpcachecontrol | Required | - | - | - |
| 403 | Microsoft Windows NtUserMNDragOver Local Privilege Elevation | exploit/windows/local/ntusermndragover | Required | - | - | - |
| 404 | Nvidia (nvsvc) Display Driver Service Local Privilege Escalation | exploit/windows/local/nvidia_nvsvc | Required | - | - | - |
| 405 | Panda Security PSEvents Privilege Escalation | exploit/windows/local/panda_psevents | Required | - | - | - |
| 406 | Windows Manage Memory Payload Injection | exploit/windows/local/payload_inject | Required | - | - | - |
| 407 | Windows Persistent Registry Startup Payload Installer | exploit/windows/local/persistence | Required | - | - | - |
| 408 | Windows Silent Process Exit Persistence | exploit/windows/local/persistence_image_exec_options | Required | - | - | - |
| 409 | Windows Persistent Service Installer | exploit/windows/local/persistence_service | Required | - | - | - |
| 410 | Plantronics Hub SpokesUpdateService Privilege Escalation | exploit/windows/local/plantronics_hub_spokesupdateservice_privesc | Required | - | - | - |
| 411 | Windows Command Shell Upgrade (Powershell) | exploit/windows/local/powershell_cmd_upgrade | Required | - | - | - |
| 412 | Powershell Remoting Remote Command Execution | exploit/windows/local/powershell_remoting | Required | - | - | - |
| 413 | Windows EPATHOBJ::pprFlattenRec Local Privilege Escalation | exploit/windows/local/ppr_flatten_rec | Required | - | - | - |
| 414 | Powershell Payload Execution | exploit/windows/local/ps_persist | Required | - | - | - |
| 415 | Authenticated WMI Exec via Powershell | exploit/windows/local/ps_wmi_exec | Required | - | - | - |
| 416 | PXE Exploit Server | exploit/windows/local/pxeexploit | Required | - | - | - |
| 417 | Razer Synapse rzpnk.sys ZwOpenProcess | exploit/windows/local/razer_zwopenprocess | Required | - | - | - |
| 418 | Windows Registry Only Persistence | exploit/windows/local/registry_persistence | Required | - | - | - |
| 419 | Ricoh Driver Privilege Escalation | exploit/windows/local/ricoh_driver_privesc | Required | - | - | - |
| 420 | Windows Run Command As User | exploit/windows/local/run_as | Required | - | - | - |
| 421 | Windows Manage User Level Persistent Payload Installer | exploit/windows/local/s4u_persistence | Required | - | - | - |
| 422 | Windows Escalate Service Permissions Local Privilege Escalation | exploit/windows/local/service_permissions | Required | - | - | - |
| 423 | Windows Unquoted Service Path Privilege Escalation | exploit/windows/local/unquoted_service_path | Required | - | - | - |
| 424 | VirtualBox Guest Additions VBoxGuest.sys Privilege Escalation | exploit/windows/local/virtual_box_guest_additions | Required | - | - | - |
| 425 | VirtualBox 3D Acceleration Virtual Machine Escape | exploit/windows/local/virtual_box_opengl_escape | Required | - | - | - |
| 426 | Persistent Payload in Windows Volume Shadow Copy | exploit/windows/local/vss_persistence | Required | - | - | - |
| 427 | WebEx Local Service Permissions Exploit | exploit/windows/local/webexec | Required | - | - | - |
| 428 | Windscribe WindscribeService Named Pipe Privilege Escalation | exploit/windows/local/windscribe_windscribeservice_priv_esc | Required | - | - | - |
| 429 | Windows Management Instrumentation (WMI) Remote Command Execution | exploit/windows/local/wmi | Required | - | - | - |
| 430 | WMI Event Subscription Persistence | exploit/windows/local/wmi_persistence | Required | - | - | - |
| 431 | Achat Unicode SEH Buffer Overflow | exploit/windows/misc/achat_bof | Required | - | Required | - |
| 432 | Avaya WinPMD UniteHostRouter Buffer Overflow | exploit/windows/misc/avaya_winpmd_unihostrouter | Required | - | Required | - |
| 433 | Bomberclone 0.11.6 Buffer Overflow | exploit/windows/misc/bomberclone_overflow | Required | - | Required | - |
| 434 | Citrix Provisioning Services 5.6 streamprocess.exe Buffer Overflow | exploit/windows/misc/citrix_streamprocess | Required | - | Required | - |
| 435 | Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020000 Buffer Overflow | exploit/windows/misc/citrix_streamprocess_data_msg | Required | - | Required | - |
| 436 | Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020004 Buffer Overflow | exploit/windows/misc/citrix_streamprocess_get_boot_record_request | Required | - | Required | - |
| 437 | Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020002 Buffer Overflow | exploit/windows/misc/citrix_streamprocess_get_footer | Required | - | Required | - |
| 438 | Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020006 Buffer Overflow | exploit/windows/misc/citrix_streamprocess_get_objects | Required | - | Required | - |
| 439 | Anviz CrossChex Buffer Overflow | exploit/windows/misc/crosschex_device_bof | Required | - | - | - |
| 440 | Enterasys NetSight nssyslogd.exe Buffer Overflow | exploit/windows/misc/enterasys_netsight_syslog_bof | Required | - | Required | - |
| 441 | HP Intelligent Management Center UAM Buffer Overflow | exploit/windows/misc/hp_imc_uam | Required | - | Required | - |
| 442 | LANDesk Management Suite 8.7 Alert Service Buffer Overflow | exploit/windows/misc/landesk_aolnsrvr | Required | - | Required | - |
| 443 | Wireshark packet-dect.c Stack Buffer Overflow | exploit/windows/misc/wireshark_packet_dect | Required | - | - | - |
| 444 | Nuuo Central Management Server Authenticated Arbitrary File Upload | exploit/windows/nuuo/nuuo_cms_fu | Required | - | Required | - |
| 445 | PostgreSQL for Microsoft Windows Payload Execution | exploit/windows/postgres/postgres_payload | Required | Required | Required | - |
| 446 | DaqFactory HMI NETB Request Overflow | exploit/windows/scada/daq_factory_bof | Required | - | Required | - |
| 447 | Yokogawa CS3000 BKFSim_vhfd.exe Buffer Overflow | exploit/windows/scada/yokogawa_bkfsim_vhfd | Required | - | Required | - |
| 448 | AIM Triton 1.0.4 CSeq Buffer Overflow | exploit/windows/sip/aim_triton_cseq | Required | - | Required | - |
| 449 | SIPfoundry sipXezPhone 0.35a CSeq Field Overflow | exploit/windows/sip/sipxezphone_cseq | Required | - | Required | - |
| 450 | SIPfoundry sipXphone 2.6.0.27 CSeq Buffer Overflow | exploit/windows/sip/sipxphone_cseq | Required | - | Required | - |
| 451 | MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+ | exploit/windows/smb/ms17_010_eternalblue_win8 | Required | - | Required | - |
| 452 | Allied Telesyn TFTP Server 1.9 Long Filename Overflow | exploit/windows/tftp/attftp_long_filename | Required | - | Required | - |
| 453 | Distinct TFTP 3.10 Writable Directory Traversal Execution | exploit/windows/tftp/distinct_tftp_traversal | Required | - | Required | - |
| 454 | D-Link TFTP 1.0 Long Filename Buffer Overflow | exploit/windows/tftp/dlink_long_filename | Required | - | Required | - |
| 455 | FutureSoft TFTP Server 2000 Transfer-Mode Overflow | exploit/windows/tftp/futuresoft_transfermode | Required | - | Required | - |
| 456 | NetDecision 4.2 TFTP Writable Directory Traversal Execution | exploit/windows/tftp/netdecision_tftp_traversal | Required | - | Required | - |
| 457 | OpenTFTP SP 1.4 Error Packet Overflow | exploit/windows/tftp/opentftp_error_code | Required | - | Required | - |
| 458 | Quick FTP Pro 2.1 Transfer-Mode Overflow | exploit/windows/tftp/quick_tftp_pro_mode | Required | - | Required | - |
| 459 | TFTPD32 Long Filename Buffer Overflow | exploit/windows/tftp/tftpd32_long_filename | Required | - | Required | - |
| 460 | TFTPDWIN v0.4.2 Long Filename Buffer Overflow | exploit/windows/tftp/tftpdwin_long_filename | Required | - | Required | - |
| 461 | TFTP Server for Windows 1.4 ST WRQ Buffer Overflow | exploit/windows/tftp/tftpserver_wrq_bof | Required | - | Required | - |
| 462 | 3CTftpSvc TFTP Long Mode Buffer Overflow | exploit/windows/tftp/threectftpsvc_long_mode | Required | - | Required | - |
| 463 | SafeNet SoftRemote IKE Service Buffer Overflow | exploit/windows/vpn/safenet_ike_11 | Required | - | Required | - |
| 464 | Multi Escalate Metasploit pcap_log Local Privilege Escalation | post/multi/escalate/metasploit_pcaplog | - | Required | Required | - |
| 465 | Gather AWS EC2 Instance Metadata | post/multi/gather/aws_ec2_instance_metadata | - | - | - | Required |
| 466 | Multi Manage DbVisualizer Add Db Admin | post/multi/manage/dbvis_add_db_admin | - | Required | - | - |
| 467 | Windows Manage Trojanize Support Account | post/windows/manage/enable_support_account | - | Required | - | - |
| 468 | Grafana 2.0 through 5.2.2 authentication bypass for LDAP and OAuth | auxiliary/admin/http/grafana_auth_bypass | - | - | Required | - |
| 469 | MS14-068 Microsoft Kerberos Checksum Validation Vulnerability | auxiliary/admin/kerberos/ms14_068_kerberos_checksum | - | - | Required | - |
| 470 | VMware vCenter Server vmdir Authentication Bypass | auxiliary/admin/ldap/vmware_vcenter_vmdir_auth_bypass | - | - | Required | - |
| 471 | NAT-PMP Port Mapper | auxiliary/admin/natpmp/natpmp_map | - | - | Required | - |
| 472 | NetBIOS Response Brute Force Spoof (Direct) | auxiliary/admin/netbios/netbios_spoof | - | - | Required | - |
| 473 | Arista Configuration Importer | auxiliary/admin/networking/arista_config | - | - | Required | - |
| 474 | Brocade Configuration Importer | auxiliary/admin/networking/brocade_config | - | - | Required | - |
| 475 | Cisco ASA Authentication Bypass (EXTRABACON) | auxiliary/admin/networking/cisco_asa_extrabacon | - | - | Required | - |
| 476 | Cisco Configuration Importer | auxiliary/admin/networking/cisco_config | - | - | Required | - |
| 477 | F5 Configuration Importer | auxiliary/admin/networking/f5_config | - | - | Required | - |
| 478 | Juniper Configuration Importer | auxiliary/admin/networking/juniper_config | - | - | Required | - |
| 479 | Mikrotik Configuration Importer | auxiliary/admin/networking/mikrotik_config | - | - | Required | - |
| 480 | Ubiquiti Configuration Importer | auxiliary/admin/networking/ubiquiti_config | - | - | Required | - |
| 481 | VyOS Configuration Importer | auxiliary/admin/networking/vyos_config | - | - | Required | - |
| 482 | Oracle SMB Relay Code Execution | auxiliary/admin/oracle/ora_ntlm_stealer | - | Required | Required | - |
| 483 | Oracle DB Privilege Escalation via Function-Based Index | auxiliary/admin/oracle/oracle_index_privesc | - | Required | Required | - |
| 484 | Oracle Account Discovery | auxiliary/admin/oracle/oracle_login | - | - | Required | - |
| 485 | Oracle SQL Generic Query | auxiliary/admin/oracle/oracle_sql | - | Required | Required | - |
| 486 | Oracle Database Enumeration | auxiliary/admin/oracle/oraenum | - | Required | Required | - |
| 487 | Oracle Java execCommand (Win32) | auxiliary/admin/oracle/post_exploitation/win32exec | - | Required | Required | - |
| 488 | Oracle URL Download | auxiliary/admin/oracle/post_exploitation/win32upload | - | Required | Required | - |
| 489 | PostgreSQL Server Generic Query | auxiliary/admin/postgres/postgres_readfile | - | Required | Required | - |
| 490 | PostgreSQL Server Generic Query | auxiliary/admin/postgres/postgres_sql | - | Required | Required | - |
| 491 | Moxa Device Credential Retrieval | auxiliary/admin/scada/moxa_credentials_recovery | - | - | Required | - |
| 492 | Teradata ODBC SQL Query Module | auxiliary/admin/teradata/teradata_odbc_sql | - | Required | - | - |
| 493 | TFTP File Transfer Utility | auxiliary/admin/tftp/tftp_transfer_util | - | - | Required | - |
| 494 | Apple Airport Extreme Password Extraction (WDBRPC) | auxiliary/admin/vxworks/apple_airport_extreme_password | - | - | Required | - |
| 495 | D-Link i2eye Video Conference AutoAnswer (WDBRPC) | auxiliary/admin/vxworks/dlink_i2eye_autoanswer | - | - | Required | - |
| 496 | VxWorks WDB Agent Remote Memory Dump | auxiliary/admin/vxworks/wdbrpc_memory_dump | - | - | Required | - |
| 497 | VxWorks WDB Agent Remote Reboot | auxiliary/admin/vxworks/wdbrpc_reboot | - | - | Required | - |
| 498 | Extract zip from Modbus communication | auxiliary/analyze/modbus_zip | - | - | Required | - |
| 499 | BIND TKEY Query Denial of Service | auxiliary/dos/dns/bind_tkey | - | - | Required | - |
| 500 | BIND TSIG Query Denial of Service | auxiliary/dos/dns/bind_tsig | - | - | Required | - |
| 501 | BIND TSIG Badtime Query Denial of Service | auxiliary/dos/dns/bind_tsig_badtime | - | - | Required | - |
| 502 | RPC DoS targeting *nix rpcbind/libtirpc | auxiliary/dos/rpc/rpcbomb | - | - | Required | - |
| 503 | Beckhoff TwinCAT SCADA PLC 2.11.0.2004 DoS | auxiliary/dos/scada/beckhoff_twincat | - | - | Required | - |
| 504 | General Electric D20ME TFTP Server Buffer Overflow DoS | auxiliary/dos/scada/d20_tftp_overflow | - | - | Required | - |
| 505 | Siemens SIPROTEC 4 and SIPROTEC Compact EN100 Ethernet Module - Denial of Service | auxiliary/dos/scada/siemens_siprotec4 | - | - | Required | - |
| 506 | Yokogawa CENTUM CS 3000 BKCLogSvr.exe Heap Buffer Overflow | auxiliary/dos/scada/yokogawa_logsvr | - | - | Required | - |
| 507 | OpenSSL DTLS ChangeCipherSpec Remote DoS | auxiliary/dos/ssl/dtls_changecipherspec | - | - | Required | - |
| 508 | OpenSSL DTLS Fragment Buffer Overflow DoS | auxiliary/dos/ssl/dtls_fragment_overflow | - | - | Required | - |
| 509 | rsyslog Long Tag Off-By-Two DoS | auxiliary/dos/syslog/rsyslog_long_tag | - | - | Required | - |
| 510 | TCP SYN Flooder | auxiliary/dos/tcp/synflood | - | - | Required | - |
| 511 | MiniUPnPd 1.4 Denial of Service (DoS) Exploit | auxiliary/dos/upnp/miniupnpd_dos | - | - | Required | - |
| 512 | Kaillera 0.86 Server Denial of Service | auxiliary/dos/windows/games/kaillera | - | - | Required | - |
| 513 | Microsoft Windows DNSAPI.dll LLMNR Buffer Underrun DoS | auxiliary/dos/windows/llmnr/ms11_030_dnsapi | - | - | Required | - |
| 514 | Microsoft Windows NAT Helper Denial of Service | auxiliary/dos/windows/nat/nat_helper | - | - | Required | - |
| 515 | Microsoft Windows Browser Pool DoS | auxiliary/dos/windows/smb/ms11_019_electbowser | - | - | Required | - |
| 516 | PacketTrap TFTP Server 2.2.5459.0 DoS | auxiliary/dos/windows/tftp/pt360_write | - | - | Required | - |
| 517 | SolarWinds TFTP Server 10.4.0.10 Denial of Service | auxiliary/dos/windows/tftp/solarwinds | - | - | Required | - |
| 518 | Wireshark CAPWAP Dissector DoS | auxiliary/dos/wireshark/capwap | - | - | Required | - |
| 519 | NTP Protocol Fuzzer | auxiliary/fuzzers/ntp/ntp_protocol_fuzzer | - | - | Required | - |
| 520 | Citrix MetaFrame ICA Published Applications Scanner | auxiliary/gather/citrix_published_applications | - | - | Required | - |
| 521 | Citrix MetaFrame ICA Published Applications Bruteforcer | auxiliary/gather/citrix_published_bruteforce | - | - | Required | - |
| 522 | General Electric D20 Password Recovery | auxiliary/gather/d20pass | - | - | Required | - |
| 523 | Kerberos Domain User Enumeration | auxiliary/gather/kerberos_enumusers | - | - | Required | - |
| 524 | LDAP Information Disclosure | auxiliary/gather/ldap_hashdump | - | - | Required | - |
| 525 | NAT-PMP External Address Scanner | auxiliary/gather/natpmp_external_address | - | - | Required | - |
| 526 | Nuuo Central Management Server User Session Token Bruteforce | auxiliary/gather/nuuo_cms_bruteforce | - | - | Required | - |
| 527 | Nuuo Central Management Server Authenticated Arbitrary File Download | auxiliary/gather/nuuo_cms_file_download | - | - | Required | - |
| 528 | VMware vCenter Server vmdir Information Disclosure | auxiliary/gather/vmware_vcenter_vmdir_ldap | - | - | Required | - |
| 529 | Chargen Probe Utility | auxiliary/scanner/chargen/chargen_probe | - | - | Required | - |
| 530 | DB2 Discovery Service Detection | auxiliary/scanner/db2/discovery | - | - | Required | - |
| 531 | UDP Empty Prober | auxiliary/scanner/discovery/empty_udp | - | - | Required | - |
| 532 | DNS Amplification Scanner | auxiliary/scanner/dns/dns_amp | - | - | Required | - |
| 533 | GTP Echo Scanner | auxiliary/scanner/gprs/gtp_echo | - | - | Required | - |
| 534 | Web Site Crawler | auxiliary/scanner/http/crawler | - | - | Required | - |
| 535 | OWA Exchange Web Services (EWS) Login Scanner | auxiliary/scanner/http/owa_ews_login | - | - | Required | - |
| 536 | Cisco IKE Information Disclosure | auxiliary/scanner/ike/cisco_ike_benigncertain | - | - | Required | - |
| 537 | IPID Sequence Scanner | auxiliary/scanner/ip/ipidseq | - | - | Required | - |
| 538 | IPMI 2.0 Cipher Zero Authentication Bypass Scanner | auxiliary/scanner/ipmi/ipmi_cipher_zero | - | - | Required | - |
| 539 | IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval | auxiliary/scanner/ipmi/ipmi_dumphashes | - | Required | Required | - |
| 540 | IPMI Information Discovery | auxiliary/scanner/ipmi/ipmi_version | - | - | Required | - |
| 541 | Gather Kademlia Server Information | auxiliary/scanner/kademlia/server_info | - | - | Required | - |
| 542 | LLMNR Query | auxiliary/scanner/llmnr/query | - | - | Required | - |
| 543 | mDNS Query | auxiliary/scanner/mdns/query | - | - | Required | - |
| 544 | Memcached Stats Amplification Scanner | auxiliary/scanner/memcached/memcached_amp | - | - | Required | - |
| 545 | Memcached UDP Version Scanner | auxiliary/scanner/memcached/memcached_udp_version | - | - | Required | - |
| 546 | Rosewill RXS-3211 IP Camera Password Retriever | auxiliary/scanner/misc/rosewill_rxs3211_passwords | - | - | Required | - |
| 547 | Motorola Timbuktu Service Detection | auxiliary/scanner/motorola/timbuktu_udp | - | - | Required | - |
| 548 | NAT-PMP External Port Scanner | auxiliary/scanner/natpmp/natpmp_portscan | - | - | Required | - |
| 549 | NetBIOS Information Discovery | auxiliary/scanner/netbios/nbname | - | - | Required | - |
| 550 | NTP Monitor List Scanner | auxiliary/scanner/ntp/ntp_monlist | - | - | Required | - |
| 551 | NTP "NAK to the Future" | auxiliary/scanner/ntp/ntp_nak_to_the_future | - | - | Required | - |
| 552 | NTP Mode 7 PEER_LIST DoS Scanner | auxiliary/scanner/ntp/ntp_peer_list_dos | - | - | Required | - |
| 553 | NTP Mode 7 PEER_LIST_SUM DoS Scanner | auxiliary/scanner/ntp/ntp_peer_list_sum_dos | - | - | Required | - |
| 554 | NTP Clock Variables Disclosure | auxiliary/scanner/ntp/ntp_readvar | - | - | Required | - |
| 555 | NTP Mode 6 REQ_NONCE DRDoS Scanner | auxiliary/scanner/ntp/ntp_req_nonce_dos | - | - | Required | - |
| 556 | NTP Mode 7 GET_RESTRICT DRDoS Scanner | auxiliary/scanner/ntp/ntp_reslist_dos | - | - | Required | - |
| 557 | NTP Mode 6 UNSETTRAP DRDoS Scanner | auxiliary/scanner/ntp/ntp_unsettrap_dos | - | - | Required | - |
| 558 | Oracle Password Hashdump | auxiliary/scanner/oracle/oracle_hashdump | - | Required | Required | - |
| 559 | PcAnywhere UDP Service Discovery | auxiliary/scanner/pcanywhere/pcanywhere_udp | - | - | Required | - |
| 560 | Portmapper Amplification Scanner | auxiliary/scanner/portmap/portmap_amp | - | - | Required | - |
| 561 | Postgres Password Hashdump | auxiliary/scanner/postgres/postgres_hashdump | - | Required | Required | - |
| 562 | PostgreSQL Login Utility | auxiliary/scanner/postgres/postgres_login | - | - | Required | - |
| 563 | Postgres Schema Dump | auxiliary/scanner/postgres/postgres_schemadump | - | Required | Required | - |
| 564 | PostgreSQL Version Probe | auxiliary/scanner/postgres/postgres_version | - | Required | Required | - |
| 565 | Gather Quake Server Information | auxiliary/scanner/quake/server_info | - | - | Required | - |
| 566 | Rogue Gateway Detection: Receiver | auxiliary/scanner/rogue/rogue_recv | - | - | Required | - |
| 567 | Rogue Gateway Detection: Sender | auxiliary/scanner/rogue/rogue_send | - | - | Required | - |
| 568 | Digi ADDP Remote Reboot Initiator | auxiliary/scanner/scada/digi_addp_reboot | - | Required | Required | - |
| 569 | Digi ADDP Information Discovery | auxiliary/scanner/scada/digi_addp_version | - | Required | Required | - |
| 570 | Koyo DirectLogic PLC Password Brute Force Utility | auxiliary/scanner/scada/koyo_login | - | - | Required | - |
| 571 | Moxa UDP Device Discovery | auxiliary/scanner/scada/moxa_discover | - | - | Required | - |
| 572 | SIP Username Enumerator (UDP) | auxiliary/scanner/sip/enumerator | - | - | Required | - |
| 573 | SIP Endpoint Scanner (UDP) | auxiliary/scanner/sip/options | - | - | Required | - |
| 574 | AIX SNMP Scanner Auxiliary Module | auxiliary/scanner/snmp/aix_version | - | - | Required | - |
| 575 | Arris DG950A Cable Modem Wifi Enumeration | auxiliary/scanner/snmp/arris_dg950 | - | - | Required | - |
| 576 | Brocade Password Hash Enumeration | auxiliary/scanner/snmp/brocade_enumhash | - | - | Required | - |
| 577 | Cisco IOS SNMP Configuration Grabber (TFTP) | auxiliary/scanner/snmp/cisco_config_tftp | - | - | Required | - |
| 578 | Cisco IOS SNMP File Upload (TFTP) | auxiliary/scanner/snmp/cisco_upload_file | - | - | Required | - |
| 579 | Cambium cnPilot r200/r201 SNMP Enumeration | auxiliary/scanner/snmp/cnpilot_r_snmp_loot | - | - | Required | - |
| 580 | Cambium ePMP 1000 SNMP Enumeration | auxiliary/scanner/snmp/epmp1000_snmp_loot | - | - | Required | - |
| 581 | Netopia 3347 Cable Modem Wifi Enumeration | auxiliary/scanner/snmp/netopia_enum | - | - | Required | - |
| 582 | ARRIS / Motorola SBG6580 Cable Modem SNMP Enumeration Module | auxiliary/scanner/snmp/sbg6580_enum | - | - | Required | - |
| 583 | SNMP Enumeration Module | auxiliary/scanner/snmp/snmp_enum | - | - | Required | - |
| 584 | HP LaserJet Printer SNMP Enumeration | auxiliary/scanner/snmp/snmp_enum_hp_laserjet | - | - | Required | - |
| 585 | SNMP Windows SMB Share Enumeration | auxiliary/scanner/snmp/snmp_enumshares | - | - | Required | - |
| 586 | SNMP Windows Username Enumeration | auxiliary/scanner/snmp/snmp_enumusers | - | - | Required | - |
| 587 | SNMP Community Login Scanner | auxiliary/scanner/snmp/snmp_login | - | - | Required | - |
| 588 | SNMP Set Module | auxiliary/scanner/snmp/snmp_set | - | - | Required | - |
| 589 | Ubee DDW3611b Cable Modem Wifi Enumeration | auxiliary/scanner/snmp/ubee_ddw3611 | - | - | Required | - |
| 590 | Xerox WorkCentre User Enumeration (SNMP) | auxiliary/scanner/snmp/xerox_workcentre_enumusers | - | - | Required | - |
| 591 | Apache Karaf Default Credentials Command Execution | auxiliary/scanner/ssh/apache_karaf_command_execution | - | Required | Required | - |
| 592 | Cerberus FTP Server SFTP Username Enumeration | auxiliary/scanner/ssh/cerberus_sftp_enumusers | - | - | Required | - |
| 593 | Juniper SSH Backdoor Scanner | auxiliary/scanner/ssh/juniper_backdoor | - | - | Required | - |
| 594 | Apache Karaf Login Utility | auxiliary/scanner/ssh/karaf_login | - | - | Required | - |
| 595 | SSH Username Enumeration | auxiliary/scanner/ssh/ssh_enumusers | - | - | Required | - |
| 596 | SSH Public Key Acceptance Scanner | auxiliary/scanner/ssh/ssh_identify_pubkeys | - | - | Required | - |
| 597 | Gather Steam Server Information | auxiliary/scanner/steam/server_info | - | - | Required | - |
| 598 | Lantronix Telnet Password Recovery | auxiliary/scanner/telnet/lantronix_telnet_password | - | - | Required | - |
| 599 | IpSwitch WhatsUp Gold TFTP Directory Traversal | auxiliary/scanner/tftp/ipswitch_whatsupgold_tftp | - | - | Required | - |
| 600 | NetDecision 4.2 TFTP Directory Traversal | auxiliary/scanner/tftp/netdecision_tftp | - | - | Required | - |
| 601 | TFTP Brute Forcer | auxiliary/scanner/tftp/tftpbrute | - | - | Required | - |
| 602 | Ubiquiti Discovery Scanner | auxiliary/scanner/ubiquiti/ubiquiti_discover | - | - | Required | - |
| 603 | SSDP ssdp:all M-SEARCH Amplification Scanner | auxiliary/scanner/upnp/ssdp_amp | - | - | Required | - |
| 604 | UPnP SSDP M-SEARCH Information Discovery | auxiliary/scanner/upnp/ssdp_msearch | - | - | Required | - |
| 605 | VxWorks WDB Agent Boot Parameter Scanner | auxiliary/scanner/vxworks/wdbrpc_bootline | - | - | Required | - |
| 606 | VxWorks WDB Agent Version Scanner | auxiliary/scanner/vxworks/wdbrpc_version | - | - | Required | - |
| 607 | WS-Discovery Information Discovery | auxiliary/scanner/wsdd/wsdd_query | - | - | Required | - |
| 608 | Oracle DB SQL Injection via SYS.DBMS_CDC_IPUBLISH.ALTER_HOTLOG_INTERNAL_CSOURCE | auxiliary/sqli/oracle/dbms_cdc_ipublish | - | Required | Required | - |
| 609 | Oracle DB SQL Injection via SYS.DBMS_CDC_PUBLISH.ALTER_AUTOLOG_CHANGE_SOURCE | auxiliary/sqli/oracle/dbms_cdc_publish | - | Required | Required | - |
| 610 | Oracle DB SQL Injection via SYS.DBMS_CDC_PUBLISH.DROP_CHANGE_SOURCE | auxiliary/sqli/oracle/dbms_cdc_publish2 | - | Required | Required | - |
| 611 | Oracle DB SQL Injection via SYS.DBMS_CDC_PUBLISH.CREATE_CHANGE_SET | auxiliary/sqli/oracle/dbms_cdc_publish3 | - | Required | Required | - |
| 612 | Oracle DB SQL Injection via SYS.DBMS_CDC_SUBSCRIBE.ACTIVATE_SUBSCRIPTION | auxiliary/sqli/oracle/dbms_cdc_subscribe_activate_subscription | - | Required | Required | - |
| 613 | Oracle DB SQL Injection via DBMS_EXPORT_EXTENSION | auxiliary/sqli/oracle/dbms_export_extension | - | Required | Required | - |
| 614 | Oracle DB SQL Injection via SYS.DBMS_METADATA.GET_GRANTED_XML | auxiliary/sqli/oracle/dbms_metadata_get_granted_xml | - | Required | Required | - |
| 615 | Oracle DB SQL Injection via SYS.DBMS_METADATA.GET_XML | auxiliary/sqli/oracle/dbms_metadata_get_xml | - | Required | Required | - |
| 616 | Oracle DB SQL Injection via SYS.DBMS_METADATA.OPEN | auxiliary/sqli/oracle/dbms_metadata_open | - | Required | Required | - |
| 617 | Oracle DB 10gR2, 11gR1/R2 DBMS_JVM_EXP_PERMS OS Command Execution | auxiliary/sqli/oracle/jvm_os_code_10g | - | Required | Required | - |
| 618 | Oracle DB 11g R1/R2 DBMS_JVM_EXP_PERMS OS Code Execution | auxiliary/sqli/oracle/jvm_os_code_11g | - | Required | Required | - |
| 619 | Oracle DB SQL Injection via SYS.LT.COMPRESSWORKSPACE | auxiliary/sqli/oracle/lt_compressworkspace | - | Required | Required | - |
| 620 | Oracle DB SQL Injection via SYS.LT.FINDRICSET Evil Cursor Method | auxiliary/sqli/oracle/lt_findricset_cursor | - | Required | Required | - |
| 621 | Oracle DB SQL Injection via SYS.LT.MERGEWORKSPACE | auxiliary/sqli/oracle/lt_mergeworkspace | - | Required | Required | - |
| 622 | Oracle DB SQL Injection via SYS.LT.REMOVEWORKSPACE | auxiliary/sqli/oracle/lt_removeworkspace | - | Required | Required | - |
| 623 | Oracle DB SQL Injection via SYS.LT.ROLLBACKWORKSPACE | auxiliary/sqli/oracle/lt_rollbackworkspace | - | Required | Required | - |
| 624 | SIP Deregister Extension | auxiliary/voip/sip_deregister | - | - | Required | - |
| 625 | SIP Invite Spoof | auxiliary/voip/sip_invite_spoof | - | - | Required | - |
| 626 | Applocker Evasion - .NET Framework Installation Utility | evasion/windows/applocker_evasion_install_util | Required | - | - | - |
| 627 | Applocker Evasion - MSBuild | evasion/windows/applocker_evasion_msbuild | Required | - | - | - |
| 628 | Applocker Evasion - Windows Presentation Foundation Host | evasion/windows/applocker_evasion_presentationhost | Required | - | - | - |
| 629 | Applocker Evasion - Microsoft .NET Assembly Registration Utility | evasion/windows/applocker_evasion_regasm_regsvcs | Required | - | - | - |
| 630 | Applocker Evasion - Microsoft Workflow Compiler | evasion/windows/applocker_evasion_workflow_compiler | Required | - | - | - |
| 631 | Microsoft Windows Defender Evasive Executable | evasion/windows/windows_defender_exe | Required | - | - | - |
| 632 | Microsoft Windows Defender Evasive JS.Net and HTA | evasion/windows/windows_defender_js_hta | Required | - | - | - |
