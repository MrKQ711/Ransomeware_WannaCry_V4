# Implement

IMPLEMENT FOR WANNACRY RANSOMWARE

CONTENT

---

Background

---

WannaCry Mitgation

---

WannaCry Detection and Indicators of Compromise

---

WannaCry Command and Control TOR Network

---

WannaCry Onion Sites

---

WannaCry File Name

---

WannaCry Hashes/IoCs

---

WannaCry Extensions Encrypted by WannaCry Ransomware

---

1. Background
- WannaCry falls under the classification of Ransomware or more specifically Crypto ransomware. Organizations infected with WannaCry will encrypt the files and other user data and seeks out a ransom in bitcoins (typically USD $300-$600). The WannaCry ransomware has worm like capabilities and uses a known SMB (Server Message Block) vulnerability in the Microsoft Windows operating system. SMB is a protocol that allows for file-sharing over a company network. Once the initial machine is infected, the malware scans for other vulnerable machines in the network, looking for network shares and removable storage devices. 
- It checks for certain file extensions and encrypts them using strong encryption.
2. WannaCry Mitigation
- The table below provides a list of mitigation techniques for the WannaCry ransomware attack.

| Security Control | Control Summary |
| --- | --- |
| Patch the vulnerability. Apply patches for MS17-010 from Microsoft. This also includes patches under KB4012598 for end-of-life Microsoft Windows operating systems. | This patch mitigates the exploits revealed by the NSA Shadow Brokers dump. |
| Contain the spread of the ransomware. Disable outdated and legacy protocol SMBv1 | The exploit takes advantage of vulnerabilities in the SMB protocol in an organization’s network.
 • A quick way to verify that SMBv1 is disable is through the Windows registry.
• LanmanServer\Parameters\SMB1 for value 0 (which will be disable, 1 is enable)
• Another option is through Powershell.
• Also block incoming SMB traffic over port 445
• Additionally, filter and block NetBIOS port 139 from allexternally accessible hosts.
• Filter RDP port 3389 to prevent WannacRY from infecting other devices within that network. |
| Monitor and block the WannaCry network indicators of compromise. These are listed in the section below | • These include blocking outbound traffic on port 9001
• Also includes blocking outgoing request to IP address on port 80/443 that do not resolve into a domain
• Also, there should be not rationale for a device on your company network to connect to a TOR node. Block all outbound connections to TOR exit nodes.
• Sinkhole the kill-switch domains and redirect the following to webserver in your control.
• hxxp://iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com |
| Advanced deception techniques | WannaCry malware has behavior that avoids infecting the same machine twice. It does this by creating a mutex infection maker on that host. |
3. WannaCry Detection and Indicators of Compromise
- The table below is quick summary of all the know indicators of compromises for the WannaCry ransomware, how to detect it within your environment.

| Ransomware indicator | Malware Technique Summary |
| --- | --- |
| WannaCry Command and Control over the TOR network | The WannaCry ransomware communications are done using the anonymous TOR network |
| WannaCry ONION sites | The ransomware tries to connect to various .onion sites as part of its infection propagation process |
4. WannaCry Command and Control TOR Network
- The following is the list of TOR gateway nodes that the WannaCry ransomware tries to establish connections to all command and control of the malware port infection is done by utilizing these TOR nodes. Osprey Security recommends that the following IP addresses be blocked for any outbound network communications. Also, monitor for all traffic originating over port 9001. Detect and block accesses on IP addresses communicating over port 80/443 and that do not resolve in a domain.
- The following list below has been sourced from various security partners and leaders in McAfee, IBM XForce, Cisco Talos and Payload Security sandbox.

> 18.82.1.29:9001
> 
> 
> 37.187.22.87:9001
> 
> 38.229.72.16
> 
> 50.7.151.47:443
> 
> 50.7.161.218:9001
> 
> 51.255.41.65:9001
> 
> 62.138.7.231:9001
> 
> 62.138.10.60:9001
> 
> 79.172.193.32
> 
> 81.30.158.223
> 
> 82.94.251.227:443
> 
> 83.162.202.182:9001
> 
> 83.169.6.12:9001
> 
> 86.59.21.38:443
> 
> 89.39.67.33:443
> 
> 89.45.235.21
> 
> 94.23.173.93:443
> 
> 104.131.84.119:443
> 
> 128.31.0.39:9101
> 
> 136.243.176.148:443
> 
> 146.0.32.144:9001
> 
> 163.172.25.118:22
> 
> 163.172.129.29:9001
> 
> 163.172.153.12:9001
> 
> 163.172.185.132:443
> 
> 171.25.193.9:80
> 
> 178.62.173.203:9001
> 
> 178.254.44.135:9001
> 
> 185.97.32.18:9001
> 
> 188.138.33.220
> 
> 188.166.23.127:443
> 
> 192.42.115.102:9004
> 
> 193.22.244.244:443
> 
> 194.109.206.212:443
> 
> 195.154.164.243:443
> 
> 198.199.64.217:443
> 
> 212.47.232.237
> 
> 213.61.66.116:9003
> 
> 213.239.216.222:443
> 
5. WannaCry Onion Sites
- The Onion sites are part of the TOR network and typically constitutes the dark web of the Internet. The WannaCry ransomware tries to connect to various .onion sites which are listed below

> iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com (sinkholed)
> 
> 
> gx7ekbenv2riucmf.onion
> 
> 57g7spgrzlojinas.onion Xxlvbrloxvriy2c5.onion 76jdd2ir2embyv47.onion cwwnhwhlz52maqm7.onion sqjolphimrr7jqw6.onion
> 
6. WannaCry File Names
    
    d5e0e8694ddc0548d8e6b87c83d50f4ab85c1debadb106d6a6a794c3e746f4fa b.wnry
    
    055c7760512c98c8d51e4427227fe2a7ea3b34ee63178fe78631fa8aa6d15622 c.wnry
    
    402751fa49e0cb68fe052cb3db87b05e71c1d950984d339940cf6b29409f2a7c r.wnry
    
    e18fdd912dfe5b45776e68d578c3af3547886cf1353d7086c8bee037436dff4b s.wnry
    
    4a468603fdcb7a2eb5770705898cf9ef37aade532a7964642ecd705a74794b79 taskdl.exe
    
    2ca2d550e603d74dedda03156023135b38da3630cb014e3d00b1263358c5f00d tasksche.exe
    
    97ebce49b14c46bebc9ec2448d00e1e397123b256e2be9eba5140688e7bc0ae6 t.wnry
    
    b9c5d4339809e0ad9a00d4d3dd26fdf44a32819a54abf846bb9b560d81391c25 u.wnry
    
77. WannaCry Hashes / IoCs

| File Names | MD5 | SHA256 |
| --- | --- | --- |
| qeriuwjhrf | 3175E4BA26E1E75E52935009A526002C | 7E369022DA51937781B3EFE6C57F824F05CF43CBD66B4A24367A19488D2939E4 |
| mssecsvc.exe | 31DAB68B11824153B4C975399DF0354F | 9B60C622546DC45CCA64DF935B71C26DCF4886D6FA811944DBC4E23DB9335640 |
| cliconfg.exe | 4FEF5E34143E646DBF9907C4374276F5 | 4A468603FDCB7A2EB5770705898CF9EF37AADE532A7964642ECD705A74794B79 |
| diskpart.exe | 509C41EC97BB81 B0567B059AA2F50FE8 | 09A46B3E1BE080745A6D8D88D6B5BD351B1C7586AE0DC94D0C238EE36421CAFA |
| hdfrgui.exe | 5BEF35496FCBDBE841C82F4D1AB8B7C2 | 4186675CB6706F9D51167FB0F14CD3F8FCFB0065093F62B10A15F7D9A6C8D982 |
| waitfor.exe | 8495400F199AC77853C53B5A3F278F3E | 2CA2D550E603D74DEDDA03156023135B38DA3630CB014E3D00B1263358C5F00D |
| tasksche.exe | 84C82835A5D21B BCF75A61706D8AB549 | ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA |
| ransomware07_no_detection.exe | D6114BA5F10AD67A4131AB72531F02DA | 7C465EA7BCCCF4F94147ADD808F24629644BE11C0BA4823F16E8C19E0090F0FF |
| Ransomware.wannacry.exe | DB349B97C37D22 F5EA1D1841E3C89EB4 | 24D004A104D4D54034DBCFFC2A4B19A11F39008A575AA614EA04703480B1022C |
| localfile~ | B3N9697537D22TF7EA3P1351E34T9ED3 | 24D004A104D4D54034DBCFFC2A4B19A11F39008A575AA614EA04703480B1022C |
| taskhcst.exe | 3BC855BFADFEA71A445080BA72B26C1C | 043E0D0D8B8CDA56851F5B853F244F677BD1FD50F869075EF7BA1110771F70C2 |
| Cmd.Exe | 66DDBD108B0C347550F18BB953E1831D | F7C7B5E4B051EA5BD0017803F40AF 13BED224C4B0FD60B890B6784DF5
BD63494 |
| WCry_WannaCry_ransomware.exe | 4DA1F312A214C07143ABEEAFB695 D904 | AEE20F9188A5C3954623583C6B0E6623EC90D5CD3FDEC4E1001646E27664002C |
8. File Name Extensions Encrypted By WannaCry Ransomware

> .der, .pfx, .key, .crt, .csr, .p12, .pem, .odt, .sxw, .stw, .3ds,
> 
> 
> .max, .3dm, .ods, .sxc, .stc, .dif, .slk, .wb2, .odp, .sxd, .std,
> 
> .sxm, .sqlite3, .sqlitedb, .sql, .accdb, .mdb, .dbf, .odb, .mdf,
> 
> .ldf, .cpp, .pas, .asm, .cmd, .bat, .vbs, .sch, .jsp, .php, .asp,
> 
> .java, .jar, .class, .mp3, .wav, .swf, .fla, .wmv, .mpg, .vob,
> 
> .mpeg, .asf, .avi, .mov, .mp4, .mkv, .flv, .wma, .mid, .m3u,
> 
> .m4u, .svg, .psd, .tiff, .tif, .raw, .gif, .png, .bmp, .jpg,
> 
> .jpeg, .iso, .backup, .zip, .rar, .tgz, .tar, .bak, .ARC, .vmdk,
> 
> .vdi, .sldm, .sldx, .sti, .sxi, .dwg, .pdf, .wk1, .wks, .rtf,
> 
> .csv, .txt, .msg, .pst, .ppsx, .ppsm, .pps, .pot, .pptm, .pptx,
> 
> .ppt, .xltm, .xltx, .xlc, .xlm, .xlt, .xlw, .xlsb, .xlsm,
> 
> .xlsx, .xls, .dotm, .dot, .docm, .docx, .doc
>
