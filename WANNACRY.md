# WANNACRY

WANNACRY – RANSOMEWARE

| TABLE CONTENT |  |
| --- | --- |
| Virtural Machine | FlareVM |
| EXECUTIVE SUMMARY |  |
| HIGH-LEVEL TECHNICAL SUMMARY |  |
| MALWARE COMPOSITION | Ransomeware.wannacry.exe |
|  | tasksche.exe |
| BASIC STATIC ANALYSIS | Strings-Extracted using Floss |
|  | PEView |
|  | PE-Bear |
|  | Cutter |
| BASIC DYNAMIC ANALYSIS | Analysis with fakenet turned on (Use wireshark to analysize) |
|  | TCPView |
|  | Procmon |
|  | Task manager and Service |
|  | X32Dbg |
| INDICATORS OF COMPROMISE | Network Indicators |
|  | Host-based Indicators |
| RULES AND SIGNATURES |  |
1. PREPARED
- The FlareVM that is disable the internet so that the VM and the host is isolated.
- We have all of tools we need in FlareVM.
2. EXECUTIVE SUMMARY
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image1.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image1.png)
    
- The WannaCry ransomware attack was a global epidemic that took place in May 2017. This ransomware attack spread through computers operating Microsoft Windows. User’s files were held hostage, and a Bitcoin ransom was demanded for their return. Were it not for the continued use of outdated computer systems and poor education around the need to update software, the damage caused by this attack could have been avoided.
- WannaCry is written in C++ language. On executing the malware it checks for a hardcoded URL, if it successfully pings that URL malware does not execute. If the URL was not found then malware execution takes place. Symptoms of the infection include ransomware payment window popup, encryption of the files, new desktop shortcuts and new services created. After executing the malware it creates a file named “C:\Windows\tasksche.exe” which contains the payloads, and then starts encrypting all the files on computer.
- Beside that, we can copy SHA256 hash and search it on VirusTotal, then we will have

> 
> 
3. HIGH-LEVEL TECHNICAL SUMMARY
- It consists of two parts:

> + Stage 0: executable and an unpacked.
> 
> 
> + Stage 1: encryption and worm program.
> 
- It first attempts to contact its kill switch (hxxps://iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.local). If the URL is alive it does not execute. If the URL is not found then the malware unpacks tasksche.exe and creates a service to start tasksche.exe on startup. This executable encrypts all the files, shows the popup ransom window and changes the background of Desktop. It creates a random folder inside C:\ProgramData to store all the wannacry files.
- Kill Switch URL: A kill switch URL is a URL that can be used to shut down a website or other online service. It is typically used to prevent access to the service in the event of an emergency or malicious attack. The URL usually contains an authentication code that must be entered in order to disable the service.
- Beside that, It exploits the EternalBlue vulnerability on port 445 to spread to other computers.
- External vulnerability: is a type of security vulnerability that arises from outside of a system or network. This type of vulnerability can occur when malicious actors (such as hackers) attempt to gain access to the system through the internet or other external means, such as through a wireless network. External vulnerabilities can also be caused by flaws in the system's software, hardware, or configuration.
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image3.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image3.png)
    
4. MALWARE COMPOSITON
- It contains of two composition:

| Ransomeware.wannacry.exe | 24D004A104D4D54034DBCFFC2A4B19A11F39008A575AA614EA04703480B1022C |
| --- | --- |
| Tasksche.exe | ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA |
- Ransomeware.wannacry.exe:
    
    + This initial executable that runs and checks the kill switch URL
    
    + If alive don’t run else unpack tasksche.exe
    
- Tasksche.exe:
    
    + This is used for persistence.
    
    + It creates a random folder for wannacry staging area inside ProgramData
    
    + After execution on host computer, it tries to spread itself to other windows computer on port 445
    
    + It starts encrypting all the files and after that it displays the ransomeware popup and message.
    
5. BASIC STATIC ANALYSIS
- Strings – Extracted using Floss
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image4.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image4.png)
    
- When open file floss.txt, we have somethings:
    
    + Module is used to open URL
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image5.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image5.png)
    
    + The name of services, Kill Switch URL and random path
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image6.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image6.png)
    
    + The name of services, random path.
    
    + Icacls is used for modifying access controls of the file
    
    (icacls . /grant Everyone:F /T /C /Q is meaning: This is an Icacls command used to grant Full Control permissions to all files and sub-folders within the current folder. The /T switch is used to specify that the command should apply to all sub-folders, while the /Q switch will execute the command without requiring confirmation from the user.)
    
    + attrib +h is used to hide the file attribute
    
    (attrib +h . is meaning: The command attrib +h . is used to set the hidden attribute for the current folder. This means that it will hide the folder from the folder list, unless you set the folder list filter to include hidden folders.)
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image7.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image7.png)
    
- PEView
- IMAGE_SECTION_HEADER.text
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image8.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image8.png)
    
- Import Address Table
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image9.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image9.png)
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image10.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image10.png)
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image11.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image11.png)
    
- PE-Bear
    
    + Basic Information about Executable like kind of machine, checksum, …
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image12.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image12.png)
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image13.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image13.png)
    
- Cutter
- Main function view inside cutter mode
- We can see in 0x00408140 is the kill switch URL
- This assembly code opens an URL on the internet and holds a handle of it. It starts by storing a text string in a variable, mov esi, str.http:__www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com.
- It then calls the InternetOpenA function to open a file on the internet, call dword [InternetOpenA] ; 0x40a134.
- It will return a handle which then can be used for other access requests.
- It can also use this handle to open the URL, call dword [InternetOpenUrlA] ; 0x40a138. The handle will be returned and finally the InternetCloseHandle function is called to close the handle, push esi , mov esi, dword [InternetCloseHandle] ; 0x40a13c.
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image14.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image14.png)
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image15.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image15.png)
    
- Finally is test edi,edi is check the handle returned by the InternetOpenUrlA function
- If url doesnot exists this block gets executed which has a function call
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image16.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image16.png)
    
- Or if url exists, ransomeware is not execute and it exists out of the program
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image17.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image17.png)
    
6. BASIC DYNAMIC ANALYSIS
- Analysis with fakenet turned on (Using wireshark to analysize)
- Network traffic when malware is executed. The requests are unreachable.
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image18.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image18.png)
    
- Wannacry creates tasksche.exe and executes it. Tasksche.exe creates a file with a random name in C:\ProgramData\{random name}. This folder is a staging area for wannacry ransomeware.
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image19.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image19.png)
    
- TCP View
- Tasksche.exe tries to locate and infect computers using port 445 (SMB)
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image20.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image20.png)
    
- C:\ProgramData\{random name} folder which is staging area for wannacry.
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image21.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image21.png)
    
- Procmon process tree
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image22.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image22.png)
    
- Task manager and Service
- Task Manager. Service name is same as the random file name created by tasksche.exe
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image23.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image23.png)
    
- Service. Service name is same as the random file name created by tasksche.exe. This service just invokes the tasksche.exe command on startup.
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image24.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image24.png)
    
- New files added and old files are encrypted.
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image25.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image25.png)
    
- After Infection. New desktop icons and ransom payment popup
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image26.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image26.png)
    
- After Infection. Ransom message
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image27.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image27.png)
    
- X32Dbg
- Set a breakpoint on kill switch URL
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image28.jpeg](WANNACRY%20508423cfe30643349c015ebf0547358a/image28.jpeg)
    
- The kill switch URL was not found therefore the EDI has value 0
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image29.jpeg](WANNACRY%20508423cfe30643349c015ebf0547358a/image29.jpeg)
    
- The zero flag is evaluated to 1 but we change it to 0
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image30.jpeg](WANNACRY%20508423cfe30643349c015ebf0547358a/image30.jpeg)
    
- Changing the zero flag to 0. This makes the program to take the jump call and the malware is not executed.
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image31.jpeg](WANNACRY%20508423cfe30643349c015ebf0547358a/image31.jpeg)
    
7. INDICATORS OF COMPROMISE
- Network Indicators
- Locating other machines and exploiting them using 445 port (SMB)
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image20.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image20.png)
    
- Host-based indicators
- Random folder present inside C:\ProgramData which contains tasksche.exe. This exe is executed on startup.
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image21.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image21.png)
    
- @WanaDecryptor@.exe present on User’s desktop
    
    ![WANNACRY%20508423cfe30643349c015ebf0547358a/image27.png](WANNACRY%20508423cfe30643349c015ebf0547358a/image27.png)
    
8. YARA RULE
    
    (Yara rules are predefined rules that are used to automatically detect and classify malware by using keywords, list of constants, regular expressions, combining conditions, and other operations. These rules can be used to identify malicious code, detect specific behavior, and alert security teams to potential threats.)
    
    Rule Ransomeware_WannaCry {
    
    Meta:
    
    Description: “Wanna Cry Strings”
    
    Strings:
    

> $string1 = "attrib +h ." fullword ascii
> 
> 
> $string2 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
> 
> $string3 = "C:\\%s\\qeriuwjhrf" fullword ascii
> 
> $string4 = "WNcry@2ol7" fullword ascii
> 
> $string5 = "wnry" ascii
> 
> $url = ["www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"](http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/) ascii
> 
> $payload = "tasksche.exe" ascii
> 
> $PE_magic_byte = "MZ"
> 

Conditions:

Any of them

}
