#!/bin/bash

output() {
    printf "\E[0;33;40m"
    echo $1
    printf "\E[0m"
}

displayErr() {
    echo
    echo $1;
    echo
    exit 1;
}

cd ~

output " "
output "Read the description! enter the valid data are needed"
output " "

read -e -p "Enter time zone (See your variant https://en.wikipedia.org/wiki/List_of_tz_database_time_zones e.g. America/New_York) : " TIME
var1=1
while [ $var1 -gt 0 ]
do
read -e -p "Your domain name that you bought (no http:// Example: t40xrniei8.mn.hydnoracoin.com) : " server_name
label=`curl -s "https://mn.hydnoracoin.com/api/v2/script?action=node_url&value=${server_name}"`
if [ $label = "true" ]
then
break
fi
output " "
output "Error: Invalid Domain"
output " "
done

var1=1
while [ $var1 -gt 0 ]
do
read -e -p "Enter your username (which you registered on the site https://mn.hydnoracoin.com) : " USERNAME
label=`curl -s "https://mn.hydnoracoin.com/api/v2/script?action=user&value=${USERNAME}"`
if [ $label = "true" ]
then
break
fi
output " "
output "Error: Invalid USERNAME"
output " "
done

var1=1
while [ $var1 -gt 0 ]
do
read -e -p "Enter your e-mail (which you registered on the site https://mn.hydnoracoin.com) : " EMAIL
label=`curl -s "https://mn.hydnoracoin.com/api/v2/script?action=email&value=${EMAIL}"`
if [ $label = "true" ]
then
break
fi
output " "
output "Error: Invalid E-MAIL"
output " "
done

output " "
output "Updating system and installing required packages."
output " "
sleep 3

    coin="horanode"
    git_hub="https://github.com/hydnoracoin/hora_geth.git"
    script_dir="masternode_install_scrypt_ubuntu18.10"

# update package and upgrade Ubuntu
    export DEBIAN_FRONTEND="noninteractive"
    sudo apt-get -y update 
    sudo apt-get -y upgrade
    sudo apt-get -y autoremove
    
    output " "
    output "Switching to Aptitude"
    output " "
    sleep 3
    
    sudo apt-get -y install aptitude
    
    output " "
    output "Installing Nginx server."
    output " "
    sleep 3
    
    sudo aptitude -y install nginx
    sudo systemctl start nginx.service
    sudo systemctl enable nginx.service
    sudo systemctl start cron.service
    sudo systemctl enable cron.service
	sudo aptitude -y install pwgen

    
    output " "
    output "Installing Go and other needed files."
    output " "
    sleep 3
    
    
    # create random password
    rootpasswd=$(pwgen 6 1)
    encryptpasswd=$(openssl passwd ${rootpasswd})
    sudo aptitude -y install software-properties-common
    sudo aptitude -y install git
    sudo aptitude -y install build-essential
    sudo aptitude -y install libgmp3-dev
    sudo aptitude -y install golang
    sudo aptitude -y install screen
    sudo aptitude -y install mc
    sudo aptitude -y install htop
    sudo aptitude -y install nano

    wget https://dl.google.com/go/go1.12.1.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.12.1.linux-amd64.tar.gz
    export GOROOT=/usr/local/go
    export PATH=$GOROOT/bin:$PATH
    export GOPATH=$HOME/go

    output " "
    output "Installing Geth"
    output " "
    sleep 3

if [[ ! -e $coin ]]; then
        sudo  git clone $git_hub $coin
        cd $coin
        sudo chmod 0755 build/env.sh
        output " "
        output "Make Hora Masternode"
        output " "
        sleep 3
        sudo make geth
        sudo cp build/bin/geth /usr/bin
        cd ~
elif [[ ! -d $coin ]]; then
    output "horanode already exists.... Skipping" 1>&2
fi

if [[ ! -e '.mnhora' ]]; then
        mkdir .mnhora
        output " "
        output "init Hora Masternode"
        output " "
        sleep 3
        wget https://github.com/hydnoracoin/progminer/releases/download/v1.1.3/genesis.json
        geth --datadir /home/hora/.mnhora init genesis.json
        rm genesis.json
        cd ~
elif [[ ! -d '.mnhora' ]]; then
    output ".mnhora already exists.... Skipping" 1>&2
fi

    output " "
    output "Install UFW"
    output " "
    sudo apt-get install ufw
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    sudo ufw allow http
    sudo ufw allow https
	sudo ufw allow 19799
    sudo ufw --force enable
    
    


    output " "
    output "Update default timezone."
    output " "
    
    # check if link file
    sudo [ -L /etc/localtime ] &&  sudo unlink /etc/localtime
    
    # update time zone
    sudo ln -sf /usr/share/zoneinfo/$TIME /etc/localtime
    sudo aptitude -y install ntpdate
    
    # write time to clock.
    sudo hwclock -w
    
    
    
    output " "
    output "Install LetsEncrypt and setting SSL"
    output " "
    
    sudo systemctl stop nginx.service
    sudo add-apt-repository -y universe
    sudo add-apt-repository -y ppa:certbot/certbot
    sudo apt-get update
    sudo aptitude -y install certbot python-certbot-nginx
    sudo certbot certonly --standalone -m "$EMAIL" --agree-tos -d "$server_name"
    sudo rm /etc/nginx/sites-enabled/default
    sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    # I am SSL Man!
    echo 'server {
    if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
	listen 443 ssl http2;
	listen [::]:443 ssl http2;

	server_name '"${server_name}"';

    access_log /var/log/nginx/'"${server_name}"'.app-access.log;
    error_log  /var/log/nginx/'"${server_name}"'.app-error.log;

	# strengthen ssl security
    ssl_certificate /etc/letsencrypt/live/'"${server_name}"'/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/'"${server_name}"'/privkey.pem;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
    ssl_dhparam /etc/ssl/certs/dhparam.pem;

    location ~ \.php$ {
        return 404;
        }
	location ~ \.sh {
		return 404;
        }
    location ~ /\.ht {
            deny all;
        }

	location /geth/hora {
		auth_basic "Protected Hydnora client";
		auth_basic_user_file /etc/nginx/pma_pass;
		proxy_pass http://localhost:8504/;
		proxy_read_timeout  90;
		proxy_set_header Connection "";
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_pass_header X-Transmission-Session-Id;
	}
	# Add headers to serve security related headers
    add_header Strict-Transport-Security "max-age=15768000; preload;";
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Robots-Tag none;
    add_header Content-Security-Policy "frame-ancestors 'self'";

	# gzip
	gzip on;
	gzip_vary on;
	gzip_proxied any;
	gzip_comp_level 6;
	gzip_types text/plain text/css text/xml application/json application/javascript application/xml+rss application/atom+xml image/svg+xml;
}

# HTTP redirect
server {
	listen 80;
	listen [::]:80;


	server_name '"${server_name}"';

	location / {
		return 301 https://'"${server_name}"'$request_uri;
	}
}
' | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1

echo ''"$USERNAME"':'"$encryptpasswd"'
' | sudo -E tee /etc/nginx/pma_pass >/dev/null 2>&1
    sudo chmod 0644 /etc/nginx/pma_pass

echo '
Please enter this data when creating the masternode:

Username: '"${USERNAME}"'
Password: '"${rootpasswd}"'

Command for node:
Node start:                sudo systemctl start geth
Node stop:                 sudo systemctl stop geth
Node restart:              sudo systemctl restart geth
See statistic:             sudo journalctl -f -u geth

' | sudo -E tee ~/$script_dir/login.txt >/dev/null 2>&1
    sudo chmod 0400 ~/$script_dir/login.txt
    sudo ln -s /etc/nginx/sites-available/$server_name.conf /etc/nginx/sites-enabled/$server_name.conf
    sudo systemctl start nginx.service
	
    
    output " "
    output "Create Masternode Service"
    output " "
    sleep 3
    

echo '
[Unit]
Description=Hydnoracoin MasterNode
After=network-online.target
Wants=network-online.target
[Service]
WorkingDirectory=/root
User=root
ExecStart=/usr/bin/geth --gcmode archive --syncmode full --datadir /home/hora/.mnhora  --rpc --rpcaddr "127.0.0.1" --rpcvhosts=* --rpcport "8504" --networkid 19783111 --port "19799" --rpcapi "admin,db,eth,miner,net,txpool,personal,web3,debug" --ethstats "'"${USERNAME}"'_'"${server_name::5}"':mnhora@nodes.hydnora.org:3000"
Restart=always
RestartSec=5s
[Install]
WantedBy=multi-user.target
' | sudo -E tee /lib/systemd/system/geth.service >/dev/null 2>&1
    output " "
    output "Start Masternode Server"
    output " "
    sleep 3
    sudo systemctl enable geth
    sudo systemctl start geth

output " "
output " "
output " "
output " "
output "Installation was successful. Your username: '"${USERNAME}"' and password: '"${rootpasswd}"' to start the masternode, "
output "There is also a file in this folder login.txt  Watch it with the command: sudo nano login.txt"
output "Enter this data on the site https://mn.hydnoracoin.com when creating masternode"
output "Wait until the node is fully synchronized. The work of the masternode can be viewed using the command: sudo journalctl -f -u geth "
output " "
output "Command for node:"
output " "
output "Node start:"
output "                sudo systemctl start geth"
output "Node stop:"
output "                sudo systemctl stop geth"
output "Node restart:"
output "                sudo systemctl restart geth"
output "See statistic:"
output "                sudo journalctl -f -u geth"
output " "
output " "
