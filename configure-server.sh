#!/bin/bash

if [$1 == ""] then;
  echo "No input specified, please parse a domain, for example:

  configure-server.sh example.com
  "
  exit
fi


if (($EUID != 0)); then
  if [[ -t 1 ]]; then
    echo "
    Terribly sorry but in order to install nginx and letsencrypt and also make changes to /var/www, /etc/nginx, and /etc/letsencrypt we need sudo. If you're not comfortable with this please feel free to read the contents of this script, in fact you really should have already, just saying, I mean we could be scp copying the root of your system to some external server for all you know, we're not, but we could be. Always read the contents of scripts from unknown sources, especially if they ask for sudo like we are.
    "
    sudo "$0" "$@"
  else
    exec 1>output_file
    gksu "$0 $@"
  fi
  exit
fi


echo "
Before we can get started we're going to need a few things, namely nginx letsencrypt and ufw.
"
apt-get install nginx letsencrypt ufw


## Setup nginx config after backing up an existing file if it exists.
if [ -e /etc/nginx/sites-available/$1 ]; then
  echo "
  Backing up existing nginx config like a boss.
  "
  mv /etc/nginx/sites-available/$1 /etc/nginx/sites-available/$1.bak
fi

## Make sure we have a directory for our letencrypt validation stuff to go in.
mkdir /var/www/$1

## Write a temporary nginx config just for let's encrypt.
echo "
Writing temporary nginx config file for Let's Encrypt Setup $1
"
echo "
server {
        listen 80;
        listen [::]:80;

        root /var/www/$1;

        server_name $1 www.$1;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files $uri $uri/ =404;
        }

        location ~ /.well-known {
                allow all;
        }
}
" > $1

nginx -t



if [ ! -e /etc/nginx/sites-enabled/$1 ]; then
  echo "
  Enabled this site is!
  "
  ln -s /etc/nginx/sites-available/$1 /etc/nginx/sites-enabled/$1
else
  echo "
  Check the backup config, you should! Already enabled this site was!
  "
fi

echo "
Restarting nginx with the new configuration for letsencrypt.
"
service nginx restart

## Setup let's encrypt certs
echo "
We're now going to setup the letsencrypt certs, if this is the first time letsencrypt has been run on this machine it will prompt you for some input please be sure to fill out your details correctly as they will be needed should you ever need to recover or revoke ssl certs as part of damage mitigation.
"

letsencrypt certonly -a webroot --webroot-path=/var/www/$1 -d $1 -d $1

echo "
Should you need to backup your ssl certs for this site, or access them for any other reasons, they are located under /etc/letsencrypt/live/$1 You should see the files listed below.
"
ls -l /etc/letsencrypt/live/$1

mkdir /etc/nginx/snippets
echo "
Creating site specific ssl config file for easy inclusion in main configuration file. If you would like to edit any of the following config files manually they are located under /etc/nginx/snippets/
"
echo "
ssl_certificate /etc/letsencrypt/live/$1/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/$1/privkey.pem;
" > /etc/nginx/snippets/ssl-$1.conf


if [ ! -e /etc/ssl/certs/dhparam.pem ]; then
  echo "
  We are now going to generate a strong Diffie-Hellman group to strengthen the ssl encryption, this will take some time depending on your systems configuration.
  "
  openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
fi
if [ ! -e /etc/nginx/snippets/ssl-params.conf ]; then
  echo "
  We're also creating a config file for the Diffie-Hellman group, this is reusable so you won't see messages relating to Diffie-Hellman the next time you create a site on this server. Please note that there is a HSTS option that you may wish to configure in this file, ssl-params.conf
  "
  echo "
  # from https://cipherli.st/
  # and https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html

  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ssl_prefer_server_ciphers on;
  ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
  ssl_ecdh_curve secp384r1;
  ssl_session_cache shared:SSL:10m;
  ssl_session_tickets off;
  ssl_stapling on;
  ssl_stapling_verify on;
  resolver 8.8.8.8 8.8.4.4 valid=300s;
  resolver_timeout 5s;
  # Disable preloading HSTS for now.  You can use the commented out header line that includes
  # the \"preload\" directive if you understand the implications.
  #add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
  add_header Strict-Transport-Security "max-age=63072000; includeSubdomains";
  add_header X-Frame-Options DENY;
  add_header X-Content-Type-Options nosniff;

  ssl_dhparam /etc/ssl/certs/dhparam.pem;
  " > /etc/nginx/snippets/ssl-params.conf
fi


## Setup final nginx config 

echo "
Writing final nginx config file, this includes a redirect from http to https and configuration of the .well-known/ directory for the letsencrypt's automated renewal service which we'll setup in a minute and a proxy for forwarding traffic to a node.js instance running on a non-standard port.
"
echo "
server {
    listen 80;
    listen [::]:80;
    server_name $1 www.$1;
    return 301 https://\$server_name\$request_uri;
}


server {

        # SSL configuration

        listen 443 ssl http2;
        listen [::]:443 ssl http2;

        include snippets/ssl-$1.conf;
        include snippets/ssl-params.conf;

        server_name $1 www.$1;

        location / {
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                proxy_set_header X-NginX-Proxy true;
                proxy_pass http://127.0.0.1:7890/;
                proxy_http_version 1.1;
                proxy_set_header Upgrade \$http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host \$host;
                proxy_cache_bypass \$http_upgrade;
        }

        location ~ /.well-known {
                root /var/www/$1;
                allow all;
        }


}
" > $1

service nginx restart

echo "
Would you like to do a first time setup of UFW? [y/n]"
read prompt
if [prompt == 'y']; then

  echo "
  Setting UFW rules to allow for inbound nginx traffic, we're also making sure that OpenSSH is allowed to ensure we don't lock you out of your server because 'Awkward that would be mrrrh?'
  "
  ufw default deny incoming
  ufw default allow outgoing
  ufw delete allow 'Nginx HTTP'
  ufw delete allow 'Nginx HTTPS'
  ufw allow 'Nginx Full'
  ufw allow ssh
  ufw enable

else
  
  ufw allow 'Nginx Full'
  ufw allow ssh
  ufw enable

fi

sudo ufw status

echo "UFW is now enabled. If you need to configure it further, although we do recommend routing all incoming traffic through nginx, there's a comprehensive guide on UFW available here. https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-with-ufw-on-ubuntu-14-04"
echo ""
echo "Now is a good time to acknowledge the good folks over at Digital Ocean for their fantastic guides, the vast majority of the configs used in this script were provided by their guides. If you'd like to read more excellent guides on server configs head over to https://www.digitalocean.com/community/"
echo ""
echo "There's one last thing to be done before you can go tinker with your newely setup server and that is make sure that you have a crontab setup to automatically renew the letsencrypt certs for you as they expire every 90 days. Unfortunately we can't just do this bit for you so if this is your first time running this script you'll want to copy the below output before making a selection at the prompt that appears after it.

Note: we also recommend selecting nano as your editor.

## Let's Encrypt auto renewal cron service.
30 2 * * 1 /usr/bin/letsencrypt renew >> /var/log/le-renew.log
35 2 * * 1 /bin/systemctl reload nginx
## End Let's Encrypt cron service

"
crontab -e

echo "Congratulations your new webserver for $1 has been configured.

May the coffee be with you!
Exiting"
