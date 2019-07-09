# /bin/bash

re='^[0-9]+$';

templateHTML='<!doctype html>
	      <html lang="en">
		<head>
			<meta charset="utf-8">
			<title>TEMPLATE</title>
			<meta name="description" content="The HTML5 Herald">
			<meta name="author" content="SitePoint">
			<link rel="stylesheet" href="css/styles.css?v=1.0">
		</head>
		<body>
			<h1>template file </h1>
			<script src="js/scripts.js"></script>
		</body>
	       </html>'

				#check if the parameter is set
			 if [ ! $1 ]; then

			 		echo "Error:You must provide the name of the host"
			 		exit 0

			 fi


			 echo "Do you want to set a proxy for the host?[Y/N]"
			 read proxy;

			 if [ ${proxy^^} =  'Y' ] || [ ${proxy^^} =  'YES' ]; then

				  echo "Provide the port"
				  read port;

					#check if the port is integer
					if ! [[ $port =~ $re ]] ; then

							echo "Error:The port must be an integer"
							exit 0

					fi

			 fi


	checkName() {
                 #gets the matching name of the parameter
                 getName=`ls /etc/nginx/sites-available/ | grep -w "$1.com"`

                 if [ "$getName" = "" ]; then
                     echo 0;
                 else
                     echo 1;
		 fi
         }

        checkPort() {
	#check if the user added an integer port when asked
		 if [ -z ${port+x} ]; then
			echo 1
			 exit;
		fi

                 #get the matching port
                 getPort=$(netstat -vatn | awk '{print $4}' | grep -w "$1");

		#return true if there is another port active
                 if [ "$getPort" = "" ]; then
                      echo 0;
		else
		      echo 1;
                 fi
         }

		if [ $(checkName $1) -eq 1 ]; then

			echo 0;

		else
		#create hostname
		 www=/var/www/$1.com/html #root directory path

		#creating your page root directory
		 sudo mkdir -p $www;

		#check if there is a template html file
		  if [ "`cat /var/www/html/index.html`" = '' ]; then

			echo "Notice:You don't have a template html file.Do you want me to create it?[Y/N]"
			read ans;

			case ${ans^^} in
			'Y'|'YES')
				echo $templateHTML >> $www/index.html
			;;
			N'|'NO')
				echo "k"
			;;
			*)
			echo "Wrong input"
			exit 0;
			;;
			esac

			fi

			if [ "`cat /etc/nginx/sites-available/default`" = '' ]; then

				echo "Warngin:You don't have a template configuration file"

			fi

			available=/etc/nginx/sites-available/$1.com #nginx configuration file path
			enabled=/etc/nginx/sites-enabled #nginx configuration file path



			#adding a dummy html file to your host
			sudo cp /var/www/html/index.html $www/index.html

			#adding a configuration file for your host
			#sudo cp /etc/nginx/sites-available/default $available

			#removind the 'default server' configuration
			sudo sed -i 's/default_server//g' $available

			#adding the root directory path to the nginx configuration file
			sudo sed -i "s/\/var\/www\/html/\/var\/www\/$1.com\/html/1" $available

			#adding the host name to the nginx configuration file
			sudo sed -i "s/server_name _/server_name $1.com www.$1.com/1" $available

			if [ $(checkPort $port) -eq 0 ]; then

				#setting up the proxy for nginx where $1 is the host name and $2 is the port
				sudo sed -i "0,/location \/ {/s//location \/ {\n\t\tproxy_pass http:\/\/www.$1.com:$port\;/" $available

			fi

				#creating link to sites-avaialable configuration file
				sudo ln -s /etc/nginx/sites-available/$1.com $enabled

				#restaring the nginx service
				sudo systemctl restart nginx
		   #/create hostname

		#configuring php

		#check if php fpm is running
		phpFPM="/etc/php/7.1/fpm/php.ini"
		phpCLI="/etc/php/7.1/cli/php.ini"
		phpwwwConf="/etc/php/7.1/fpm/pool.d"

		if [ "`ps aux | grep php-fpm`" = "" ]; then

			sudo apt install software-properties-common -y
			sudo add-apt-repository ppa:ondrej/php -y
			sudo apt install php7.1-fpm php7.1-mcrypt php7.1-curl php7.1-cli php7.1-mysql php7.1-gd php7.1-iconv php7.1-xsl php7.1-json php7.1-intl php-pear php-imagick php7.1-dev php7.1-common php7.1-mbstring php7.1-zip php7.1-soap -y
			#add a timezone
			sudo sed -i "s/;date.timezone/date.timezone = Europe\/Bucharest /1" $phpFPM
			sudo sed -i "s/;cgi.fix_pathinfo=/cgi.fix_pathinfo=0/1" $phpFPM

			sudo sed -i "s/;date.timezone/date.timezone = Europe\/Bucharest /1" $phpCLI
			sudo sed -i "s/;cgi.fix_pathinfo=/cgi.fix_pathinfo=0/1" $phpCLI

			sudo sed -i "s/;env\[HOSTNAME\] \= \$HOSTNAME/env\[HOSTNAME\] \= \$HOSTNAME/1" $phpwwwConf
			sudo sed -i "s/;env\[PATH\] \= \/usr\/local\/bin:\/usr\/bin:\/bin/env\[PATH\] \= \/usr\/local\/bin:\/usr\/bin:\/bin/1" $phpwwwConf
			sudo sed -i "s/;env\[TMP\] \= \/tmp/env\[TMP\] \= \/tmp/1" $phpwwwConf
			sudo sed -i "s/;env\[TMPDIR\] \= \/tmp/env\[TMPDIR\] \= \/tmp/1" $phpwwwConf
			sudo sed -i "s/;env\[TEMP\] \= \/tmp/env\[TEMP\] \= \/tmp/1" $phpwwwConf

				# timeZone="`grep -o ';date.timezone.*' $phpFPM`"
				#
				# if ! [ "$timeZone" = "" ]; then
				#
				# 		sudo sed -i "s/;date.timezone =/date.timezone = Europe\/Bucharest /1" $phpFPM
				#
				# fi

			#/configurin php

			#restarting php
			sudo systemctl restart php7.1-fpm
			sudo systemctl enable php7.1-fpm

		fi

		timeZone="`grep -o ';date.timezone.*' $phpFPM`"

		if ! [ "$timeZone" = "" ]; then

			sudo sed -i "s/;date.timezone =/date.timezone = Europe\/Bucharest /1" $phpFPM

		fi

		#check if mysql is installed if not:
		#possibly to do
		#install mysql


		echo "Please provide the password for mysql:"

		read -s mysqlPasswd

		echo "Provide the name for the database:"

		read dbname

		echo "Provide the name of the user:"

		read user

		echo "Provide the password for the user:"

		read -s userPasswd


		createDb="create database $dbname;"
		createUsr="create user $user@localhost identified by '$userPasswd';
			   grant all privileges on $dbname.* to $user@localhost identified by '$userPasswd';
			   flush privileges;"

		#?insecure find another alternative
		sudo mysql -u root -p$mysqlPasswd -e "$createDb $createUsr"

		#create the subdomain
		perl ./dnsmeapi.pl https://api.dnsmadeeasy.com/V2.0/dns/managed/5841904/records/ -X POST -H accept:application/json -H content-type:application/json -d "{\"name\":\"$1\",\"type\":\"A\",\"value\":\"$2\",\"gtdLocation\":\"DEFAULT\",\"ttl\":86400}"

		#add the ssl certificate
		sudo certbot --nginx -d $1.virtomat.com

		#install unzip & wget
		sudo apt install wget unzip zip -y

		#download nextcloud zip
		sudo wget https://download.nextcloud.com/server/releases/latest.zip -P $www

		#unzip it
		sudo unzip latest.zip -d $www

		#change owner to www-data
		sudo chown -R www-data:www-data $www/nextcloud/

		#delete the zip
		sudo rm $www/latest.zip


		conf="upstream php-handler {
			#server 127.0.0.1:9000;
			server unix:/run/php/php7.1-fpm.sock;
			}
		server {
			listen 80;
			listen [::]:80;
			server_name $1.virtomat.com;
			# enforce https
			return 301 https://\$server_name\$request_uri;
			}
		server {
			listen 443 ssl http2;
			listen [::]:443 ssl http2;
			server_name $1.virtomat.com;

			ssl_certificate /etc/letsencrypt/live/$1.virtomat.com/fullchain.pem;
			ssl_certificate_key /etc/letsencrypt/live/$1.virtomat.com/privkey.pem;

			\# Add headers to serve security related headers
			\# Before enabling Strict-Transport-Security headers please read into this
			\# topic first.
			\# add_header Strict-Transport-Security \"max-age=15552000;
			\# includeSubDomains; preload;\";
			\#
			\# WARNING: Only add the preload option once you read about
			\# the consequences in https://hstspreload.org/. This option
			\# will add the domain to a hardcoded list that is shipped
			\# in all major browsers and getting removed from this list
			\# could take several months.

			add_header X-Content-Type-Options nosniff;
			add_header X-XSS-Protection \"1; mode=block\";
			add_header X-Robots-Tag none;
			add_header X-Download-Options noopen;
			add_header X-Permitted-Cross-Domain-Policies none;

			\# Path to the root of your installation
    			root $www/nextcloud/;

			location = /robots.txt {
				allow all;
				log_not_found off;
				access_log off;
			 }

			\# The following 2 rules are only needed for the user_webfinger app.
			\# Uncomment it if you're planning to use this app.
			\#rewrite ^/.well-known/host-meta /public.php?service=host-meta last;
			\#rewrite ^/.well-known/host-meta.json /public.php?service=host-meta-json
			\# last;

			location = /.well-known/carddav {
				return 301 \$scheme://\$host/remote.php/dav;
				}
			location = /.well-known/caldav {
				return 301 \$scheme://\$host/remote.php/dav;
				}

			# set max upload size
			client_max_body_size 512M;
			fastcgi_buffers 64 4K;

			\# Enable gzip but do not remove ETag headers
			gzip on;
			gzip_vary on;
			gzip_comp_level 4;
			gzip_min_length 256;
			gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
			gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;


			\# Uncomment if your server is built with the ngx_pagespeed module
			\# This module is currently not supported.
			\#pagespeed off;

			location / {
				rewrite ^ /index.php\$uri;
				}

			location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)/ {
				deny all;
				}
			location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console) {
				deny all;
				}


			location ~ ^/(?:index|remote|public|cron|core/ajax/update|status|ocs/v[12]|updater/.+|ocs-provider/.+)\.php(?:\$|/) {
				fastcgi_split_path_info ^(.+\.php)(/.*)\$;
				include fastcgi_params;
				fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
				fastcgi_param PATH_INFO \$fastcgi_path_info;
				fastcgi_param HTTPS on;
				#Avoid sending the security headers twice
				fastcgi_param modHeadersAvailable true;
				fastcgi_param front_controller_active true;
				fastcgi_pass php-handler;
				fastcgi_intercept_errors on;
				fastcgi_request_buffering off;
				}

			location ~ ^/(?:updater|ocs-provider)(?:\$|/) {
				try_files \$uri/ =404;
				index index.php;
				}

			\# Adding the cache control header for js and css files
			# Make sure it is BELOW the PHP block
				location ~ \.(?:css|js|woff|svg|gif)\$ {
																		try_files \$uri /index.php\$uri\$is_args\$args;
																		add_header Cache-Control \"public, max-age=15778463\";
																		\# Add headers to serve security related headers (It is intended to
																		\# have those duplicated to the ones above)
																		\# Before enabling Strict-Transport-Security headers please read into
																		\# this topic first.
																		\# add_header Strict-Transport-Security \"max-age=15768000; includeSubDomains; preload;\";
																		\#
																		\# WARNING: Only add the preload option once you read about
																		\# the consequences in https://hstspreload.org/. This option
																		\# will add the domain to a hardcoded list that is shipped
																		\# in all major browsers and getting removed from this list
																		\# could take several months.
																		add_header X-Content-Type-Options nosniff;
																		add_header X-XSS-Protection \"1; mode=block\";
																		add_header X-Robots-Tag none;
																		add_header X-Download-Options noopen;
																		add_header X-Permitted-Cross-Domain-Policies none;
																		\# Optional: Don't log access to assets
																		access_log off;
																}

																location ~ \.(?:png|html|ttf|ico|jpg|jpeg)\$ {
																		try_files \$uri /index.php\$uri\$is_args\$args;
																		\# Optional: Don't log access to other assets
																		access_log off;
																}
															}

													"
												sudo echo $conf >> $available
												sudo	ln -s /etc/nginx/sites-available/$1.com /etc/nginx/sites-enabled/

												sudo systemctl restart nginx
												sudo systemctl restart php7.1-fpm

								echo 1;
				fi
