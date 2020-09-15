#! /bin/bash
echo "Hello $USER."
echo "Today is $(date)"
echo "Current working directory : $(pwd)"
echo '**************************************************************************'
echo '                                'Update
echo '**************************************************************************'
# install all the update 
sudo apt-get -y update
sudo apt-get -y upgrade
#Adding log file
sudo touch /var/log/installs
sudo chown root:sudo /var/log/installs
echo -e "Finsh Installing Updates" > /var/log/installs
# adding time zone
timedatectl set-timezone America/Chicago
echo '**************************************************************************'
echo '                        'Implement Firewall Rulls
echo '**************************************************************************'

# add firewall rules
sudo touch /etc/iptables.firewall.rules
sudo chmod 777 /etc/iptables.firewall.rules
sudo cat<<EOF>>/etc/iptables.firewall.rules
*filter

#  Allow all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
-A INPUT -i lo -j ACCEPT
-A INPUT -d 127.0.0.0/8 -j REJECT

#  Accept all established inbound connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#  Allow all outbound traffic - you can modify this to only allow certain traffic
-A OUTPUT -j ACCEPT

#  Allow HTTP and HTTPS connections from anywhere (the normal ports for websites and SSL).
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

#  Allow Application Server connections from anywhere (the normal port for Tomcat).
-A INPUT -p tcp --dport 8080 -j ACCEPT
-A INPUT -p tcp --dport 8443 -j ACCEPT

# all DNS connections from anywhere
-A INPUT -p tcp --dport 53 -j ACCEPT
-A INPUT -p udp --dport 53 -j ACCEPT

#allow LDAP connections from anywhere
-A INPUT -p tcp --dport 389 -j ACCEPT
-A INPUT -p udp --dport 389 -j ACCEPT
-A INPUT -p tcp --dport 636 -j ACCEPT
-A INPUT -p tcp --dport 3268 -j ACCEPT
-A INPUT -p tcp --dport 3269 -j ACCEPT

# allow mysql connections from anywhere
-A INPUT -p tcp --dport 3306 -j ACCEPT
-A INPUT -p udp --dport 3306 -j ACCEPT

#  Allow SSH connections
#  The -dport number should be the same port number you set in sshd_config
-A INPUT -p tcp -m state --state NEW --dport 22 -j ACCEPT

#  Allow ping
-A INPUT -p icmp -j ACCEPT

#  Log iptables denied calls
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

#  Drop all other inbound - default deny unless explicitly allowed policy
-A INPUT -j DROP
-A FORWARD -j DROP

COMMIT
EOF
sudo chmod 644 /etc/iptables.firewall.rules
sudo touch /etc/network/if-pre-up.d/firewall
sudo chmod 777 /etc/network/if-pre-up.d/firewall
sudo iptables-restore < /etc/iptables.firewall.rules
sudo cat<<EOF>>/etc/network/if-pre-up.d/firewall
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.firewall.rules
EOF
sudo chmod 771 /etc/network/if-pre-up.d/firewall
echo -e "Finsh Implentment Firewall rules" >> /var/log/installs
echo '**************************************************************************'
echo '                        ' Install Fail2ban
echo '**************************************************************************'

##install jail program
sudo apt-get -y install fail2ban
#Set max retries and lockout time in configuration file
sudo touch /etc/fail2ban/jail.local
sudo chown root:root /etc/fail2ban/jail.local
sudo chmod 666 /etc/fail2ban/jail.local
sudo cat<<EOF>>/etc/fail2ban/jail.local
maxtry = 5
bantime = 600
EOF

sudo chmod 777 /etc/fail2ban/jail.local
echo -e "Finsh installing Fail2ban" >> /var/log/installs
echo '**************************************************************************'
echo '                        ' Install Mysql
echo '**************************************************************************'
sudo touch /var/log/installs
sudo chown root:sudo /var/log/installs

#install mysql
sudo debconf-set-selections <<< 'mysql-server mysql-server/root_password password Wbyrnygr'
sudo debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password Wbyrnygr'
sudo apt-get -y install mysql-server


if grep -q -F [client] /etc/mysql/my.cnf; then
    echo -e "--\nmy.cnf was NOT changed" >> /var/log/install
else
    echo -e "[client]\nuser = root\npassword = Wbyrnygr" >> /etc/mysql/my.cnf
fi


echo -e "--\nMySQL installed, changed my.cnf" >> /var/log/install
echo ""


#Create database
mysql -e "CREATE database it410_data;" #-u root -p'Wbyrnygr'
#Grant access
mysql -e "GRANT All on it410_data.* to 'xxl13b'@'localhost' identified by 'Wbyrnygr';" #-u root -p'Wbyrnygr'
mysql -e "Grant SELECT on *.* to 'splunkuser@%' identified by 'Wbyrnygr';"
mysql -e "grant all on *.* to 'root'@'%' identified by 'Wbyrnygr';"
mysql -e "FLUSH PRIVILEGES;"
echo -e "Finsh installing Mysql" >> /var/log/installs
echo '**************************************************************************'
echo '                      ' Mysql_Secure_Installation
echo '**************************************************************************'

# mysql_secure_installation
mysql -u root -p'Wbyrnygr' -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('Wbyrnygr');"
mysql -u root -p'Wbyrnygr' -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
mysql -u root -p'Wbyrnygr' -e "DELETE FROM mysql.user WHERE User='';"
mysql -u root -p'Wbyrnygr' -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';"
mysql -u root -p'Wbyrnygr' -e "FLUSH PRIVILEGES;"

#echo  $DATE >> log.text /var/log/installs
echo -e "Finsh Mysql_Secure_Installation" >> /var/log/installs
echo '**************************************************************************'
echo '                             'Openssl
echo '**************************************************************************'

# set correct permission on public key
echo Start making dir
mkdir .ssh
chown -R xxl13b:xxl13b .ssh
chmod 700 .ssh
touch .ssh/authorized_keys
chmod 600 .ssh/authorized_keys

#set "PermitRootLogin no"
sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
echo -e "Finsh Changing OpenSSL" >> /var/log/installs
echo '**************************************************************************'
echo '                          'Install Apache2
echo '**************************************************************************'

sudo apt-get -y install apache2
sudo a2enmod ssl
sudo service apache2 restart
sudo mkdir /etc/apache2/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/apache2/ssl/apache.key -out /etc/apache2/ssl/apache.crt -subj "/C=US/ST=Texas/L=Abilene/O=ACU/CN=150.252.118.199"

#add virtual host 443. Insert file with port 80 info into itself and make appropriate changes for port 443 
#port 80:
sudo chmod 777 -R /etc/apache2/sites-available/000-default.conf
sudo sed -i 's/ServerAdmin.*/ServerAdmin xxl13b@acu.edu/' /etc/apache2/sites-available/000-default.conf
sudo sed -i '/ServerAdmin.*/a \               \ ServerName xxl13b-acu.edu:80' /etc/apache2/sites-available/000-default.conf
sudo sed -i 's@DocumentRoot.*@DocumentRoot /var/www/html@' /etc/apache2/sites-available/000-default.conf

#port 443
sudo chmod 777 -R /etc/apache2/sites-available/default-ssl.conf
sudo sed -i 's/ServerAdmin.*/ServerAdmin xxl13b@acu.edu/' /etc/apache2/sites-available/default-ssl.conf
sudo sed -i '/ServerAdmin.*/a \               \ ServerName xxl13b-acu.edu:443' /etc/apache2/sites-available/default-ssl.conf
sudo sed -i 's@DocumentRoot.*@DocumentRoot /var/www/html@' /etc/apache2/sites-available/default-ssl.conf
sudo sed -i '/SSLEngine.*/a \                 \ SSLCertificateFile /etc/apache2/ssl/apache.crt\n \                 \SSLCertificateKeyFile /etc/apache2/ssl/apache.key' /etc/apache2/sites-available/default-ssl.conf
cd /etc/apache2/sites-available
sudo a2ensite default-ssl.conf
sudo service apache2 reload
cd ~
sudo service apache2 restart
echo -e "Finsh installing Apache2" >> /var/log/installs
echo '**************************************************************************'
echo '                        ' Install Phpmyadmin
echo '**************************************************************************'

#install php, phpmyadmin and mail 
sudo apt-get -y install php php-mysql libapache2-mod-php php-curl php-pear php-db php-ldap php-gd php-xmlrpc mailutils ssmtp php-intl php-soap php-xml php-intl php-zip 

echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
echo "phpmyadmin phpmyadmin/app-password-confirm password Wbyrnygr" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/admin-pass password Wbyrnygr" | debconf-set-selections
echo "phpmyadmin phpmyadmin/mysql/app-pass password Wbyrnygr" | debconf-set-selections
echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2" | debconf-set-selections

sudo apt-get -y install phpmyadmin

sudo cp /etc/phpmyadmin/apache.conf /etc/apache2/conf.d
sudo service apache2 restart
sudo service mysql restart
echo -e "Finsh installing Phpmyadmin" >> /var/log/installs
echo '**************************************************************************'
echo '                        ' Install Maldecter
echo '**************************************************************************'

#install maldecter
sudo wget https://www.rfxn.com/downloads/maldetect-current.tar.gz
tar xfz maldetect-current.tar.gz
cd maldetect-*
./install.sh
#sudo service ssh restart
echo '**************************************************************************'
echo '                        ' Install Wordpress
echo '**************************************************************************'

#download world press
cd ~
sudo wget http://wordpress.org/latest.tar.gz
sudo tar -xzvf latest.tar.gz 

#create database and user
mysql -e "CREATE DATABASE wordpress;" -u root -p'Wbyrnygr'
mysql -e "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,CREATE TEMPORARY TABLES,DROP,INDEX,ALTER ON wordpress.* TO 'wordpressuser'@'localhost' IDENTIFIED BY 'Wbyrnygr';" -u root -p'Wbyrnygr'
mysql -e "flush privileges;" -u root -p'Wbyrnygr'

#setip wordpress configuration
sudo cp ~/wordpress/wp-config-sample.php ~/wordpress/wp-config.php
#change mode from read only 
sudo chmod 777 -R ~/wordpress/wp-config.php 

#change configuration
# vi ~/wordpress/wp-config.php 
#// ** MySQL settings - You can get this info from your web host ** //
#/** The name of the database for WordPress */
#define('DB_NAME', 'wordpress');
sudo sed -i "s@define('DB_NAME', 'database_name_here');@define('DB_NAME', 'wordpress');@" ~/wordpress/wp-config.php
#/** MySQL database username */
#define('DB_USER', 'wordpressuser');
sudo sed -i "s@define('DB_USER', 'username_here');@define('DB_USER', 'wordpressuser');@" ~/wordpress/wp-config.php
#/** MySQL database password */
#define('DB_PASSWORD', 'password');
sudo sed -i "s@define('DB_PASSWORD', 'password_here');@define('DB_PASSWORD', 'Wbyrnygr');@" ~/wordpress/wp-config.php
sudo rsync -avP ~/wordpress/ /var/www/html
sudo chown xxl13b:www-data /var/www/html -R 
sudo chmod g+w /var/www/html -R 
curl --data-urlencode "weblog_title=Security blog" \
     --data-urlencode "user_name=xxl13b" \
     --data-urlencode "admin_password=Wbyrnygr" \
     --data-urlencode "admin_password2=Wbyrnygr" \
     --data-urlencode "admin_email=xxl13b@acu.edu" \
     --data-urlencode "Submit=Install+WordPress" \
     http://150.252.118.199/wp-admin/install.php?step=2
echo -e "Finsh installing WP" >> /var/log/installs
echo '**************************************************************************'
echo '                        ' Install SugarCRM
echo '**************************************************************************'

#install unzip
sudo apt-get -y install unzip
#install surgar CRM
sudo mkdir /var/www/html/sugarcrm
cd /tmp
sudo wget http://sourceforge.net/projects/sugarcrm/files/latest/download -O SugarCE-6.5.20.zip
sudo unzip /tmp/SugarCE-6.5.20.zip
sudo mv SugarCE-Full-6.5.25/ /var/www/html/sugarcrm
sudo chmod 777 -R /var/www/html/sugarcrm
#create database
mysql -e "CREATE DATABASE sugarcrm;" -u root -p'Wbyrnygr'
mysql -e "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,CREATE TEMPORARY TABLES,DROP,INDEX,ALTER ON sugarcrm.* TO 'sugaruser'@'localhost' IDENTIFIED BY 'Wbyrnygr';" -u root -p'Wbyrnygr'
mysql -e "flush privileges;" -u root -p'Wbyrnygr'
cd /etc/php/7.0/apache2/
sudo chmod 777 -R php.ini
sudo sed -i 's/upload_max_filesize.*/upload_max_filesize= 10M/' /etc/php/7.0/apache2/php.ini
sudo /etc/init.d/apache2 restart
cd /var/www/html
sudo touch /var/www/html/.htaccess
sudo chmod 777 /var/www/html/.htaccess
sudo cat<<EOF>>/var/www/html/.htaccess

# BEGIN SUGARCRM RESTRICTIONS
RedirectMatch 403 (?i).*\.log$
RedirectMatch 403 (?i)/+not_imported_.*\.txt
RedirectMatch 403 (?i)/+(soap|cache|xtemplate|data|examples|include|log4php|metadata|modules)/+.*\.(php|tpl)
RedirectMatch 403 (?i)/+emailmandelivery\.php
RedirectMatch 403 (?i)/+upload
RedirectMatch 403 (?i)/+custom/+blowfish
RedirectMatch 403 (?i)/+cache/+diagnostic
RedirectMatch 403 (?i)/+files\.md5$
# END SUGARCRM RESTRICTIONS
EOF
sudo chmod 644 /var/www/html/.htaccess
echo -e "Finsh installing SugarCRM" >> /var/log/installs
echo '**************************************************************************'
echo '                        ' Install Moodle
echo '**************************************************************************'
#create new directory for moodle in 
cd /var/www/html
sudo apt-get -qq install git-core
#pull code GIT repository 
sudo git clone git://git.moodle.org/moodle.git   

#"login" as moodle admin 
cd moodle

#lists all available branches 
git branch -a                                                   

#create a new local branch called MOODLE_32_STABLE
sudo git branch --track MOODLE_32_STABLE origin/MOODLE_32_STABLE     

#switches to the newly created local branch 
sudo git checkout MOODLE_32_STABLE                                  

#Secure Moodle Files 
sudo chown -R root /var/www/html/moodle
sudo chmod -R 0755 /var/www/html/moodle 
#sudo find /path/to/moodle -type f -exec chmod 0644 {} \;


#make directory and change permissions
sudo mkdir /home/moodledata
sudo chmod 777 -R /home/moodledata

sudo chown www-data /var/www/html/moodle

cd ~

# Finish Moodle automaticlly 
sudo -u www-data /usr/bin/php /var/www/html/moodle/admin/cli/install.php --non-interactive --agree-license --chmod='777' --lang='en' --wwwroot='http://150.252.118.199/moodle' --dataroot='/home/moodledata' --dbtype='mysqli' --dbhost='localhost' --dbname='moodle' --dbuser='moodleuser' --dbpass='Wbyrnygr' --adminuser='admin' --adminpass='Wbyrnygr' --adminemail='xxl13b@acu.edu' --fullname='moodle' --shortname='moodle'


#create database for Moodle

mysql -e "CREATE DATABASE moodle DEFAULT CHARACTER SET UTF8 COLLATE utf8_unicode_ci;" -u root -p'Wbyrnygr'
mysql -e "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,CREATE TEMPORARY TABLES,DROP,INDEX,ALTER ON moodle.* TO 'moodleuser'@'%' IDENTIFIED BY 'Wbyrnygr';" -u root -p'Wbyrnygr'
mysql -e "flush privileges;" -u root -p'Wbyrnygr'

#Adding Cronjob

(crontab -l 2>/dev/null; echo "*/15 * * * * /usr/bin/php /var/www/html/moodle/admin/cli/cron.php") | crontab -

#web Address -> http://150.252.118.199/moodle
#Full Site Name -> http://150.252.118.199/moodle 
#Short Name For Site -> http://150.252.118.199/moodle 
#Admin account Username ->admin
#Admin User Email Address -> xxl13b@acu.edu
echo -e "Finsh installing Moodle" >> /var/log/installs
echo '**************************************************************************'
echo '                        ' Install Joomla
echo '**************************************************************************'
# Install add-on
sudo apt-get -y install php-mysql php-curl php-json php-cgi php libapache2-mod-php php-mcrypt
# Create a database for Joomla
mysql -e "CREATE DATABASE joomla;"
mysql -e "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,CREATE TEMPORARY TABLES,DROP,INDEX,ALTER ON joomla.* TO 'juser'@'localhost' IDENTIFIED BY 'Wbyrnygr';"
mysql -e "flush privileges;"

#Install Joomla
cd /var/www/html
sudo wget https://github.com/joomla/joomla-cms/releases/download/3.7.0-rc4/Joomla_3.7.0-rc4-Release_Candidate-Full_Package.zip
mkdir -p /var/www/html/joomla
sudo unzip -q Joomla_3.7.0-rc4-Release_Candidate-Full_Package.zip -d /var/www/html/joomla
sudo chown -R www-data.www-data /var/www/html
sudo chmod -R 755 /var/www/html
# Restart Service
sudo service apache2 restart
sudo service mysql restart

# Adding Config file for Joomla 
sudo a2enmod rewrite 
sudo touch /etc/apache2/sites-available/joomla.conf
sudo ln -s /etc/apache2/sites-available/joomla.conf /etc/apache2/sites-enabled/joomla.conf

sudo cat <<EOF>> /etc/apache2/sites-available/joomla.conf
<VirtualHost *:80>
ServerAdmin xxl13b@acu.edu
DocumentRoot /var/www/html/
ServerName 69.28.90.132
ServerAlias it410-xxl13b
<Directory /var/www/html/>
Options FollowSymLinks
AllowOverride All
Order allow,deny
allow from all
</Directory>
ErrorLog /var/log/apache2/69.28.90.132-error_log
CustomLog /var/log/apache2/69.28.90.132-access_log common
</VirtualHost>
EOF
systemctl restart apache2.service




echo -e "Finsh installing Joomla" >> /var/log/installs



echo '**************************************************************************'
echo '                        ' Install Tomcat
echo '**************************************************************************'
#install Java
sudo apt-get -y install default-jdk
# Create Tomcat User
sudo groupadd tomcat
sudo useradd -s /bin/false -g tomcat -d /opt/tomcat tomcat
# Download Tomcat
sudo wget wget http://mirror.its.dal.ca/apache/tomcat/tomcat-9/v9.0.0.M20/bin/apache-tomcat-9.0.0.M20.tar.gz

sudo tar -xzvf apache-tomcat-9.0.0.M20.tar.gz
sudo mv apache-tomcat-9.0.0.M20/ /opt/tomcat
sudo chgrp -R tomcat /opt/tomcat
sudo chown -R tomcat /opt/tomcat
sudo chmod -R 755 /opt/tomcat
# Create systemd service file
sudo touch /etc/systemd/system/tomcat.service
sudo chmod -R 777 /etc/systemd/system/tomcat.service
sudo cat <<EOF>> /etc/systemd/system/tomcat.service
[Unit]
Description=Apache Tomcat Web Server
After=network.target

[Service]
Type=forking

Environment=JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre
Environment=CATALINA_PID=/opt/tomcat/temp/tomcat.pid
Environment=CATALINA_HOME=/opt/tomcat/
Environment=CATALINA_BASE=/opt/tomcat/
Environment='CATALINA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC'
Environment='JAVA_OPTS=-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom'

ExecStart=/opt/tomcat/bin/startup.sh
ExecStop=/opt/tomcat/bin/shutdown.sh

User=tomcat
Group=tomcat
UMask=0007
RestartSec=15
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl start tomcat
sudo systemctl enable tomcat
sudo ufw allow 8080

sudo chmod -R 777 /opt/tomcat/conf/tomcat-users.xml

#Add a user who can access the manager-gui and admin-gui

sudo sed -i '44i  <role rolename="manager-gui"/>' /opt/tomcat/conf/tomcat-users.xml
sudo sed -i '45i  <role rolename="admin-gui"/>' /opt/tomcat/conf/tomcat-users.xml
sudo sed -i '46i  <user username="admin" password="Wbyrnygr" roles="manager-gui,admin-gui"/>' /opt/tomcat/conf/tomcat-users.xml

sudo chmod -R 777 /opt/tomcat/webapps/manager/META-INF/context.xml
sudo sed -i '19i  <!--' /opt/tomcat/webapps/manager/META-INF/context.xml
sudo sed -i '22i  -->' /opt/tomcat/webapps/manager/META-INF/context.xml


sudo chmod -R 777 /opt/tomcat/webapps/host-manager/META-INF/context.xml
sudo sed -i '19i  <!--' /opt/tomcat/webapps/host-manager/META-INF/context.xml
sudo sed -i '22i  -->' /opt/tomcat/webapps/host-manager/META-INF/context.xml

sudo systemctl restart tomcat
echo -e "Finsh installing Tomcat" >> /var/log/installs
echo '**************************************************************************'
echo '                        ' Install ldap
echo '**************************************************************************'
echo -e " \
slapd slapd/internal/generated_adminpw password Wbyrnygr
slapd slapd/password2 password Wbyrnygr
slapd slapd/internal/adminpw password Wbyrnygr
slapd slapd/password1 password Wbyrnygr
" | sudo debconf-set-selections
sudo apt-get -y install slapd ldap-utils

#sudo dpkg-reconfigure slapd

#Omit OpenLDAP server configuration? No
#DNS domain name? it410-xxl13b
#Administrator password? Wbyrnygr
#Database backend to use? HDB
#Remove the database when slapd is purged? No
#Move old database? Yes

#install phpldapadmin
sudo apt-get -y install phpldapadmin
sudo chmod -R 777 /etc/phpldapadmin/
# Change Configuration
sed -i "s/$servers->setValue('server','host','127.0.0.1');/$servers->setValue('server','host','150.252.118.199');/" /etc/phpldapadmin/config.php

sed -i "s/$servers->setValue('server','base',array('dc=example,dc=com'));/$servers->setValue('server','base',array('dc=acu,dc=local'));/" /etc/phpldapadmin/config.php


sed -i "s/$servers->setValue('login','bind_id','cn=admin,dc=example,dc=com');/$servers->setValue('login','bind_id','cn=admin,dc=acu,dc=local');/" /etc/phpldapadmin/config.php

# PROBLEM
sudo sed -i "161i \$config->custom->appearance['hide_template_warning'] = true;" /etc/phpldapadmin/config.php

echo -e "Finsh installing ldap" >> /var/log/installs








sudo chmod -R 777 /etc/mysql
sudo sed -i "s/bind-address.*/bind-address            = 0.0.0.0/" /etc/mysql/mysql.conf.d/mysqld.cnf 



