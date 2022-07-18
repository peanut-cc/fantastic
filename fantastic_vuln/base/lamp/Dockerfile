FROM debian:stable-slim

ARG PHP_VERSION=7.2

# need to install php package
ENV PHP_PACKAGE="php${PHP_VERSION} php${PHP_VERSION}-cli php${PHP_VERSION}-fpm php${PHP_VERSION}-common php${PHP_VERSION}-opcache \
	php${PHP_VERSION}-readline php${PHP_VERSION}-curl php${PHP_VERSION}-xml php${PHP_VERSION}-json php${PHP_VERSION}-gd php${PHP_VERSION}-mbstring \
	php${PHP_VERSION}-mysql php-mysql php${PHP_VERSION}-xmlrpc php${PHP_VERSION}-bcmath mime-support libapache2-mod-php${PHP_VERSION}" \
    TOOLS_PACKAGE="python3 python3-pip net-tools wget curl lsb-release apt-transport-https dpkg-dev ca-certificates" \
    APACHE_MYSQL="apache2 default-mysql-server mysql-client mysql-server" \
    PHP_SOCK=/var/run/php${PHP_VERSION}-fpm.sock \
    PHP_CONFIG=/etc/php/${PHP_VERSION}/fpm \
    PHP_INI=/etc/php/${PHP_VERSION}/cli/php.ini \
    PHP_ROOT=/opt/www \
    SUPERVISORCONF=/etc/supervisor/conf.d \
	APACHE=/etc/apache2 \
	APACHE_RUN_DIR=/var/log \
	APACHE_PID_FILE=/var/run/apache.pid \
	APACHE_RUN_USER=nobody \
	APACHE_RUN_GROUP=nogroup \
	APACHE_LOG_DIR=/var/log/apache2


RUN set -x \
    # update apt source
    && sed -E -i 's/(deb|security).debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends ${TOOLS_PACKAGE} \
    && rm -fr /var/cache/apt/archives/* \
    # https://packages.sury.org/php/README.txt
    && curl -sSLo /usr/share/keyrings/deb.sury.org-php.gpg https://packages.sury.org/php/apt.gpg \
    && sh -c 'echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list' \
    && apt-get update \
    && apt-get install -y ${PHP_PACKAGE} \
    #update pip source
    && pip3 config set 'global.index-url' ' https://pypi.tuna.tsinghua.edu.cn/simple' \
    && pip3 config set 'global.trusted-host' 'https://pypi.tuna.tsinghua.edu.cn' \
    && pip3 install supervisor \
    && rm -rf $APACHE/sites-enabled/ \
# copy config
COPY php_config/www.conf $PHP_CONFIG/pool.d
COPY php_config/php-fpm.conf $PHP_CONFIG/
COPY supervisor_config /etc/supervisor/
COPY apache_config/apache2.conf apache_config/ports.conf $APACHE/
COPY apache_config/sites-enabled/php.conf $APACHE/sites-enabled/

ENTRYPOINT [ "/usr/local/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf" ]


