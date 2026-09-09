FROM php:8.3-apache

# pdo_mysql is not compiled into the official PHP images. docker-php-ext-install
# is a helper script specific to those images, not a general PHP tool.
RUN docker-php-ext-install pdo_mysql

# SECURITY-RELEVANT: when Docker first populates a named volume it copies the
# image directory's ownership and mode along with its contents. Creating this
# directory as www-data here is what lets the Apache workers append to app.log
# without the container running as root.
RUN mkdir -p /var/log/app && chown www-data:www-data /var/log/app

COPY src/   /var/www/html/
# specs/ lives OUTSIDE the document root. That is what makes download.php the
# only route to those files, and therefore what makes the traversal meaningful.
COPY specs/ /var/www/specs/
RUN chown -R www-data:www-data /var/www/html /var/www/specs

# Errors rendered into the page are normally a vulnerability (CWE-209). Left on
# deliberately so injection and traversal failures are visible during a demo.
RUN printf "display_errors=On\nlog_errors=On\nerror_reporting=E_ALL\n" \
    > /usr/local/etc/php/conf.d/lab.ini
