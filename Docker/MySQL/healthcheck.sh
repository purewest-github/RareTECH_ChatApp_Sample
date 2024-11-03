#!/bin/bash
set -eo pipefail

if [ "$MYSQL_USER" ] && [ "$MYSQL_PASSWORD" ]; then
    mysql_user="$MYSQL_USER"
    mysql_password="$MYSQL_PASSWORD"
else
    mysql_user="root"
    mysql_password="$MYSQL_ROOT_PASSWORD"
fi

if mysqladmin ping -h "localhost" -u "$mysql_user" --password="$mysql_password" --silent; then
    exit 0
fi

exit 1