FROM postgres:12.3-alpine

# Override postgres entrypoint to log all queries
COPY postgresql.conf /etc/postgresql/postgresql.conf
COPY init.sql /docker-entrypoint-initdb.d/01-init.sql

CMD ["postgres", "-c", "config_file=/etc/postgresql/postgresql.conf"]
