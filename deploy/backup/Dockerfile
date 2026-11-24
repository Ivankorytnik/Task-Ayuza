# Backup tools: pg_dump/pg_restore of the same major version as the database, plus age.
FROM postgres:16
RUN apt-get update \
 && apt-get install -y --no-install-recommends age \
 && rm -rf /var/lib/apt/lists/*
COPY backup.sh restore-check.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/backup.sh /usr/local/bin/restore-check.sh
