FROM alpine:latest
ADD out/gobis-server_linux_386 /usr/bin/gobis-server
RUN chmod +x /usr/bin/gobis-server

ENV PORT 8080

EXPOSE 8080

RUN mkdir /config

CMD gobis-server --log-json -c /config/gobis-config.yml