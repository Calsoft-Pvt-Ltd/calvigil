FROM ubuntu:latest
USER root
RUN apt-get update
ADD https://example.com/file.tar.gz /tmp/
RUN curl https://example.com/install.sh | bash
EXPOSE 22
