FROM golang:alpine
RUN apk update && apk upgrade
RUN apk add --update xmlsec-dev
RUN apk add --update curl bash vim
RUN curl https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip -o ngrok-stable-linux-amd64.zip
RUN unzip ngrok-stable-linux-amd64.zip
RUN mv ./ngrok /usr/local/bin

RUN mkdir -p /go
WORKDIR /go
