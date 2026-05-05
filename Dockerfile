FROM ubuntu:26.04

WORKDIR /app
RUN apt update
RUN apt-get install -y zlib1g-dev openssl build-essential
COPY . .
RUN make
EXPOSE 80 443

CMD ["./build/main.bin", "private", "public"]