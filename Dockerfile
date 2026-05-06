FROM ubuntu:26.04

WORKDIR /app
RUN apt update
RUN apt-get install -y zlib1g-dev libssl-dev build-essential
COPY . .
RUN mkdir -p build
RUN make
EXPOSE 80 443

CMD ["./build/main.bin", "private", "public"]
