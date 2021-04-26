FROM ubuntu:20.04 
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -qy dist-upgrade && apt-get -qy install git golang libbpfcc-dev clang make gcc-multilib
RUN go get github.com/dropbox/goebpf
COPY . /upf-xdp
WORKDIR /upf-xdp
RUN make
WORKDIR /upf-xdp/build
ENTRYPOINT ["/upf-xdp/build/main"]