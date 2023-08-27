FROM node:lts-buster

ENV GO_VERSION_FILE go1.21.0.linux-arm64.tar.gz

WORKDIR /var/app

RUN apt update -y
RUN apt install -y build-essential cmake

RUN wget https://go.dev/dl/${GO_VERSION_FILE} && \
    tar -C /usr/local -xzf ${GO_VERSION_FILE}

ENV PATH=$PATH:/usr/local/go/bin
COPY . .
RUN npm install


CMD ["npm", "run", "start"]
