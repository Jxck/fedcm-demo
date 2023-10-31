FROM node:20-alpine3.17

WORKDIR /workspace

RUN apk update && \
    apk upgrade && \
    apk add --no-cache make gcc g++ python3
COPY package*.json ./
RUN npm install
COPY . .

CMD [ "npm", "start" ]