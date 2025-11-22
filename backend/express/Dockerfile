FROM node:20-alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY index.js ./
RUN mkdir -p logs
EXPOSE 3000
CMD ["node", "index.js"]
