
FROM node
COPY . /app
WORKDIR /app

RUN npm i
EXPOSE 4000
CMD ["node" ,"index.js"]