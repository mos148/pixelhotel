FROM node:20-slim
RUN apt-get update && apt-get install -y build-essential libcairo2-dev libpango1.0-dev libjpeg-dev libgif-dev librsvg2-dev
WORKDIR /app
COPY package.json package-lock.json ./
RUN rm -rf node_modules && npm install --build-from-source
COPY . .
CMD ["npm", "start"]