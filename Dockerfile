# Use a slim version of Node to save VPS space
FROM node:20-alpine

WORKDIR /app

# Copy package files first (better caching)
COPY package*.json ./
RUN npm install --omit=dev

# Copy the rest of your code
COPY . .

# Match this to your Express port (usually 3000)
EXPOSE 3000

# Start the app
CMD ["node", "app.js"]
