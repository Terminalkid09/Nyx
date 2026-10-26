FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json .npmrc ./
# npm ci + the committed lockfile: the same resolution CI uses. .npmrc keeps
# legacy-peer-deps on for eslint-plugin-jsx-a11y's lagging peer range.
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
