# config/waf/Dockerfile
FROM nginx:alpine

RUN apk add --no-cache modsecurity-nginx

COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/modsecurity/modsecurity.conf

CMD ["nginx", "-g", "daemon off;"]