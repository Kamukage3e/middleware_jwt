FROM golang:1.19 as builder

COPY go.mod go.sum /app/

WORKDIR /app

RUN go mod download

COPY . /app/

RUN go build -buildmode=plugin -o middleware_jwt.so

FROM traefik:v2.4

COPY --from=builder /app/middleware_jwt.so /usr/local/traefik/middleware_jwt.so