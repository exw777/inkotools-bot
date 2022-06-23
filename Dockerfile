FROM golang:1.18-alpine AS build

WORKDIR /go/src/

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o inkotools-bot


FROM alpine

WORKDIR /app/

RUN apk add --no-cache tzdata

VOLUME ["/app/config"]
VOLUME ["/app/data"]

CMD ["/app/inkotools-bot"]

COPY --chown=1000:1000 templates /app/templates

COPY --from=build --chown=1000:1000 /go/src/inkotools-bot /app/
