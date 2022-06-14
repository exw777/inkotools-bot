FROM golang:1.18-alpine AS build

WORKDIR /go/src/

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o inkotools-bot


FROM alpine

RUN apk add --no-cache tzdata

RUN mkdir /data/ && \
    chown 1000:1000 /data/

VOLUME ["/data"]

CMD ["/inkotools-bot"]

COPY templates /templates

COPY --from=build /go/src/inkotools-bot /
