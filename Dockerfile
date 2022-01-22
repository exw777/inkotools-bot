FROM golang:1.17-alpine AS build

WORKDIR /go/src/

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o inkotools-bot


FROM alpine

RUN apk add --no-cache tzdata

COPY --from=build /go/src/inkotools-bot /

CMD ["/inkotools-bot"]
