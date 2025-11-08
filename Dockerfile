FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/broker ./cmd/broker

FROM gcr.io/distroless/static:nonroot
ENV CONFIG_PATH=/config/config.yaml
WORKDIR /
USER nonroot:nonroot
COPY --from=build /out/broker /broker
ENTRYPOINT ["/broker"]
