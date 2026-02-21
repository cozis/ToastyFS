FROM gcc:latest AS build
WORKDIR /build
COPY src/ src/
COPY include/ include/
COPY quakey/ quakey/
COPY Makefile .
RUN make toastyfs

FROM debian:bookworm-slim
RUN mkdir -p /data
COPY --from=build /build/toastyfs /usr/local/bin/toastyfs
ENTRYPOINT ["toastyfs"]
