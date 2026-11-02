FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd --system --no-create-home payesh
COPY --from=build /src/target/release/payesh-dashboard-api /usr/local/bin/payesh-dashboard-api
USER payesh
EXPOSE 8080
CMD ["payesh-dashboard-api"]
