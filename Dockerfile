FROM rust:1.67
LABEL authors="UmiKami"

WORKDIR /usr/src/axum-demo
COPY . .

RUN cargo install --path .

CMD ["axum-demo"]