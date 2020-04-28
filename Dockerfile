FROM rust:slim
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev git && \
    rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/tornadocash/phase2-bn254
WORKDIR /phase2-bn254/phase2
RUN cargo build --release --bin tornado
CMD cargo run --release --bin tornado
