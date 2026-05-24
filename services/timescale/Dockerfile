FROM timescale/timescaledb:latest-pg15

RUN apk add build-base make clang15 llvm15 git
COPY w4rya /w4rya
RUN cd /w4rya && make USE_PGXS=1 install && cd / && \
	git clone https://github.com/ossc-db/pg_hint_plan --branch PG15 && \
	cd pg_hint_plan && make USE_PGXS=1 install
