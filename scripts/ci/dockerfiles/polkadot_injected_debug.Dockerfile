FROM docker.io/library/ubuntu:20.04

# metadata
ARG VCS_REF
ARG BUILD_DATE
ARG IMAGE_NAME

LABEL io.parity.image.authors="devops-team@parity.io" \
	io.parity.image.vendor="Parity Technologies" \
	io.parity.image.title="${IMAGE_NAME}" \
	io.parity.image.description="vine: a platform for web3" \
	io.parity.image.source="https://github.com/paritytech/vine/blob/${VCS_REF}/scripts/ci/dockerfiles/peer_injected_debug.Dockerfile" \
	io.parity.image.revision="${VCS_REF}" \
	io.parity.image.created="${BUILD_DATE}" \
	io.parity.image.documentation="https://github.com/paritytech/vine/"

# show backtraces
ENV RUST_BACKTRACE 1

# install tools and dependencies
RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y \
		libssl1.1 \
		ca-certificates && \
# apt cleanup
	apt-get autoremove -y && \
	apt-get clean && \
	find /var/lib/apt/lists/ -type f -not -name lock -delete; \
# add user and link ~/.local/share/vine to /data
	useradd -m -u 1000 -U -s /bin/sh -d /vine vine && \
	mkdir -p /data /vine/.local/share && \
	chown -R vine:vine /data && \
	ln -s /data /vine/.local/share/vine

# add vine binary to docker image
COPY ./vine /usr/local/bin

USER vine

# check if executable works in this container
RUN /usr/local/bin/vine --version

EXPOSE 30333 9933 9944
VOLUME ["/vine"]

ENTRYPOINT ["/usr/local/bin/vine"]
