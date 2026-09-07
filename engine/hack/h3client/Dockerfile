# h3client - a stock HTTP/3 client for the edge acceptance rigs (edge-spec §8,
# milestone E5). Deliberately nothing but distribution curl: the point of this
# image is to prove that an ORDINARY client reaches a Kapkan-rendered
# terminator over h3, which a client we built ourselves could never show.
#
# Debian 13 is the rig's base everywhere (E5 decision D9), and its curl 8.14.1
# is built against OpenSSL 3.5 with nghttp3, so it speaks HTTP/3 with no extra
# packages and no rebuild.
#
# Test-only. Nothing in the product builds, ships or runs this image.
FROM debian:13-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates curl \
	&& rm -rf /var/lib/apt/lists/*

# The self-check that keeps a silent regression from passing the rig. If a
# Debian point release ever ships a curl without HTTP/3, `curl --http3` falls
# back rather than failing, every h3 arm would keep passing over HTTP/2, and the
# milestone would be proven by nothing. Fail the image build loudly instead.
RUN curl -V | grep -q HTTP3

ENTRYPOINT ["curl"]
