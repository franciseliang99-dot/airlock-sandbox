# Image for the one-shot agent sandbox. Runs under gVisor with no network.
FROM alpine:3.22
RUN apk add --no-cache git bash python3 && addgroup -g 1000 agent && adduser -D -u 1000 -G agent -h /home/agent -s /bin/bash agent
# Keep Python bytecode caches out of the agent's diff.
ENV PYTHONDONTWRITEBYTECODE=1
USER 1000:1000
WORKDIR /work
CMD ["sleep", "3600"]
