# The agent side of the boundary. It exists so FR-004 can be asserted rather
# than assumed: this container is attached to agent_edge only, so a test can
# prove from inside it that the gateway answers and the upstream tools network
# does not.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY sdks/python ./sdks/python
RUN pip install --no-cache-dir ./sdks/python
COPY examples/demo-agent ./examples/demo-agent
WORKDIR /app/examples/demo-agent

# Idle by default: tests exec into it, and the demo runs on demand with
# `docker compose exec agent python main.py`.
CMD ["sleep", "infinity"]
