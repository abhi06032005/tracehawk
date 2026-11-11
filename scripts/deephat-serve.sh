#!/usr/bin/env bash
set -euo pipefail
export HF_HOME=/workspace/.cache/huggingface
export HF_HUB_OFFLINE=1
test -r /workspace/deephat-chat.jinja
exec /venv/main/bin/vllm serve DeepHat/DeepHat-V1-7B \
  --chat-template /workspace/deephat-chat.jinja \
  --dtype half \
  --max-model-len 100000 \
  --hf-overrides '{"max_position_embeddings":131072,"rope_parameters":{"rope_type":"yarn","factor":4.0,"original_max_position_embeddings":32768,"rope_theta":1000000.0}}' \
  --max-num-seqs 1 \
  --max-num-batched-tokens 2048 \
  --gpu-memory-utilization 0.90 \
  --enforce-eager \
  --host 127.0.0.1 \
  --port 8001
