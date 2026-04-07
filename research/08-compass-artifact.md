# KVCOS and MAR system: engineering reality check across seven critical targets

**The most important finding across all seven research targets: no one has built a universal, agent-native KV cache object store with semantic retrieval, cross-model transfer, and persistent storage — but every individual component now has at least one working implementation.** The gap between what exists and what KVCOS proposes is narrowing fast, with LMCache at 6.6k GitHub stars and MemArt demonstrating latent-space KV retrieval at ICLR 2026. The window for building this system is open but closing. Below is a dense engineering assessment of each target, focused on what works today and what blocks a Phase 1 build.

---

## T1: Raw KV tensor extraction remains unsolved

**There is no way to extract structured KV cache tensors from Ollama or llama.cpp through any public API, flag, fork, or PR.** The state save/restore functionality in both systems serializes KV cache data as opaque binary blobs — not structured `[n_layers, 2, n_heads, ctx_len, head_dim]` float tensors.

llama.cpp provides `llama_state_get_data()` / `llama_state_save_file()` and per-sequence variants (`llama_state_seq_get_data()`, added in PR #6341), but these produce a binary blob containing cell metadata interleaved with raw tensor data in ggml format (f16/q8_0/etc). The `llama_kv_cache_view` API provides **metadata only** — which cells are used, sequence IDs, positions — with zero access to actual tensor values. llama-cpp-python's `save_state()` wraps this same opaque blob in a `LlamaState` object. The `scores` attribute is a numpy array, but it contains logits, not KV data. Known bugs include garbage output when `n_gpu_layers > 0` (Issue #743) and Vulkan crashes on state save (Issue #1149).

Ollama offers even less — **no API endpoint, no shared memory hook, no environment variable** for KV cache export. `OLLAMA_KV_CACHE_TYPE` controls dtype only (f16/q8_0/q4_0). The Go `kvcache.Cache` interface is internal.

The most viable path forward is **parsing the opaque state blob** by reverse-engineering `llama_kv_cache::state_write()`. The format writes KV cache metadata, then per-layer K tensor data (contiguous via `ggml_backend_tensor_get`), then V tensor data (row-by-row if non-contiguous). This is fragile and version-dependent but achievable given knowledge of the model architecture. Alternatively, a **C-level patch** to llama.cpp adding a `llama_kv_cache_get_tensor(ctx, layer, kv_type)` function that calls `ggml_backend_tensor_get()` on `kv_self.k_l[il]` would be the cleanest solution — roughly 50-100 lines of C code. No existing fork (modelai-llama.cpp, DataBridge, spiritbuun/turboquant) provides this.

---

## T2: FAISS works for K→K similarity but fails catastrophically for Q→K retrieval

**The most critical finding for the MAR architecture: off-the-shelf FAISS indexes fail for attention-style Q→K retrieval due to an out-of-distribution (OOD) problem.** Microsoft Research's RetrievalAttention (ICLR 2025) demonstrated that query and key vectors are projected by different weight matrices, creating a distribution gap that defeats standard ANN indexes. HNSW "always fails" to retrieve relevant keys; IVF requires scanning ~30% of vectors to match a custom attention-aware index that needs only **1-3%** scanning.

This matters specifically for the MAR retrieval step. If KVCOS stores KV cache blocks indexed by their key-state embeddings and retrieves them using query vectors at inference time, standard FAISS will not work. However, if the retrieval is **K→K** (finding stored cache blocks similar to the current prompt's key representation), FAISS works fine because both sides share the same distribution.

For the K→K use case at KV-state dimensions (**128-512**), IndexFlatIP is appropriate up to ~100K vectors with sub-15ms latency per query on CPU with MKL. Beyond 100K vectors, IVFFlat with `nlist=4*sqrt(n)` is recommended. Memory: d=512, float32, 1M vectors = ~2GB. A documented parallelization issue (GitHub #4121) shows IndexFlatIP underperforms a naive custom implementation by **2-3x** on high core-count machines due to FAISS parallelizing over queries rather than index segments. The faiss-cpu conda-forge build without MKL can be **18x slower** than PyTorch `torch.mm` (Issue #2499).

**Inner product (MIPS) is the theoretically correct metric** for KV cache retrieval since attention computes `softmax(QK^T/√d)`. Cosine similarity discards magnitude information that is semantically meaningful. For persistence, `faiss.write_index` has documented pitfalls: GPU indexes cannot be serialized directly (must convert to CPU first), concurrent read/write causes corruption (Issue #861), and version/platform incompatibility can make index files unreadable across FAISS versions (Issue #3888). Best practice: write to temp file + atomic rename, version-lock FAISS, use `faiss.serialize_index()` for in-memory transfer.

---

## T3: Pre-RoPE key vectors are the right extraction target, validated on small models

**ShadowKV (ICML 2025 Spotlight, ByteDance) explicitly validates the SALS finding on both Phi-3-Mini-128K and Llama-3.1-8B.** Pre-RoPE keys exhibit the sharpest singular value decay of any representation tested (layer inputs, post-RoPE keys, values, weight matrices) and can be compressed **6x via truncated SVD** (rank-256 from full dimension) without degradation. The finding generalizes across all tested RoPE-based architectures, with one caveat: models with QK-Norm (e.g., Gemma3) behave differently and may not exhibit the same low-rank structure.

Last-layer-only extraction is **partially validated but insufficient alone**. Layer-Condensed KV Cache (ACL 2024) confirms the top layer is "most informative" as a single layer, but exclusive last-layer extraction causes measurable quality degradation. Cross-Layer Attention research shows that first and last layers benefit from "special treatment" — sharing them hurts most. The empirical consensus points to **middle-to-deep layers (roughly layers 8-31 for a 32-layer model) as most compressible/shareable**, with early layers (especially layer 0) and the final 1-2 layers preserved at higher fidelity.

The best state extraction methods, ranked by validation strength:

- **Truncated SVD on pre-RoPE keys** — strongest evidence. ShadowKV uses rank-160 for Llama-3.1-8B. Code available at `github.com/ByteDance-Seed/ShadowKV`.
- **Cross-layer SVD** (xKV, arXiv:2503.18893) — groups 4 adjacent layers, extracts shared basis vectors. Achieves **6.8x compression** vs 2.5x for single-layer SVD on Llama-3.1-8B. Key:value rank ratio of **1:1.5** optimal. Code at `github.com/abdelfattah-lab/xKV`.
- **Mean pooling of key chunks** — used by CTkvr for retrieval indexing centroids. Simple, lossy, but effective for approximate matching. No code dependency.
- **NVIDIA kvpress** (`github.com/NVIDIA/kvpress`) implements 20+ compression methods and supports both Phi-3 and Llama-3 out of the box — the best starting point for experimentation.

A critical nuance from ShadowKV: pre-RoPE keys share low-rank subspaces *within* sequences but differ *across* sequences. This means SVD projection is **prompt-dependent** and must be computed online, not precomputed globally.

---

## T4: TurboQuant has real working code, but QJL is a trap

**All three specified repos are real and contain working code.** The TurboQuant paper (Google Research, ICLR 2026, arXiv:2504.19874) dropped ~March 24, 2026, and the ecosystem exploded within a week with 10+ independent implementations.

**TheTom/turboquant_plus** is the most mature: 511+ Python tests, 100% coverage, C port integrated into llama.cpp with Metal GPU kernels (`--cache-type-k turbo3 --cache-type-v turbo3` works end-to-end), sparse V attention-gated decoding (+22.8% decode speed at 32K), and layer-adaptive compression. Production-viable on Apple Silicon. The llama.cpp upstream PR #21089 is not yet merged (P2 priority). A CUDA fork by spiritbuun is tested on RTX 3090.

**0xSero/turboquant** has working Triton kernels (3 fused decode kernels in `triton_kernels.py`) plus vLLM integration adapter. Tested on RTX 5090 and 8x RTX 3090 cluster. Small repo (9 stars, 2 commits) but functional. **hackimov/turboquant-kv** has the most feature-complete Triton implementation with GQA/MQA support and paged KV in vLLM style.

**tonbistudio/turboquant-pytorch** is educational/research quality. Its most valuable contribution is discovering that **QJL hurts in practice** — confirmed by 6+ independent teams across Python, C, and Rust implementations. Softmax amplifies QJL variance, making the two-stage approach (PolarQuant + QJL) worse than MSE-only (all bits to Lloyd-Max centroids) for actual attention computation. This is the single most important community finding.

For Phase 1 fallback, **llama.cpp q8_0 KV cache is the safest bet**: fully merged in mainline, available in Ollama, ~2x compression, <5% speed hit, +0.002-0.05 PPL. The q4_0 option has documented issues at 64K+ context (92% dequantization slowdown). Other validated alternatives include **HuggingFace Transformers INT4** (KIVI-inspired, built-in), **KIVI** (jy-yuan/KIVI, ICML 2024, most academically validated 2-bit method), **ExLlamaV2 Q4**, and **vLLM FP8** (H100+ only, FlashInfer backend recommended).

---

## T5: No direct competitor exists, but the gap is closing on five fronts

**No existing system combines persistent cross-session storage, semantic/latent-space retrieval over cached KV blocks, cross-model transfer, agent-native APIs, and a standalone REST/gRPC service.** Each competitor covers 2-3 of these five features.

**LMCache** (6.6k GitHub stars, TensorMesh) is the closest open-source contender. It offers multi-tier storage (GPU→CPU→Disk→S3/Ceph), cross-engine sharing (vLLM, SGLang), non-prefix reuse via CacheBlend, and P2P transfer. Integrated with NVIDIA Dynamo, Mooncake, CoreWeave, Google Cloud. What it lacks: **no cross-model transfer** (cache is model-specific, keyed by token hash), **no semantic search** over stored blocks, **no agent-native abstractions** (no session/agent ID management).

**Mooncake Store** (kvcache-ai, FAST 2025 Best Paper) powers Kimi chatbot at scale — 128 H200 GPUs, 224k tok/s prefill. It's a distributed cache transport engine focused on PD disaggregation and RDMA-optimized cross-node transfer, not an object store with retrieval semantics.

**Pure Storage KVA** is the first enterprise persistent KV cache product (shipped 2026), offering 20x faster inference via NFS and S3-backed cache. Protocol-agnostic, integrates with vLLM natively. But it's proprietary, prefix-based only, with no semantic layer or agent abstractions.

**MemArt** (ICLR 2026 submission) is the most architecturally relevant competitor. It stores conversational turns as reusable KV cache blocks and retrieves them by computing **attention scores in latent space** — exactly what KVCOS needs. Achieves **+11-39.4% accuracy** over plaintext memory and **91-135x prefill token reduction**. But it's research-only with no public code, no persistence, and single-model only.

**agent-memory** (arXiv:2603.04428, Feb 2026) is the first shipped system treating KV cache as per-agent persistent memory — safetensors format, Q4 quantization, 136x TTFT reduction on Gemma 3 12B. But it's Apple Silicon/MLX only, with no semantic retrieval, no cross-model transfer, and no network sharing.

The ICLR 2026 MemAgents workshop signals academic convergence on KV cache as the native memory substrate for agents. The infrastructure gap is real and well-timed.

---

## T6: Credible TTFT benchmarks and what to target for a demo

**The "RAG prefill is 95% of TTFT" claim is validated** — FusionRAG (arXiv:2601.12904, Jan 2026) measured **95.53%** on the Musique dataset (17K average tokens prefill, <5 tokens decode). For typical RAG configurations with shorter contexts, the proportion is likely **80-95%**. The claim is directionally correct and well-sourced.

TurboRAG's 8.6-9.4x TTFT reduction claim has **not been independently replicated**. Their own GitHub demo (MooreThreads/TurboRAG, 93 stars) measures **6.35x** (0.65s vs 4.13s, 10 documents at 512 tokens/chunk). FusionRAG documents quality degradation from TurboRAG's full cache reuse approach due to overlapping position IDs and lack of cross-attention. FusionRAG achieves 73.3% TTFT reduction with 15% selective recomputation, recovering 99% of quality.

Concrete TTFT baselines gathered from multiple sources:

| Model | Context | Hardware | Cold TTFT | Cached TTFT | Speedup | Source |
|---|---|---|---|---|---|---|
| Llama 3.1 8B Q4 | 16K | Apple Silicon | **47.6s** | **430ms** | **111x** | agent-memory paper |
| Qwen3-32B | 10K | H100 | **4.3s** | **0.6s** | **7.2x** | vLLM APC benchmarks |
| Qwen3-32B | 128K | H100 + VAST | **>11s** | **1.5s** | **~10x** | VAST Data + LMCache |
| Llama 3.1 70B AWQ | 16K | A6000 | **~15s** | — | — | SGLang Issue #922 |
| RAGCache (7B models) | varied | A10G/H800 | — | — | **4x vs vLLM** | ACM TOCS Nov 2025 |

For a credible Phase 1 demo targeting **Llama 3.1 8B on consumer/datacenter GPU**:

- **4K context**: Cold ~200-500ms, cached target <100ms (4-10x improvement)
- **8K context**: Cold ~500-1,500ms, cached target <200ms (5-15x)
- **16K context**: Cold ~1,500-5,000ms, cached target <500ms (10-50x)
- **Production SLO reference**: NVIDIA/Sarvam AI targets P95 TTFT < 1,000ms for a 30B MoE model on 2x H100

SGLang's RadixAttention achieves **1.7x** average TTFT reduction in Chatbot Arena production (52-74% cache hit rates). vLLM prefix caching delivers **~7x** at high hit rates. These are the baselines to beat — a KVCOS demo should target **>10x** at 16K+ context to be differentiated.

---

## T7: Safetensors is the right format, and the ecosystem is converging on it

**Safetensors + JSON metadata is the correct serialization format for a KV cache object store.** Three independent signals confirm this direction: (1) vLLM PR #14228 by KuntaiDu (LMCache/vLLM maintainer) explicitly replaces pickle with safetensors for KV cache serialization in MooncakePipe, citing security; (2) the agent-memory paper (arXiv:2603.04428) uses safetensors for persistent Q4 KV cache on Apple Silicon; (3) safetensors is **76.6x faster** than PyTorch pickle on CPU due to zero-copy mmap, with 2.1x GPU advantage.

The format stores an 8-byte header size prefix, a JSON header with per-tensor metadata (name, dtype, shape, data_offsets) and an optional `__metadata__` field for arbitrary string→string key-value pairs, followed by contiguous packed tensor data. For a KV cache block with 32 layers × 2 (K+V) = 64 tensors, the JSON header is ~5-10KB — negligible. HTTP Range requests can read just the header from S3 to inspect metadata without downloading tensor data.

Key caveats: **no native FP8 dtype** (store as U8 with metadata annotation), **string-only metadata values** (JSON-stringify complex structures), and **no built-in compression** (layer CacheGen or zstd on top). For network-fetched objects from S3, CacheGen's 3.5-4.3x compression matters more than safetensors' mmap advantage.

**GGUF is not worth targeting.** It's designed for self-contained model files, not granular cache objects. llama.cpp's own KV cache persistence uses raw binary, not GGUF. Higher per-file overhead with typed metadata and 32-byte alignment padding. Zero ecosystem momentum for GGUF-based KV cache storage.

**LMCache currently uses pickle** (naive mode) or CacheGen bitstream. Adding a `"safetensors"` serde backend to LMCache would align with PR #14228's direction and provide the natural integration point for KVCOS. The recommended object layout: one safetensors file per 256-token cache block, with `__metadata__` containing model name, layer count, KV heads, head_dim, dtype, quantization type, and creation timestamp. Block identity via SHA-256 hash of the token sequence maps directly to S3 object keys.

---

## Conclusion: what this means for a Phase 1 build

The research reveals five critical engineering decisions for KVCOS Phase 1. First, **tensor extraction requires a custom patch** — either a ~100-line C addition to llama.cpp exposing per-layer KV tensors via the public API, or a Python-side parser for the opaque state blob format. No existing tool does this. Second, **FAISS is fine for K→K retrieval indexing** (finding similar cached prompts) but fundamentally broken for Q→K attention retrieval — design the system around prompt-similarity matching, not attention-score approximation. Third, **pre-RoPE SVD-projected key vectors** are the validated state representation, with ShadowKV and xKV providing working code for Llama-3.1-8B and Phi-3. Fourth, **safetensors is the serialization answer** with active ecosystem convergence (vLLM PR, agent-memory paper, 76x speed advantage over pickle). Fifth, the competitive landscape has a clear gap — LMCache provides infrastructure, MemArt demonstrates the retrieval concept, but nobody has shipped the combined agent-native, semantically-searchable, persistent KV cache object store that KVCOS proposes. The most credible Phase 1 demo target is **>10x TTFT reduction at 16K context** on Llama 3.1 8B, using pre-RoPE key-state similarity for cache block retrieval, safetensors persistence, and llama.cpp q8_0 as the quantization fallback while TurboQuant matures.