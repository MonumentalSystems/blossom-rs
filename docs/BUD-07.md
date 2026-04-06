# BUD-07: Chunked Blob Storage with Merkle Integrity

**Status:** Draft
**Version:** 1.0
**Authors:** MonumentalSystems

## Abstract

Defines how large blobs can be split into fixed-size chunks, stored as
individual Blossom blobs, and reassembled with Merkle-tree integrity
verification. This enables parallel upload/download, chunk-level
deduplication, per-chunk integrity verification, and resume of partial
transfers.

## Motivation

Blossom (BUD-01) stores blobs identified by SHA-256 hash. Large files
(e.g., ML models, datasets, media assets tracked via Git LFS) benefit from
being split into smaller chunks:

- **Parallelism** — chunks can be uploaded/downloaded concurrently
- **Deduplication** — identical chunks across files are stored once
- **Resume** — only missing chunks need to be transferred
- **Integrity** — Merkle proofs allow verifying individual chunks without
  downloading the entire file

## Manifest Format

A manifest is a JSON document stored as a regular Blossom blob. Its
SHA-256 hash (of the canonical JSON) serves as the blob OID that clients
reference.

**Content-Type:** `application/x-blossom-manifest+json`

```json
{
  "version": "1.0",
  "file_size": 104857600,
  "chunk_size": 8388608,
  "chunks": 13,
  "merkle_root": "a3f2...b8c1",
  "chunk_hashes": [
    "e5d7...01ab",
    "c9f1...88de"
  ],
  "original_filename": "large-model.bin",
  "content_type": "application/octet-stream",
  "created_at": 1712345678,
  "blossom_server": "https://blossom.example.com"
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | `"1.0"` |
| `file_size` | uint64 | Yes | Total file size in bytes |
| `chunk_size` | uint | Yes | Maximum chunk size in bytes |
| `chunks` | uint | Yes | Number of chunks |
| `merkle_root` | string | Yes | Hex-encoded Merkle root hash |
| `chunk_hashes` | string[] | Yes | SHA-256 hex digest of each chunk, in order |
| `original_filename` | string | No | Original filename for reference |
| `content_type` | string | No | MIME type of the original file |
| `created_at` | uint64 | Yes | Unix timestamp of manifest creation |
| `blossom_server` | string | No | Blossom server URL where chunks are stored |

## Chunking Rules

1. **Fixed-size splitting.** The file is split into sequential,
   non-overlapping byte ranges of `chunk_size` bytes. The last chunk may
   be smaller.
2. **Chunk identity.** Each chunk is a regular Blossom blob, identified
   by its SHA-256 hash (the value in `chunk_hashes`).
3. **Chunk i** is bytes `[i * chunk_size, min((i+1) * chunk_size,
   file_size))` of the original file.

## Merkle Tree Construction

1. **Leaves** are the SHA-256 hashes from `chunk_hashes`, in order.
2. **Parent node** = `SHA256(hex_decode(left_child) ||
   hex_decode(right_child))`. Both child hashes are decoded from hex to
   raw 32-byte values before concatenation and hashing.
3. **Odd levels:** When a level has an odd number of nodes, the last
   node is paired with itself (duplicated).
4. **Root** is the single node at the top level, stored as `merkle_root`
   (hex-encoded 64-character lowercase string).

### Merkle Proofs

A Merkle proof for chunk `i` consists of a list of `(sibling_hash,
is_left)` pairs, one per tree level. Each pair provides the sibling node
needed to recompute the parent. Verification starts from the leaf hash
and walks up to the root, comparing the final computed value against
`merkle_root`.

- `is_left = true` means the sibling is on the left (current node is on
  the right)
- `is_left = false` means the sibling is on the right (current node is
  on the left)

## Discovery

A client downloading a blob by SHA-256 SHOULD attempt to parse the
response as a Manifest by checking:

1. The response Content-Type is `application/x-blossom-manifest+json`, OR
2. The JSON contains `"version": "1.0"` and a `"chunk_hashes"` array

If the blob is a manifest:

1. Download each chunk blob by its SHA-256 hash
2. Verify each chunk hash matches `chunk_hashes[i]`
3. (Optional) Verify Merkle proofs for individual chunks
4. Reassemble chunks in order to produce the original file

If parsing fails, treat the blob as a regular file.

## Upload Protocol

1. Split file into chunks of `chunk_size` bytes, compute SHA-256 for each
2. Build Merkle tree from chunk hashes, compute root
3. For each chunk, check `HEAD /<sha256>` (exists) — skip if present
   (dedup)
4. Upload missing chunks as regular blobs (`PUT /upload`)
5. Create Manifest JSON, compute its SHA-256 hash
6. Check `HEAD /<manifest_sha256>` — skip if present
7. Upload Manifest as a regular blob with Content-Type
   `application/x-blossom-manifest+json`

The manifest hash becomes the OID that clients use to reference the file.

## Integrity Verification

A client MAY verify integrity by:

1. Rebuilding the Merkle tree from `chunk_hashes` and confirming it
   matches `merkle_root`
2. Downloading individual chunks and verifying their hash matches
   `chunk_hashes[i]`
3. Using Merkle proofs to verify individual chunks without downloading
   all chunks

## Backward Compatibility

Servers that do not implement BUD-07 treat manifests as ordinary blobs.
Clients that do not implement BUD-07 download the manifest JSON instead
of the original file — they will see a JSON document rather than binary
data. Implementors SHOULD check for the manifest content type or version
field before attempting to use the data as a file.

## Security Considerations

- All chunk and manifest blobs use standard Blossom authentication (BUD-01)
- The Merkle root provides a single hash that commits to all chunk data —
  any chunk substitution is detectable
- Manifest creators should use `serde_json::to_string_pretty` for
  deterministic serialization, ensuring the manifest hash is reproducible
