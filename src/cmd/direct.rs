// SPDX-License-Identifier: Apache-2.0
//
// Direct block-device writer for full OTA payloads (recovery integration).
//
// The caller (recovery) opens and exclusively claims every target block device
// and hands the descriptors over with `--direct-fd`, one per `-p` partition and
// in the same order. This module never opens, creates, truncates or unlinks a
// path, and never maps a device into memory:
//
//   * `pwrite` of fully overwritten pages avoids the read-before-write a
//     writable `mmap` of a block device incurs for every page it touches.
//   * Operations are decoded as a stream in 1 MiB chunks, so memory use is
//     bounded by the worker count, not by the operation size.
//
// Scheduling is strictly largest-partition-first. SHA-256 is inherently
// sequential, so each large partition gets a hasher that follows the written
// frontier: it hashes the image in offset order, straight from the page cache,
// as soon as the operations covering the next stretch have completed. Hashing
// therefore runs alongside decoding instead of after it, and the end of the
// flash is not stretched by one long serial hash of the biggest image. Small
// partitions are simply hashed by the worker that finishes their last
// operation. Every partition is fsync'd before it reports 100%.
//
// The validate-everything-before-the-first-write structure, the descriptor
// hand-over and the streaming decode follow the design of the AERA Recovery
// Project's direct writer (Apache-2.0).

use super::Cmd;
use crate::payload::{Payload, PayloadData};
use crate::proto::chromeos_update_engine::{
    DeltaArchiveManifest, InstallOperation, PartitionUpdate,
};
use anyhow::{Context, Result, bail, ensure};
use ring::digest::{self, SHA256};
use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write as _};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const IO_CHUNK: usize = 1024 * 1024;
const HASH_CHUNK: usize = 4 * 1024 * 1024;
/// Partitions at least this large are hashed by a dedicated frontier hasher.
const STREAM_HASH_MIN: u64 = 64 * 1024 * 1024;
/// Bounds liblzma's dictionary allocation per concurrent operation.
const XZ_MEMLIMIT: u64 = 80 * 1024 * 1024;
/// Bounds zstd's window (2^27 = 128 MiB, the zstd decoder default ceiling).
const ZSTD_WINDOW_LOG_MAX: u32 = 27;

// Linux block-device ioctls (64-bit ABI).
const BLKROGET: u32 = 0x125e;
const BLKFLSBUF: u32 = 0x1261;
const BLKGETSIZE64: u32 = 0x8008_1272;

// Per-partition state, read by the progress reporter.
const PENDING: u8 = 0;
const WRITING: u8 = 1;
const VERIFIED: u8 = 2;
const FAILED: u8 = 3;

thread_local! {
    static IO_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; IO_CHUNK]);
}

struct Target<'a> {
    name: &'a str,
    part: &'a PartitionUpdate,
    file: File,
    size: u64,
    /// verify by re-reading from the device (cache dropped) instead of from the page cache
    readback: bool,
}

pub(super) fn run(
    cmd: &Cmd,
    payload: &Payload<'_>,
    manifest: &DeltaArchiveManifest,
    block_size: usize,
) -> Result<()> {
    ensure!(
        !cmd.partitions.is_empty() && cmd.partitions.len() == cmd.direct_fd.len(),
        "direct mode needs exactly one --direct-fd per -p partition"
    );
    let data = match &payload.data {
        PayloadData::Local(bytes) => *bytes,
        #[cfg(feature = "remote")]
        _ => bail!("direct mode requires a local package"),
    };
    let block = block_size as u64;

    // Validate every partition and claim every descriptor before any write.
    let mut names = HashSet::new();
    let mut devices = HashSet::new();
    let mut targets = Vec::with_capacity(cmd.partitions.len());
    for (name, &fd) in cmd.partitions.iter().zip(&cmd.direct_fd) {
        ensure!(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
            "invalid partition name '{name}'"
        );
        ensure!(names.insert(name.as_str()), "duplicate partition '{name}'");
        let part = manifest
            .partitions
            .iter()
            .find(|p| &p.partition_name == name)
            .with_context(|| format!("partition \"{name}\" not found in manifest"))?;
        let size = validate(part, block, data.len() as u64)
            .with_context(|| format!("partition '{name}'"))?;
        let (file, device) =
            open_target(fd, size).with_context(|| format!("target of '{name}'"))?;
        ensure!(devices.insert(device), "'{name}' aliases another target device");
        let readback = cmd.readback || cmd.readback_for.iter().any(|n| n == name);
        targets.push(Target { name: name.as_str(), part, file, size, readback });
    }
    // a name that matches no -p partition is a caller bug, not something to ignore
    for n in &cmd.readback_for {
        ensure!(names.contains(n.as_str()), "--readback-for names '{n}', which is not a -p partition");
    }

    let workers = worker_count(cmd.threads);
    eprintln!(
        "direct: {} partition(s), {} worker(s) ({})",
        targets.len(),
        workers,
        if cmd.threads.is_some_and(|t| t > 0) { "set with -t" } else { "automatic" }
    );
    let total: u64 = targets.iter().map(|t| t.size).sum();
    let started = Instant::now();
    write_targets(&targets, block, data, workers, STREAM_HASH_MIN)?;
    let secs = started.elapsed().as_secs_f64().max(f64::EPSILON);
    eprintln!(
        "direct: {} partition(s), {} in {:.2}s ({:.2} GB/s), {} workers{}",
        targets.len(),
        indicatif::HumanBytes(total),
        secs,
        total as f64 / secs / 1e9,
        workers,
        match targets.iter().filter(|t| t.readback).count() {
            0 => String::new(),
            n if n == targets.len() => ", device readback".to_string(),
            n => format!(", device readback for {n}"),
        }
    );
    Ok(())
}

/// Checks everything that can be checked from the manifest alone.
/// Returns the image size. Guarantees that the operations cover the image
/// exactly (no gaps, no overlaps), so every block of the target is written.
fn validate(p: &PartitionUpdate, block: u64, data_len: u64) -> Result<u64> {
    ensure!(
        p.old_partition_info.is_none(),
        "incremental image is not supported"
    );
    let info = p
        .new_partition_info
        .as_ref()
        .context("missing image information")?;
    let size = info.size.context("missing image size")?;
    ensure!(
        size > 0 && size <= i64::MAX as u64 && size % block == 0,
        "invalid image size {size}"
    );
    ensure!(
        info.hash.as_ref().is_some_and(|h| h.len() == 32),
        "missing image SHA-256"
    );
    ensure!(!p.operations.is_empty(), "image has no operations");

    let image_blocks = size / block;
    let mut ranges = Vec::with_capacity(p.operations.len());
    for op in &p.operations {
        ensure!(
            matches!(op.r#type, 0 | 1 | 6 | 7 | 8 | 14)
                && op.src_extents.is_empty()
                && op.src_sha256_hash.is_none(),
            "unsupported operation type {}",
            op.r#type
        );
        let mut decoded = 0u64;
        for e in &op.dst_extents {
            let start = e.start_block.context("extent without start")?;
            let count = e.num_blocks.context("extent without length")?;
            ensure!(
                count > 0 && start < image_blocks && count <= image_blocks - start,
                "extent outside the image"
            );
            decoded += count * block;
            ranges.push((start * block, (start + count) * block));
        }
        ensure!(decoded > 0, "operation without destination");

        let length = op.data_length.unwrap_or(0);
        if matches!(op.r#type, 6 | 7) {
            ensure!(length == 0, "zero operation carries data");
            continue;
        }
        let offset = op.data_offset.context("operation without data offset")?;
        ensure!(
            length > 0 && offset <= data_len && length <= data_len - offset,
            "operation data lies outside the payload"
        );
        if let Some(h) = &op.data_sha256_hash {
            ensure!(h.len() == 32, "malformed operation SHA-256");
        }
        if op.r#type == 0 {
            // raw data may be shorter than its extents only by block padding
            ensure!(
                length <= decoded && length.div_ceil(block) * block == decoded,
                "raw operation size does not match its extents"
            );
        }
    }

    ranges.sort_unstable();
    let mut end = 0;
    for (start, next) in ranges {
        ensure!(start == end, "operations overlap or leave a gap");
        end = next;
    }
    ensure!(end == size, "operations do not cover the whole image");
    Ok(size)
}

/// Duplicates an inherited descriptor and verifies it is a writable block
/// device large enough for the image. Returns the file and its device number.
fn open_target(fd: i32, size: u64) -> Result<(File, u64)> {
    ensure!(fd >= 3, "invalid descriptor {fd}");
    // SAFETY: the descriptor is only borrowed long enough to be duplicated; an
    // invalid one makes the duplication fail with EBADF.
    let owned = unsafe { BorrowedFd::borrow_raw(fd) }
        .try_clone_to_owned()
        .with_context(|| format!("descriptor {fd} is not open"))?;
    let file = File::from(owned);
    let meta = file.metadata()?;
    ensure!(
        meta.file_type().is_block_device(),
        "descriptor {fd} is not a block device"
    );
    let mut capacity = 0u64;
    let mut readonly = 1i32;
    // SAFETY: both ioctls write one integer through the supplied pointer.
    let ok = unsafe {
        libc::ioctl(file.as_raw_fd(), BLKGETSIZE64 as _, &mut capacity) == 0
            && libc::ioctl(file.as_raw_fd(), BLKROGET as _, &mut readonly) == 0
    };
    ensure!(ok, "cannot query the block device");
    ensure!(readonly == 0, "block device is read-only");
    ensure!(
        capacity >= size,
        "block device holds {capacity} bytes but the image needs {size}"
    );
    Ok((file, meta.rdev()))
}

fn worker_count(requested: Option<usize>) -> usize {
    if let Some(t) = requested
        && t > 0
    {
        return t.min(64);
    }
    const RESERVE: u64 = 512 << 20;
    // dictionary + buffers of one concurrently running decoder, with headroom
    const PER_WORKER: u64 = 96 << 20;
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    let memory_limit = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("MemAvailable:")?
                    .trim()
                    .trim_end_matches("kB")
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
        })
        .map_or(4, |kib| ((kib << 10).saturating_sub(RESERVE) / PER_WORKER) as usize);
    // decoding is CPU-bound but pwrite can block on dirty-page throttling, so a
    // little oversubscription keeps the cores busy
    (2 * cpus.min(8)).min(memory_limit).clamp(1, 16)
}

fn write_targets(
    targets: &[Target<'_>],
    block: u64,
    data: &[u8],
    workers: usize,
    stream_hash_min: u64,
) -> Result<()> {
    // Largest partition first, so the biggest image is under way (and hashed
    // alongside) while the smaller ones are still being decoded.
    let mut order: Vec<usize> = (0..targets.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(targets[i].size));
    let tasks: Vec<(usize, usize)> = order
        .iter()
        .flat_map(|&i| (0..targets[i].part.operations.len()).map(move |op| (i, op)))
        .collect();

    let done: Vec<AtomicU64> = targets.iter().map(|_| AtomicU64::new(0)).collect();
    let phase: Vec<AtomicU8> = targets.iter().map(|_| AtomicU8::new(PENDING)).collect();
    let remaining: Vec<AtomicUsize> = targets
        .iter()
        .map(|t| AtomicUsize::new(t.part.operations.len()))
        .collect();
    // large partitions are hashed as they are written, unless a device
    // readback replaces the hash anyway
    let streaming: Vec<bool> = targets
        .iter()
        .map(|t| !t.readback && t.size >= stream_hash_min)
        .collect();
    let op_done: Vec<Vec<AtomicBool>> = targets
        .iter()
        .map(|t| t.part.operations.iter().map(|_| AtomicBool::new(false)).collect())
        .collect();
    let layouts: Vec<Vec<(u64, u64, usize)>> = targets
        .iter()
        .enumerate()
        .map(|(i, t)| if streaming[i] { extent_layout(t.part, block) } else { Vec::new() })
        .collect();
    let cursor = AtomicUsize::new(0);
    let cancelled = AtomicBool::new(false);
    let stop = AtomicBool::new(false);
    let first_error: Mutex<Option<anyhow::Error>> = Mutex::new(None);

    let fail = |i: usize, e: anyhow::Error| {
        // record the cause before raising the flag, so the "cancelled" errors
        // of the other workers can never be the one that gets reported
        if let Ok(mut slot) = first_error.lock()
            && slot.is_none()
        {
            *slot = Some(e.context(format!("partition '{}'", targets[i].name)));
        }
        phase[i].store(FAILED, Ordering::Release);
        cancelled.store(true, Ordering::Release);
    };

    // A worker that panicked (release builds abort instead) must fail the run,
    // not silently leave operations undone.
    let worker_panicked = || {
        if let Ok(mut slot) = first_error.lock()
            && slot.is_none()
        {
            *slot = Some(anyhow::anyhow!("a worker thread panicked"));
        }
        cancelled.store(true, Ordering::Release);
    };

    let write_worker = || {
        loop {
            if cancelled.load(Ordering::Acquire) {
                return;
            }
            let Some(&(i, op)) = tasks.get(cursor.fetch_add(1, Ordering::Relaxed)) else {
                return;
            };
            let t = &targets[i];
            let _ = phase[i].compare_exchange(PENDING, WRITING, Ordering::AcqRel, Ordering::Acquire);
            if let Err(e) = write_operation(
                &t.file,
                &t.part.operations[op],
                block,
                data,
                &cancelled,
                &done[i],
            ) {
                fail(i, e);
                return;
            }
            op_done[i][op].store(true, Ordering::Release);
            if remaining[i].fetch_sub(1, Ordering::AcqRel) == 1 && !streaming[i] {
                // last operation of a small partition: hash it (unless a
                // device readback follows) and flush it while the others go on
                match finish_partition(t) {
                    Ok(()) if !t.readback => phase[i].store(VERIFIED, Ordering::Release),
                    Ok(()) => {}
                    Err(e) => {
                        fail(i, e);
                        return;
                    }
                }
            }
        }
    };

    let hash_worker = |i: usize| match hash_as_written(
        &targets[i],
        &layouts[i],
        &op_done[i],
        &cancelled,
    ) {
        Ok(true) => phase[i].store(VERIFIED, Ordering::Release),
        Ok(false) => {} // cancelled by a failure elsewhere
        Err(e) => fail(i, e),
    };

    // partitions verified from the device after all writes are done
    let readback_order: Vec<usize> = order
        .iter()
        .copied()
        .filter(|&i| targets[i].readback)
        .collect();
    let next_verify = AtomicUsize::new(0);
    let readback_worker = || {
        loop {
            if cancelled.load(Ordering::Acquire) {
                return;
            }
            let Some(&i) = readback_order.get(next_verify.fetch_add(1, Ordering::Relaxed)) else {
                return;
            };
            let t = &targets[i];
            match verify_from_device(t) {
                Ok(()) => phase[i].store(VERIFIED, Ordering::Release),
                Err(e) => {
                    fail(i, e);
                    return;
                }
            }
        }
    };

    std::thread::scope(|s| {
        let reporter = s.spawn(|| report_progress(targets, &done, &phase, &stop));
        let hash_worker = &hash_worker;
        let hashers: Vec<_> = (0..targets.len())
            .filter(|&i| streaming[i])
            .map(|i| s.spawn(move || hash_worker(i)))
            .collect();
        let writers: Vec<_> = (0..workers).map(|_| s.spawn(&write_worker)).collect();
        for w in writers {
            if w.join().is_err() {
                worker_panicked();
            }
        }
        for h in hashers {
            if h.join().is_err() {
                worker_panicked();
            }
        }
        if !readback_order.is_empty() && !cancelled.load(Ordering::Acquire) {
            let verifiers: Vec<_> = (0..workers.min(readback_order.len()))
                .map(|_| s.spawn(&readback_worker))
                .collect();
            for v in verifiers {
                if v.join().is_err() {
                    worker_panicked();
                }
            }
        }
        stop.store(true, Ordering::Release);
        let _ = reporter.join();
    });

    let recorded = first_error
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match recorded {
        Some(e) => Err(e),
        None if cancelled.load(Ordering::Acquire) => bail!("flash was cancelled before it finished"),
        None => Ok(()),
    }
}

fn expected_hash(t: &Target<'_>) -> Result<&[u8]> {
    t.part
        .new_partition_info
        .as_ref()
        .and_then(|i| i.hash.as_deref())
        .context("missing image SHA-256")
}

/// (start, end, operation) of every destination extent, in image order.
/// After validation these tile the image exactly.
fn extent_layout(p: &PartitionUpdate, block: u64) -> Vec<(u64, u64, usize)> {
    let mut layout = Vec::new();
    for (index, op) in p.operations.iter().enumerate() {
        for e in &op.dst_extents {
            let start = e.start_block.unwrap_or(0) * block;
            layout.push((start, start + e.num_blocks.unwrap_or(0) * block, index));
        }
    }
    layout.sort_unstable();
    layout
}

/// Hashes the image in offset order while it is being written: each stretch is
/// read back from the page cache as soon as the operation that produced it has
/// completed. Then compares, flushes and returns Ok(true). Ok(false) means the
/// run was cancelled by a failure elsewhere.
fn hash_as_written(
    t: &Target<'_>,
    layout: &[(u64, u64, usize)],
    op_done: &[AtomicBool],
    cancelled: &AtomicBool,
) -> Result<bool> {
    let mut ctx = digest::Context::new(&SHA256);
    let mut buf = vec![0u8; HASH_CHUNK];
    for &(start, end, op) in layout {
        while !op_done[op].load(Ordering::Acquire) {
            if cancelled.load(Ordering::Acquire) {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let mut offset = start;
        while offset < end {
            let n = (end - offset).min(HASH_CHUNK as u64) as usize;
            t.file
                .read_exact_at(&mut buf[..n], offset)
                .context("partition read-back failed")?;
            ctx.update(&buf[..n]);
            offset += n as u64;
        }
    }
    check_digest(t, ctx.finish())?;
    t.file.sync_all().context("partition flush failed")?;
    Ok(true)
}

fn finish_partition(t: &Target<'_>) -> Result<()> {
    if !t.readback {
        // the data was just written, so this is served from the page cache
        check_hash(t)?;
    }
    t.file.sync_all().context("partition flush failed")
}

fn verify_from_device(t: &Target<'_>) -> Result<()> {
    // SAFETY: BLKFLSBUF takes no argument; it flushes and invalidates the cache.
    let rc = unsafe { libc::ioctl(t.file.as_raw_fd(), BLKFLSBUF as _, 0) };
    ensure!(rc == 0, "cannot drop the device cache before readback");
    check_hash(t)
}

fn check_hash(t: &Target<'_>) -> Result<()> {
    let mut ctx = digest::Context::new(&SHA256);
    let mut buf = vec![0u8; HASH_CHUNK];
    let mut offset = 0u64;
    while offset < t.size {
        let n = (t.size - offset).min(HASH_CHUNK as u64) as usize;
        t.file
            .read_exact_at(&mut buf[..n], offset)
            .context("partition read-back failed")?;
        ctx.update(&buf[..n]);
        offset += n as u64;
    }
    check_digest(t, ctx.finish())
}

fn check_digest(t: &Target<'_>, got: digest::Digest) -> Result<()> {
    let expected = expected_hash(t)?;
    ensure!(
        got.as_ref() == expected,
        "image SHA-256 mismatch: expected {}, got {}",
        hex::encode(expected),
        hex::encode(got.as_ref())
    );
    Ok(())
}

/// Fills `buf` from `r`; a short count means end of stream.
fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn write_operation(
    file: &File,
    op: &InstallOperation,
    block: u64,
    data: &[u8],
    cancelled: &AtomicBool,
    done: &AtomicU64,
) -> Result<()> {
    let total: u64 = op
        .dst_extents
        .iter()
        .map(|e| e.num_blocks.unwrap_or(0) * block)
        .sum();

    let mut reader: Box<dyn Read + '_> = if matches!(op.r#type, 6 | 7) {
        // ZERO/DISCARD: the target holds old data, so zeros must be written
        Box::new(io::repeat(0))
    } else {
        let offset = op.data_offset.unwrap_or(0) as usize;
        let length = op.data_length.unwrap_or(0) as usize;
        let input = &data[offset..offset + length];
        if let Some(hash) = &op.data_sha256_hash {
            ensure!(
                digest::digest(&SHA256, input).as_ref() == hash.as_slice(),
                "operation data SHA-256 mismatch"
            );
        }
        match op.r#type {
            0 => Box::new(input),
            1 => Box::new(bzip2::read::BzDecoder::new(input)),
            8 => {
                let stream = liblzma::stream::Stream::new_stream_decoder(XZ_MEMLIMIT, 0)?;
                Box::new(liblzma::read::XzDecoder::new_stream(input, stream))
            }
            14 => {
                let mut decoder = zstd::stream::read::Decoder::new(input)?;
                decoder.window_log_max(ZSTD_WINDOW_LOG_MAX)?;
                Box::new(decoder)
            }
            t => bail!("unsupported operation type {t}"),
        }
    };

    IO_BUF.with(|cell| -> Result<()> {
        let mut buf = cell.borrow_mut();
        let mut produced = 0u64;
        let mut ended = false;
        for extent in &op.dst_extents {
            let mut offset = extent.start_block.unwrap_or(0) * block;
            let mut left = extent.num_blocks.unwrap_or(0) * block;
            while left > 0 {
                ensure!(!cancelled.load(Ordering::Acquire), "cancelled");
                let count = left.min(IO_CHUNK as u64) as usize;
                let got = if ended {
                    0
                } else {
                    read_full(&mut *reader, &mut buf[..count])?
                };
                if got < count {
                    // the stream may end inside the last block: pad with zeros
                    ended = true;
                    buf[got..count].fill(0);
                }
                produced += got as u64;
                file.write_all_at(&buf[..count], offset)
                    .context("partition write failed")?;
                offset += count as u64;
                left -= count as u64;
                done.fetch_add(count as u64, Ordering::Relaxed);
            }
        }
        if !matches!(op.r#type, 6 | 7) {
            if !ended {
                // reading to the end also runs the decoder's trailer/CRC check
                let mut probe = [0u8; 1];
                ensure!(
                    read_full(&mut *reader, &mut probe)? == 0,
                    "decoded data exceeds the destination extents"
                );
            }
            ensure!(
                produced.div_ceil(block) * block == total,
                "decoded size does not match the destination extents"
            );
        }
        Ok(())
    })
}

/// Prints "<partition>:<percent>" whenever a percentage changes. A partition
/// stays at 99 until it has been written, hashed and flushed; only then does it
/// report 100.
fn report_progress(
    targets: &[Target<'_>],
    done: &[AtomicU64],
    phase: &[AtomicU8],
    stop: &AtomicBool,
) {
    let mut last = vec![u64::MAX; targets.len()];
    loop {
        let stopping = stop.load(Ordering::Acquire);
        let mut out = String::new();
        for (i, t) in targets.iter().enumerate() {
            let pct = if phase[i].load(Ordering::Acquire) == VERIFIED {
                100
            } else {
                (done[i].load(Ordering::Relaxed).min(t.size) * 100 / t.size).min(99)
            };
            if pct != last[i] {
                last[i] = pct;
                out.push_str(&format!("{}:{}\n", t.name, pct));
            }
        }
        if !out.is_empty() {
            let mut stdout = io::stdout().lock();
            let _ = stdout.write_all(out.as_bytes());
            let _ = stdout.flush();
        }
        if stopping {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::chromeos_update_engine::{Extent, PartitionInfo};
    use std::io::Write;

    const BLOCK: u64 = 512;

    fn sha(bytes: &[u8]) -> Vec<u8> {
        digest::digest(&SHA256, bytes).as_ref().to_vec()
    }

    fn op(kind: i32, start: u64, blocks: u64, input: &[u8]) -> InstallOperation {
        let zero = matches!(kind, 6 | 7);
        InstallOperation {
            r#type: kind,
            dst_extents: vec![Extent { start_block: Some(start), num_blocks: Some(blocks) }],
            data_offset: (!zero).then_some(0),
            data_length: (!zero).then_some(input.len() as u64),
            data_sha256_hash: (!zero).then(|| sha(input)),
            ..Default::default()
        }
    }

    fn part(ops: Vec<InstallOperation>, image: &[u8]) -> PartitionUpdate {
        PartitionUpdate {
            partition_name: "boot".into(),
            operations: ops,
            new_partition_info: Some(PartitionInfo {
                size: Some(image.len() as u64),
                hash: Some(sha(image)),
            }),
            ..Default::default()
        }
    }

    fn target<'a>(p: &'a PartitionUpdate, file: File) -> Target<'a> {
        let size = p.new_partition_info.as_ref().unwrap().size.unwrap();
        Target { name: "boot", part: p, file, size, readback: false }
    }

    fn contents(file: &File, len: usize) -> Vec<u8> {
        let mut v = vec![0; len];
        file.read_exact_at(&mut v, 0).unwrap();
        v
    }

    #[test]
    fn overwrites_old_data_zeroes_and_keeps_larger_target_tail() {
        let data = vec![0xab; 512];
        let image = [vec![0xab; 512], vec![0; 1024]].concat();
        let p = part(vec![op(0, 0, 1, &data), op(6, 1, 1, &[]), op(7, 2, 1, &[])], &image);
        let file = tempfile::tempfile().unwrap();
        file.write_all_at(&vec![0x55; 2048], 0).unwrap();
        write_targets(&[target(&p, file.try_clone().unwrap())], BLOCK, &data, 4, u64::MAX).unwrap();
        let got = contents(&file, 2048);
        assert_eq!(&got[..1536], &image[..]);
        assert_eq!(&got[1536..], &vec![0x55; 512][..]);
    }

    #[test]
    fn every_codec_writes_multiple_extents_in_manifest_order() {
        let plain: Vec<u8> = (0..1024).map(|n| (n / 512 + 1) as u8).collect();
        let image = [vec![2u8; 512], vec![1u8; 512]].concat();
        for kind in [0, 1, 8, 14] {
            let input = match kind {
                1 => {
                    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
                    e.write_all(&plain).unwrap();
                    e.finish().unwrap()
                }
                8 => {
                    let mut e = liblzma::write::XzEncoder::new(Vec::new(), 6);
                    e.write_all(&plain).unwrap();
                    e.finish().unwrap()
                }
                14 => zstd::encode_all(&plain[..], 3).unwrap(),
                _ => plain.clone(),
            };
            let mut o = op(kind, 1, 1, &input);
            o.dst_extents.push(Extent { start_block: Some(0), num_blocks: Some(1) });
            let p = part(vec![o], &image);
            let file = tempfile::tempfile().unwrap();
            file.set_len(1024).unwrap();
            write_targets(&[target(&p, file.try_clone().unwrap())], BLOCK, &input, 2, u64::MAX).unwrap();
            assert_eq!(contents(&file, 1024), image, "codec {kind}");
        }
    }

    #[test]
    fn stream_ending_inside_last_block_is_zero_padded() {
        let plain = vec![7u8; 700];
        let mut e = liblzma::write::XzEncoder::new(Vec::new(), 1);
        e.write_all(&plain).unwrap();
        let input = e.finish().unwrap();
        let image = [plain.clone(), vec![0u8; 324]].concat();
        let p = part(vec![op(8, 0, 2, &input)], &image);
        let file = tempfile::tempfile().unwrap();
        file.write_all_at(&vec![0x55; 1024], 0).unwrap();
        write_targets(&[target(&p, file.try_clone().unwrap())], BLOCK, &input, 1, u64::MAX).unwrap();
        assert_eq!(contents(&file, 1024), image);
    }

    #[test]
    fn bad_operation_hash_aborts_before_writing_it() {
        let data = vec![7u8; 512];
        let mut o = op(0, 0, 1, &data);
        o.data_sha256_hash = Some(vec![0; 32]);
        let p = part(vec![o], &data);
        let file = tempfile::tempfile().unwrap();
        file.write_all_at(&vec![0x55; 512], 0).unwrap();
        assert!(write_targets(&[target(&p, file.try_clone().unwrap())], BLOCK, &data, 1, u64::MAX).is_err());
        assert_eq!(contents(&file, 512), vec![0x55; 512]);
    }

    #[test]
    fn wrong_image_hash_is_reported() {
        let data = vec![7u8; 512];
        let mut p = part(vec![op(0, 0, 1, &data)], &data);
        p.new_partition_info.as_mut().unwrap().hash = Some(vec![0; 32]);
        let file = tempfile::tempfile().unwrap();
        let err = write_targets(&[target(&p, file)], BLOCK, &data, 1, u64::MAX).unwrap_err();
        assert!(format!("{err:#}").contains("SHA-256 mismatch"));
    }

    #[test]
    fn frontier_hasher_handles_out_of_order_operations_and_bad_hashes() {
        // eight one-block operations listed in reverse image order, run on
        // four workers: the frontier hasher must still hash in image order
        let image: Vec<u8> = (0..8u8).flat_map(|b| vec![b + 1; 512]).collect();
        let ops: Vec<InstallOperation> = (0..8u64)
            .rev()
            .map(|b| {
                let mut o = op(0, b, 1, &image[b as usize * 512..(b as usize + 1) * 512]);
                o.data_offset = Some(b * 512);
                o
            })
            .collect();
        for (hash_ok, workers) in [(true, 4), (true, 1), (false, 4)] {
            let mut p = part(ops.clone(), &image);
            if !hash_ok {
                p.new_partition_info.as_mut().unwrap().hash = Some(vec![0; 32]);
            }
            let file = tempfile::tempfile().unwrap();
            let result = write_targets(&[target(&p, file.try_clone().unwrap())], BLOCK, &image, workers, 0);
            assert_eq!(result.is_ok(), hash_ok);
            assert_eq!(contents(&file, image.len()), image);
        }
    }

    #[test]
    fn readback_is_per_partition_and_needs_a_real_block_device() {
        // a regular file cannot drop a device cache, so asking for readback on
        // one must fail loudly rather than quietly fall back to the cache
        let data = vec![7u8; 512];
        let p = part(vec![op(0, 0, 1, &data)], &data);
        let file = tempfile::tempfile().unwrap();
        let mut t = target(&p, file.try_clone().unwrap());
        t.readback = true;
        let err = write_targets(&[t], BLOCK, &data, 1, u64::MAX).unwrap_err();
        assert!(format!("{err:#}").contains("device cache"));
        // the same partition without the flag is fine
        write_targets(&[target(&p, file)], BLOCK, &data, 1, u64::MAX).unwrap();
    }

    #[test]
    fn validation_rejects_gaps_overlaps_and_foreign_operations() {
        let data = vec![7u8; 512];
        let image = vec![7u8; 1024];
        for bad in [op(0, 0, 1, &data), op(0, 2, 1, &data), op(4, 1, 1, &data)] {
            let p = part(vec![op(0, 0, 1, &data), bad], &image);
            assert!(validate(&p, BLOCK, 512).is_err());
        }
        let p = part(vec![op(0, 0, 1, &data)], &data);
        assert!(validate(&p, BLOCK, 511).is_err());
        assert_eq!(validate(&p, BLOCK, 512).unwrap(), 512);
    }

    #[test]
    fn regular_files_are_not_accepted_as_targets() {
        let file = tempfile::tempfile().unwrap();
        let fd = file.as_raw_fd();
        assert!(open_target(fd, 512).is_err());
    }
}
