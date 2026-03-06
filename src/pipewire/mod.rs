use ::pipewire as pw;
use bytes::Bytes;
use std::process::Command;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use crate::core::{PcmChunk, PcmFormat, SampleFormat};
use crate::error::{Error, Result};

const CHANNEL_CAPACITY: usize = 64;
const CHUNK_FRAMES: u32 = 352;
const SAMPLE_BYTES_S16LE: usize = 2;

static MONO_START: OnceLock<Instant> = OnceLock::new();

#[derive(Debug, Clone)]
/// Desired virtual PipeWire sink identity and capture format.
pub struct VirtualSinkSpec {
    /// PipeWire node name used as a stable sink identifier.
    pub name: String,
    /// Human-readable sink description shown in audio tools.
    pub description: String,
    /// PCM format the capture pipeline expects from the monitor stream.
    pub format: PcmFormat,
}

#[derive(Debug)]
/// Handle returned by capture startup for consuming audio and stopping capture.
pub struct CaptureHandle {
    /// Bounded channel receiving captured PCM chunks.
    pub pcm_rx: mpsc::Receiver<PcmChunk>,
    /// Optional shutdown signal sender for the capture thread.
    pub stop_tx: Option<oneshot::Sender<()>>,
}

#[derive(Debug)]
pub struct AudioRouteSession {
    previous_default_sink: Option<String>,
    virtual_sink: String,
    module_id: Option<u32>,
    changed_default_sink: bool,
}

#[derive(Debug)]
struct CaptureUserData {
    pending: Vec<u8>,
    pcm_tx: mpsc::Sender<PcmChunk>,
    format: PcmFormat,
    chunk_bytes: usize,
    should_stop: Arc<AtomicBool>,
}

/// Starts PipeWire capture by creating a virtual sink and monitor stream.
///
/// The returned handle exposes captured PCM frames and a stop signal for
/// coordinated session teardown.
pub fn start_capture(spec: VirtualSinkSpec) -> Result<CaptureHandle> {
    if spec.format.sample != SampleFormat::S16LE
        || spec.format.rate_hz != 44_100
        || spec.format.channels != 2
    {
        return Err(Error::PipeWire(
            "PipeWire capture currently requires S16LE/44100Hz/2ch".to_string(),
        ));
    }

    let (pcm_tx, pcm_rx) = mpsc::channel::<PcmChunk>(CHANNEL_CAPACITY);
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

    let thread_name = format!("airsink-pipewire-capture-{}", spec.name);
    let spawn_result = thread::Builder::new().name(thread_name).spawn(move || {
        if let Err(err) = run_capture_thread(spec, pcm_tx, &mut stop_rx) {
            error!(error = %err, "pipewire capture thread exited with error");
        }
    });

    if let Err(err) = spawn_result {
        return Err(Error::PipeWire(format!(
            "failed to spawn PipeWire capture thread: {err}"
        )));
    }

    Ok(CaptureHandle {
        pcm_rx,
        stop_tx: Some(stop_tx),
    })
}

pub fn route_system_audio_to_virtual_sink(spec: &VirtualSinkSpec) -> Result<AudioRouteSession> {
    let previous_default_sink = query_default_sink().ok();
    let module_id = ensure_virtual_sink(spec)?;
    set_sink_mute(&spec.name, false)?;
    set_sink_volume_percent(&spec.name, 100)?;

    Ok(AudioRouteSession {
        previous_default_sink,
        virtual_sink: spec.name.clone(),
        module_id,
        changed_default_sink: false,
    })
}

impl AudioRouteSession {
    pub fn restore(self) -> Result<()> {
        if self.changed_default_sink {
            let should_restore_default = match query_default_sink() {
                Ok(current_default) => current_default == self.virtual_sink,
                Err(_) => true,
            };

            if should_restore_default {
                if let Some(previous) = &self.previous_default_sink {
                    set_default_sink(previous)?;
                    move_all_sink_inputs(previous)?;
                }
            } else {
                debug!(
                    virtual_sink = %self.virtual_sink,
                    "skipping default sink restore because default changed externally"
                );
            }
        }

        if let Some(module_id) = self.module_id {
            unload_module(module_id)?;
        }

        debug!(virtual_sink = %self.virtual_sink, "restored audio routing session");
        Ok(())
    }
}

fn run_capture_thread(
    spec: VirtualSinkSpec,
    pcm_tx: mpsc::Sender<PcmChunk>,
    stop_rx: &mut oneshot::Receiver<()>,
) -> Result<()> {
    pw::init();

    let mainloop = pw::main_loop::MainLoopBox::new(None)
        .map_err(|err| Error::PipeWire(format!("failed to create mainloop: {err}")))?;
    let context = pw::context::ContextBox::new(mainloop.loop_(), None)
        .map_err(|err| Error::PipeWire(format!("failed to create context: {err}")))?;
    let core = context
        .connect(None)
        .map_err(|err| Error::PipeWire(format!("failed to connect core: {err}")))?;

    let should_stop = Arc::new(AtomicBool::new(false));
    let chunk_bytes =
        (CHUNK_FRAMES as usize) * (spec.format.channels as usize) * SAMPLE_BYTES_S16LE;

    let user_data = CaptureUserData {
        pending: Vec::with_capacity(chunk_bytes * 2),
        pcm_tx,
        format: spec.format,
        chunk_bytes,
        should_stop: should_stop.clone(),
    };

    let mut props = pw::properties::properties! {
        *pw::keys::MEDIA_TYPE => "Audio",
        *pw::keys::MEDIA_CATEGORY => "Capture",
        *pw::keys::MEDIA_ROLE => "Music",
        *pw::keys::STREAM_CAPTURE_SINK => "true",
    };
    props.insert("node.autoconnect", "true");

    let stream = pw::stream::StreamBox::new(&core, "airsink-capture", props)
    .map_err(|err| Error::PipeWire(format!("failed to create stream: {err}")))?;

    let _listener = stream
        .add_local_listener_with_user_data(user_data)
        .state_changed(|_, user_data, old, new| {
            info!(?old, ?new, "pipewire stream state changed");
            if matches!(new, pw::stream::StreamState::Error(_)) {
                user_data.should_stop.store(true, Ordering::Relaxed);
            }
        })
        .process(|stream, user_data| {
            while let Some(mut buffer) = stream.dequeue_buffer() {
                let datas = buffer.datas_mut();
                if datas.is_empty() {
                    continue;
                }

                let mut selected: Option<Vec<u8>> = None;
                let mut fallback: Option<Vec<u8>> = None;

                for data in datas.iter_mut() {
                    let chunk_size = data.chunk().size() as usize;
                    if chunk_size == 0 {
                        continue;
                    }
                    let chunk_offset = data.chunk().offset() as usize;

                    let Some(raw) = data.data() else {
                        continue;
                    };
                    if chunk_offset >= raw.len() {
                        continue;
                    }

                    let available = raw.len() - chunk_offset;
                    let readable = std::cmp::min(chunk_size, available);
                    if readable == 0 {
                        continue;
                    }
                    let end = chunk_offset + readable;
                    let mut bytes = raw[chunk_offset..end].to_vec();

                    if bytes.iter().all(|b| *b == 0)
                        && let Some(non_zero_at) = raw.iter().position(|b| *b != 0)
                    {
                        let alt_end = std::cmp::min(non_zero_at + readable, raw.len());
                        if alt_end > non_zero_at {
                            let alt = raw[non_zero_at..alt_end].to_vec();
                            if alt.iter().any(|b| *b != 0) {
                                bytes = alt;
                            }
                        }
                    }

                    if fallback.is_none() {
                        fallback = Some(bytes.clone());
                    }
                    if bytes.iter().any(|b| *b != 0) {
                        selected = Some(bytes);
                        break;
                    }
                }

                if let Some(bytes) = selected.or(fallback) {
                    user_data.pending.extend_from_slice(&bytes);
                } else {
                    continue;
                }

                while user_data.pending.len() >= user_data.chunk_bytes {
                    let next = user_data
                        .pending
                        .drain(..user_data.chunk_bytes)
                        .collect::<Vec<u8>>();
                    let chunk = PcmChunk {
                        format: user_data.format,
                        frames: CHUNK_FRAMES,
                        pts_host_ns: host_now_ns(),
                        data: Bytes::from(next),
                    };

                    match user_data.pcm_tx.try_send(chunk) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            warn!("pipewire PCM channel full; dropping chunk");
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            user_data.should_stop.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                }
            }
        })
        .register()
        .map_err(|err| Error::PipeWire(format!("failed to register stream listener: {err}")))?;

    let mut audio_info = pw::spa::param::audio::AudioInfoRaw::new();
    audio_info.set_format(pw::spa::param::audio::AudioFormat::S16LE);
    audio_info.set_rate(spec.format.rate_hz);
    audio_info.set_channels(spec.format.channels as u32);

    let format_obj = pw::spa::pod::Object {
        type_: pw::spa::utils::SpaTypes::ObjectParamFormat.as_raw(),
        id: pw::spa::param::ParamType::EnumFormat.as_raw(),
        properties: audio_info.into(),
    };

    let format_bytes = pw::spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &pw::spa::pod::Value::Object(format_obj),
    )
    .map_err(|err| Error::PipeWire(format!("failed to serialize format params: {err}")))?
    .0
    .into_inner();

    let mut params = [pw::spa::pod::Pod::from_bytes(&format_bytes)
        .ok_or_else(|| Error::PipeWire("failed to build PipeWire format pod".to_string()))?];

    stream
        .connect(
            pw::spa::utils::Direction::Input,
            None,
            pw::stream::StreamFlags::AUTOCONNECT
                | pw::stream::StreamFlags::MAP_BUFFERS
                | pw::stream::StreamFlags::RT_PROCESS,
            &mut params,
        )
        .map_err(|err| Error::PipeWire(format!("failed to connect stream: {err}")))?;

    while !should_stop.load(Ordering::Relaxed) {
        match stop_rx.try_recv() {
            Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                should_stop.store(true, Ordering::Relaxed);
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
        }

        let dispatch = mainloop.loop_().iterate(Duration::from_millis(50));
        if dispatch < 0 {
            return Err(Error::PipeWire(
                "PipeWire loop iteration failed while capturing".to_string(),
            ));
        }
    }

    let _ = stream.disconnect();
    info!("pipewire capture thread exited");
    Ok(())
}

fn host_now_ns() -> u64 {
    let origin = MONO_START.get_or_init(Instant::now);
    let nanos = origin.elapsed().as_nanos();
    if nanos > u64::MAX as u128 {
        u64::MAX
    } else {
        nanos as u64
    }
}

fn query_default_sink() -> Result<String> {
    let out = run_pactl(&["info"])?;
    let sink = out
        .lines()
        .find_map(|line| line.strip_prefix("Default Sink: "))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| Error::PipeWire("failed to detect current default sink from pactl".to_owned()))?;
    Ok(sink.to_owned())
}

fn ensure_virtual_sink(spec: &VirtualSinkSpec) -> Result<Option<u32>> {
    if sink_exists(&spec.name)? {
        if sink_matches_format(&spec.name, spec)? {
            return Ok(None);
        }

        if let Some(existing_module_id) = find_null_sink_module_for_name(&spec.name)? {
            warn!(
                sink = %spec.name,
                module_id = existing_module_id,
                "existing virtual sink format is incompatible; recreating sink"
            );
            unload_module(existing_module_id)?;
        } else {
            warn!(
                sink = %spec.name,
                "existing sink is incompatible and not owned by module-null-sink; reusing as-is"
            );
            return Ok(None);
        }
    }

    let desc = spec.description.replace(' ', "_");
    let out = run_pactl(&[
        "load-module",
        "module-null-sink",
        &format!("sink_name={}", spec.name),
        &format!("rate={}", spec.format.rate_hz),
        &format!("channels={}", spec.format.channels),
        "format=s16le",
        &format!("sink_properties=device.description={desc}"),
    ])?;
    let module_id = out.trim().parse::<u32>().map_err(|err| {
        Error::PipeWire(format!(
            "failed to parse module id returned by pactl load-module: {err}"
        ))
    })?;
    Ok(Some(module_id))
}

fn sink_matches_format(name: &str, spec: &VirtualSinkSpec) -> Result<bool> {
    let out = run_pactl(&["list", "short", "sinks"])?;
    let expected_rate = format!("{}Hz", spec.format.rate_hz);
    for line in out.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.get(1) != Some(&name) {
            continue;
        }
        let Some(format_col) = cols.get(3) else {
            return Ok(false);
        };
        let Some(channels_col) = cols.get(4) else {
            return Ok(false);
        };
        let Some(rate_col) = cols.get(5) else {
            return Ok(false);
        };

        let sample_ok = format_col.eq_ignore_ascii_case(&"s16le");
        let channels_ok = *channels_col == format!("{}ch", spec.format.channels);
        let rate_ok = *rate_col == expected_rate;
        return Ok(sample_ok && channels_ok && rate_ok);
    }
    Ok(false)
}

fn find_null_sink_module_for_name(name: &str) -> Result<Option<u32>> {
    let out = run_pactl(&["list", "short", "modules"])?;
    let needle = format!("sink_name={name}");
    for line in out.lines() {
        let mut cols = line.split_whitespace();
        let Some(id_col) = cols.next() else {
            continue;
        };
        let Some(module_name) = cols.next() else {
            continue;
        };
        if module_name != "module-null-sink" {
            continue;
        }
        if !line.contains(&needle) {
            continue;
        }

        let module_id = id_col.parse::<u32>().map_err(|err| {
            Error::PipeWire(format!("failed parsing module id '{id_col}': {err}"))
        })?;
        return Ok(Some(module_id));
    }
    Ok(None)
}

fn sink_exists(name: &str) -> Result<bool> {
    let out = run_pactl(&["list", "short", "sinks"])?;
    for line in out.lines() {
        let mut parts = line.split_whitespace();
        let _idx = parts.next();
        let sink_name = parts.next();
        if sink_name == Some(name) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn select_capture_monitor_name(preferred_sink: &str) -> Result<String> {
    let sink_names_by_id = sink_names_by_id()?;
    if let Some(active_sink_name) = first_uncorked_sink_name(&sink_names_by_id)? {
        return Ok(format!("{active_sink_name}.monitor"));
    }

    if let Ok(default_sink) = query_default_sink()
        && !default_sink.is_empty()
    {
        return Ok(format!("{default_sink}.monitor"));
    }

    Ok(format!("{preferred_sink}.monitor"))
}

fn sink_names_by_id() -> Result<std::collections::HashMap<String, String>> {
    let out = run_pactl(&["list", "short", "sinks"])?;
    let mut result = std::collections::HashMap::new();
    for line in out.lines() {
        let mut parts = line.split_whitespace();
        let Some(id) = parts.next() else {
            continue;
        };
        let Some(name) = parts.next() else {
            continue;
        };
        result.insert(id.to_owned(), name.to_owned());
    }
    Ok(result)
}

fn first_uncorked_sink_name(
    sink_names_by_id: &std::collections::HashMap<String, String>,
) -> Result<Option<String>> {
    let out = run_pactl(&["list", "sink-inputs"])?;

    let mut sink_id: Option<String> = None;
    let mut corked: Option<bool> = None;

    let finalize = |sink_id: &Option<String>, corked: &Option<bool>| -> Option<String> {
        if *corked != Some(false) {
            return None;
        }
        let sink_id = sink_id.as_ref()?;
        sink_names_by_id.get(sink_id).cloned()
    };

    for raw_line in out.lines() {
        let line = raw_line.trim();
        if line.starts_with("Sink Input #") {
            if let Some(name) = finalize(&sink_id, &corked) {
                return Ok(Some(name));
            }
            sink_id = None;
            corked = None;
            continue;
        }

        if let Some(value) = line.strip_prefix("Sink:") {
            sink_id = Some(value.trim().to_owned());
            continue;
        }

        if let Some(value) = line.strip_prefix("Corked:") {
            corked = Some(value.trim().eq_ignore_ascii_case("yes"));
            continue;
        }
    }

    Ok(finalize(&sink_id, &corked))
}

fn find_source_id_by_name(name: &str) -> Result<Option<String>> {
    let out = run_pactl(&["list", "short", "sources"])?;
    for line in out.lines() {
        let mut parts = line.split_whitespace();
        let Some(source_id) = parts.next() else {
            continue;
        };
        let Some(source_name) = parts.next() else {
            continue;
        };
        if source_name == name {
            return Ok(Some(source_id.to_owned()));
        }
    }
    Ok(None)
}

fn set_default_sink(name: &str) -> Result<()> {
    run_pactl(&["set-default-sink", name]).map(|_| ())
}

fn move_all_sink_inputs(target_sink: &str) -> Result<()> {
    let out = run_pactl(&["list", "short", "sink-inputs"])?;
    for line in out.lines() {
        let mut parts = line.split_whitespace();
        let Some(input_id) = parts.next() else {
            continue;
        };
        run_pactl(&["move-sink-input", input_id, target_sink])?;
        let _ = run_pactl(&["set-sink-input-mute", input_id, "0"]);
        let _ = run_pactl(&["set-sink-input-volume", input_id, "100%"]);
    }
    Ok(())
}

fn set_sink_mute(name: &str, muted: bool) -> Result<()> {
    let mute_value = if muted { "1" } else { "0" };
    run_pactl(&["set-sink-mute", name, mute_value]).map(|_| ())
}

fn set_sink_volume_percent(name: &str, percent: u16) -> Result<()> {
    run_pactl(&["set-sink-volume", name, &format!("{percent}%")]).map(|_| ())
}

fn unload_module(module_id: u32) -> Result<()> {
    run_pactl(&["unload-module", &module_id.to_string()]).map(|_| ())
}

fn run_pactl(args: &[&str]) -> Result<String> {
    let output = Command::new("pactl").args(args).output().map_err(|err| {
        Error::PipeWire(format!(
            "failed to execute pactl {:?}: {err}. Install PulseAudio tools (pactl) or run within the Nix dev shell",
            args
        ))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(Error::PipeWire(format!(
            "pactl {:?} failed (status {}): {}",
            args,
            output
                .status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string()),
            stderr
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
