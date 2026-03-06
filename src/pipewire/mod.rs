use ::pipewire as pw;
use bytes::Bytes;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

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

    let _virtual_sink = core
        .create_object::<pw::node::Node>(
            "adapter",
            &pw::properties::properties! {
                "factory.name" => "support.null-audio-sink",
                "node.name" => spec.name.as_str(),
                "node.description" => spec.description.as_str(),
                "media.class" => "Audio/Sink",
                "audio.rate" => "44100",
                "audio.channels" => "2",
                "audio.position" => "FL,FR",
                "object.linger" => "true",
            },
        )
        .map_err(|err| Error::PipeWire(format!("failed to create virtual sink: {err}")))?;

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

    let stream = pw::stream::StreamBox::new(
        &core,
        "airsink-pipewire-monitor",
        pw::properties::properties! {
            *pw::keys::MEDIA_TYPE => "Audio",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Music",
            *pw::keys::STREAM_CAPTURE_SINK => "true",
            "target.object" => spec.name.as_str(),
        },
    )
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

                let data = &mut datas[0];
                let chunk_size = data.chunk().size() as usize;
                if chunk_size == 0 {
                    continue;
                }

                let Some(raw) = data.data() else {
                    continue;
                };

                let readable = std::cmp::min(chunk_size, raw.len());
                user_data.pending.extend_from_slice(&raw[..readable]);

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
