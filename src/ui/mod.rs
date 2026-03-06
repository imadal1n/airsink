//! Terminal User Interface for AirSink.
//!
//! This module implements the `ratatui`-based frontend, handling user input,
//! rendering the application state, and communicating with the core supervisor
//! via `AppHandle`.

use std::io::{self, Stdout};
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Wrap},
};
use tokio::time::interval;

use crate::app::{AppHandle, Command};
use crate::core::{AppModel, ConnState};

const C_BASE: Color = Color::Rgb(30, 30, 46); // #1e1e2e
const C_SURFACE0: Color = Color::Rgb(49, 50, 68); // #313244
const C_TEXT: Color = Color::Rgb(205, 214, 244); // #cdd6f4
const C_SUBTEXT0: Color = Color::Rgb(166, 173, 200); // #a6adc8
const C_BLUE: Color = Color::Rgb(137, 180, 250); // #89b4fa
const C_GREEN: Color = Color::Rgb(166, 227, 161); // #a6e3a1
const C_YELLOW: Color = Color::Rgb(249, 226, 175); // #f9e2af
const C_RED: Color = Color::Rgb(243, 139, 168); // #f38ba8
const C_MAUVE: Color = Color::Rgb(203, 166, 247); // #cba6f7
const C_LAVENDER: Color = Color::Rgb(180, 190, 254); // #b4befe

/// Runs the TUI event loop.
///
/// This function takes ownership of the terminal, enables raw mode, and runs the
/// main application loop until a quit command is issued or an error occurs.
pub async fn run(mut handle: AppHandle) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = UiState::new();

    let model = handle.model_rx.borrow().clone();
    state.update_from_model(&model);

    let mut ticker = interval(Duration::from_millis(16));
    let res = run_loop(&mut terminal, &mut state, &mut handle, &mut ticker).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &mut UiState,
    handle: &mut AppHandle,
    ticker: &mut tokio::time::Interval,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, state))?;

        tokio::select! {
            _ = ticker.tick() => {
                if handle.model_rx.has_changed()? {
                    let model = handle.model_rx.borrow_and_update().clone();
                    state.update_from_model(&model);
                }
            }
        }

        if event::poll(Duration::from_millis(0))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && let Some(cmd) = state.handle_input(key)
        {
            if let Command::Quit = cmd {
                handle.cmd_tx.send(Command::Quit).await.ok();
                return Ok(());
            }
            handle.cmd_tx.send(cmd).await.ok();
        }
    }
}

struct UiState {
    model: AppModel,
    list_state: ListState,
    logs: Vec<String>,
    pin_input: String,
    pin_mode: bool,
}

fn current_time() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    let secs = since_the_epoch.as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

impl UiState {
    fn new() -> Self {
        Self {
            model: AppModel::default(),
            list_state: ListState::default(),
            logs: Vec::new(),
            pin_input: String::new(),
            pin_mode: false,
        }
    }

    fn update_from_model(&mut self, model: &AppModel) {
        if self.model.state != model.state {
            let msg = format!(
                "[{}] State changed: {}",
                current_time(),
                state_desc(&model.state)
            );
            self.logs.push(msg);
            if self.logs.len() > 100 {
                self.logs.remove(0);
            }

            if let ConnState::Pairing { .. } = model.state {
                if !matches!(self.model.state, ConnState::Pairing { .. }) {
                    self.pin_mode = true;
                    self.pin_input.clear();
                    self.logs.push(format!("[{}] Enter PIN...", current_time()));
                }
            } else {
                self.pin_mode = false;
            }
        }

        if let Some(err) = &model.last_error
            && self.model.last_error.as_ref() != Some(err)
        {
            let msg = format!("[{}] ERROR: {}", current_time(), err);
            self.logs.push(msg);
        }

        self.model = model.clone();

        if self.list_state.selected().is_none() && !self.model.devices.is_empty() {
            self.list_state.select(Some(0));
        }
    }

    fn handle_input(&mut self, key: event::KeyEvent) -> Option<Command> {
        if self.pin_mode {
            return match key.code {
                KeyCode::Esc => {
                    self.pin_mode = false;
                    None
                }
                KeyCode::Enter => {
                    let pin = self.pin_input.clone();
                    self.pin_input.clear();
                    self.pin_mode = false;
                    Some(Command::PairWithPin { pin })
                }
                KeyCode::Backspace => {
                    self.pin_input.pop();
                    None
                }
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    self.pin_input.push(c);
                    None
                }
                KeyCode::Char('q') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                    Some(Command::Quit)
                }
                _ => None,
            };
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => Some(Command::Quit),
            KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                Some(Command::Quit)
            }

            KeyCode::Up | KeyCode::Char('k') => {
                let i = match self.list_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            0
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.list_state.select(Some(i));
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let i = match self.list_state.selected() {
                    Some(i) => {
                        if i >= self.model.devices.len().saturating_sub(1) {
                            self.model.devices.len().saturating_sub(1)
                        } else {
                            i + 1
                        }
                    }
                    None => 0,
                };
                self.list_state.select(Some(i));
                None
            }

            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(idx) = self.list_state.selected()
                    && let Some(device) = self.model.devices.get(idx)
                {
                    match &self.model.state {
                        ConnState::Selected { device: d } | ConnState::Connected { device: d }
                            if d.id == device.id =>
                        {
                            return Some(Command::StartStreaming);
                        }
                        ConnState::Streaming { device: d } if d.id == device.id => {
                            return Some(Command::StopStreaming);
                        }
                        _ => {
                            return Some(Command::SelectDevice(device.id.clone()));
                        }
                    }
                }
                None
            }

            KeyCode::Char('s') => Some(Command::StopStreaming),

            KeyCode::Char('+') | KeyCode::Char('=') => {
                let new_vol = (self.model.volume + 0.05).min(1.0);
                Some(Command::SetVolume(new_vol))
            }
            KeyCode::Char('-') | KeyCode::Char('_') => {
                let new_vol = (self.model.volume - 0.05).max(0.0);
                Some(Command::SetVolume(new_vol))
            }

            KeyCode::Char('p') => {
                if let ConnState::Pairing { .. } = self.model.state {
                    self.pin_mode = !self.pin_mode;
                    if self.pin_mode {
                        self.pin_input.clear();
                    }
                }
                None
            }

            _ => None,
        }
    }
}

fn state_desc(state: &ConnState) -> String {
    match state {
        ConnState::Idle => "Idle".to_string(),
        ConnState::Discovering => "Discovering...".to_string(),
        ConnState::Selected { device } => format!("Selected: {}", device.name),
        ConnState::Pairing { device } => format!("Pairing: {}", device.name),
        ConnState::Verifying { device } => format!("Verifying: {}", device.name),
        ConnState::Connecting { device } => format!("Connecting: {}", device.name),
        ConnState::Connected { device } => format!("Connected: {}", device.name),
        ConnState::Streaming { device } => format!("Streaming: {}", device.name),
        ConnState::Reconnecting { device, attempt } => {
            format!("Reconnecting: {} (#{})", device.name, attempt)
        }
        ConnState::Failed { message, .. } => format!("Failed: {}", message),
    }
}

fn ui(f: &mut Frame, state: &mut UiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(f.area());

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[0]);

    render_devices(f, main_chunks[0], state);
    render_status(f, main_chunks[1], state);
    render_logs(f, chunks[1], state);
    render_footer(f, chunks[2], state);

    if state.pin_mode {
        render_pin_popup(f, state);
    }
}

fn render_devices(f: &mut Frame, area: Rect, state: &mut UiState) {
    let items: Vec<ListItem> = state
        .model
        .devices
        .iter()
        .map(|d| {
            let is_selected = match &state.model.state {
                ConnState::Selected { device }
                | ConnState::Pairing { device }
                | ConnState::Verifying { device }
                | ConnState::Connecting { device }
                | ConnState::Connected { device }
                | ConnState::Streaming { device }
                | ConnState::Reconnecting { device, .. } => d.id == device.id,
                _ => false,
            };

            let style = if is_selected {
                Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_TEXT)
            };

            ListItem::new(d.name.clone()).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_LAVENDER))
                .title(" Devices "),
        )
        .highlight_style(
            Style::default()
                .bg(C_SURFACE0)
                .fg(C_BLUE)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(list, area, &mut state.list_state);
}

fn render_status(f: &mut Frame, area: Rect, state: &UiState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_LAVENDER))
        .title(" Status ");
    f.render_widget(block.clone(), area);

    let inner = block.inner(area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(3),
        ])
        .split(inner);

    let status_text = state_desc(&state.model.state);
    let status_color = match state.model.state {
        ConnState::Streaming { .. } => C_GREEN,
        ConnState::Pairing { .. }
        | ConnState::Verifying { .. }
        | ConnState::Reconnecting { .. } => C_YELLOW,
        ConnState::Failed { .. } => C_RED,
        _ => C_TEXT,
    };

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("State: "),
            Span::styled(status_text, Style::default().fg(status_color)),
        ])),
        chunks[0],
    );

    let device_name = match &state.model.state {
        ConnState::Selected { device }
        | ConnState::Pairing { device }
        | ConnState::Verifying { device }
        | ConnState::Connecting { device }
        | ConnState::Connected { device }
        | ConnState::Streaming { device }
        | ConnState::Reconnecting { device, .. } => &device.name,
        ConnState::Failed {
            device: Some(d), ..
        } => &d.name,
        _ => "-",
    };

    f.render_widget(
        Paragraph::new(format!("Device: {}", device_name)).style(Style::default().fg(C_TEXT)),
        chunks[1],
    );

    let vol_percent = (state.model.volume * 100.0) as u16;
    let gauge = Gauge::default()
        .block(Block::default().title("Volume").borders(Borders::NONE))
        .gauge_style(Style::default().fg(C_MAUVE).bg(C_SURFACE0))
        .ratio(state.model.volume as f64)
        .label(format!("{}%", vol_percent));
    f.render_widget(gauge, chunks[2]);
}

fn render_logs(f: &mut Frame, area: Rect, state: &UiState) {
    let logs_to_show: Vec<ListItem> = state
        .logs
        .iter()
        .rev()
        .take(area.height as usize - 2)
        .rev()
        .map(|s| ListItem::new(s.as_str()).style(Style::default().fg(C_SUBTEXT0)))
        .collect();

    let list = List::new(logs_to_show).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_LAVENDER))
            .title(" Log "),
    );
    f.render_widget(list, area);
}

fn render_footer(f: &mut Frame, area: Rect, _state: &UiState) {
    let keys = "[q]uit [↑↓]select [enter]connect [s]top [+/-]vol [p]in";
    f.render_widget(
        Paragraph::new(keys)
            .style(Style::default().fg(C_SUBTEXT0).bg(C_BASE))
            .alignment(Alignment::Center),
        area,
    );
}

fn render_pin_popup(f: &mut Frame, state: &UiState) {
    let area = centered_rect(60, 20, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .title(" Enter PIN ")
        .borders(Borders::ALL)
        .style(Style::default().bg(C_BASE).fg(C_YELLOW));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let text = format!(
        "PIN: {}\n\nEnter the 4-digit code shown on the device.\nPress Enter to submit, Esc to cancel.",
        state.pin_input
    );
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Center)
            .style(Style::default().fg(C_TEXT)),
        inner,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
