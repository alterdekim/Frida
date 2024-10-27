#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod tab;
pub mod tab_button;
pub mod tab_panel;

use std::{
    ffi::OsStr,
    path::{Path, PathBuf}, sync::mpsc::SyncSender,
    borrow::Cow
  };
use std::sync::mpsc;
use log::{info, error};
use log::LevelFilter;
use env_logger::Builder;
use tray_item::{IconSource, TrayItem};
use iced::{widget::container, window, Element, Settings, Task as Command};
use iced::widget::{button, column, pick_list, radio, text, Column, Container, scrollable};

use crate::tab_button::TabButton;
use crate::tab_panel::TabPanel;
use crate::tab::Tab;

fn get_configs_dir() -> PathBuf {
    let mut p = dirs::home_dir().unwrap();
    p.push(".frida");
    p
}

#[derive(Debug, Clone)]
pub enum Message {
    ButtonPressed(u8),
    ChangeUI
}


struct State {
    tab_panel: TabPanel,
}

impl State {
    fn new() -> Self {
        Self { tab_panel: TabPanel::new() }
    }
}

enum App {
    Preloaded,
    Loaded(State)
}

impl App {
    pub fn new() -> (Self, Command<Message>) {
        (Self::Preloaded, Command::done(Message::ChangeUI))
    }

    pub fn view(&self) -> Element<Message> {
        match self {
            App::Preloaded => {
                return container(text("Loading")).into();
            }
            App::Loaded(state) => {
                return state.tab_panel.view();
            }
        }
    }

    pub fn update(&mut self, message: Message) -> Command<Message> {
        match self {
            App::Preloaded => {
                let mut panel = TabPanel::new();
                panel.push_tab(TabButton::new("First", 0), Tab::new());
                *self = App::Loaded(State { tab_panel: panel });
                return Command::done(Message::ChangeUI);
            }
            App::Loaded(state) => {
                state.tab_panel.update(message);
            }
        }
        Command::none()
    }
}

fn main() -> iced::Result {
    iced::application("title", App::update, App::view)
        .window_size((640.0, 480.0))
        .run_with(App::new)
}