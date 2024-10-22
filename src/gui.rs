#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Context, Frame, Label, ScrollArea, Spacing, Vec2};
use egui_file::FileDialog;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
  };
use egui_extras::{Column, TableBuilder};
use log::{info, error};
use crate::config::ClientConfiguration;
use log::LevelFilter;
use env_logger::Builder;

mod toggle_switch;
mod config;

fn get_configs_dir() -> PathBuf {
    let mut p = dirs::home_dir().unwrap();
    p.push(".frida");
    p
}

fn main() -> eframe::Result {
    egui_logger::builder().max_level(LevelFilter::Error).init().unwrap();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([640.0, 480.0]),
        ..Default::default()
    };
    let cfgs = std::fs::read_dir(get_configs_dir()).unwrap();
    let mut cv = Vec::new();
    for path in cfgs {
        cv.push(path.unwrap().path());
    }
    eframe::run_native(
        "Frida",
        options,
        Box::new(|cc| {
            Ok(Box::new(App::new(cv)))
        }),
    )
}

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, PartialEq)]
enum AppScreens {
    Configs,
    Log
}

struct App {
    screen: AppScreens,
    configs: Configs,
    logs: Logs,
}

impl App {
    fn new(cfgs: Vec<PathBuf>) -> Self {
        Self {
            screen: AppScreens::Configs,
            configs: Configs::new(cfgs),
            logs: Logs::default()
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.screen, AppScreens::Configs, "Configs");
                ui.selectable_value(&mut self.screen, AppScreens::Log, "Log");
            });
            ui.separator();
            match self.screen {
                AppScreens::Configs => {
                    self.configs.ui(ui, ctx);
                }
                AppScreens::Log => {
                    self.logs.ui(ui, ctx);
                }
            }
        });
    }
}

struct Logs {
}

impl Default for Logs {
    fn default() -> Self {
        Self{}
    }
}

impl Logs {
    fn ui(&mut self, ui: &mut egui::Ui, ctx: &Context) {
        egui::CentralPanel::default()
            .show_inside(ui, |ui| {
                egui_logger::logger_ui().show(ui);
            });
    }
}

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
#[derive(Debug)]
struct Configs {
    num: u32,
    btn_status: bool,
    open_config_dialog: Option<FileDialog>,
    cfgs: Vec<PathBuf>,
    selected_cfg: Option<(ClientConfiguration, String)>
}

impl Configs {
    fn new(cfgs: Vec<PathBuf>) -> Self {
        Self {
            num: 32,
            btn_status: false,
            open_config_dialog: None,
            cfgs,
            selected_cfg: None
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, ctx: &Context) {
        let Self {
            num,
            btn_status,
            open_config_dialog,
            cfgs, 
            selected_cfg
        } = self;

        egui::SidePanel::left("clist")
            .resizable(false)
            .exact_width(150.0)
            .show_inside(ui, |ui| {
                ScrollArea::vertical()
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        self.cfgs.iter().for_each(|f| {
                            let filename = f.file_name().unwrap().to_str().unwrap();
                            let mut b = egui::Button::new(filename);
                            if self.selected_cfg.is_some() && self.selected_cfg.as_ref().unwrap().1 == filename.to_string() {
                                b = b.fill(egui::Color32::LIGHT_BLUE); 
                            }
                            let e = ui.add_sized(
                                Vec2::new(ui.available_width(), 0.0),
                                b,
                            );
                            if e.clicked() {
                                let data = std::fs::read(f.clone());
                                let cfg_raw = &String::from_utf8(data.unwrap()).unwrap();
                                let config: ClientConfiguration = serde_yaml::from_str(cfg_raw).expect("Bad client config file structure");
                                self.selected_cfg = Some((config, filename.to_string()));
                            }
                        });
                    });
            });

        egui::CentralPanel::default()
            .show_inside(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 20.0;
                
                if self.selected_cfg.is_none() { return; }

                let cfg = &self.selected_cfg.as_ref().unwrap().0;

                ui.group(|ui| {
                    ui.spacing_mut().item_spacing.y = 5.0;
                    ui.set_width(ui.available_width());
                    ui.label(format!("Interface: {}", &self.selected_cfg.as_ref().unwrap().1));
                    ui.label("Status: inactive");
                    ui.label(format!("Public key: {}", &cfg.client.public_key));
                    ui.label(format!("Address: {}", &cfg.client.address));
                    ui.horizontal(|ui| {
                        ui.label("Activate: ");
                        ui.add(crate::toggle_switch::toggle(&mut self.btn_status));
                    });
                });

                ui.group(|ui| {
                    ui.spacing_mut().item_spacing.y = 5.0;
                    ui.set_width(ui.available_width());
                    ui.label(format!("Public key: {}", &cfg.server.public_key));
                    ui.label(format!("Endpoint: {}", &cfg.server.endpoint));
                    ui.label(format!("Keepalive: {}", &cfg.server.keepalive));
                });
            });

        egui::TopBottomPanel::bottom("btns")
            .resizable(false)
            .show_inside(ui, |ui| {
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;

                    if ui.button("Add config").clicked() {
                        let filter = Box::new({
                            let ext = Some(OsStr::new("yaml"));
                            move |path: &Path| -> bool { path.extension() == ext }
                        });
                        let mut dialog = FileDialog::open_file(None).show_files_filter(filter);
                        dialog.open();

                        self.open_config_dialog = Some(dialog);
                    }

                    if let Some(dialog) = &mut self.open_config_dialog {
                        if dialog.show(ctx).selected() {
                            if let Some(file) = dialog.path() {
                                let mut h = get_configs_dir();
                                std::fs::create_dir_all(&h);
                                h.push(file.file_name().unwrap());
                                std::fs::copy(file, &h);
                                self.cfgs.push(h);
                            }
                        }
                    }

                    if ui.button("Remove selected").clicked() {
                        if self.selected_cfg.is_none() { return; }
                        let mut fp = get_configs_dir();
                        fp.push(&self.selected_cfg.as_ref().unwrap().1);
                        let path = &fp.to_str().unwrap().to_string();
                        if let Ok(r) = std::fs::remove_file(path) {
                            for i in 0..self.cfgs.len() {
                                if &self.selected_cfg.as_ref().unwrap().1 == self.cfgs[i].file_name().unwrap().to_str().unwrap() {
                                    self.cfgs.remove(i);
                                    break;
                                }
                            }
                            self.selected_cfg = None;
                        }
                    }
                });
            });
    }
}