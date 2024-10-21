#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Frame, Label, Spacing, Vec2};

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([320.0, 240.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Frida",
        options,
        Box::new(|cc| {
            Ok(Box::<App>::default())
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
    configs: Configs
}

impl Default for App {
    fn default() -> Self {
        Self {
            screen: AppScreens::Configs,
            configs: Configs::default()
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
                    self.configs.ui(ui);
                }
                AppScreens::Log => {

                }
            }
        });
    }
}

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
#[derive(PartialEq)]
struct Configs {
    num: u32,
    btn_status: bool,
}

impl Default for Configs {
    fn default() -> Self {
        Self {
            num: 32,
            btn_status: true
        }
    }
}

impl Configs {
    fn ui(&mut self, ui: &mut egui::Ui) {
        let Self {
            num,
            btn_status
        } = self;

        egui::SidePanel::left("clist")
            .resizable(false)
            .exact_width(150.0)
            .show_inside(ui, |ui| {
                
            });

        

        egui::CentralPanel::default()
            .show_inside(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 20.0;

                ui.group(|ui| {
                    ui.spacing_mut().item_spacing.y = 5.0;
                    ui.set_width(ui.available_width());
                    ui.label("Interface:");
                    ui.label("Status:");
                    ui.label("Public key:");
                    ui.label("Address:");
                    if ui.add_visible(self.btn_status, egui::Button::new("Activate")).clicked() {
                        self.btn_status = false;
                    };
                    if ui.add_visible(!self.btn_status, egui::Button::new("Deactivate")).clicked() {
                        self.btn_status = true;
                    }
                });

                ui.group(|ui| {
                    ui.spacing_mut().item_spacing.y = 5.0;
                    ui.set_width(ui.available_width());
                    ui.label("Public key:");
                    ui.label("Endpoint:");
                });
            });
    }
}