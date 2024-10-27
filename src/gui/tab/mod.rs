use crate::Message;

use iced::{Task as Command, Element};
use iced::widget::{button, column, pick_list, radio, text, Column, Container, scrollable};

pub struct Tab {
}

impl Tab {
    pub fn new() -> Self {
        Self{}
    }
}