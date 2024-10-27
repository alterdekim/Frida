use crate::Message;

use iced::{Task as Command, Element};
use iced::widget::{button, column, pick_list, radio, text, Column, Container, scrollable};

#[derive(Debug, Clone)]
pub struct TabButton {
    label: String, 
    pub id: u8,
}

impl TabButton {
    pub fn new<S: AsRef<str>>(label: S, id: u8) -> Self {
        Self { label: label.as_ref().to_string(), id }
    }

    pub fn view(&self, selected_id: u8) -> Container<Message> {
        let label = text(&self.label);

        let button = button(label).style(if self.id == selected_id {
            button::text
        } else {
            button::primary
        });
        Container::new(button.on_press(Message::ButtonPressed(self.id)).padding(8))
    }
}