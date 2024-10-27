use crate::Tab;
use crate::TabButton;

use crate::Message;

use iced::{Task as Command, Element};
use iced::widget::{button, column, pick_list, radio, text, Column, Container, scrollable};

pub struct TabPanel {
    tabs: Vec<(TabButton, Tab)>,
    current_tab: u8
}

impl TabPanel {
    pub fn view(&self) -> Element<Message> {        
        //let selected_tab = self.tabs.iter()
        //         .filter(|t| t.0.id == self.current_tab)
        //         .next();

        //if selected_tab.is_some() {}

        let mut btns: Vec<Element<Message>> = Vec::new();

        self.tabs.iter().for_each(|t| {
            btns.push(t.0.view(self.current_tab).into());   
        });

        scrollable(iced::widget::Column::with_children(btns)).into()
    }

    pub fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::ButtonPressed(id) => {
                self.current_tab = id;
            }
            _ => {}
        }
        Command::none()
    }

    pub fn new() -> Self {
        Self { tabs: Vec::new(), current_tab: 0 }
    }

    pub fn push_tab(&mut self, button: TabButton, tab: Tab) {
        self.tabs.push((button, tab));
    }
}