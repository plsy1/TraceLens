use std::sync::mpsc::{self, Receiver, Sender};

use tracelens_events::TraceEvent;

#[derive(Debug, Default)]
pub struct EventBus {
    subscribers: Vec<Sender<TraceEvent>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subscribe(&mut self) -> Receiver<TraceEvent> {
        let (sender, receiver) = mpsc::channel();
        self.subscribers.push(sender);
        receiver
    }

    pub fn publish(&mut self, event: TraceEvent) {
        self.subscribers
            .retain(|subscriber| subscriber.send(event.clone()).is_ok());
    }
}
