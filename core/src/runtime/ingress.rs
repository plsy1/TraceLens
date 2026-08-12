use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};

use tracelens_events::TraceEvent;

#[derive(Debug, Clone)]
pub struct EventQueueStats {
    capacity: usize,
    dropped: Arc<AtomicU64>,
}

impl EventQueueStats {
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
pub struct EventSender {
    sender: mpsc::SyncSender<TraceEvent>,
    stats: EventQueueStats,
}

impl EventSender {
    pub fn try_send(&self, event: TraceEvent) -> bool {
        match self.sender.try_send(event) {
            Ok(()) => true,
            Err(mpsc::TrySendError::Full(_)) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(mpsc::TrySendError::Disconnected(_)) => false,
        }
    }

    pub fn stats(&self) -> EventQueueStats {
        self.stats.clone()
    }
}

pub fn event_channel(capacity: usize) -> (EventSender, mpsc::Receiver<TraceEvent>) {
    assert!(capacity > 0, "event queue capacity must be non-zero");
    let (sender, receiver) = mpsc::sync_channel(capacity);
    let stats = EventQueueStats {
        capacity,
        dropped: Arc::new(AtomicU64::new(0)),
    };
    (EventSender { sender, stats }, receiver)
}

#[cfg(test)]
mod tests {
    use super::event_channel;
    use crate::Core;

    #[test]
    fn full_event_queue_drops_without_blocking_and_reports_it() {
        let (sender, receiver) = event_channel(1);
        let stats = sender.stats();
        assert!(sender.try_send(Core::example_event()));
        assert!(!sender.try_send(Core::example_event()));
        assert_eq!(stats.capacity(), 1);
        assert_eq!(stats.dropped(), 1);
        assert!(receiver.try_recv().is_ok());
    }
}
