use std::fmt;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObservationLevel {
    #[default]
    L1 = 1,
    L2 = 2,
    L3 = 3,
    L4 = 4,
    L5 = 5,
}

impl ObservationLevel {
    pub fn from_number(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::L1),
            2 => Some(Self::L2),
            3 => Some(Self::L3),
            4 => Some(Self::L4),
            5 => Some(Self::L5),
            _ => None,
        }
    }
}

impl fmt::Display for ObservationLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "L{}", *self as u8)
    }
}
