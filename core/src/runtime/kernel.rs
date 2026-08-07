//! Kernel eBPF runtime boundary.

#[derive(Debug, Default)]
pub struct KernelRuntime {
    attached: bool,
}

impl KernelRuntime {
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    pub fn attach(&mut self) {
        // libbpf loading will be implemented after the event ABI is validated
        // against the first process/network probes.
        self.attached = true;
    }

    pub fn detach(&mut self) {
        self.attached = false;
    }
}
