pub use crate::macos::arm64_runtime::{
    bind_process_fd_target, block_active_arm64_thread_on_cond, block_current_arm64_thread_on_cond,
    close_directory_stream, close_synthetic_fd, dispatch_pending_arm64_thread,
    dispatch_pending_arm64_thread_by_id, fstat_guest_file, has_pipe_endpoint_ref,
    open_directory_stream, open_guest_file, read_guest_directory_entry, read_guest_file,
    register_process_fd, resolve_directory_stream_fd, resolve_process_fd_target, stat_guest_path,
    terminate_synthetic_process, wake_arm64_cond_waiters, wake_one_arm64_cond_waiter,
    yield_active_arm64_thread, ActiveArm64Thread, Arm64ThreadRuntime, ForkParentResume,
    PendingArm64Thread, SyntheticFdTarget, SyntheticKeventRegistration, SyntheticPipe,
    SyntheticProcess, WaitingArm64Thread, ARM64_SYNTHETIC_THREAD_STACK_BASE,
    ARM64_SYNTHETIC_THREAD_STACK_SIZE, MAX_SYNTHETIC_THREADS,
};

pub type SyntheticOsRuntime = crate::macos::arm64_runtime::Arm64SyntheticOsRuntime;
pub type ThreadContext = crate::macos::arm64_runtime::Arm64ThreadContext;

pub fn save_context(
    emu: &mut crate::UnicornEmulator,
) -> crate::macos::arm64_runtime::Arm64ThreadContext {
    crate::macos::arm64_runtime::save_arm64_context(emu)
}

pub fn restore_context(
    emu: &mut crate::UnicornEmulator,
    ctx: &crate::macos::arm64_runtime::Arm64ThreadContext,
    retval: u64,
    resume_pc: u64,
) -> Result<(), crate::macos::MacOsError> {
    crate::macos::arm64_runtime::restore_arm64_context(emu, ctx, retval, resume_pc)
        .map_err(|err| crate::macos::MacOsError::LoaderError(err.to_string()))
}

pub fn wake_one_cond_waiter(
    runtime: &mut crate::macos::arm64_runtime::Arm64ThreadRuntime,
) -> Option<(u64, u64)> {
    crate::macos::arm64_runtime::wake_one_arm64_cond_waiter(runtime)
}

pub fn wake_cond_waiters(
    runtime: &mut crate::macos::arm64_runtime::Arm64ThreadRuntime,
    limit: usize,
) -> Vec<(u64, u64)> {
    crate::macos::arm64_runtime::wake_arm64_cond_waiters(runtime, limit)
}
