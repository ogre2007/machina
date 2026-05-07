//! Synthetic Apple framework imports used by the current macOS userland runner.

use std::collections::HashMap;

use crate::macos::runner_support::{
    emit_arm64_event, record_arm64_import, Arm64ImportTracker, Arm64SharedState,
};
use crate::macos::{process_event, runtime_process_metadata, Emulator, SharedTraceBus};
use crate::UnicornEmulator;

fn read_guest_bytes(emu: &mut dyn Emulator, addr: u64, len: usize, cap: usize) -> Vec<u8> {
    if addr == 0 || len == 0 {
        return Vec::new();
    }
    emu.read_memory(addr, len.min(cap)).unwrap_or_default()
}

fn read_guest_u64_array(emu: &mut dyn Emulator, addr: u64, count: usize, cap: usize) -> Vec<u64> {
    if addr == 0 || count == 0 {
        return Vec::new();
    }
    let capped = count.min(cap);
    let mut out = Vec::with_capacity(capped);
    for i in 0..capped {
        let Ok(bytes) = emu.read_memory(addr + (i as u64 * 8), 8) else {
            break;
        };
        let Ok(array) = <[u8; 8]>::try_from(bytes.as_slice()) else {
            break;
        };
        out.push(u64::from_le_bytes(array));
    }
    out
}

fn install_returning_hook<F>(
    emulator: &mut UnicornEmulator,
    addr: u64,
    handler: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: Fn(&mut machina::UnicornEmulator) -> u64 + Send + 'static,
{
    emulator.add_code_hook(
        addr,
        addr + 4,
        move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
            let result = handler(emu);
            let lr = emu.read_reg("lr").unwrap_or(0);
            let _ = emu.write_reg("x0", result);
            if lr != 0 {
                let _ = emu.write_reg("pc", lr);
            }
        },
    )?;
    Ok(())
}

pub fn install_apple_imports(
    emulator: &mut UnicornEmulator,
    stub_map: &HashMap<String, u64>,
    trace_bus: &Option<SharedTraceBus>,
    shared_state: &Arm64SharedState,
    import_tracker: &Arm64ImportTracker,
    process_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = runtime_process_metadata(process_name.to_string());

    if let Some(&addr) = stub_map.get("_CFStringCreateWithBytes") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let bytes_ptr = emu.read_reg("x1").unwrap_or(0);
            let len = emu.read_reg("x2").unwrap_or(0) as usize;
            let encoding = emu.read_reg("x3").unwrap_or(0);
            let data = read_guest_bytes(emu, bytes_ptr, len, 64 * 1024);
            let string_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_string(data.clone(), encoding)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFStringCreateWithBytes(bytes=0x{:X}, len={}, enc=0x{:X}) -> 0x{:X}",
                    bytes_ptr, len, encoding, string_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfstring", "CFStringCreateWithBytes")
                    .arg("Bytes", format!("0x{:X}", bytes_ptr))
                    .arg("Len", len.to_string())
                    .arg("Encoding", format!("0x{:X}", encoding))
                    .arg("Result", format!("0x{:X}", string_ref))
                    .arg("Preview", crate::macos::lossy_data_preview(&data, 128)),
            );
            string_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFStringCreateExternalRepresentation") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let string_ref = emu.read_reg("x1").unwrap_or(0);
            let data_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                let Some(data) = runtime.object_data(string_ref) else {
                    return 0;
                };
                runtime.alloc_data(data)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFStringCreateExternalRepresentation(string=0x{:X}) -> 0x{:X}",
                    string_ref, data_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(
                    &metadata,
                    "cfstring",
                    "CFStringCreateExternalRepresentation",
                )
                .arg("String", format!("0x{:X}", string_ref))
                .arg("Result", format!("0x{:X}", data_ref)),
            );
            data_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFDataCreate") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let bytes_ptr = emu.read_reg("x1").unwrap_or(0);
            let len = emu.read_reg("x2").unwrap_or(0) as usize;
            let data = read_guest_bytes(emu, bytes_ptr, len, 8 * 1024 * 1024);
            let data_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_data(data.clone())
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFDataCreate(bytes=0x{:X}, len={}) -> 0x{:X}",
                    bytes_ptr, len, data_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfdata", "CFDataCreate")
                    .arg("Bytes", format!("0x{:X}", bytes_ptr))
                    .arg("Len", len.to_string())
                    .arg("Result", format!("0x{:X}", data_ref))
                    .arg("Preview", crate::macos::lossy_data_preview(&data, 128)),
            );
            data_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFDataGetLength") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let data_ref = emu.read_reg("x0").unwrap_or(0);
            let len = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.object_len(data_ref).unwrap_or(0) as u64
            };
            record_arm64_import(
                &tracker,
                format!("_CFDataGetLength(data=0x{:X}) -> {}", data_ref, len),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfdata", "CFDataGetLength")
                    .arg("Data", format!("0x{:X}", data_ref))
                    .arg("Result", len.to_string()),
            );
            len
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFDataGetBytePtr") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let data_ref = emu.read_reg("x0").unwrap_or(0);
            let exported_ptr = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                let Some(data) = runtime.object_data(data_ref) else {
                    return 0;
                };
                runtime.export_bytes(emu, &data).unwrap_or(0)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFDataGetBytePtr(data=0x{:X}) -> 0x{:X}",
                    data_ref, exported_ptr
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfdata", "CFDataGetBytePtr")
                    .arg("Data", format!("0x{:X}", data_ref))
                    .arg("Result", format!("0x{:X}", exported_ptr)),
            );
            exported_ptr
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFArrayCreateMutable") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |_emu| {
            let array_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_array()
            };
            record_arm64_import(
                &tracker,
                format!("_CFArrayCreateMutable() -> 0x{:X}", array_ref),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfarray", "CFArrayCreateMutable")
                    .arg("Result", format!("0x{:X}", array_ref)),
            );
            array_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFArrayCreate") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let values_ptr = emu.read_reg("x1").unwrap_or(0);
            let count = emu.read_reg("x2").unwrap_or(0) as usize;
            let values = read_guest_u64_array(emu, values_ptr, count, 4096);
            let array_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_array_with_values(values.clone())
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFArrayCreate(values=0x{:X}, count={}) -> 0x{:X}",
                    values_ptr, count, array_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfarray", "CFArrayCreate")
                    .arg("Values", format!("0x{:X}", values_ptr))
                    .arg("Count", count.to_string())
                    .arg("Result", format!("0x{:X}", array_ref)),
            );
            array_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFArrayAppendValue") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let array_ref = emu.read_reg("x0").unwrap_or(0);
                let value_ref = emu.read_reg("x1").unwrap_or(0);
                let (ok, array_desc) = {
                    let mut runtime = match apple_runtime.lock() {
                        Ok(runtime) => runtime,
                        Err(_) => return,
                    };
                    let ok = runtime.array_append(array_ref, value_ref);
                    let desc = runtime.describe(array_ref);
                    (ok, desc)
                };
                record_arm64_import(
                    &tracker,
                    format!(
                        "_CFArrayAppendValue(array=0x{:X}, value=0x{:X}) ok={}",
                        array_ref, value_ref, ok
                    ),
                );
                emit_arm64_event(
                    &trace,
                    process_event(&metadata, "cfarray", "CFArrayAppendValue")
                        .arg("Array", format!("0x{:X}", array_ref))
                        .arg("Value", format!("0x{:X}", value_ref))
                        .arg("Ok", ok.to_string())
                        .arg("ArrayDesc", array_desc),
                );
                let lr = emu.read_reg("lr").unwrap_or(0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_CFArrayGetCount") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let array_ref = emu.read_reg("x0").unwrap_or(0);
            let count = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.array_len(array_ref).unwrap_or(0) as u64
            };
            record_arm64_import(
                &tracker,
                format!("_CFArrayGetCount(array=0x{:X}) -> {}", array_ref, count),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfarray", "CFArrayGetCount")
                    .arg("Array", format!("0x{:X}", array_ref))
                    .arg("Result", count.to_string()),
            );
            count
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFArrayGetValueAtIndex") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let array_ref = emu.read_reg("x0").unwrap_or(0);
            let index = emu.read_reg("x1").unwrap_or(0) as usize;
            let value_ref = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.array_get(array_ref, index).unwrap_or(0)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFArrayGetValueAtIndex(array=0x{:X}, index={}) -> 0x{:X}",
                    array_ref, index, value_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfarray", "CFArrayGetValueAtIndex")
                    .arg("Array", format!("0x{:X}", array_ref))
                    .arg("Index", index.to_string())
                    .arg("Result", format!("0x{:X}", value_ref)),
            );
            value_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFDateCreate") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let absolute_time = f64::from_bits(emu.read_reg("x1").unwrap_or(0));
            let date_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_date(absolute_time)
            };
            record_arm64_import(
                &tracker,
                format!("_CFDateCreate(abs={}) -> 0x{:X}", absolute_time, date_ref),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfdate", "CFDateCreate")
                    .arg("AbsoluteTime", absolute_time.to_string())
                    .arg("Result", format!("0x{:X}", date_ref)),
            );
            date_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_xpc_date_create_from_current") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |_emu| {
            let date_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_date(0.0)
            };
            record_arm64_import(
                &tracker,
                format!("_xpc_date_create_from_current() -> 0x{:X}", date_ref),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "xpcdate", "xpc_date_create_from_current")
                    .arg("Result", format!("0x{:X}", date_ref)),
            );
            date_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFRelease") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let object_ref = emu.read_reg("x0").unwrap_or(0);
                let desc = {
                    let mut runtime = match apple_runtime.lock() {
                        Ok(runtime) => runtime,
                        Err(_) => return,
                    };
                    let desc = runtime.describe(object_ref);
                    runtime.release(object_ref);
                    desc
                };
                record_arm64_import(&tracker, format!("_CFRelease(0x{:X})", object_ref));
                emit_arm64_event(
                    &trace,
                    process_event(&metadata, "cfobject", "CFRelease")
                        .arg("Object", format!("0x{:X}", object_ref))
                        .arg("Desc", desc),
                );
                let lr = emu.read_reg("lr").unwrap_or(0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_CFRetain") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let object_ref = emu.read_reg("x0").unwrap_or(0);
            let desc = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return object_ref,
                };
                let _ = runtime.retain(object_ref);
                runtime.describe(object_ref)
            };
            record_arm64_import(&tracker, format!("_CFRetain(0x{:X})", object_ref));
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfobject", "CFRetain")
                    .arg("Object", format!("0x{:X}", object_ref))
                    .arg("Desc", desc),
            );
            object_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFErrorGetCode") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let error_ref = emu.read_reg("x0").unwrap_or(0);
            let code = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.error_code(error_ref).unwrap_or(0) as u64
            };
            record_arm64_import(
                &tracker,
                format!("_CFErrorGetCode(error=0x{:X}) -> {}", error_ref, code),
            );
            code
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFErrorCreate") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let domain = emu.read_reg("x1").unwrap_or(0);
            let code = emu.read_reg("x2").unwrap_or(0) as i64;
            let error_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_error(code, format!("machina synthetic error {}", code))
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFErrorCreate(domain=0x{:X}, code={}) -> 0x{:X}",
                    domain, code, error_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cferror", "CFErrorCreate")
                    .arg("Domain", format!("0x{:X}", domain))
                    .arg("Code", code.to_string())
                    .arg("Result", format!("0x{:X}", error_ref)),
            );
            error_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFErrorCopyDescription") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let error_ref = emu.read_reg("x0").unwrap_or(0);
            let description_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                let description = runtime
                    .error_description(error_ref)
                    .unwrap_or_else(|| "machina synthetic error".to_string());
                runtime.alloc_string(description.into_bytes(), 0x8000_0100)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFErrorCopyDescription(error=0x{:X}) -> 0x{:X}",
                    error_ref, description_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cferror", "CFErrorCopyDescription")
                    .arg("Error", format!("0x{:X}", error_ref))
                    .arg("Result", format!("0x{:X}", description_ref)),
            );
            description_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFDictionaryCreate") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let keys_ptr = emu.read_reg("x1").unwrap_or(0);
            let values_ptr = emu.read_reg("x2").unwrap_or(0);
            let count = emu.read_reg("x3").unwrap_or(0) as usize;
            let keys = read_guest_u64_array(emu, keys_ptr, count, 4096);
            let values = read_guest_u64_array(emu, values_ptr, count, 4096);
            let entries = keys.into_iter().zip(values).collect::<Vec<_>>();
            let dict_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_dictionary(entries)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_CFDictionaryCreate(keys=0x{:X}, values=0x{:X}, count={}) -> 0x{:X}",
                    keys_ptr, values_ptr, count, dict_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfdictionary", "CFDictionaryCreate")
                    .arg("Keys", format!("0x{:X}", keys_ptr))
                    .arg("Values", format!("0x{:X}", values_ptr))
                    .arg("Count", count.to_string())
                    .arg("Result", format!("0x{:X}", dict_ref)),
            );
            dict_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFDictionaryGetValueIfPresent") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let dict_ref = emu.read_reg("x0").unwrap_or(0);
            let key_ref = emu.read_reg("x1").unwrap_or(0);
            let value_out = emu.read_reg("x2").unwrap_or(0);
            let value_ref = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.dictionary_get(dict_ref, key_ref).unwrap_or(0)
            };
            let present = value_ref != 0;
            if present && value_out != 0 {
                let _ = emu.write_memory(value_out, &value_ref.to_le_bytes());
            }
            record_arm64_import(
                &tracker,
                format!(
                    "_CFDictionaryGetValueIfPresent(dict=0x{:X}, key=0x{:X}, out=0x{:X}) -> {}",
                    dict_ref, key_ref, value_out, present as u64
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfdictionary", "CFDictionaryGetValueIfPresent")
                    .arg("Dictionary", format!("0x{:X}", dict_ref))
                    .arg("Key", format!("0x{:X}", key_ref))
                    .arg("ValueOut", format!("0x{:X}", value_out))
                    .arg("Value", format!("0x{:X}", value_ref))
                    .arg("Present", present.to_string()),
            );
            present as u64
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFGetTypeID") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let object_ref = emu.read_reg("x0").unwrap_or(0);
            let type_id = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.type_id(object_ref)
            };
            record_arm64_import(
                &tracker,
                format!("_CFGetTypeID(obj=0x{:X}) -> 0x{:X}", object_ref, type_id),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfobject", "CFGetTypeID")
                    .arg("Object", format!("0x{:X}", object_ref))
                    .arg("Result", format!("0x{:X}", type_id)),
            );
            type_id
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFNumberGetTypeID") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |_emu| {
            let type_id = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.number_type_id()
            };
            record_arm64_import(&tracker, format!("_CFNumberGetTypeID() -> 0x{:X}", type_id));
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfnumber", "CFNumberGetTypeID")
                    .arg("Result", format!("0x{:X}", type_id)),
            );
            type_id
        })?;
    }

    if let Some(&addr) = stub_map.get("_CFNumberGetValue") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let number_ref = emu.read_reg("x0").unwrap_or(0);
            let number_type = emu.read_reg("x1").unwrap_or(0);
            let out_ptr = emu.read_reg("x2").unwrap_or(0);
            let value = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.number_value(number_ref).unwrap_or(0)
            };
            if out_ptr != 0 {
                let _ = emu.write_memory(out_ptr, &value.to_le_bytes());
            }
            record_arm64_import(
                &tracker,
                format!(
                    "_CFNumberGetValue(num=0x{:X}, type=0x{:X}, out=0x{:X}) -> 1",
                    number_ref, number_type, out_ptr
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "cfnumber", "CFNumberGetValue")
                    .arg("Number", format!("0x{:X}", number_ref))
                    .arg("Type", format!("0x{:X}", number_type))
                    .arg("Out", format!("0x{:X}", out_ptr))
                    .arg("Value", value.to_string())
                    .arg("Result", "1"),
            );
            1
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecCertificateCreateWithData") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let data_ref = emu.read_reg("x1").unwrap_or(0);
            let cert_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_certificate(data_ref)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_SecCertificateCreateWithData(data=0x{:X}) -> 0x{:X}",
                    data_ref, cert_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "seccertificate", "SecCertificateCreateWithData")
                    .arg("Data", format!("0x{:X}", data_ref))
                    .arg("Result", format!("0x{:X}", cert_ref)),
            );
            cert_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecCertificateCopyData") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let cert_ref = emu.read_reg("x0").unwrap_or(0);
            let data_ref = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.certificate_data(cert_ref).unwrap_or(0)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_SecCertificateCopyData(cert=0x{:X}) -> 0x{:X}",
                    cert_ref, data_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "seccertificate", "SecCertificateCopyData")
                    .arg("Certificate", format!("0x{:X}", cert_ref))
                    .arg("Result", format!("0x{:X}", data_ref)),
            );
            data_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecPolicyCreateSSL") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let server = emu.read_reg("x0").unwrap_or(0) != 0;
            let hostname = emu.read_reg("x1").unwrap_or(0);
            let policy_ref = {
                let mut runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.alloc_policy_ssl(server, hostname)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_SecPolicyCreateSSL(server={}, hostname=0x{:X}) -> 0x{:X}",
                    server, hostname, policy_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "secpolicy", "SecPolicyCreateSSL")
                    .arg("Server", server.to_string())
                    .arg("Hostname", format!("0x{:X}", hostname))
                    .arg("Result", format!("0x{:X}", policy_ref)),
            );
            policy_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecTrustCreateWithCertificates") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let certificates = emu.read_reg("x0").unwrap_or(0);
                let policies = emu.read_reg("x1").unwrap_or(0);
                let trust_out = emu.read_reg("x2").unwrap_or(0);
                let trust_ref = {
                    let mut runtime = match apple_runtime.lock() {
                        Ok(runtime) => runtime,
                        Err(_) => return,
                    };
                    runtime.alloc_trust(certificates, policies)
                };
                if trust_out != 0 {
                    let _ = emu.write_memory(trust_out, &trust_ref.to_le_bytes());
                }
                record_arm64_import(
                    &tracker,
                    format!(
                        "_SecTrustCreateWithCertificates(certs=0x{:X}, policies=0x{:X}, out=0x{:X}) -> 0x{:X}",
                        certificates, policies, trust_out, trust_ref
                    ),
                );
                emit_arm64_event(
                    &trace,
                    process_event(&metadata, "sectrust", "SecTrustCreateWithCertificates")
                        .arg("Certificates", format!("0x{:X}", certificates))
                        .arg("Policies", format!("0x{:X}", policies))
                        .arg("TrustOut", format!("0x{:X}", trust_out))
                        .arg("Trust", format!("0x{:X}", trust_ref)),
                );
                let lr = emu.read_reg("lr").unwrap_or(0);
                let _ = emu.write_reg("x0", 0u64);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
            },
        )?;
    }

    if let Some(&addr) = stub_map.get("_SecTrustEvaluateWithError") {
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let trust_ref = emu.read_reg("x0").unwrap_or(0);
            let error_out = emu.read_reg("x1").unwrap_or(0);
            if error_out != 0 {
                let _ = emu.write_memory(error_out, &0u64.to_le_bytes());
            }
            record_arm64_import(
                &tracker,
                format!(
                    "_SecTrustEvaluateWithError(trust=0x{:X}, error=0x{:X}) -> 1",
                    trust_ref, error_out
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "sectrust", "SecTrustEvaluateWithError")
                    .arg("Trust", format!("0x{:X}", trust_ref))
                    .arg("ErrorOut", format!("0x{:X}", error_out))
                    .arg("Result", "1"),
            );
            1
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecTrustGetCertificateCount") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let trust_ref = emu.read_reg("x0").unwrap_or(0);
            let count = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime.trust_certificate_count(trust_ref).unwrap_or(0) as u64
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_SecTrustGetCertificateCount(trust=0x{:X}) -> {}",
                    trust_ref, count
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "sectrust", "SecTrustGetCertificateCount")
                    .arg("Trust", format!("0x{:X}", trust_ref))
                    .arg("Result", count.to_string()),
            );
            count
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecTrustGetCertificateAtIndex") {
        let apple_runtime = shared_state.apple_runtime.clone();
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        install_returning_hook(emulator, addr, move |emu| {
            let trust_ref = emu.read_reg("x0").unwrap_or(0);
            let index = emu.read_reg("x1").unwrap_or(0) as usize;
            let cert_ref = {
                let runtime = match apple_runtime.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return 0,
                };
                runtime
                    .trust_certificate_at_index(trust_ref, index)
                    .unwrap_or(0)
            };
            record_arm64_import(
                &tracker,
                format!(
                    "_SecTrustGetCertificateAtIndex(trust=0x{:X}, index={}) -> 0x{:X}",
                    trust_ref, index, cert_ref
                ),
            );
            emit_arm64_event(
                &trace,
                process_event(&metadata, "sectrust", "SecTrustGetCertificateAtIndex")
                    .arg("Trust", format!("0x{:X}", trust_ref))
                    .arg("Index", index.to_string())
                    .arg("Result", format!("0x{:X}", cert_ref)),
            );
            cert_ref
        })?;
    }

    if let Some(&addr) = stub_map.get("_SecTrustSetVerifyDate") {
        let tracker = import_tracker.clone();
        let trace = trace_bus.clone();
        let metadata = metadata.clone();
        emulator.add_code_hook(
            addr,
            addr + 4,
            move |emu: &mut machina::UnicornEmulator, _address: u64, _size: u32| {
                let trust_ref = emu.read_reg("x0").unwrap_or(0);
                let date_ref = emu.read_reg("x1").unwrap_or(0);
                record_arm64_import(
                    &tracker,
                    format!(
                        "_SecTrustSetVerifyDate(trust=0x{:X}, date=0x{:X})",
                        trust_ref, date_ref
                    ),
                );
                emit_arm64_event(
                    &trace,
                    process_event(&metadata, "sectrust", "SecTrustSetVerifyDate")
                        .arg("Trust", format!("0x{:X}", trust_ref))
                        .arg("Date", format!("0x{:X}", date_ref)),
                );
                let lr = emu.read_reg("lr").unwrap_or(0);
                if lr != 0 {
                    let _ = emu.write_reg("pc", lr);
                }
            },
        )?;
    }

    Ok(())
}
