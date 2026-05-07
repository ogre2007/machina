//! Synthetic Apple framework object runtime shared across emulation hooks.

use std::collections::HashMap;

use crate::macos::Emulator;

#[derive(Clone, Debug)]
pub enum AppleObject {
    String { data: Vec<u8>, encoding: u64 },
    Data { data: Vec<u8> },
    Array { values: Vec<u64> },
    Dictionary { entries: Vec<(u64, u64)> },
    Number { value: i64 },
    Certificate { data_ref: u64 },
    PolicySsl { server: bool, hostname: u64 },
    Trust { certificates: u64, policies: u64 },
    Date { absolute_time: f64 },
    Error { code: i64, description: String },
}

#[derive(Debug)]
pub struct AppleRuntime {
    next_handle: u64,
    next_guest_buffer: u64,
    pub objects: HashMap<u64, AppleObject>,
}

impl Default for AppleRuntime {
    fn default() -> Self {
        Self {
            next_handle: 0x6A11_0000_0000,
            next_guest_buffer: 0x5000_0000,
            objects: HashMap::new(),
        }
    }
}

impl AppleRuntime {
    const TYPE_ID_STRING: u64 = 0x1001;
    const TYPE_ID_DATA: u64 = 0x1002;
    const TYPE_ID_ARRAY: u64 = 0x1003;
    const TYPE_ID_DICTIONARY: u64 = 0x1004;
    const TYPE_ID_NUMBER: u64 = 0x1005;
    const TYPE_ID_CERTIFICATE: u64 = 0x1006;
    const TYPE_ID_POLICY_SSL: u64 = 0x1007;
    const TYPE_ID_TRUST: u64 = 0x1008;
    const TYPE_ID_DATE: u64 = 0x1009;
    const TYPE_ID_ERROR: u64 = 0x100A;

    pub fn retain(&self, handle: u64) -> u64 {
        handle
    }

    pub fn release(&mut self, _handle: u64) {
        // We intentionally keep objects alive for the whole emulation session.
        // Malware samples often rely on loose ownership patterns, and premature
        // synthetic deallocation makes control flow less realistic than a leak.
    }

    pub fn alloc_string(&mut self, data: Vec<u8>, encoding: u64) -> u64 {
        self.alloc(AppleObject::String { data, encoding })
    }

    pub fn alloc_data(&mut self, data: Vec<u8>) -> u64 {
        self.alloc(AppleObject::Data { data })
    }

    pub fn alloc_array(&mut self) -> u64 {
        self.alloc(AppleObject::Array { values: Vec::new() })
    }

    pub fn alloc_array_with_values(&mut self, values: Vec<u64>) -> u64 {
        self.alloc(AppleObject::Array { values })
    }

    pub fn alloc_dictionary(&mut self, entries: Vec<(u64, u64)>) -> u64 {
        self.alloc(AppleObject::Dictionary { entries })
    }

    pub fn dictionary_get(&self, dict_ref: u64, key_ref: u64) -> Option<u64> {
        match self.objects.get(&dict_ref) {
            Some(AppleObject::Dictionary { entries }) => entries
                .iter()
                .find(|(key, _)| *key == key_ref)
                .map(|(_, value)| *value),
            _ => None,
        }
    }

    pub fn alloc_number(&mut self, value: i64) -> u64 {
        self.alloc(AppleObject::Number { value })
    }

    pub fn number_value(&self, number_ref: u64) -> Option<i64> {
        match self.objects.get(&number_ref) {
            Some(AppleObject::Number { value }) => Some(*value),
            _ => None,
        }
    }

    pub fn array_append(&mut self, array_ref: u64, value: u64) -> bool {
        match self.objects.get_mut(&array_ref) {
            Some(AppleObject::Array { values }) => {
                values.push(value);
                true
            }
            _ => false,
        }
    }

    pub fn array_len(&self, array_ref: u64) -> Option<usize> {
        match self.objects.get(&array_ref) {
            Some(AppleObject::Array { values }) => Some(values.len()),
            _ => None,
        }
    }

    pub fn array_get(&self, array_ref: u64, index: usize) -> Option<u64> {
        match self.objects.get(&array_ref) {
            Some(AppleObject::Array { values }) => values.get(index).copied(),
            _ => None,
        }
    }

    pub fn alloc_certificate(&mut self, data_ref: u64) -> u64 {
        self.alloc(AppleObject::Certificate { data_ref })
    }

    pub fn alloc_policy_ssl(&mut self, server: bool, hostname: u64) -> u64 {
        self.alloc(AppleObject::PolicySsl { server, hostname })
    }

    pub fn certificate_data(&self, cert_ref: u64) -> Option<u64> {
        match self.objects.get(&cert_ref) {
            Some(AppleObject::Certificate { data_ref }) => Some(*data_ref),
            _ => None,
        }
    }

    pub fn alloc_trust(&mut self, certificates: u64, policies: u64) -> u64 {
        self.alloc(AppleObject::Trust {
            certificates,
            policies,
        })
    }

    pub fn trust_certificate_count(&self, trust_ref: u64) -> Option<usize> {
        let certificates = match self.objects.get(&trust_ref) {
            Some(AppleObject::Trust { certificates, .. }) => *certificates,
            _ => return None,
        };
        match self.objects.get(&certificates) {
            Some(AppleObject::Array { values }) => Some(values.len()),
            Some(AppleObject::Certificate { .. }) => Some(1),
            _ if certificates != 0 => Some(1),
            _ => Some(0),
        }
    }

    pub fn trust_certificate_at_index(&self, trust_ref: u64, index: usize) -> Option<u64> {
        let certificates = match self.objects.get(&trust_ref) {
            Some(AppleObject::Trust { certificates, .. }) => *certificates,
            _ => return None,
        };
        match self.objects.get(&certificates) {
            Some(AppleObject::Array { values }) => values.get(index).copied(),
            Some(AppleObject::Certificate { .. }) if index == 0 => Some(certificates),
            _ if certificates != 0 && index == 0 => Some(certificates),
            _ => None,
        }
    }

    pub fn alloc_date(&mut self, absolute_time: f64) -> u64 {
        self.alloc(AppleObject::Date { absolute_time })
    }

    pub fn alloc_error(&mut self, code: i64, description: impl Into<String>) -> u64 {
        self.alloc(AppleObject::Error {
            code,
            description: description.into(),
        })
    }

    pub fn type_id(&self, handle: u64) -> u64 {
        match self.objects.get(&handle) {
            Some(AppleObject::String { .. }) => Self::TYPE_ID_STRING,
            Some(AppleObject::Data { .. }) => Self::TYPE_ID_DATA,
            Some(AppleObject::Array { .. }) => Self::TYPE_ID_ARRAY,
            Some(AppleObject::Dictionary { .. }) => Self::TYPE_ID_DICTIONARY,
            Some(AppleObject::Number { .. }) => Self::TYPE_ID_NUMBER,
            Some(AppleObject::Certificate { .. }) => Self::TYPE_ID_CERTIFICATE,
            Some(AppleObject::PolicySsl { .. }) => Self::TYPE_ID_POLICY_SSL,
            Some(AppleObject::Trust { .. }) => Self::TYPE_ID_TRUST,
            Some(AppleObject::Date { .. }) => Self::TYPE_ID_DATE,
            Some(AppleObject::Error { .. }) => Self::TYPE_ID_ERROR,
            None => 0,
        }
    }

    pub fn number_type_id(&self) -> u64 {
        Self::TYPE_ID_NUMBER
    }

    pub fn error_code(&self, error_ref: u64) -> Option<i64> {
        match self.objects.get(&error_ref) {
            Some(AppleObject::Error { code, .. }) => Some(*code),
            _ => None,
        }
    }

    pub fn error_description(&self, error_ref: u64) -> Option<String> {
        match self.objects.get(&error_ref) {
            Some(AppleObject::Error { description, .. }) => Some(description.clone()),
            _ => None,
        }
    }

    pub fn object_data(&self, handle: u64) -> Option<Vec<u8>> {
        match self.objects.get(&handle) {
            Some(AppleObject::String { data, .. }) => Some(data.clone()),
            Some(AppleObject::Data { data }) => Some(data.clone()),
            Some(AppleObject::Certificate { data_ref }) => self.object_data(*data_ref),
            _ => None,
        }
    }

    pub fn object_len(&self, handle: u64) -> Option<usize> {
        self.object_data(handle).map(|data| data.len())
    }

    pub fn export_bytes(
        &mut self,
        emu: &mut crate::UnicornEmulator,
        data: &[u8],
    ) -> Result<u64, crate::macos::MacOsError> {
        let len = data.len().max(1) as u64;
        let size = (len + 0xFFF) & !0xFFF;
        let addr = self.next_guest_buffer;
        self.next_guest_buffer = self.next_guest_buffer.saturating_add(size);
        emu.map_data_memory(addr, size)?;
        emu.write_memory(addr, data)?;
        Ok(addr)
    }

    pub fn describe(&self, handle: u64) -> String {
        match self.objects.get(&handle) {
            Some(AppleObject::String { data, encoding }) => format!(
                "CFString(len={}, enc=0x{:X}, preview={})",
                data.len(),
                encoding,
                crate::macos::lossy_data_preview(data, 64)
            ),
            Some(AppleObject::Data { data }) => format!(
                "CFData(len={}, preview={})",
                data.len(),
                crate::macos::lossy_data_preview(data, 64)
            ),
            Some(AppleObject::Array { values }) => format!("CFArray(count={})", values.len()),
            Some(AppleObject::Dictionary { entries }) => {
                format!("CFDictionary(count={})", entries.len())
            }
            Some(AppleObject::Number { value }) => format!("CFNumber({})", value),
            Some(AppleObject::Certificate { data_ref }) => {
                format!("SecCertificate(data=0x{:X})", data_ref)
            }
            Some(AppleObject::PolicySsl { server, hostname }) => {
                format!("SecPolicySSL(server={}, hostname=0x{:X})", server, hostname)
            }
            Some(AppleObject::Trust {
                certificates,
                policies,
            }) => format!(
                "SecTrust(certificates=0x{:X}, policies=0x{:X})",
                certificates, policies
            ),
            Some(AppleObject::Date { absolute_time }) => {
                format!("CFDate(abs={})", absolute_time)
            }
            Some(AppleObject::Error { code, description }) => {
                format!("CFError(code={}, desc={})", code, description)
            }
            None => format!("0x{:X}", handle),
        }
    }

    fn alloc(&mut self, object: AppleObject) -> u64 {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(0x100);
        self.objects.insert(handle, object);
        handle
    }
}
