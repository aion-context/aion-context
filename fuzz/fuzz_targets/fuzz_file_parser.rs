#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Placeholder fuzz target
    // Will be replaced with actual file parser fuzzing once implemented
    // 
    // The parser should NEVER panic, only return Err for invalid input
    let _ = data;
});
