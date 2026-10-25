fn main() {
    println!(
        "component=kryvola-fabric status=foundation execution_available=false control_max_bytes={}",
        kryvola_fabric_core::limits::CONTROL_BYTES
    );
}
