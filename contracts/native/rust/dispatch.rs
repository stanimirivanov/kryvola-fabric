// Generated typed codec dispatch; not authorization.
pub fn typed_roundtrip(name: &str, bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
use prost::Message;
Ok(match name {
"ArtifactRef" => ArtifactRef::decode(bytes)?.encode_to_vec(),
"KeyContextRef" => KeyContextRef::decode(bytes)?.encode_to_vec(),
"PlanRef" => PlanRef::decode(bytes)?.encode_to_vec(),
"DisclosureIdentity" => DisclosureIdentity::decode(bytes)?.encode_to_vec(),
"Operation" => Operation::decode(bytes)?.encode_to_vec(),
"Attempt" => Attempt::decode(bytes)?.encode_to_vec(),
"Execution" => Execution::decode(bytes)?.encode_to_vec(),
"Capabilities" => Capabilities::decode(bytes)?.encode_to_vec(),
"GetCapabilitiesRequest" => GetCapabilitiesRequest::decode(bytes)?.encode_to_vec(),
"GetCapabilitiesResponse" => GetCapabilitiesResponse::decode(bytes)?.encode_to_vec(),
"ExecuteRequest" => ExecuteRequest::decode(bytes)?.encode_to_vec(),
"ExecuteResponse" => ExecuteResponse::decode(bytes)?.encode_to_vec(),
"GetExecutionStatusRequest" => GetExecutionStatusRequest::decode(bytes)?.encode_to_vec(),
"GetExecutionStatusResponse" => GetExecutionStatusResponse::decode(bytes)?.encode_to_vec(),
"CancelExecutionRequest" => CancelExecutionRequest::decode(bytes)?.encode_to_vec(),
"CancelExecutionResponse" => CancelExecutionResponse::decode(bytes)?.encode_to_vec(),
"ExecutionObservedEvent" => ExecutionObservedEvent::decode(bytes)?.encode_to_vec(),
_ => return Err("unknown message".into()),
})
}
