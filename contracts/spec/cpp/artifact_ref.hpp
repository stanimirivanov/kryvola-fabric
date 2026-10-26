// Generated structural projection; not a decoder or authorization check.
#pragma once
#include <string>

namespace kryvola::spec {
struct ArtifactRef {
  std::string opaque_artifact_id;
  std::string tenant_scope;
  std::string immutable_version;
  std::string manifest_digest;
  std::string byte_length;
  std::string media_type;
  std::string schema_version;
};
}  // namespace kryvola::spec
