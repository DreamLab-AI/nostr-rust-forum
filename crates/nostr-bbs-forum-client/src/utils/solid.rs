//! Solid Pod client — builds typed URL accessors from a pod_url + pubkey.
//!
//! The pod_url is provided by the passkey auth server response and identifies
//! the user's Solid data pod. PodClient computes well-known endpoint URLs
//! following the Solid specification conventions.

/// A lightweight Solid pod client that computes endpoint URLs from a pod base URL.
pub struct PodClient {
    pub pod_url: String,
    pub pubkey_hex: String,
}

impl PodClient {
    pub fn new(pod_url: String, pubkey_hex: String) -> Self {
        Self {
            pod_url,
            pubkey_hex,
        }
    }

    /// Inbox URL for incoming Linked Data Notifications.
    pub fn inbox_url(&self) -> String {
        format!("{}/inbox/", self.pod_url.trim_end_matches('/'))
    }

    /// WebID profile document URL.
    pub fn profile_url(&self) -> String {
        format!("{}/profile/card", self.pod_url.trim_end_matches('/'))
    }

    /// Type index URL. `public=true` returns the public type index,
    /// `public=false` returns the private type index.
    pub fn type_index_url(&self, public: bool) -> String {
        let idx = if public {
            "publicTypeIndex"
        } else {
            "privateTypeIndex"
        };
        format!(
            "{}/settings/{}.jsonld",
            self.pod_url.trim_end_matches('/'),
            idx
        )
    }

    /// Base media folder URL for uploaded files.
    pub fn media_url(&self) -> String {
        format!("{}/media/public/", self.pod_url.trim_end_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::PodClient;

    #[test]
    fn type_index_urls_match_provisioned_jsonld_paths() {
        let client = PodClient::new("https://pods.example/pods/alice/".into(), "alice".into());
        assert_eq!(
            client.type_index_url(true),
            "https://pods.example/pods/alice/settings/publicTypeIndex.jsonld"
        );
        assert_eq!(
            client.type_index_url(false),
            "https://pods.example/pods/alice/settings/privateTypeIndex.jsonld"
        );
    }
}
