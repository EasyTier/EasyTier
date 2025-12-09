use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::common::PeerId;

include!(concat!(env!("OUT_DIR"), "/peer_rpc.rs"));

impl PeerGroupInfo {
    pub fn generate_with_proof(group_name: String, group_secret: String, peer_id: PeerId) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(group_secret.as_bytes())
            .expect("HMAC can take key of any size");

        let mut data_to_sign = group_name.as_bytes().to_vec();
        data_to_sign.push(0x00); // Add a delimiter byte
        data_to_sign.extend_from_slice(&peer_id.to_be_bytes());

        mac.update(&data_to_sign);

        let proof = mac.finalize().into_bytes().to_vec();

        PeerGroupInfo {
            group_name,
            group_proof: proof,
        }
    }

    pub fn verify(&self, group_secret: &str, peer_id: PeerId) -> bool {
        let mut verifier = Hmac::<Sha256>::new_from_slice(group_secret.as_bytes())
            .expect("HMAC can take key of any size");

        let mut data_to_sign = self.group_name.as_bytes().to_vec();
        data_to_sign.push(0x00); // Add a delimiter byte
        data_to_sign.extend_from_slice(&peer_id.to_be_bytes());

        verifier.update(&data_to_sign);

        verifier.verify_slice(&self.group_proof).is_ok()
    }
}

impl From<RouteConnBitmap> for sync_route_info_request::ConnInfo {
    fn from(val: RouteConnBitmap) -> Self {
        Self::ConnBitmap(val)
    }
}

impl From<RouteConnPeerList> for sync_route_info_request::ConnInfo {
    fn from(val: RouteConnPeerList) -> Self {
        Self::ConnPeerList(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_group_info_new() {
        let group_name = "test_group".to_string();
        let group_secret = "secret123".to_string();
        let peer_id = 42u32;

        let peer_group_info =
            PeerGroupInfo::generate_with_proof(group_name.clone(), group_secret, peer_id);

        assert_eq!(peer_group_info.group_name, group_name);
        assert!(!peer_group_info.group_proof.is_empty());
        // HMAC-SHA256 produces a 32-byte output
        assert_eq!(peer_group_info.group_proof.len(), 32);
    }

    #[test]
    fn test_peer_group_info_verify_valid() {
        let group_name = "test_group".to_string();
        let group_secret = "secret123".to_string();
        let peer_id = 42u32;

        let peer_group_info =
            PeerGroupInfo::generate_with_proof(group_name, group_secret.clone(), peer_id);

        // Verification should succeed using the same secret and peer_id
        assert!(peer_group_info.verify(&group_secret, peer_id));
    }

    #[test]
    fn test_peer_group_info_verify_invalid_secret() {
        let group_name = "test_group".to_string();
        let group_secret = "secret123".to_string();
        let peer_id = 42u32;

        let peer_group_info = PeerGroupInfo::generate_with_proof(group_name, group_secret, peer_id);

        // Verification should fail with a wrong secret
        assert!(!peer_group_info.verify("wrong_secret", peer_id));
    }

    #[test]
    fn test_peer_group_info_verify_invalid_peer_id() {
        let group_name = "test_group".to_string();
        let group_secret = "secret123".to_string();
        let peer_id = 42u32;

        let peer_group_info =
            PeerGroupInfo::generate_with_proof(group_name, group_secret.clone(), peer_id);

        // Verification should fail with a wrong peer_id
        assert!(!peer_group_info.verify(&group_secret, 999u32));
    }

    #[test]
    fn test_peer_group_info_different_groups_different_proofs() {
        let group_secret = "secret123".to_string();
        let peer_id = 42u32;

        let group1 =
            PeerGroupInfo::generate_with_proof("group1".to_string(), group_secret.clone(), peer_id);
        let group2 =
            PeerGroupInfo::generate_with_proof("group2".to_string(), group_secret, peer_id);

        // Different group names should produce different proofs
        assert_ne!(group1.group_proof, group2.group_proof);
    }

    #[test]
    fn test_peer_group_info_same_params_same_proof() {
        let group_name = "test_group".to_string();
        let group_secret = "secret123".to_string();
        let peer_id = 42u32;

        let group1 =
            PeerGroupInfo::generate_with_proof(group_name.clone(), group_secret.clone(), peer_id);
        let group2 = PeerGroupInfo::generate_with_proof(group_name, group_secret, peer_id);

        // Same parameters should produce the same proof
        assert_eq!(group1.group_proof, group2.group_proof);
    }

    #[test]
    fn test_peer_group_info_empty_group_name() {
        let group_name = "".to_string();
        let group_secret = "secret123".to_string();
        let peer_id = 42u32;

        let peer_group_info =
            PeerGroupInfo::generate_with_proof(group_name.clone(), group_secret.clone(), peer_id);

        assert_eq!(peer_group_info.group_name, group_name);
        assert!(peer_group_info.verify(&group_secret, peer_id));
    }

    #[test]
    fn test_peer_group_info_empty_secret() {
        let group_name = "test_group".to_string();
        let group_secret = "".to_string();
        let peer_id = 42u32;

        let peer_group_info =
            PeerGroupInfo::generate_with_proof(group_name, group_secret.clone(), peer_id);

        assert!(peer_group_info.verify(&group_secret, peer_id));
    }

    #[test]
    fn test_peer_group_info_unicode_group_name() {
        let group_name = "测试组🚀".to_string();
        let group_secret = "secret123".to_string();
        let peer_id = 42u32;

        let peer_group_info =
            PeerGroupInfo::generate_with_proof(group_name.clone(), group_secret.clone(), peer_id);

        assert_eq!(peer_group_info.group_name, group_name);
        assert!(peer_group_info.verify(&group_secret, peer_id));
    }

    #[test]
    fn test_peer_group_info_unicode_secret() {
        let group_name = "test_group".to_string();
        let group_secret = "密码123🔐".to_string();
        let peer_id = 42u32;

        let peer_group_info =
            PeerGroupInfo::generate_with_proof(group_name, group_secret.clone(), peer_id);

        assert!(peer_group_info.verify(&group_secret, peer_id));
    }

    #[test]
    fn test_peer_group_info_zero_peer_id() {
        let group_name = "test_group".to_string();
        let group_secret = "secret123".to_string();
        let peer_id = 0u32;

        let peer_group_info =
            PeerGroupInfo::generate_with_proof(group_name, group_secret.clone(), peer_id);

        assert!(peer_group_info.verify(&group_secret, peer_id));
    }

    #[test]
    fn test_peer_group_info_max_peer_id() {
        let group_name = "test_group".to_string();
        let group_secret = "secret123".to_string();
        let peer_id = u32::MAX;

        let peer_group_info =
            PeerGroupInfo::generate_with_proof(group_name, group_secret.clone(), peer_id);

        assert!(peer_group_info.verify(&group_secret, peer_id));
    }

    #[test]
    #[ignore]
    fn perf_test_generate_with_proof() {
        let group_name = "test_group".to_string();
        let group_secret = "secret123".to_string();
        let peer_id = 42u32;
        let iterations = 100000;

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = PeerGroupInfo::generate_with_proof(
                group_name.clone(),
                group_secret.clone(),
                peer_id,
            );
        }
        let duration = start.elapsed();

        println!(
            "generate_with_proof took {:?} for {} iterations",
            duration, iterations
        );
        println!("Avg time per iteration: {:?}", duration / iterations as u32);
    }

    #[test]
    #[ignore]
    fn perf_test_verify() {
        let group_name = "test_group".to_string();
        let group_secret = "secret123".to_string();
        let peer_id = 42u32;
        let iterations = 100000;

        let peer_group_info =
            PeerGroupInfo::generate_with_proof(group_name, group_secret.clone(), peer_id);

        let start = std::time::Instant::now();
        for _ in 0..iterations {
            assert!(peer_group_info.verify(&group_secret, peer_id));
        }
        let duration = start.elapsed();

        println!("verify took {:?} for {} iterations", duration, iterations);
        println!("Avg time per iteration: {:?}", duration / iterations as u32);
    }
}
