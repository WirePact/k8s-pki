use local_store::LocalStore;
use store::CertificateStore;

use crate::cert_store::kubernetes_store::KubernetesStore;

mod kubernetes_store;
mod local_store;
pub mod store;
mod utils;

pub fn create_store(local: bool, kubernetes_secret: String) -> Box<dyn CertificateStore> {
    match local {
        true => Box::new(LocalStore::default()),
        false => {
            let mut store = KubernetesStore::default();
            store.secret_name = kubernetes_secret;
            Box::new(store)
        }
    }
}
