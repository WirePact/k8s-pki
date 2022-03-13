use local_store::LocalStore;
use store::CertificateStore;

mod kubernetes_store;
mod local_store;
pub mod store;
mod utils;

pub fn create_store(local: bool) -> Box<dyn CertificateStore> {
    match local {
        true => Box::new(LocalStore::default()),
        false => Box::new(LocalStore::default()),
        // false => Box::new(KubernetesStore {}),
    }
}
