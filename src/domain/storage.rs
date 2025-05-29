pub mod oss {
    use std::error::Error;

    use async_trait::async_trait;
    use downcast_rs::{impl_downcast, DowncastSend};

    #[async_trait]
    pub trait OssBucket: DowncastSend {
        type ObjectType: Send;

        async fn get_object(&self, key: &str) -> Result<Self::ObjectType, Box<dyn Error>>;
        async fn put_object(&self, key: &str, data: Self::ObjectType) -> Result<(), Box<dyn Error>>;
        async fn delete_object(&self, key: &str) -> Result<(), Box<dyn Error>>;
        async fn list_objects(&self, prefix: Option<&str>) -> Result<Vec<String>, Box<dyn Error>>;

    }
    impl_downcast!(OssBucket assoc ObjectType);
}