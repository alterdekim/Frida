#![cfg(target_os = "android")]

use ::jni::objects::GlobalRef;
use ::jni::JavaVM;
use robusta_jni::bridge;
use std::sync::OnceLock;
use robusta_jni::jni::JNIEnv;
use std::fs::File;
use std::io::Write;

mod config;
mod client;
mod udp;
mod mobile;

static TUN_QUIT: std::sync::Mutex<Option<tokio_util::sync::CancellationToken>> = std::sync::Mutex::new(None);

#[bridge]
mod jni {
    use jni::objects::{GlobalRef, JObject, JValue, JString};
    use jni::sys::{jboolean, jchar, jint, jstring};
    use log::{info, trace};
    use log::LevelFilter;
    use log4rs::append::file::FileAppender;
    use log4rs::encode::pattern::PatternEncoder;
    use log4rs::config::{Appender, Config, Root};
    use robusta_jni::convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue};
    use robusta_jni::jni::errors::Result as JniResult;
    use robusta_jni::jni::objects::AutoLocal;
    use robusta_jni::jni::JNIEnv;
    use crate::mobile;
    use crate::TUN_QUIT;
    use std::fs::File;

    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(com.alterdekim.frida)]
    pub struct FridaLib<'env: 'borrow, 'borrow> {
        #[instance]
        raw: AutoLocal<'env, 'borrow>,
    }

    impl<'env: 'borrow, 'borrow> FridaLib<'env, 'borrow> {
        pub extern "jni" fn start(self, env: &JNIEnv, config_b32: String,
            tun_fd: i32,
            close_fd_on_drop: bool,
            temp_file: String) -> JniResult<i32> {
            
            let logfile = FileAppender::builder()
                .encoder(Box::new(PatternEncoder::new("{l} - {m}\n")))
                .build(&temp_file).unwrap();

            let config = Config::builder()
                .appender(Appender::builder().build("logfile", Box::new(logfile)))
                .build(Root::builder()
                        .appender("logfile")
                        .build(LevelFilter::Info)).unwrap();

            log4rs::init_config(config);
            
            let close_token = tokio_util::sync::CancellationToken::new();
            if let Ok(mut l) = TUN_QUIT.lock() {
                if l.is_some() {
                    return Ok(-1);
                }
                *l = Some(close_token.clone());
            } else {
                return Ok(-2);
            }

            let main_loop = async move {
                let config: ClientConfiguration = serde_yaml::from_slice(hex::decode(config_b32).unwrap().as_slice()).expect("Bad client config file structure");
                let client = AndroidClient{client_config: config, fd: tun_fd, close_token};
                client.start().await;
            };
        
            let exit_code = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Err(_e) => -3,
                Ok(rt) => { rt.block_on(main_loop); -4 }
            };
        
            Ok(exit_code)
        }

        pub extern "jni" fn stop(self, env: &JNIEnv) -> JniResult<i32> {
            if let Ok(mut l) = TUN_QUIT.lock() {
                if let Some(close_token) = l.take() {
                    close_token.cancel();
                    return Ok(0);
                }
            }
            Ok(-1)
        }

        pub extern "java" fn traceFromNative(
            env: &JNIEnv,
            text: String,
        ) -> JniResult<()> {

        }
    }
}