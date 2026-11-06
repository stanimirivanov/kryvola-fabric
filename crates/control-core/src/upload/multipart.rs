//! One application chunk is one final S3 multipart part (at most 4 MiB).
use super::*;
use object_store::{MultipartUpload, ObjectStoreExt};

pub(super) struct Pending {
    upload: Option<Box<dyn MultipartUpload>>,
    objects: Arc<dyn ObjectStore>,
    key: Path,
    armed: bool,
}

impl Pending {
    async fn transfer(
        &mut self,
        declared: usize,
        mut body: impl AsyncRead + Unpin,
        check: impl Fn() -> Result<()>,
    ) -> Result<()> {
        let mut data = vec![0; CHUNK_MAX_BYTES];
        let mut length = 0;
        while length < declared {
            let end = (length + 64 * 1024).min(declared);
            let n = body
                .read(&mut data[length..end])
                .await
                .map_err(|_| UploadError::Unavailable)?;
            if n == 0 {
                return Err(UploadError::Size);
            }
            length += n;
        }
        if body
            .read(&mut [0; 1])
            .await
            .map_err(|_| UploadError::Unavailable)?
            != 0
        {
            return Err(UploadError::Size);
        }
        data.truncate(declared);
        check()?;
        self.upload
            .as_mut()
            .ok_or(UploadError::Unavailable)?
            .put_part(data.into())
            .await
            .map_err(|_| UploadError::Unavailable)?;
        check()?;
        self.upload
            .as_mut()
            .ok_or(UploadError::Unavailable)?
            .complete()
            .await
            .map_err(|_| UploadError::Unavailable)?;
        self.upload = None;
        check()
    }

    async fn cleanup(&mut self) -> Result<()> {
        let aborted = if let Some(upload) = self.upload.as_mut() {
            matches!(
                timeout(IO_TIMEOUT, upload.abort()).await,
                Ok(Ok(())) | Ok(Err(object_store::Error::NotFound { .. }))
            )
        } else {
            true
        };
        if aborted {
            self.upload = None;
        }
        let deleted = matches!(
            timeout(IO_TIMEOUT, self.objects.delete(&self.key)).await,
            Ok(Ok(())) | Ok(Err(object_store::Error::NotFound { .. }))
        );
        if !aborted || !deleted {
            return Err(UploadError::Unavailable);
        }
        self.armed = false;
        Ok(())
    }

    async fn run(
        &mut self,
        declared: usize,
        body: impl AsyncRead + Unpin,
        check: impl Fn() -> Result<()>,
    ) -> Result<()> {
        if !(1..=CHUNK_MAX_BYTES).contains(&declared) {
            self.cleanup().await?;
            return Err(UploadError::Size);
        }
        let outcome = timeout(IO_TIMEOUT, self.transfer(declared, body, check))
            .await
            .unwrap_or(Err(UploadError::Unavailable));
        if outcome.is_err() {
            self.cleanup().await?;
        }
        outcome
    }
    pub(super) fn retain_for_commit(mut self) {
        // A lost SQL commit acknowledgement must not delete a possibly referenced object.
        self.armed = false;
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let mut cleanup = Self {
                upload: self.upload.take(),
                objects: self.objects.clone(),
                key: self.key.clone(),
                armed: false,
            };
            runtime.spawn(async move {
                if cleanup.cleanup().await.is_err() {
                    eprintln!("upload_cleanup_failed");
                }
            });
        }
    }
}

pub(super) async fn stage(
    objects: Arc<dyn ObjectStore>,
    key: Path,
    declared: usize,
    body: impl AsyncRead + Unpin,
    check: impl Fn() -> Result<()>,
) -> Result<Pending> {
    if !(1..=CHUNK_MAX_BYTES).contains(&declared) {
        return Err(UploadError::Size);
    }
    check()?;
    let upload = timeout(
        IO_TIMEOUT,
        objects.put_multipart_opts(&key, Default::default()),
    )
    .await
    .map_err(|_| UploadError::Unavailable)?
    .map_err(|_| UploadError::Unavailable)?;
    let mut pending = Pending {
        upload: Some(upload),
        objects,
        key,
        armed: true,
    };
    pending.run(declared, body, check).await?;
    Ok(pending)
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::{PutPayload, PutResult, UploadPart, memory::InMemory};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    #[derive(Debug, Default)]
    struct State {
        aborts: AtomicUsize,
        completes: AtomicUsize,
        bytes: AtomicUsize,
        started: Notify,
        aborted: Notify,
    }
    #[derive(Debug)]
    struct Fake {
        state: Arc<State>,
        failure: u8,
    }
    #[async_trait::async_trait]
    impl MultipartUpload for Fake {
        fn put_part(&mut self, data: PutPayload) -> UploadPart {
            self.state
                .bytes
                .store(data.content_length(), Ordering::SeqCst);
            let state = self.state.clone();
            let failure = self.failure;
            Box::pin(async move {
                state.started.notify_one();
                if failure == 3 {
                    std::future::pending::<()>().await;
                }
                if failure == 1 {
                    return Err(fault());
                }
                Ok(())
            })
        }
        async fn complete(&mut self) -> object_store::Result<PutResult> {
            self.state.completes.fetch_add(1, Ordering::SeqCst);
            if self.failure == 2 {
                return Err(fault());
            }
            Ok(PutResult {
                e_tag: None,
                version: None,
                extensions: Default::default(),
            })
        }
        async fn abort(&mut self) -> object_store::Result<()> {
            self.state.aborts.fetch_add(1, Ordering::SeqCst);
            self.state.aborted.notify_one();
            if self.failure == 4 {
                return Err(fault());
            }
            Ok(())
        }
    }
    fn fault() -> object_store::Error {
        object_store::Error::Generic {
            store: "fixture",
            source: "fault".into(),
        }
    }
    fn pending(state: Arc<State>, failure: u8) -> Pending {
        Pending {
            upload: Some(Box::new(Fake { state, failure })),
            objects: Arc::new(InMemory::new()),
            key: Path::from("private-test"),
            armed: true,
        }
    }

    #[tokio::test]
    async fn multipart_lifecycle_aborts_short_extra_write_and_completion_failures() {
        for (failure, declared, body, expected) in [
            (0, 4, &b"abc"[..], UploadError::Size),
            (0, 4, &b"abcde"[..], UploadError::Size),
            (1, 4, &b"data"[..], UploadError::Unavailable),
            (2, 4, &b"data"[..], UploadError::Unavailable),
        ] {
            let state = Arc::new(State::default());
            assert_eq!(
                pending(state.clone(), failure)
                    .run(declared, body, || Ok(()))
                    .await,
                Err(expected)
            );
            assert_eq!(state.aborts.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn cancelled_multipart_runs_abort_without_waiting_for_the_stalled_part() {
        let state = Arc::new(State::default());
        let mut pending = pending(state.clone(), 3);
        let task = tokio::spawn(async move { pending.run(4, &b"data"[..], || Ok(())).await });
        state.started.notified().await;
        task.abort();
        let _ = task.await;
        timeout(Duration::from_secs(2), state.aborted.notified())
            .await
            .unwrap();
        assert_eq!(state.aborts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn multipart_completed_bytes_are_private_and_expired_writes_are_deleted() {
        let objects = Arc::new(InMemory::new());
        let key = Path::from("staging/private/0/nonce");
        let calls = AtomicUsize::new(0);
        assert!(matches!(
            stage(objects.clone(), key.clone(), 4, &b"data"[..], || {
                if calls.fetch_add(1, Ordering::SeqCst) == 3 {
                    Err(UploadError::Denied)
                } else {
                    Ok(())
                }
            })
            .await,
            Err(UploadError::Denied)
        ));
        assert!(matches!(
            objects.head(&key).await,
            Err(object_store::Error::NotFound { .. })
        ));
    }
    struct Generated {
        remaining: usize,
        reads: Arc<AtomicUsize>,
    }
    impl AsyncRead for Generated {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            assert!(buf.remaining() <= 64 * 1024);
            self.reads.fetch_add(1, Ordering::SeqCst);
            let n = self.remaining.min(buf.remaining());
            buf.put_slice(&[7; 64 * 1024][..n]);
            self.remaining -= n;
            std::task::Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn multipart_buffer_and_reads_stay_bounded_at_maximum_and_invalid_declarations() {
        for declared in [CHUNK_MAX_BYTES, CHUNK_MAX_BYTES + 1] {
            let reads = Arc::new(AtomicUsize::new(0));
            let body = Generated {
                remaining: declared,
                reads: reads.clone(),
            };
            let state = Arc::new(State::default());
            let result = pending(state.clone(), 0)
                .run(declared, body, || Ok(()))
                .await;
            if declared == CHUNK_MAX_BYTES {
                assert_eq!(result, Ok(()));
                assert_eq!(state.bytes.load(Ordering::SeqCst), CHUNK_MAX_BYTES);
            } else {
                assert_eq!(result, Err(UploadError::Size));
                assert_eq!(reads.load(Ordering::SeqCst), 0);
                assert_eq!(state.aborts.load(Ordering::SeqCst), 1);
            }
        }
    }
    struct Disconnected;
    impl AsyncRead for Disconnected {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
        }
    }
    #[tokio::test]
    async fn disconnected_reader_aborts_before_publication() {
        let state = Arc::new(State::default());
        assert_eq!(
            pending(state.clone(), 0)
                .run(4, Disconnected, || Ok(()))
                .await,
            Err(UploadError::Unavailable)
        );
        assert_eq!(state.aborts.load(Ordering::SeqCst), 1);
        assert_eq!(state.completes.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn cleanup_attempts_private_object_deletion_even_when_abort_fails() {
        let mut part = pending(Arc::new(State::default()), 4);
        part.objects
            .put(&part.key, b"data".to_vec().into())
            .await
            .unwrap();
        assert_eq!(part.cleanup().await, Err(UploadError::Unavailable));
        assert!(matches!(
            part.objects.head(&part.key).await,
            Err(object_store::Error::NotFound { .. })
        ));
    }
    #[tokio::test]
    async fn cancellation_before_sql_commit_deletes_completed_private_bytes() {
        let objects = Arc::new(InMemory::new());
        let key = Path::from("staging/private/0/nonce");
        let staged = stage(objects.clone(), key.clone(), 4, &b"data"[..], || Ok(()))
            .await
            .unwrap();
        assert!(objects.head(&key).await.is_ok());
        drop(staged);
        timeout(Duration::from_secs(2), async {
            while objects.head(&key).await.is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let staged = stage(objects.clone(), key.clone(), 4, &b"data"[..], || Ok(()))
            .await
            .unwrap();
        staged.retain_for_commit();
        assert_eq!(
            objects
                .get(&key)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            b"data"
        );
    }
}
