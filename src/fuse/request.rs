//! Filesystem operation request
//!
//! A request represents information about a filesystem operation the kernel driver wants us to
//! perform.
//!
//! TODO: This module is meant to go away soon in favor of `ll::Request`.

use libc::{EIO, ENOSYS, EPROTO};
use log::{debug, error, warn};
use std::convert::TryFrom;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::abi::consts::{
    FATTR_ATIME, FATTR_FH, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_SIZE, FATTR_UID,
    FUSE_ASYNC_READ, FUSE_RELEASE_FLUSH,
};
#[cfg(target_os = "macos")]
use super::abi::consts::{
    FATTR_BKUPTIME, FATTR_CHGTIME, FATTR_CRTIME, FATTR_FLAGS, FUSE_CASE_INSENSITIVE,
    FUSE_VOL_RENAME, FUSE_XTIMES,
};

use super::abi::{
    fuse_init_out, fuse_setattr_in, fuse_setxattr_in, FUSE_KERNEL_MINOR_VERSION,
    FUSE_KERNEL_VERSION,
};
use super::channel::FuseChannelSender;
use super::ll_request;
use super::reply::{Reply, ReplyDirectory, ReplyEmpty, ReplyRaw};
use super::session::{Session, BUFFER_SIZE, MAX_WRITE_SIZE};
#[cfg(target_os = "macos")]
use super::FsExchangeParam;
use super::{
    Cast, Filesystem, FsGetlkParam, FsReleaseParam, FsSetattrParam, FsSetlkParam, FsSetxattrParam,
    FsWriteParam,
};

/// We generally support async reads
#[cfg(not(target_os = "macos"))]
const INIT_FLAGS: u32 = FUSE_ASYNC_READ;
// TODO: Add FUSE_EXPORT_SUPPORT and FUSE_BIG_WRITES (requires ABI 7.10)

/// On macOS, we additionally support case insensitiveness, volume renames and xtimes
/// TODO: we should eventually let the filesystem implementation decide which flags to set
#[cfg(target_os = "macos")]
const INIT_FLAGS: u32 = FUSE_ASYNC_READ | FUSE_CASE_INSENSITIVE | FUSE_VOL_RENAME | FUSE_XTIMES;
// TODO: Add FUSE_EXPORT_SUPPORT and FUSE_BIG_WRITES (requires ABI 7.10)

/// Request data structure
#[derive(Debug)]
pub struct Request<'a> {
    /// Channel sender for sending the reply
    ch: FuseChannelSender,
    /// Request raw data
    data: &'a [u8],
    /// Parsed request
    pub request: ll_request::Request<'a>,
}

impl<'a> Request<'a> {
    /// Create a new request from the given data
    pub fn new(ch: FuseChannelSender, data: &'a [u8]) -> Option<Request<'a>> {
        let request = match ll_request::Request::try_from(data) {
            Ok(request) => request,
            Err(err) => {
                // FIXME: Reply with ENOSYS?
                error!("{}", err);
                return None;
            }
        };

        Some(Self { ch, data, request })
    }

    /// Dispatch request to the given filesystem.
    /// This calls the appropriate filesystem operation method for the
    /// request and sends back the returned reply to the kernel
    #[allow(clippy::too_many_lines)]
    pub fn dispatch<FS: Filesystem>(&self, se: &mut Session<FS>) {
        #[cfg(target_os = "macos")]
        #[inline]
        /// Get macos setattr
        fn get_macos_setattr(
            arg: &fuse_setattr_in,
        ) -> (
            Option<SystemTime>,
            Option<SystemTime>,
            Option<SystemTime>,
            Option<u32>,
        ) {
            let crtime = match arg.valid & FATTR_CRTIME {
                0 => None,
                _ => Some(
                    match UNIX_EPOCH.checked_add(Duration::new(arg.crtime, arg.crtimensec)) {
                        Some(crt) => crt,
                        None => SystemTime::now(),
                    },
                ), // _ => Some(UNIX_EPOCH + Duration::new(arg.crtime, arg.crtimensec)),
            };
            let chgtime = match arg.valid & FATTR_CHGTIME {
                0 => None,
                _ => Some(
                    match UNIX_EPOCH.checked_add(Duration::new(arg.chgtime, arg.chgtimensec)) {
                        Some(cht) => cht,
                        None => SystemTime::now(),
                    },
                ), // _ => Some(UNIX_EPOCH + Duration::new(arg.chgtime, arg.chgtimensec)),
            };
            let bkuptime = match arg.valid & FATTR_BKUPTIME {
                0 => None,
                _ => Some(
                    match UNIX_EPOCH.checked_add(Duration::new(arg.bkuptime, arg.bkuptimensec)) {
                        Some(bkt) => bkt,
                        None => SystemTime::now(),
                    },
                ), // _ => Some(UNIX_EPOCH + Duration::new(arg.bkuptime, arg.bkuptimensec)),
            };
            let flags = match arg.valid & FATTR_FLAGS {
                0 => None,
                _ => Some(arg.flags),
            };
            (crtime, chgtime, bkuptime, flags)
        }
        #[cfg(target_os = "macos")]
        #[inline]
        /// Get position
        const fn get_position(arg: &fuse_setxattr_in) -> u32 {
            arg.position
        }
        #[cfg(not(target_os = "macos"))]
        #[inline]
        /// Get position
        const fn get_position(_arg: &fuse_setxattr_in) -> u32 {
            0
        }
        #[cfg(not(target_os = "macos"))]
        #[inline]
        /// Get macos setattr
        const fn get_macos_setattr(
            _arg: &fuse_setattr_in,
        ) -> (
            Option<SystemTime>,
            Option<SystemTime>,
            Option<SystemTime>,
            Option<u32>,
        ) {
            (None, None, None, None)
        }
        debug!("{}", self.request);

        match self.request.operation() {
            // Filesystem initialization
            ll_request::Operation::Init { arg } => {
                debug!("Init args: {:?}", arg);
                let reply: ReplyRaw<fuse_init_out> = self.reply();
                // We don't support ABI versions before 7.6
                if arg.major < 7 || (arg.major == 7 && arg.minor < 6) {
                    error!("Unsupported FUSE ABI version {}.{}", arg.major, arg.minor);
                    reply.error(EPROTO);
                    return;
                }
                // Remember ABI version supported by kernel
                se.proto_major = arg.major;
                se.proto_minor = arg.minor;
                // Call filesystem init method and give it a chance to return an error
                let res = se.filesystem.init(self);
                if let Err(err) = res {
                    reply.error(err);
                    return;
                }
                // Reply with our desired version and settings. If the kernel supports a
                // larger major version, it'll re-send a matching init message. If it
                // supports only lower major versions, we replied with an error above.
                let init = fuse_init_out {
                    major: FUSE_KERNEL_VERSION,
                    minor: FUSE_KERNEL_MINOR_VERSION,
                    // max_readahead: arg.max_readahead, // accept any readahead size
                    max_readahead: if BUFFER_SIZE.cast::<u32>() < arg.max_readahead {
                        BUFFER_SIZE.cast()
                    } else {
                        arg.max_readahead
                    }, // TODO: adjust BUFFER_SIZE according to max_readahead
                    flags: arg.flags & INIT_FLAGS, // use features given in INIT_FLAGS and reported as capable
                    #[cfg(not(feature = "abi-7-13"))]
                    unused: 0,
                    #[cfg(feature = "abi-7-13")]
                    max_background: 0_u16,
                    #[cfg(feature = "abi-7-13")]
                    congestion_threshold: 0_u16,
                    max_write: MAX_WRITE_SIZE.cast(), // TODO: use a max write size that fits into the session's buffer
                };
                debug!(
                    "INIT response: ABI {}.{}, flags {:#x}, max readahead {}, max write {}",
                    init.major, init.minor, init.flags, init.max_readahead, init.max_write
                );
                se.initialized = true;
                reply.ok(&init);
            }
            // Any operation is invalid before initialization
            _ if !se.initialized => {
                warn!("Ignoring FUSE operation before init: {}", self.request);
                self.reply::<ReplyEmpty>().error(EIO);
            }
            // Filesystem destroyed
            ll_request::Operation::Destroy => {
                se.filesystem.destroy(self);
                se.destroyed = true;
                self.reply::<ReplyEmpty>().ok();
            }
            // Any operation is invalid after destroy
            _ if se.destroyed => {
                warn!("Ignoring FUSE operation after destroy: {}", self.request);
                self.reply::<ReplyEmpty>().error(EIO);
            }

            ll_request::Operation::Interrupt { .. } => {
                // TODO: handle FUSE_INTERRUPT
                self.reply::<ReplyEmpty>().error(ENOSYS);
            }

            ll_request::Operation::Lookup { name } => {
                se.filesystem
                    .lookup(self, self.request.nodeid(), name, self.reply());
            }
            ll_request::Operation::Forget { arg } => {
                se.filesystem
                    .forget(self, self.request.nodeid(), arg.nlookup); // no reply
            }
            ll_request::Operation::GetAttr => {
                se.filesystem
                    .getattr(self, self.request.nodeid(), self.reply());
            }
            ll_request::Operation::SetAttr { arg } => {
                let mode = match arg.valid & FATTR_MODE {
                    0 => None,
                    _ => Some(arg.mode),
                };
                let user_id = match arg.valid & FATTR_UID {
                    0 => None,
                    _ => Some(arg.uid),
                };
                let group_id = match arg.valid & FATTR_GID {
                    0 => None,
                    _ => Some(arg.gid),
                };
                let size = match arg.valid & FATTR_SIZE {
                    0 => None,
                    _ => Some(arg.size),
                };
                let atime = match arg.valid & FATTR_ATIME {
                    0 => None,
                    _ => Some(UNIX_EPOCH + Duration::new(arg.atime, arg.atimensec)),
                };
                let m_time = match arg.valid & FATTR_MTIME {
                    0 => None,
                    _ => Some(UNIX_EPOCH + Duration::new(arg.mtime, arg.mtimensec)),
                };
                let fh = match arg.valid & FATTR_FH {
                    0 => None,
                    _ => Some(arg.fh),
                };
                let (crtime, chgtime, bkuptime, flags) = get_macos_setattr(arg);
                se.filesystem.setattr(
                    self,
                    FsSetattrParam {
                        ino: self.request.nodeid(),
                        mode,
                        uid: user_id,
                        gid: group_id,
                        size,
                        atime,
                        mtime: m_time,
                        fh,
                        crtime,
                        chgtime,
                        bkuptime,
                        flags,
                    },
                    self.reply(),
                );
            }
            ll_request::Operation::ReadLink => {
                se.filesystem
                    .readlink(self, self.request.nodeid(), self.reply());
            }
            ll_request::Operation::MkNod { arg, name } => {
                se.filesystem.mknod(
                    self,
                    self.request.nodeid(),
                    name,
                    arg.mode,
                    arg.rdev,
                    self.reply(),
                );
            }
            ll_request::Operation::MkDir { arg, name } => {
                se.filesystem
                    .mkdir(self, self.request.nodeid(), name, arg.mode, self.reply());
            }
            ll_request::Operation::Unlink { name } => {
                se.filesystem
                    .unlink(self, self.request.nodeid(), name, self.reply());
            }
            ll_request::Operation::RmDir { name } => {
                se.filesystem
                    .rmdir(self, self.request.nodeid(), name, self.reply());
            }
            ll_request::Operation::SymLink { name, link } => {
                se.filesystem.symlink(
                    self,
                    self.request.nodeid(),
                    name,
                    Path::new(link),
                    self.reply(),
                );
            }
            ll_request::Operation::Rename { arg, name, newname } => {
                se.filesystem.rename(
                    self,
                    self.request.nodeid(),
                    name,
                    arg.newdir,
                    newname,
                    self.reply(),
                );
            }
            ll_request::Operation::Link { arg, name } => {
                se.filesystem.link(
                    self,
                    arg.oldnodeid,
                    self.request.nodeid(),
                    name,
                    self.reply(),
                );
            }
            ll_request::Operation::Open { arg } => {
                se.filesystem
                    .open(self, self.request.nodeid(), arg.flags, self.reply());
            }
            ll_request::Operation::Read { arg } => {
                se.filesystem.read(
                    self,
                    self.request.nodeid(),
                    arg.fh,
                    arg.offset.cast(),
                    arg.size,
                    self.reply(),
                );
            }
            ll_request::Operation::Write { arg, data } => {
                assert_eq!(data.len(), arg.size.cast());
                se.filesystem.write(
                    self,
                    FsWriteParam {
                        ino: self.request.nodeid(),
                        fh: arg.fh,
                        offset: arg.offset.cast(),
                        data,
                        flags: arg.write_flags,
                    },
                    self.reply(),
                );
            }
            ll_request::Operation::Flush { arg } => {
                se.filesystem.flush(
                    self,
                    self.request.nodeid(),
                    arg.fh,
                    arg.lock_owner,
                    self.reply(),
                );
            }
            ll_request::Operation::Release { arg } => {
                let flush_parameter = !matches!(arg.release_flags & FUSE_RELEASE_FLUSH, 0);

                se.filesystem.release(
                    self,
                    FsReleaseParam {
                        ino: self.request.nodeid(),
                        fh: arg.fh,
                        flags: arg.flags,
                        lock_owner: arg.lock_owner,
                        flush: flush_parameter,
                    },
                    self.reply(),
                );
            }
            ll_request::Operation::FSync { arg } => {
                let datasync = !matches!(arg.fsync_flags & 1, 0);
                se.filesystem
                    .fsync(self, self.request.nodeid(), arg.fh, datasync, self.reply());
            }
            ll_request::Operation::OpenDir { arg } => {
                se.filesystem
                    .opendir(self, self.request.nodeid(), arg.flags, self.reply());
            }
            ll_request::Operation::ReadDir { arg } => {
                se.filesystem.readdir(
                    self,
                    self.request.nodeid(),
                    arg.fh,
                    arg.offset.cast(),
                    ReplyDirectory::new(self.request.unique(), self.ch, arg.size.cast()),
                );
            }
            ll_request::Operation::ReleaseDir { arg } => {
                se.filesystem.releasedir(
                    self,
                    self.request.nodeid(),
                    arg.fh,
                    arg.flags,
                    self.reply(),
                );
            }
            ll_request::Operation::FSyncDir { arg } => {
                let datasync = !matches!(arg.fsync_flags & 1, 0);
                se.filesystem
                    .fsyncdir(self, self.request.nodeid(), arg.fh, datasync, self.reply());
            }
            ll_request::Operation::StatFs => {
                se.filesystem
                    .statfs(self, self.request.nodeid(), self.reply());
            }
            ll_request::Operation::SetXAttr { arg, name, value } => {
                assert!(value.len() == arg.size.cast());
                se.filesystem.setxattr(
                    self,
                    FsSetxattrParam {
                        ino: self.request.nodeid(),
                        name,
                        value,
                        flags: arg.flags,
                        position: get_position(arg),
                    },
                    self.reply(),
                );
            }
            ll_request::Operation::GetXAttr { arg, name } => {
                se.filesystem
                    .getxattr(self, self.request.nodeid(), name, arg.size, self.reply());
            }
            ll_request::Operation::ListXAttr { arg } => {
                se.filesystem
                    .listxattr(self, self.request.nodeid(), arg.size, self.reply());
            }
            ll_request::Operation::RemoveXAttr { name } => {
                se.filesystem
                    .removexattr(self, self.request.nodeid(), name, self.reply());
            }
            ll_request::Operation::Access { arg } => {
                se.filesystem
                    .access(self, self.request.nodeid(), arg.mask, self.reply());
            }
            ll_request::Operation::Create { arg, name } => {
                se.filesystem.create(
                    self,
                    self.request.nodeid(),
                    name,
                    arg.mode,
                    arg.flags,
                    self.reply(),
                );
            }
            ll_request::Operation::GetLk { arg } => {
                se.filesystem.getlk(
                    self,
                    FsGetlkParam {
                        ino: self.request.nodeid(),
                        fh: arg.fh,
                        lock_owner: arg.owner,
                        start: arg.lk.start,
                        end: arg.lk.end,
                        typ: arg.lk.typ,
                        pid: arg.lk.pid,
                    },
                    self.reply(),
                );
            }
            ll_request::Operation::SetLk { arg } => {
                se.filesystem.setlk(
                    self,
                    FsSetlkParam {
                        ino: self.request.nodeid(),
                        fh: arg.fh,
                        lock_owner: arg.owner,
                        start: arg.lk.start,
                        end: arg.lk.end,
                        typ: arg.lk.typ,
                        pid: arg.lk.pid,
                        sleep: false,
                    },
                    self.reply(),
                );
            }
            ll_request::Operation::SetLkW { arg } => {
                se.filesystem.setlk(
                    self,
                    FsSetlkParam {
                        ino: self.request.nodeid(),
                        fh: arg.fh,
                        lock_owner: arg.owner,
                        start: arg.lk.start,
                        end: arg.lk.end,
                        typ: arg.lk.typ,
                        pid: arg.lk.pid,
                        sleep: true,
                    },
                    self.reply(),
                );
            }
            ll_request::Operation::BMap { arg } => {
                se.filesystem.bmap(
                    self,
                    self.request.nodeid(),
                    arg.blocksize,
                    arg.block,
                    self.reply(),
                );
            }

            #[cfg(target_os = "macos")]
            ll_request::Operation::SetVolName { name } => {
                se.filesystem.setvolname(self, name, self.reply());
            }
            #[cfg(target_os = "macos")]
            ll_request::Operation::GetXTimes => {
                se.filesystem
                    .getxtimes(self, self.request.nodeid(), self.reply());
            }
            #[cfg(target_os = "macos")]
            ll_request::Operation::Exchange {
                arg,
                oldname,
                newname,
            } => {
                se.filesystem.exchange(
                    self,
                    FsExchangeParam {
                        parent: arg.olddir,
                        name: oldname,
                        newparent: arg.newdir,
                        newname,
                        options: arg.options,
                    },
                    self.reply(),
                );
            }
            ll_request::Operation::NoImplementation => {
                error!("Operation is not implemented!");
            }
        }
    }

    /// Create a reply object for this request that can be passed to the filesystem
    /// implementation and makes sure that a request is replied exactly once
    fn reply<T: Reply>(&self) -> T {
        Reply::new(self.request.unique(), self.ch)
    }

    /// Returns the unique identifier of this request
    #[inline]
    #[allow(dead_code)]
    pub const fn unique(&self) -> u64 {
        self.request.unique()
    }

    /// Returns the uid of this request
    #[inline]
    #[allow(dead_code)]
    pub const fn uid(&self) -> u32 {
        self.request.uid()
    }

    /// Returns the gid of this request
    #[inline]
    #[allow(dead_code)]
    pub const fn gid(&self) -> u32 {
        self.request.gid()
    }

    /// Returns the pid of this request
    #[inline]
    #[allow(dead_code)]
    pub const fn pid(&self) -> u32 {
        self.request.pid()
    }
}
