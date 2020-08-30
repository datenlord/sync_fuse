//! FUSE kernel interface.
//!
//! Types and definitions used for communication between the kernel driver and the userspace
//! part of a FUSE filesystem. Since the kernel driver may be installed independently, the ABI
//! interface is versioned and capabilities are exchanged during the initialization (mounting)
//! of a filesystem.
//!
//! OSXFUSE (macOS): <https://github.com/osxfuse/fuse/blob/master/include/fuse_kernel.h>
//! - supports ABI 7.8 in OSXFUSE 2.x
//! - supports ABI 7.19 since OSXFUSE 3.0.0
//!
//! libfuse (Linux/BSD): <https://github.com/libfuse/libfuse/blob/master/include/fuse_kernel.h>
//! - supports ABI 7.8 since FUSE 2.6.0
//! - supports ABI 7.12 since FUSE 2.8.0
//! - supports ABI 7.18 since FUSE 2.9.0
//! - supports ABI 7.19 since FUSE 2.9.1
//! - supports ABI 7.26 since FUSE 3.0.0
//!
//! Items without a version annotation are valid with ABI 7.8 and later

#![warn(missing_debug_implementations, rust_2018_idioms)]
#![allow(missing_docs)]

use std::convert::TryFrom;

/// fuse kernel version
pub const FUSE_KERNEL_VERSION: u32 = 7;

#[cfg(not(feature = "abi-7-9"))]
/// fuse kernel minor version
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 8;
#[cfg(all(feature = "abi-7-9", not(feature = "abi-7-10")))]
/// fuse kernel minor version
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 9;
/// fuse kernel minor version
#[cfg(all(feature = "abi-7-10", not(feature = "abi-7-11")))]
/// fuse kernel minor version
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 10;
#[cfg(all(feature = "abi-7-11", not(feature = "abi-7-12")))]
/// fuse kernel minor version
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 11;
#[cfg(all(feature = "abi-7-12", not(feature = "abi-7-13")))]
/// fuse kernel minor version
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 12;
#[cfg(all(feature = "abi-7-13", not(feature = "abi-7-14")))]
/// fuse kernel minor version
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 13;
#[cfg(all(feature = "abi-7-14", not(feature = "abi-7-15")))]
/// fuse kernel minor version
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 14;
#[cfg(all(feature = "abi-7-15", not(feature = "abi-7-16")))]
/// fuse kernel minor version
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 15;
#[cfg(all(feature = "abi-7-16", not(feature = "abi-7-17")))]
/// fuse kernel minor version
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 16;
#[cfg(all(feature = "abi-7-17", not(feature = "abi-7-18")))]
/// fuse kernel minor version
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 17;
#[cfg(all(feature = "abi-7-18", not(feature = "abi-7-19")))]
/// fuse kernel minor version
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 18;
#[cfg(feature = "abi-7-19")]
/// fuse kernel minor version
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 19;

/// fuse root id
pub const FUSE_ROOT_ID: u64 = 1;

#[repr(C)]
#[derive(Debug)]
/// fuse attribute
pub struct fuse_attr {
    /// Inode
    pub ino: u64,
    /// Size
    pub size: u64,
    /// Blocks
    pub blocks: u64,
    /// Access time
    pub atime: u64,
    /// Modify time
    pub mtime: u64,
    /// Create time
    pub ctime: u64,
    #[cfg(target_os = "macos")]
    /// Create time
    pub crtime: u64,
    /// Access time seconds
    pub atimensec: u32,
    /// Modify time seconds
    pub mtimensec: u32,
    /// Create time seconds
    pub ctimensec: u32,
    #[cfg(target_os = "macos")]
    /// Create time seconds
    pub crtimensec: u32,
    /// Mode
    pub mode: u32,
    /// Nlink
    pub nlink: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Rdev
    pub rdev: u32,
    #[cfg(target_os = "macos")]
    /// Flags
    pub flags: u32, // see chflags(2)
    #[cfg(feature = "abi-7-9")]
    /// Block size
    pub blksize: u32,
    #[cfg(feature = "abi-7-9")]
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse kstatfs
pub struct fuse_kstatfs {
    ///Total blocks (in units of frsize)
    pub blocks: u64,
    /// Free blocks
    pub bfree: u64,
    /// Free blocks for unprivileged users
    pub bavail: u64,
    /// Total inodes
    pub files: u64,
    /// Free inodes
    pub ffree: u64,
    /// Filesystem block size
    pub bsize: u32,
    /// Maximum filename length
    pub namelen: u32,
    /// Fundamental file system block size
    pub frsize: u32,
    /// Padding
    pub padding: u32,
    /// Spare
    pub spare: [u32; 6],
}

#[repr(C)]
#[derive(Debug)]
/// Fuse file lock
pub struct fuse_file_lock {
    /// Start
    pub start: u64,
    /// End
    pub end: u64,
    /// Type
    pub typ: u32,
    /// Pid
    pub pid: u32,
}

#[allow(dead_code)]
/// Constants
pub mod consts {
    // Bitmasks for fuse_setattr_in.valid
    /// Mode
    pub const FATTR_MODE: u32 = 1;
    /// User ID
    pub const FATTR_UID: u32 = 1 << 1;
    /// Group ID
    pub const FATTR_GID: u32 = 1 << 2;
    /// Size
    pub const FATTR_SIZE: u32 = 1 << 3;
    /// Acess time
    pub const FATTR_ATIME: u32 = 1 << 4;
    /// Modify time
    pub const FATTR_MTIME: u32 = 1 << 5;
    /// File handler
    pub const FATTR_FH: u32 = 1 << 6;
    #[cfg(feature = "abi-7-9")]
    /// Access time now
    pub const FATTR_ATIME_NOW: u32 = 1 << 7;
    #[cfg(feature = "abi-7-9")]
    /// Modify time now
    pub const FATTR_MTIME_NOW: u32 = 1 << 8;
    #[cfg(feature = "abi-7-9")]
    /// Lock owner
    pub const FATTR_LOCKOWNER: u32 = 1 << 9;

    #[cfg(target_os = "macos")]
    /// Create time
    pub const FATTR_CRTIME: u32 = 1 << 28;
    #[cfg(target_os = "macos")]
    /// Change time
    pub const FATTR_CHGTIME: u32 = 1 << 29;
    #[cfg(target_os = "macos")]
    /// Backup time
    pub const FATTR_BKUPTIME: u32 = 1 << 30;
    #[cfg(target_os = "macos")]
    /// Flags
    pub const FATTR_FLAGS: u32 = 1 << 31;

    /// Flags returned by the open request
    /// File open direct IO
    pub const FOPEN_DIRECT_IO: u32 = 1; // bypass page cache for this open file
    /// File open keep cache
    pub const FOPEN_KEEP_CACHE: u32 = 1 << 1; // don't invalidate the data cache on open
    #[cfg(feature = "abi-7-10")]
    /// File open non-seekable
    pub const FOPEN_NONSEEKABLE: u32 = 1 << 2; // the file is not seekable

    #[cfg(target_os = "macos")]
    /// File open purge attr
    pub const FOPEN_PURGE_ATTR: u32 = 1 << 30;
    #[cfg(target_os = "macos")]
    /// File open purge UBC
    pub const FOPEN_PURGE_UBC: u32 = 1 << 31;

    /// Init request/reply flags
    /// Fuse async read
    pub const FUSE_ASYNC_READ: u32 = 1; // asynchronous read requests
    /// Fuse poxis locks
    pub const FUSE_POSIX_LOCKS: u32 = 1 << 1; // remote locking for POSIX file locks
    #[cfg(feature = "abi-7-9")]
    /// Fuse file ops
    pub const FUSE_FILE_OPS: u32 = 1 << 2; // kernel sends file handle for fstat, etc...
    #[cfg(feature = "abi-7-9")]
    /// Fuse atomic O_TRUNC
    pub const FUSE_ATOMIC_O_TRUNC: u32 = 1 << 3; // handles the O_TRUNC open flag in the filesystem
    #[cfg(feature = "abi-7-10")]
    /// Fuse export support
    pub const FUSE_EXPORT_SUPPORT: u32 = 1 << 4; // filesystem handles lookups of "." and ".."
    #[cfg(feature = "abi-7-9")]
    /// Fuse big writes
    pub const FUSE_BIG_WRITES: u32 = 1 << 5; // filesystem can handle write size larger than 4kB
    #[cfg(feature = "abi-7-12")]
    /// Fuse don't mask
    pub const FUSE_DONT_MASK: u32 = 1 << 6; // don't apply umask to file mode on create operations

    #[cfg(all(feature = "abi-7-14", not(target_os = "macos")))]
    /// Fuse splice write
    pub const FUSE_SPLICE_WRITE: u32 = 1 << 7; // kernel supports splice write on the device
    #[cfg(all(feature = "abi-7-14", not(target_os = "macos")))]
    /// Fuse splice move
    pub const FUSE_SPLICE_MOVE: u32 = 1 << 8; // kernel supports splice move on the device
    #[cfg(not(target_os = "macos"))]
    #[cfg(feature = "abi-7-14")]
    /// Fuse splice read
    pub const FUSE_SPLICE_READ: u32 = 1 << 9; // kernel supports splice read on the device
    #[cfg(feature = "abi-7-17")]
    /// Fuse flock locks
    pub const FUSE_FLOCK_LOCKS: u32 = 1 << 10; // remote locking for BSD style file locks
    #[cfg(feature = "abi-7-18")]
    /// Fuse has ioctl dir
    pub const FUSE_HAS_IOCTL_DIR: u32 = 1 << 11; // kernel supports ioctl on directories

    #[cfg(target_os = "macos")]
    /// Fuse allocate
    pub const FUSE_ALLOCATE: u32 = 1 << 27;
    #[cfg(target_os = "macos")]
    /// Fuse exchange data
    pub const FUSE_EXCHANGE_DATA: u32 = 1 << 28;
    #[cfg(target_os = "macos")]
    /// Fuse case insensitive
    pub const FUSE_CASE_INSENSITIVE: u32 = 1 << 29;
    #[cfg(target_os = "macos")]
    /// Fuse vol rename
    pub const FUSE_VOL_RENAME: u32 = 1 << 30;
    #[cfg(target_os = "macos")]
    /// Fuse xtimes
    pub const FUSE_XTIMES: u32 = 1 << 31;

    // CUSE init request/reply flags
    #[cfg(feature = "abi-7-12")]
    /// Cuse unrestricted ioctl
    pub const CUSE_UNRESTRICTED_IOCTL: u32 = 1 << 0; // use unrestricted ioctl

    // Release flags
    /// Fuse release flush
    pub const FUSE_RELEASE_FLUSH: u32 = 1;
    #[cfg(feature = "abi-7-17")]
    /// Fuse release flock unlock
    pub const FUSE_RELEASE_FLOCK_UNLOCK: u32 = 1 << 1;

    // Getattr flags
    #[cfg(feature = "abi-7-9")]
    /// Fuse getattr file handler
    pub const FUSE_GETATTR_FH: u32 = 1 << 0;

    // Lock flags
    #[cfg(feature = "abi-7-9")]
    /// Fuse lock flock
    pub const FUSE_LK_FLOCK: u32 = 1 << 0;

    // Write flags
    #[cfg(feature = "abi-7-9")]
    /// Fuse write cache
    pub const FUSE_WRITE_CACHE: u32 = 1 << 0; // delayed write from page cache, file handle is guessed
    #[cfg(feature = "abi-7-9")]
    /// Fuse write lockowner
    pub const FUSE_WRITE_LOCKOWNER: u32 = 1 << 1; // lock_owner field is valid

    // Read flags
    #[cfg(feature = "abi-7-9")]
    /// Fuse read lockowner
    pub const FUSE_READ_LOCKOWNER: u32 = 1 << 1;

    // IOCTL flags
    #[cfg(feature = "abi-7-11")]
    /// Fuse ioctl compat
    pub const FUSE_IOCTL_COMPAT: u32 = 1 << 0; // 32bit compat ioctl on 64bit machine
    #[cfg(feature = "abi-7-11")]
    /// Fuse ioctl unrestricted
    pub const FUSE_IOCTL_UNRESTRICTED: u32 = 1 << 1; // not restricted to well-formed ioctls, retry allowed
    #[cfg(feature = "abi-7-11")]
    /// Fuse ioctl retry
    pub const FUSE_IOCTL_RETRY: u32 = 1 << 2; // retry with new iovecs
    #[cfg(feature = "abi-7-16")]
    /// Fuse ioctl 32bit
    pub const FUSE_IOCTL_32BIT: u32 = 1 << 3; // 32bit ioctl
    #[cfg(feature = "abi-7-18")]
    /// Fuse ioctl dir
    pub const FUSE_IOCTL_DIR: u32 = 1 << 4; // is a directory
    #[cfg(feature = "abi-7-11")]
    /// Fuse ioctl max iov
    pub const FUSE_IOCTL_MAX_IOV: u32 = 256; // maximum of in_iovecs + out_iovecs

    // Poll flags
    #[cfg(feature = "abi-7-9")]
    /// Fuse poll sechedule notify
    pub const FUSE_POLL_SCHEDULE_NOTIFY: u32 = 1 << 0; // request poll notify

    // The read buffer is required to be at least 8k, but may be much larger
    /// Fuse min read buffer
    pub const FUSE_MIN_READ_BUFFER: usize = 8192;
}

/// Invalid opcode error.
#[derive(Debug)]
pub struct InvalidOpcodeError;

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
#[allow(clippy::missing_docs_in_private_items)]
pub enum fuse_opcode {
    FUSE_LOOKUP = 1,
    FUSE_FORGET = 2, // no reply
    FUSE_GETATTR = 3,
    FUSE_SETATTR = 4,
    FUSE_READLINK = 5,
    FUSE_SYMLINK = 6,
    FUSE_MKNOD = 8,
    FUSE_MKDIR = 9,
    FUSE_UNLINK = 10,
    FUSE_RMDIR = 11,
    FUSE_RENAME = 12,
    FUSE_LINK = 13,
    FUSE_OPEN = 14,
    FUSE_READ = 15,
    FUSE_WRITE = 16,
    FUSE_STATFS = 17,
    FUSE_RELEASE = 18,
    FUSE_FSYNC = 20,
    FUSE_SETXATTR = 21,
    FUSE_GETXATTR = 22,
    FUSE_LISTXATTR = 23,
    FUSE_REMOVEXATTR = 24,
    FUSE_FLUSH = 25,
    FUSE_INIT = 26,
    FUSE_OPENDIR = 27,
    FUSE_READDIR = 28,
    FUSE_RELEASEDIR = 29,
    FUSE_FSYNCDIR = 30,
    FUSE_GETLK = 31,
    FUSE_SETLK = 32,
    FUSE_SETLKW = 33,
    FUSE_ACCESS = 34,
    FUSE_CREATE = 35,
    FUSE_INTERRUPT = 36,
    FUSE_BMAP = 37,
    FUSE_DESTROY = 38,
    #[cfg(feature = "abi-7-11")]
    FUSE_IOCTL = 39,
    #[cfg(feature = "abi-7-11")]
    FUSE_POLL = 40,
    #[cfg(feature = "abi-7-15")]
    FUSE_NOTIFY_REPLY = 41,
    #[cfg(feature = "abi-7-16")]
    FUSE_BATCH_FORGET = 42,
    #[cfg(feature = "abi-7-19")]
    FUSE_FALLOCATE = 43,

    #[cfg(target_os = "macos")]
    FUSE_SETVOLNAME = 61,
    #[cfg(target_os = "macos")]
    FUSE_GETXTIMES = 62,
    #[cfg(target_os = "macos")]
    FUSE_EXCHANGE = 63,

    #[cfg(feature = "abi-7-12")]
    CUSE_INIT = 4096,
}

impl TryFrom<u32> for fuse_opcode {
    type Error = InvalidOpcodeError;

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        match n {
            1 => Ok(Self::FUSE_LOOKUP),
            2 => Ok(Self::FUSE_FORGET),
            3 => Ok(Self::FUSE_GETATTR),
            4 => Ok(Self::FUSE_SETATTR),
            5 => Ok(Self::FUSE_READLINK),
            6 => Ok(Self::FUSE_SYMLINK),
            8 => Ok(Self::FUSE_MKNOD),
            9 => Ok(Self::FUSE_MKDIR),
            10 => Ok(Self::FUSE_UNLINK),
            11 => Ok(Self::FUSE_RMDIR),
            12 => Ok(Self::FUSE_RENAME),
            13 => Ok(Self::FUSE_LINK),
            14 => Ok(Self::FUSE_OPEN),
            15 => Ok(Self::FUSE_READ),
            16 => Ok(Self::FUSE_WRITE),
            17 => Ok(Self::FUSE_STATFS),
            18 => Ok(Self::FUSE_RELEASE),
            20 => Ok(Self::FUSE_FSYNC),
            21 => Ok(Self::FUSE_SETXATTR),
            22 => Ok(Self::FUSE_GETXATTR),
            23 => Ok(Self::FUSE_LISTXATTR),
            24 => Ok(Self::FUSE_REMOVEXATTR),
            25 => Ok(Self::FUSE_FLUSH),
            26 => Ok(Self::FUSE_INIT),
            27 => Ok(Self::FUSE_OPENDIR),
            28 => Ok(Self::FUSE_READDIR),
            29 => Ok(Self::FUSE_RELEASEDIR),
            30 => Ok(Self::FUSE_FSYNCDIR),
            31 => Ok(Self::FUSE_GETLK),
            32 => Ok(Self::FUSE_SETLK),
            33 => Ok(Self::FUSE_SETLKW),
            34 => Ok(Self::FUSE_ACCESS),
            35 => Ok(Self::FUSE_CREATE),
            36 => Ok(Self::FUSE_INTERRUPT),
            37 => Ok(Self::FUSE_BMAP),
            38 => Ok(Self::FUSE_DESTROY),
            #[cfg(feature = "abi-7-11")]
            39 => Ok(Self::FUSE_IOCTL),
            #[cfg(feature = "abi-7-11")]
            40 => Ok(Self::FUSE_POLL),
            #[cfg(feature = "abi-7-15")]
            41 => Ok(Self::FUSE_NOTIFY_REPLY),
            #[cfg(feature = "abi-7-16")]
            42 => Ok(Self::FUSE_BATCH_FORGET),
            #[cfg(feature = "abi-7-19")]
            43 => Ok(Self::FUSE_FALLOCATE),

            #[cfg(target_os = "macos")]
            61 => Ok(Self::FUSE_SETVOLNAME),
            #[cfg(target_os = "macos")]
            62 => Ok(Self::FUSE_GETXTIMES),
            #[cfg(target_os = "macos")]
            63 => Ok(Self::FUSE_EXCHANGE),

            #[cfg(feature = "abi-7-12")]
            4096 => Ok(Self::CUSE_INIT),

            _ => Err(InvalidOpcodeError),
        }
    }
}

/// Invalid notify code error.
#[cfg(feature = "abi-7-11")]
#[derive(Debug)]
pub struct InvalidNotifyCodeError;

#[cfg(feature = "abi-7-11")]
#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum fuse_notify_code {
    #[cfg(feature = "abi-7-11")]
    FUSE_POLL = 1,
    #[cfg(feature = "abi-7-12")]
    FUSE_NOTIFY_INVAL_INODE = 2,
    #[cfg(feature = "abi-7-12")]
    FUSE_NOTIFY_INVAL_ENTRY = 3,
    #[cfg(feature = "abi-7-15")]
    FUSE_NOTIFY_STORE = 4,
    #[cfg(feature = "abi-7-15")]
    FUSE_NOTIFY_RETRIEVE = 5,
    #[cfg(feature = "abi-7-18")]
    FUSE_NOTIFY_DELETE = 6,
}

#[cfg(feature = "abi-7-11")]
impl TryFrom<u32> for fuse_notify_code {
    type Error = InvalidNotifyCodeError;

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        match n {
            #[cfg(feature = "abi-7-11")]
            1 => Ok(fuse_notify_code::FUSE_POLL),
            #[cfg(feature = "abi-7-12")]
            2 => Ok(fuse_notify_code::FUSE_NOTIFY_INVAL_INODE),
            #[cfg(feature = "abi-7-12")]
            3 => Ok(fuse_notify_code::FUSE_NOTIFY_INVAL_ENTRY),
            #[cfg(feature = "abi-7-15")]
            4 => Ok(fuse_notify_code::FUSE_NOTIFY_STORE),
            #[cfg(feature = "abi-7-15")]
            5 => Ok(fuse_notify_code::FUSE_NOTIFY_RETRIEVE),
            #[cfg(feature = "abi-7-18")]
            6 => Ok(fuse_notify_code::FUSE_NOTIFY_DELETE),

            _ => Err(InvalidNotifyCodeError),
        }
    }
}

#[repr(C)]
#[derive(Debug)]
/// Fuse entry out
pub struct fuse_entry_out {
    /// Node id
    pub nodeid: u64,
    /// Generation
    pub generation: u64,
    /// Entry valid
    pub entry_valid: u64,
    /// Attr valid
    pub attr_valid: u64,
    /// Entry valid nsec
    pub entry_valid_nsec: u32,
    /// Attr valid nsec
    pub attr_valid_nsec: u32,
    /// Attr
    pub attr: fuse_attr,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse forget in
pub struct fuse_forget_in {
    /// Nlookup
    pub nlookup: u64,
}

#[cfg(feature = "abi-7-16")]
#[repr(C)]
#[derive(Debug)]
/// Fuse forget one
pub struct fuse_forget_one {
    pub nodeid: u64,
    pub nlookup: u64,
}

#[cfg(feature = "abi-7-16")]
#[repr(C)]
#[derive(Debug)]
/// Fuse batch forget in
pub struct fuse_batch_forget_in {
    /// Count
    pub count: u32,
    /// Dummy
    pub dummy: u32,
}

#[cfg(feature = "abi-7-9")]
#[repr(C)]
#[derive(Debug)]
/// Fuse getattr in
pub struct fuse_getattr_in {
    /// Getattr flags
    pub getattr_flags: u32,
    /// Dummy
    pub dummy: u32,
    /// File handler
    pub fh: u64,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse attr out
pub struct fuse_attr_out {
    /// Attr valid
    pub attr_valid: u64,
    /// Attr valid nsec
    pub attr_valid_nsec: u32,
    /// Dummy
    pub dummy: u32,
    /// Attr
    pub attr: fuse_attr,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Debug)]
/// Fuse getxtimes out
pub struct fuse_getxtimes_out {
    /// Backup time
    pub bkuptime: u64,
    /// Create time
    pub crtime: u64,
    /// Backup time nsec
    pub bkuptimensec: u32,
    /// Create time nsec
    pub crtimensec: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse mknod in
pub struct fuse_mknod_in {
    /// Mode
    pub mode: u32,
    /// Rdev
    pub rdev: u32,
    #[cfg(feature = "abi-7-12")]
    /// Umask
    pub umask: u32,
    #[cfg(feature = "abi-7-12")]
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse mkdir in
pub struct fuse_mkdir_in {
    /// Mode
    pub mode: u32,
    #[cfg(not(feature = "abi-7-12"))]
    /// Padding
    pub padding: u32,
    #[cfg(feature = "abi-7-12")]
    /// Umask
    pub umask: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse rename in
pub struct fuse_rename_in {
    /// New dir
    pub newdir: u64,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Debug)]
/// Fuse exchange in
pub struct fuse_exchange_in {
    /// Old dir
    pub olddir: u64,
    /// New dir
    pub newdir: u64,
    /// Options
    pub options: u64,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse link in
pub struct fuse_link_in {
    /// Old node ID
    pub oldnodeid: u64,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse setattr in
pub struct fuse_setattr_in {
    /// Valid
    pub valid: u32,
    /// Padding
    pub padding: u32,
    /// File handler
    pub fh: u64,
    /// Size
    pub size: u64,
    #[cfg(not(feature = "abi-7-9"))]
    /// Unused1
    pub unused1: u64,
    #[cfg(feature = "abi-7-9")]
    /// Lock owner
    pub lock_owner: u64,
    /// Access time
    pub atime: u64,
    /// Modify time
    pub mtime: u64,
    /// Unused2
    pub unused2: u64,
    /// Access time nsec
    pub atimensec: u32,
    /// Modify time nsec
    pub mtimensec: u32,
    /// Unused3
    pub unused3: u32,
    /// Mode
    pub mode: u32,
    /// Unused4
    pub unused4: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Unused5
    pub unused5: u32,
    #[cfg(target_os = "macos")]
    /// Backup time
    pub bkuptime: u64,
    #[cfg(target_os = "macos")]
    /// Change time
    pub chgtime: u64,
    #[cfg(target_os = "macos")]
    /// Create time
    pub crtime: u64,
    #[cfg(target_os = "macos")]
    /// Backup time nsec
    pub bkuptimensec: u32,
    #[cfg(target_os = "macos")]
    /// Chage time nsec
    pub chgtimensec: u32,
    #[cfg(target_os = "macos")]
    /// Create time nsec
    pub crtimensec: u32,
    #[cfg(target_os = "macos")]
    /// Flags
    pub flags: u32, // see chflags(2)
}

#[repr(C)]
#[derive(Debug)]
/// Fuse open in
pub struct fuse_open_in {
    /// Flags
    pub flags: u32,
    /// Unused
    pub unused: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse create in
pub struct fuse_create_in {
    /// Flags
    pub flags: u32,
    /// Mode
    pub mode: u32,
    #[cfg(feature = "abi-7-12")]
    /// Umask
    pub umask: u32,
    #[cfg(feature = "abi-7-12")]
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse open out
pub struct fuse_open_out {
    /// File handler
    pub fh: u64,
    /// Open flags
    pub open_flags: u32,
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse release in
pub struct fuse_release_in {
    /// File handler
    pub fh: u64,
    /// Flags
    pub flags: u32,
    /// Release flags
    pub release_flags: u32,
    /// Lock owner
    pub lock_owner: u64,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse flush in
pub struct fuse_flush_in {
    /// File handler
    pub fh: u64,
    /// Unused
    pub unused: u32,
    /// Padding
    pub padding: u32,
    /// Lock owner
    pub lock_owner: u64,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse read in
pub struct fuse_read_in {
    /// File handler
    pub fh: u64,
    /// Offset
    pub offset: u64,
    /// Size
    pub size: u32,
    #[cfg(feature = "abi-7-9")]
    /// Read flags
    pub read_flags: u32,
    #[cfg(feature = "abi-7-9")]
    /// Lock owner
    pub lock_owner: u64,
    #[cfg(feature = "abi-7-9")]
    /// Flags
    pub flags: u32,
    #[cfg(feature = "abi-7-9")]
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse write in
pub struct fuse_write_in {
    /// File handler
    pub fh: u64,
    /// Offset
    pub offset: u64,
    /// Size
    pub size: u32,
    /// Write flags
    pub write_flags: u32,
    #[cfg(feature = "abi-7-9")]
    /// Lock owner
    pub lock_owner: u64,
    #[cfg(feature = "abi-7-9")]
    /// Flags
    pub flags: u32,
    #[cfg(feature = "abi-7-9")]
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse write out
pub struct fuse_write_out {
    /// Size
    pub size: u32,
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse statfs out
pub struct fuse_statfs_out {
    /// stat
    pub st: fuse_kstatfs,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse fsync in
pub struct fuse_fsync_in {
    /// File handler
    pub fh: u64,
    /// Fsync flags
    pub fsync_flags: u32,
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse setxattr in
pub struct fuse_setxattr_in {
    /// Size
    pub size: u32,
    /// Flags
    pub flags: u32,
    #[cfg(target_os = "macos")]
    /// Position
    pub position: u32,
    #[cfg(target_os = "macos")]
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse getxattr in
pub struct fuse_getxattr_in {
    /// Size
    pub size: u32,
    /// Padding
    pub padding: u32,
    #[cfg(target_os = "macos")]
    /// Position
    pub position: u32,
    #[cfg(target_os = "macos")]
    /// Padding2
    pub padding2: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse getxattr out
pub struct fuse_getxattr_out {
    /// Size
    pub size: u32,
    ///Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse lock in
pub struct fuse_lk_in {
    /// File handler
    pub fh: u64,
    /// Owner
    pub owner: u64,
    /// Lock
    pub lk: fuse_file_lock,
    #[cfg(feature = "abi-7-9")]
    /// Lock flags
    pub lk_flags: u32,
    #[cfg(feature = "abi-7-9")]
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse Lock out
pub struct fuse_lk_out {
    /// Lock
    pub lk: fuse_file_lock,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse access in
pub struct fuse_access_in {
    /// Mask
    pub mask: u32,
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse init in
pub struct fuse_init_in {
    /// Major
    pub major: u32,
    /// Minor
    pub minor: u32,
    /// Max readahead
    pub max_readahead: u32,
    /// Flags
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse init out
pub struct fuse_init_out {
    /// Major
    pub major: u32,
    /// Minor
    pub minor: u32,
    /// Max readahead
    pub max_readahead: u32,
    /// Flags
    pub flags: u32,
    #[cfg(not(feature = "abi-7-13"))]
    /// Unused
    pub unused: u32,
    #[cfg(feature = "abi-7-13")]
    /// Max background
    pub max_background: u16,
    #[cfg(feature = "abi-7-13")]
    /// Congestion threshold
    pub congestion_threshold: u16,
    /// Max write
    pub max_write: u32,
}

#[cfg(feature = "abi-7-12")]
#[repr(C)]
#[derive(Debug)]
/// Cuse init in
pub struct cuse_init_in {
    /// Major
    pub major: u32,
    /// Minor
    pub minor: u32,
    /// Unused
    pub unused: u32,
    /// Flags
    pub flags: u32,
}

#[cfg(feature = "abi-7-12")]
#[repr(C)]
#[derive(Debug)]
/// Cuse init out
pub struct cuse_init_out {
    /// Major
    pub major: u32,
    /// Minor
    pub minor: u32,
    /// Unused
    pub unused: u32,
    /// Flags
    pub flags: u32,
    /// Max read
    pub max_read: u32,
    /// Max write
    pub max_write: u32,
    /// Dev major
    pub dev_major: u32, // chardev major
    /// Dev minor
    pub dev_minor: u32, // chardev minor
    // Spare
    pub spare: [u32; 10],
}

#[repr(C)]
#[derive(Debug)]
/// Fuse interrupt in
pub struct fuse_interrupt_in {
    /// Unique
    pub unique: u64,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse bmap in
pub struct fuse_bmap_in {
    /// Block
    pub block: u64,
    /// Block size
    pub blocksize: u32,
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse bmap out
pub struct fuse_bmap_out {
    /// Block
    pub block: u64,
}

#[cfg(feature = "abi-7-11")]
#[repr(C)]
#[derive(Debug)]
/// Fuse ioctl in
pub struct fuse_ioctl_in {
    /// File handler
    pub fh: u64,
    /// Flags
    pub flags: u32,
    /// Cmd
    pub cmd: u32,
    /// Arg
    pub arg: u64,
    /// In size
    pub in_size: u32,
    /// Out size
    pub out_size: u32,
}

#[cfg(feature = "abi-7-16")]
#[repr(C)]
#[derive(Debug)]
/// Fuse ioctl iovec
pub struct fuse_ioctl_iovec {
    /// Base
    pub base: u64,
    /// Len
    pub len: u64,
}

#[cfg(feature = "abi-7-11")]
#[repr(C)]
#[derive(Debug)]
/// Fuse ioctl out
pub struct fuse_ioctl_out {
    /// Result
    pub result: i32,
    /// Flasgs
    pub flags: u32,
    /// In iovec
    pub in_iovs: u32,
    /// Out iovec
    pub out_iovs: u32,
}

#[cfg(feature = "abi-7-11")]
#[repr(C)]
#[derive(Debug)]
/// Fuse poll in
pub struct fuse_poll_in {
    /// File handler
    pub fh: u64,
    /// Kh
    pub kh: u64,
    /// Flags
    pub flags: u32,
    /// Padding
    pub padding: u32,
}

#[cfg(feature = "abi-7-11")]
#[repr(C)]
#[derive(Debug)]
/// Fuse pull out
pub struct fuse_poll_out {
    /// Revents
    pub revents: u32,
    /// Padding
    pub padding: u32,
}

#[cfg(feature = "abi-7-11")]
#[repr(C)]
#[derive(Debug)]
/// Fuse notify poll wakeup out
pub struct fuse_notify_poll_wakeup_out {
    /// Kh
    pub kh: u64,
}

#[cfg(feature = "abi-7-19")]
#[repr(C)]
#[derive(Debug)]
/// Fuse fallocate in
pub struct fuse_fallocate_in {
    /// File handler
    fh: u64,
    /// Offset
    offset: u64,
    /// Length
    length: u64,
    /// Mode
    mode: u32,
    /// Padding
    padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse in header
pub struct fuse_in_header {
    /// Len
    pub len: u32,
    /// Opcode
    pub opcode: u32,
    /// Unique
    pub unique: u64,
    /// Node id
    pub nodeid: u64,
    /// User id
    pub uid: u32,
    /// Group id
    pub gid: u32,
    /// Pid
    pub pid: u32,
    /// Padding
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse out header
pub struct fuse_out_header {
    /// Len
    pub len: u32,
    /// Error
    pub error: i32,
    /// Unique
    pub unique: u64,
}

#[repr(C)]
#[derive(Debug)]
/// Fuse dirent
pub struct fuse_dirent {
    /// Inode
    pub ino: u64,
    /// Offset
    pub off: u64,
    /// Name len
    pub namelen: u32,
    /// Type
    pub typ: u32,
    // followed by name of namelen bytes
}

#[cfg(feature = "abi-7-12")]
#[repr(C)]
#[derive(Debug)]
/// Fuse notify inval inode out
pub struct fuse_notify_inval_inode_out {
    /// Inode
    pub ino: u64,
    /// Offset
    pub off: i64,
    /// Len
    pub len: i64,
}

#[cfg(feature = "abi-7-12")]
#[repr(C)]
#[derive(Debug)]
/// Fuse notify inval entry out
pub struct fuse_notify_inval_entry_out {
    /// Parent
    pub parent: u64,
    /// Name len
    pub namelen: u32,
    /// Padding
    pub padding: u32,
}

#[cfg(feature = "abi-7-18")]
#[repr(C)]
#[derive(Debug)]
/// Fuse notify delete out
pub struct fuse_notify_delete_out {
    /// Parent
    parent: u64,
    /// Child
    child: u64,
    /// Name len
    namelen: u32,
    /// Padding
    padding: u32,
}

#[cfg(feature = "abi-7-15")]
#[repr(C)]
#[derive(Debug)]
/// Fuse notify store out
pub struct fuse_notify_store_out {
    /// Node id
    pub nodeid: u64,
    /// Offset
    pub offset: u64,
    /// Size
    pub size: u32,
    /// Padding
    pub padding: u32,
}

#[cfg(feature = "abi-7-15")]
#[repr(C)]
#[derive(Debug)]
/// Fuse notify retrieve out
pub struct fuse_notify_retrieve_out {
    /// Notify unique
    pub notify_unique: u64,
    /// Node id
    pub nodeid: u64,
    /// Offset
    pub offset: u64,
    /// Size
    pub size: u32,
    /// Padding
    pub padding: u32,
}

#[cfg(feature = "abi-7-15")]
#[repr(C)]
#[derive(Debug)]
/// Fuse notify retrieve in
pub struct fuse_notify_retrieve_in {
    // matches the size of fuse_write_in
    /// Dummy1
    pub dummy1: u64,
    /// Offset
    pub offset: u64,
    /// Size
    pub size: u32,
    /// Dummy2
    pub dummy2: u32,
    /// Dummy3
    pub dummy3: u64,
    /// Dummy4
    pub dummy4: u64,
}
