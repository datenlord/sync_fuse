use log::{debug, error};
use nix::errno::{self, Errno};
use nix::fcntl::{self, OFlag};
use nix::sys::stat::{self, FileStat, Mode};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::io::RawFd;
use std::path::Path;

#[cfg(target_os = "macos")]
use param::{
    copy_slice, parse_mount_flag, FUSE_IOC_MAGIC, FUSE_IOC_TYPE_MODE, MAXPATHLEN, MNT_NOATIME,
    MNT_NODEV, MNT_NOSUID, MNT_NOUSERXATTR,
};
use param::{get_mount_options, FuseMountArgs, MNT_FORCE};
#[cfg(target_os = "linux")]
use param::{MS_NODEV, MS_NOSUID};

use super::conversion;
#[cfg(target_os = "macos")]
use super::Cast;

/// Fuse mount option
pub struct FuseMountOption {
    /// Name
    pub name: String,
    /// Parser
    pub parser: fn(&mut FuseMountArgs, &FuseMountOption, &str),
    /// validator
    pub validator: fn(&FuseMountOption, &str) -> bool,
    #[cfg(target_os = "linux")]
    /// Flag
    pub flag: Option<u64>,
    #[cfg(target_os = "macos")]
    /// Flag
    pub flag: Option<i32>,
    #[cfg(target_os = "macos")]
    /// Fuse flag
    pub fuse_flag: Option<u64>,
}

/// Get all options
fn get_all_options() -> String {
    get_mount_options()
        .iter()
        .map(|x| x.name.clone())
        .collect::<Vec<_>>()
        .join(",")
}

/// Check if an option is valid.
pub fn options_validator(option: &str) -> Result<(), String> {
    let ret = option
        .split(',')
        .collect::<Vec<_>>()
        .iter()
        .all(|&op| get_mount_options().iter().any(|x| (x.validator)(x, op)));
    if ret {
        Ok(())
    } else {
        Err(format!(
            "Invalid option \"{}\", valid options: {}",
            option,
            get_all_options()
        ))
    }
}

/// Get mount options map
pub fn get_mount_options_map() -> HashMap<String, FuseMountOption> {
    let mut map: HashMap<String, FuseMountOption> = HashMap::new();
    for op in get_mount_options() {
        let key = op
            .name
            .clone()
            .split('=')
            .collect::<Vec<_>>()
            .get(0)
            .unwrap_or_else(|| panic!("Indexing is out of bounds"))
            .to_owned()
            .to_string();
        let val = op;

        map.insert(key, val);
    }
    map
}

#[cfg(target_os = "linux")]
/// Param
mod param {
    // https://github.com/torvalds/linux/blob/master/include/uapi/linux/mount.h#L11
    // TODO: use mount flags from libc
    /// Read-only
    pub const MS_RDONLY: u64 = 1; // Mount read-only
    /// NOSUID
    pub const MS_NOSUID: u64 = 2; // Ignore suid and sgid bits
    /// NODEV
    pub const MS_NODEV: u64 = 4; // Disallow access to device special files
    /// Force un-mount
    pub const MNT_FORCE: i32 = 1; // Force un-mount

    use super::FuseMountOption;
    use regex::Regex;
    /// Add option
    fn add_option(options: &Option<String>, option: &str) -> Option<String> {
        match options {
            None => Some(String::from(option)),
            Some(s) => {
                let mut op = s.to_owned();
                op.push_str(",");
                op.push_str(option);
                Some(op)
            }
        }
    }

    /// Get mount options
    pub fn get_mount_options() -> Vec<FuseMountOption> {
        /// Parse flag
        fn parse_flag(args: &mut FuseMountArgs, mount_option: &FuseMountOption, option: &str) {
            if let Some(flag) = mount_option.flag {
                args.flags |= flag;
                args.fusermount_opts = add_option(&args.fusermount_opts, option);
            }
        }

        /// Parse `allow_other`
        fn parse_allow_other(
            args: &mut FuseMountArgs,
            _mount_option: &FuseMountOption,
            option: &str,
        ) {
            args.allow_other = 1;
            args.kernel_opts = add_option(&args.kernel_opts, option);
        }

        /// Parse fsname
        fn parse_fsname(args: &mut FuseMountArgs, _mount_option: &FuseMountOption, option: &str) {
            let name = String::from(option.split('=').last().unwrap_or_else(|| panic!())); //Safe to use unwrap here, becuase option is always valid.
            args.fsname = Some(name);
            args.fusermount_opts = add_option(&args.fusermount_opts, option);
        }
        /// Match name
        fn name_match(mount_option: &FuseMountOption, option: &str) -> bool {
            option == mount_option.name
        }
        /// Match key value
        fn key_value_match(mount_option: &FuseMountOption, option: &str) -> bool {
            let name = String::from(
                mount_option
                    .name
                    .split('=')
                    .next()
                    .unwrap_or_else(|| panic!()),
            ); //Safe to use unwrap here, becuase name is always valid.
            let regex_str = format!(r"^{}=[^\s]+$", name);
            let option_regex = Regex::new(regex_str.as_str()).unwrap_or_else(|_| panic!()); //Safe to use unwrap here, becuase regex_str is always valid.
            option_regex.is_match(option)
        }
        vec![
            FuseMountOption {
                name: String::from("ro"),
                parser: parse_flag,
                validator: name_match,
                flag: Some(MS_RDONLY),
            },
            FuseMountOption {
                name: String::from("allow_other"),
                parser: parse_allow_other,
                validator: name_match,
                flag: None,
            },
            FuseMountOption {
                name: String::from("fsname=<name>"),
                parser: parse_fsname,
                validator: key_value_match,
                flag: None,
            },
        ]
    }

    #[repr(C)]
    #[derive(Debug)]
    /// Fuse mount args
    pub struct FuseMountArgs {
        /// Allow other
        allow_other: i32,
        /// Flags
        flags: u64,
        /// Auto_unmount
        auto_unmount: i32,
        /// Block dev
        blkdev: i32,
        /// Fsname
        fsname: Option<String>,
        /// Subtype
        subtype: Option<String>,
        /// Subtype options
        subtype_opt: Option<String>,
        /// Mtab options
        mtab_opts: Option<String>,
        /// Fusermount opts
        fusermount_opts: Option<String>,
        /// Kernel opts
        kernel_opts: Option<String>,
        /// Max read
        max_read: u32,
    }

    impl FuseMountArgs {
        /// Parse
        pub fn parse(options: &[&str]) -> Self {
            // TODO: add default arguments
            let mut args = Self {
                allow_other: 0,
                flags: 0,
                auto_unmount: 0,
                blkdev: 0,
                fsname: None,
                subtype: None,
                subtype_opt: None,
                mtab_opts: None,
                fusermount_opts: None,
                kernel_opts: None,
                max_read: 0,
            };
            let mount_options_map = super::get_mount_options_map();
            options.iter().for_each(|op| {
                let key = op
                    .split('=')
                    .collect::<Vec<_>>()
                    .get(0)
                    .unwrap_or_else(|| panic!("Indexing is out of bounds"))
                    .to_owned()
                    .to_string();
                let option = mount_options_map.get(&key).unwrap_or_else(|| panic!()); // Safe to use unwrap here, because key always exists
                (option.parser)(&mut args, option, op)
            });
            args
        }
        /// Get kernel opts
        pub fn get_kernel_opts(&self) -> Option<&String> {
            self.kernel_opts.as_ref()
        }
        /// Get fusermount opts
        pub fn get_fusermount_opts(&self) -> Option<&String> {
            self.fusermount_opts.as_ref()
        }
        /// Get mtab opts
        pub fn get_mtab_opts(&self) -> Option<&String> {
            self.mtab_opts.as_ref()
        }
        /// Get blkdev
        pub const fn get_blkdev(&self) -> i32 {
            self.blkdev
        }
        /// Get subtype
        pub fn get_subtype(&self) -> Option<&String> {
            self.subtype.as_ref()
        }
        /// Get subtype opt
        pub fn get_subtype_opt(&self) -> Option<&String> {
            self.subtype_opt.as_ref()
        }
        /// Get fsname
        pub fn get_fsname(&self) -> Option<&String> {
            self.fsname.as_ref()
        }
        /// Get flags
        pub const fn get_flags(&self) -> u64 {
            self.flags
        }
    }
}

#[cfg(target_os = "macos")]
/// Param
mod param {
    // https://github.com/apple/darwin-xnu/blob/master/bsd/sys/mount.h#L288
    // TODO: use mount flags from libc
    /// RDONLY
    pub const MNT_RDONLY: i32 = 0x0000_0001; // read only filesystem
    /// NOSUID
    pub const MNT_NOSUID: i32 = 0x0000_0008; // don't honor setuid bits on fs
    /// NODEV
    pub const MNT_NODEV: i32 = 0x0000_0010; // don't interpret special files
    /// Force unmount
    pub const MNT_FORCE: i32 = 0x0008_0000; // force unmount or readonly change
    /// NOUSERXATTR
    pub const MNT_NOUSERXATTR: i32 = 0x0100_0000; // Don't allow user extended attributes
    /// NOATIME
    pub const MNT_NOATIME: i32 = 0x1000_0000; // disable update of file access time

    #[allow(dead_code)]
    /// Fuse default configs
    pub mod fuse_default_configs {
        /// Page size
        pub const PAGE_SIZE: u32 = 4096;

        /// Fuse fssubtype unknown
        pub const FUSE_FSSUBTYPE_UNKNOWN: u32 = 0;

        /// Fuse default blocksize
        pub const FUSE_DEFAULT_BLOCKSIZE: u32 = 4096;
        /// Fuse default daemon timeout
        pub const FUSE_DEFAULT_DAEMON_TIMEOUT: u32 = 60; // seconds
        /// Fuse default iosize
        pub const FUSE_DEFAULT_IOSIZE: u32 = 16 * PAGE_SIZE;
    }
    pub use fuse_default_configs::*;

    /// Fuse ioc magic
    pub const FUSE_IOC_MAGIC: u8 = b'F';
    /// Fuse ioc type mode
    pub const FUSE_IOC_TYPE_MODE: u8 = 5;

    #[allow(dead_code)]
    /// Fuse mopt configs
    pub mod fuse_mopt_configs {
        /// Fuse mopt allow other
        pub const FUSE_MOPT_ALLOW_OTHER: u64 = 0x0000_0000_0000_0001;
        /// Fuse mopt debug
        pub const FUSE_MOPT_DEBUG: u64 = 0x0000_0000_0000_0040;
        /// Fuse mopt fsname
        pub const FUSE_MOPT_FSNAME: u64 = 0x0000_0000_0000_1000;
        /// Fuse mopt no applexattr
        pub const FUSE_MOPT_NO_APPLEXATTR: u64 = 0x0000_0000_0080_0000;
    }
    pub use fuse_mopt_configs::*;

    use libc::size_t;
    /// Type name len
    pub const MFSTYPENAMELEN: size_t = 16; // length of fs type name including null
    /// Max path len
    pub const MAXPATHLEN: size_t = 1024; //PATH_MAX

    #[repr(C)]
    /// Fuse mount args
    pub struct FuseMountArgs {
        /// Mnt path
        mntpath: [u8; MAXPATHLEN], // path to the mount point
        /// Fsname
        fsname: [u8; MAXPATHLEN], // file system description string
        /// Fs type name
        fstypename: [u8; MFSTYPENAMELEN], // file system type name
        /// Vol name
        volname: [u8; MAXPATHLEN], // volume name
        /// Alt flags
        altflags: u64, // see mount-time flags below
        /// Block size
        blocksize: u32, // fictitious block size of our "storage"
        /// Daemon timeout
        daemon_timeout: u32, // timeout in seconds for upcalls to daemon
        /// Fsid
        fsid: u32, // optional custom value for part of fsid[0]
        /// Fssubtype
        fssubtype: u32, // file system sub type id
        /// Iosize
        iosize: u32, // maximum size for reading or writing
        /// Random
        random: u32, // random "secret" from device
        /// Rdev
        rdev: u32, // dev_t for the /dev/osxfuse{n} in question
    }

    use super::FuseMountOption;
    use regex::Regex;
    /// Get mount options
    pub fn get_mount_options() -> Vec<FuseMountOption> {
        /// Empty parser
        fn empty_parser(_args: &mut FuseMountArgs, _mount_option: &FuseMountOption, _option: &str) {
        }
        /// Parse fuse flag
        fn parse_fuse_flag(
            args: &mut FuseMountArgs,
            mount_option: &FuseMountOption,
            _option: &str,
        ) {
            if let Some(flag) = mount_option.fuse_flag {
                args.altflags |= flag;
            }
        }

        /// Parse fsname
        fn parse_fsname(args: &mut FuseMountArgs, _mount_option: &FuseMountOption, option: &str) {
            let name = String::from(option.split('=').last().unwrap_or_else(|| panic!())); //Safe to use unwrap here, becuase option is always valid.
            copy_slice(
                CString::new(name)
                    .unwrap_or_else(|_| panic!("CString::new failed!"))
                    .as_bytes(),
                &mut args.fsname,
            );
        }
        /// Match name
        fn name_match(mount_option: &FuseMountOption, option: &str) -> bool {
            option == mount_option.name
        }
        /// Match key value
        fn key_value_match(mount_option: &FuseMountOption, option: &str) -> bool {
            let name = String::from(
                mount_option
                    .name
                    .split('=')
                    .next()
                    .unwrap_or_else(|| panic!()),
            ); //Safe to use unwrap here, becuase name is always valid.
            let regex_str = format!(r"^{}=[^\s]+$", name);
            let option_regex = Regex::new(regex_str.as_str()).unwrap_or_else(|_| panic!()); //Safe to use unwrap here, becuase regex_str is always valid.
            option_regex.is_match(option)
        }

        vec![
            FuseMountOption {
                name: String::from("ro"),
                parser: empty_parser,
                validator: name_match,
                flag: Some(MNT_RDONLY),
                fuse_flag: None,
            },
            FuseMountOption {
                name: String::from("allow_other"),
                parser: parse_fuse_flag,
                validator: name_match,
                flag: None,
                fuse_flag: Some(FUSE_MOPT_ALLOW_OTHER),
            },
            FuseMountOption {
                name: String::from("fsname=<name>"),
                parser: parse_fsname,
                validator: key_value_match,
                flag: None,
                fuse_flag: None,
            },
        ]
    }

    use std::ffi::CString;
    impl FuseMountArgs {
        /// Parse
        pub fn parse(options: &[&str]) -> Self {
            let fsname = CString::new("macfuse").unwrap_or_else(|_| panic!("CString::new failed"));
            let fstypename = CString::new("").unwrap_or_else(|_| panic!("CString::new failed"));
            let volname = CString::new("OSXFUSE Volume 0 (macfuse)")
                .unwrap_or_else(|_| panic!("CString::new failed"));

            let mut fsname_slice = [0_u8; MAXPATHLEN];
            copy_slice(fsname.as_bytes(), &mut fsname_slice);
            let mut fstypename_slice = [0_u8; MFSTYPENAMELEN];
            copy_slice(fstypename.as_bytes(), &mut fstypename_slice);
            let mut volname_slice = [0_u8; MAXPATHLEN];
            copy_slice(volname.as_bytes(), &mut volname_slice);

            let mut args = Self {
                mntpath: [0_u8; MAXPATHLEN],
                fsname: [0_u8; MAXPATHLEN],
                fstypename: [0_u8; MFSTYPENAMELEN],
                volname: [0_u8; MAXPATHLEN],
                altflags: 0_u64,
                blocksize: 0_u32,
                daemon_timeout: 0_u32,
                fsid: 0_u32,
                fssubtype: 0_u32,
                iosize: 0_u32,
                random: 0_u32,
                rdev: 0_u32,
            };

            let mount_options_map = super::get_mount_options_map();
            options.iter().for_each(|op| {
                let key = op
                    .split('=')
                    .collect::<Vec<_>>()
                    .get(0)
                    .unwrap_or_else(|| panic!("Indexing is out of bounds"))
                    .to_owned()
                    .to_string();
                let option = mount_options_map.get(&key).unwrap_or_else(|| panic!()); // Safe to use unwrap here, because key always exists
                (option.parser)(&mut args, option, op)
            });
            args
        }

        /// Set mntpath
        pub fn set_mntpath(&mut self, mntpath: [u8; MAXPATHLEN]) {
            self.mntpath = mntpath;
        }

        /// Set random
        pub fn set_random(&mut self, drandom: u32) {
            self.random = drandom;
        }

        /// Set rdev
        pub fn set_rdev(&mut self, rdev: u32) {
            self.rdev = rdev;
        }
    }

    /// Copy slice
    pub fn copy_slice<T: Copy>(from: &[T], to: &mut [T]) {
        let to_len = to.len();
        to.get_mut(..from.len())
            .unwrap_or_else(|| panic!("Indexing is out of bounds when copying slices, from slice length={}, to slice length={}", from.len(), to_len))
            .copy_from_slice(from);
    }

    /// Parse mount flag
    pub fn parse_mount_flag(options: &[&str]) -> i32 {
        let mut flag: i32 = 0;
        options.iter().for_each(|&op| {
            let mount_options = get_mount_options();
            let option = mount_options
                .iter()
                .find(|x| (x.validator)(x, op))
                .unwrap_or_else(|| panic!());
            if let Some(f) = option.flag {
                flag |= f;
            }
        });
        flag
    }
}

#[cfg(target_os = "linux")]
/// Umount
pub fn umount(short_path: &Path) -> i32 {
    use nix::unistd;
    use std::process::Command;

    let mntpnt = short_path.as_os_str();

    if unistd::geteuid().is_root() {
        // direct umount
        #[allow(unsafe_code)]
        #[cfg(target_arch = "aarch64")]
        let result = unsafe { libc::umount2(conversion::cast_to_ptr(mntpnt), MNT_FORCE) };
        #[allow(unsafe_code)]
        #[cfg(target_arch = "x86_64")]
        let result = unsafe { libc::umount2(conversion::cast_to_ptr(mntpnt), MNT_FORCE) };

        result
    } else {
        // use fusermount to umount
        let umount_handle = Command::new("fusermount")
            .arg("-uz") // lazy umount
            .arg(mntpnt)
            .output()
            .unwrap_or_else(|_| panic!("fusermount command failed to start"));
        if umount_handle.status.success() {
            0
        } else {
            // should be safe to use unwrap() here
            let stderr = String::from_utf8(umount_handle.stderr).unwrap_or_else(|_| panic!());
            debug!("fusermount failed to umount: {}", stderr);
            -1
        }
    }
}

#[cfg(target_os = "linux")]
/// Mount
pub fn mount(mount_point: &Path, options: &[&str]) -> RawFd {
    use nix::unistd;

    if unistd::geteuid().is_root() {
        // direct umount
        direct_mount(mount_point, options)
    } else {
        // use fusermount to mount
        fuser_mount(mount_point, options)
    }
}

#[cfg(target_os = "linux")]
/// Fusermount
fn fuser_mount(mount_point: &Path, options: &[&str]) -> RawFd {
    use nix::cmsg_space;
    use nix::sys::socket::{
        self, AddressFamily, ControlMessageOwned, MsgFlags, SockFlag, SockType,
    };
    use nix::sys::uio::IoVec;
    use std::process::Command;

    let args = FuseMountArgs::parse(options);

    let (local, remote) = socket::socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .unwrap_or_else(|_| panic!("failed to create socket pair"));

    // Default options
    let mut opts = String::from("nosuid,nodev,noexec,nonempty");
    if let Some(s) = args.get_fusermount_opts() {
        opts.push(',');
        opts.push_str(s);
    };
    if let Some(s) = args.get_kernel_opts() {
        opts.push(',');
        opts.push_str(s);
    };
    if let Some(s) = args.get_mtab_opts() {
        opts.push(',');
        opts.push_str(s);
    }
    if let Some(s) = args.get_subtype_opt() {
        opts.push(',');
        opts.push_str(s);
    }

    let mount_handle = Command::new("fusermount")
        .arg("-o")
        .arg(&opts[..])
        .arg(mount_point.as_os_str())
        .env("_FUSE_COMMFD", remote.to_string())
        .output()
        .unwrap_or_else(|_| panic!("fusermount command failed to start"));

    assert!(mount_handle.status.success());

    let mut buf = [0_u8; 5];
    let iov = [IoVec::from_mut_slice(&mut buf[..])];
    #[allow(clippy::integer_arithmetic)]
    let mut cmsgspace = cmsg_space!([RawFd; 1]);
    let msg = socket::recvmsg(local, &iov, Some(&mut cmsgspace), MsgFlags::empty())
        .unwrap_or_else(|_| panic!("failed to receive from fusermount"));

    let mut mount_fd = -1;
    for cmsg in msg.cmsgs() {
        if let ControlMessageOwned::ScmRights(fd) = cmsg {
            assert_eq!(fd.len(), 1);
            mount_fd = *fd.get(0).unwrap_or_else(|| panic!());
        } else {
            panic!("unexpected cmsg");
        }
    }

    mount_fd
}

#[cfg(target_os = "linux")]
/// Direct mount
fn direct_mount(mount_point: &Path, options: &[&str]) -> RawFd {
    use nix::sys::stat::SFlag;
    use nix::unistd;

    let args = FuseMountArgs::parse(options);
    let devpath = Path::new("/dev/fuse");

    let dev_fd: RawFd;
    let result = fcntl::open(devpath, OFlag::O_RDWR, Mode::empty());
    match result {
        Ok(fd) => {
            debug!("open fuse device successfully");
            dev_fd = fd;
        }
        Err(e) => {
            error!("open fuse device failed! {}", e);
            return -1;
        }
    }

    let full_path = fs::canonicalize(mount_point)
        .unwrap_or_else(|_| panic!("fail to get full path of mount point"));
    let cstr_path = full_path
        .to_str()
        .unwrap_or_else(|| panic!("full mount path to string failed"));

    let mnt_sb: FileStat;
    let result = stat::stat(&full_path);
    match result {
        Ok(sb) => mnt_sb = sb,
        Err(e) => {
            error!("get mount point stat failed! {}", e);
            return -1;
        }
    }

    let mntpath = CString::new(cstr_path).unwrap_or_else(|_| panic!("CString::new failed"));
    let fsname = if let Some(s) = args.get_fsname() {
        CString::new(&s[..]).unwrap_or_else(|_| panic!("CString::new failed"))
    } else if let Some(s) = args.get_subtype() {
        CString::new(&s[..]).unwrap_or_else(|_| panic!("CString::new failed"))
    } else {
        CString::new("/dev/fuse").unwrap_or_else(|_| panic!("CString::new failed"))
    };

    let mut fstype = if args.get_blkdev() == 0 {
        String::from("fuse")
    } else {
        String::from("fuseblk")
    };
    if let Some(s) = args.get_subtype() {
        fstype.push('.');
        fstype.push_str(s);
    }
    let fstype = CString::new(fstype).unwrap_or_else(|_| panic!("CString::new failed"));

    let mut opts = format!(
        "fd={},rootmode={:o},user_id={},group_id={}",
        dev_fd,
        mnt_sb.st_mode & SFlag::S_IFMT.bits(),
        unistd::getuid().as_raw(),
        unistd::getgid().as_raw()
    );
    let kernel_opts = args.get_kernel_opts();
    if let Some(s) = kernel_opts {
        opts.push_str(",");
        opts.push_str(s);
    }
    let opts = CString::new(&*opts).unwrap_or_else(|_| panic!("CString::new failed"));
    let flag = MS_NOSUID | MS_NODEV | args.get_flags();
    debug!("direct mount opts: {:?}", &opts);
    #[allow(unsafe_code)]
    unsafe {
        let result = libc::mount(
            fsname.as_ptr(),
            mntpath.as_ptr(),
            fstype.as_ptr(),
            flag,
            opts.as_ptr().cast(),
        );
        if result == 0 {
            debug!("mount {:?} to {:?} successfully!", mntpath, devpath);
            dev_fd
        } else {
            let e = Errno::from_i32(errno::errno());
            debug!("errno={}, {:?}", errno::errno(), e);
            let mount_fail_str = "mount failed!";
            #[cfg(target_arch = "aarch64")]
            libc::perror(mount_fail_str.as_ptr());
            #[cfg(target_arch = "x86_64")]
            libc::perror(mount_fail_str.as_ptr().cast());

            -1
        }
    }
}

#[cfg(any(target_os = "macos"))]
/// Umount
pub fn umount(mount_point: &Path) -> i32 {
    let mntpnt = mount_point.as_os_str();
    #[allow(unsafe_code)]
    unsafe {
        libc::unmount(conversion::cast_to_ptr(mntpnt), MNT_FORCE)
    }
}

#[cfg(any(target_os = "macos"))]
/// Mount
pub fn mount(mount_point: &Path, options: &[&str]) -> RawFd {
    let mut args = FuseMountArgs::parse(options);
    let devpath = Path::new("/dev/osxfuse1");
    let fd: RawFd;
    let res = fcntl::open(devpath, OFlag::O_RDWR, Mode::empty());
    match res {
        Ok(f) => {
            fd = f;
        }
        Err(e) => {
            error!("open fuse device failed, {}", e);
            return -1;
        }
    };

    let sb: FileStat;
    let result = stat::fstat(fd);
    match result {
        Ok(s) => sb = s,
        Err(e) => {
            error!("get fuse device stat failed! {}", e);
            return -1;
        }
    }

    // use ioctl to read device random secret
    // osxfuse/support/mount_osxfuse/mount_osxfuse.c#L1099
    // result = ioctl(fd, FUSEDEVIOCGETRANDOM, &drandom);
    // FUSEDEVIOCGETRANDOM // osxfuse/common/fuse_ioctl.h#L43
    let mut drandom: u32 = 0;
    ioctl_read!(fuse_read_random, FUSE_IOC_MAGIC, FUSE_IOC_TYPE_MODE, u32);
    use nix::ioctl_read;
    #[allow(unsafe_code)]
    let result = unsafe {
        fuse_read_random(fd, conversion::cast_to_mut_ptr(&mut drandom)).unwrap_or_else(|_| panic!())
    };
    if result == 0 {
        debug!("successfully read drandom={}", drandom);
    } else {
        let ioctl_fail_str = "ioctl read random secret failed!";
        #[allow(unsafe_code)]
        unsafe {
            libc::perror(ioctl_fail_str.as_ptr().cast());
        }
        return -1;
    }

    let full_path = fs::canonicalize(mount_point)
        .unwrap_or_else(|_| panic!("fail to get full path of mount point"));
    let cstr_path = full_path
        .to_str()
        .unwrap_or_else(|| panic!("full mount path to string failed"));

    let mntpath = CString::new(cstr_path).unwrap_or_else(|_| panic!("CString::new failed"));
    let fstype = CString::new("osxfuse").unwrap_or_else(|_| panic!("CString::new failed"));

    let mut mntpath_slice = [0_u8; MAXPATHLEN];
    copy_slice(mntpath.as_bytes(), &mut mntpath_slice);

    args.set_mntpath(mntpath_slice);
    args.set_random(drandom);
    args.set_rdev(sb.st_rdev.cast());

    // Default mount flags.
    let mut flag = MNT_NOSUID | MNT_NODEV | MNT_NOUSERXATTR | MNT_NOATIME;
    let parsed_flag = parse_mount_flag(options);
    flag |= parsed_flag;

    #[allow(unsafe_code)]
    unsafe {
        let mount_result = libc::mount(
            fstype.as_ptr(),
            mntpath.as_ptr(),
            flag,
            conversion::cast_to_mut_ptr(&mut args),
        );
        if mount_result == 0 {
            debug!("mount {:?} to {:?} successfully!", mntpath, devpath);
            fd
        } else {
            let e = Errno::from_i32(errno::errno());
            debug!("errno={}, {:?}", errno::errno(), e);
            let mount_fail_str = "mount failed!";
            libc::perror(mount_fail_str.as_ptr().cast());

            -1
        }
    }
}
