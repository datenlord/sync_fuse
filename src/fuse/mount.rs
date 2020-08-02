use log::{debug, error};
use nix::errno::{self, Errno};
use nix::fcntl::{self, OFlag};
use nix::sys::stat::{self, FileStat, Mode};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::raw::c_void;
use std::os::unix::io::RawFd;
use std::path::Path;

use param::*;

pub struct FuseMountOption {
    pub name: String,
    pub parser: fn(&mut FuseMountArgs, &FuseMountOption, &str),
    pub validator: fn(&FuseMountOption, &str) -> bool,
    #[cfg(target_os = "linux")]
    pub flag: Option<u64>,
    #[cfg(target_os = "macos")]
    pub flag: Option<i32>,
    #[cfg(target_os = "macos")]
    pub fuse_flag: Option<u64>,
}

fn get_all_options() -> String {
    get_mount_options()
        .iter()
        .map(|x| x.name.clone())
        .collect::<Vec<_>>()
        .join(",")
}

pub fn options_validator(option: String) -> Result<(), String> {
    let ret = option
        .split(',')
        .collect::<Vec<_>>()
        .iter()
        .all(|&op| get_mount_options().iter().any(|x| (x.validator)(x, &op)));
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

pub fn get_mount_options_map() -> HashMap<String, FuseMountOption> {
    get_mount_options()
        .into_iter()
        .map(|op| (op.name.split('=').collect::<Vec<_>>()[0].to_string(), op))
        .collect::<HashMap<_, _>>()
}

#[cfg(target_os = "linux")]
mod param {
    // https://github.com/torvalds/linux/blob/master/include/uapi/linux/mount.h#L11
    // TODO: use mount flags from libc
    pub const MS_RDONLY: u64 = 1; // Mount read-only
    pub const MS_NOSUID: u64 = 2; // Ignore suid and sgid bits
    pub const MS_NODEV: u64 = 4; // Disallow access to device special files
    pub const MNT_FORCE: i32 = 1; // Force un-mount

    use super::FuseMountOption;
    use regex::Regex;
    fn add_option(options: &Option<String>, option: &str) -> Option<String> {
        match options {
            None => Some(String::from(option)),
            Some(s) => Some(s.to_owned() + "," + option),
        }
    }

    pub fn get_mount_options() -> Vec<FuseMountOption> {
        fn parse_flag(args: &mut FuseMountArgs, mount_option: &FuseMountOption, _options: &str) {
            if let Some(flag) = mount_option.flag {
                args.flags |= flag;
            }
        }

        fn parse_allow_other(
            args: &mut FuseMountArgs,
            _mount_option: &FuseMountOption,
            option: &str,
        ) {
            args.allow_other = 1;
            args.kernel_opts = add_option(&args.kernel_opts, option);
        }

        fn parse_fsname(args: &mut FuseMountArgs, _mount_option: &FuseMountOption, option: &str) {
            let name = String::from(option.split('=').last().unwrap()); //Safe to use unwrap here, becuase option is always valid.
            args.fsname = Some(name);
            args.fusermount_opts = add_option(&args.fusermount_opts, option);
        }
        fn name_match(mount_option: &FuseMountOption, option: &str) -> bool {
            option == mount_option.name
        }
        fn key_value_match(mount_option: &FuseMountOption, option: &str) -> bool {
            let name = String::from(mount_option.name.split('=').nth(0).unwrap()); //Safe to use unwrap here, becuase name is always valid.
            let regex_str = format!(r"^{}=[^\s]+$", name);
            let option_regex = Regex::new(regex_str.as_str()).unwrap(); //Safe to use unwrap here, becuase regex_str is always valid.
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
    pub struct FuseMountArgs {
        allow_other: i32,
        flags: u64,
        auto_unmount: i32,
        blkdev: i32,
        fsname: Option<String>,
        subtype: Option<String>,
        subtype_opt: Option<String>,
        mtab_opts: Option<String>,
        fusermount_opts: Option<String>,
        kernel_opts: Option<String>,
        max_read: u32,
    }

    impl FuseMountArgs {
        pub fn parse(options: &[&str]) -> FuseMountArgs {
            // TODO: add default arguments
            let mut args = FuseMountArgs {
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
                let key = op.split('=').collect::<Vec<_>>()[0].to_string();
                let option = mount_options_map.get(&key).unwrap(); // Safe to use unwrap here, because key always exists
                (option.parser)(&mut args, &option, &op)
            });
            args
        }
    }
}

#[cfg(target_os = "macos")]
mod param {
    // https://github.com/apple/darwin-xnu/blob/master/bsd/sys/mount.h#L288
    // TODO: use mount flags from libc
    pub const MNT_RDONLY: i32 = 0x0000_0001; // read only filesystem
    pub const MNT_NOSUID: i32 = 0x0000_0008; // don't honor setuid bits on fs
    pub const MNT_NODEV: i32 = 0x0000_0010; // don't interpret special files
    pub const MNT_FORCE: i32 = 0x0008_0000; // force unmount or readonly change
    pub const MNT_NOUSERXATTR: i32 = 0x0100_0000; // Don't allow user extended attributes
    pub const MNT_NOATIME: i32 = 0x1000_0000; // disable update of file access time

    pub const PAGE_SIZE: u32 = 4096;

    pub const FUSE_DEFAULT_BLOCKSIZE: u32 = 4096;
    pub const FUSE_DEFAULT_DAEMON_TIMEOUT: u32 = 60; // seconds
    pub const FUSE_DEFAULT_IOSIZE: u32 = 16 * PAGE_SIZE;

    pub const FUSE_IOC_MAGIC: u8 = b'F';
    pub const FUSE_IOC_TYPE_MODE: u8 = 5;

    pub const FUSE_FSSUBTYPE_UNKNOWN: u32 = 0;
    pub const FUSE_MOPT_ALLOW_OTHER: u64 = 0x0000_0000_0000_0001;
    pub const FUSE_MOPT_DEBUG: u64 = 0x0000_0000_0000_0040;
    pub const FUSE_MOPT_FSNAME: u64 = 0x0000_0000_0000_1000;
    pub const FUSE_MOPT_NO_APPLEXATTR: u64 = 0x0000_0000_0080_0000;

    use libc::size_t;
    pub const MFSTYPENAMELEN: size_t = 16; // length of fs type name including null
    pub const MAXPATHLEN: size_t = 1024; //PATH_MAX

    #[repr(C)]
    pub struct FuseMountArgs {
        mntpath: [u8; MAXPATHLEN],        // path to the mount point
        fsname: [u8; MAXPATHLEN],         // file system description string
        fstypename: [u8; MFSTYPENAMELEN], // file system type name
        volname: [u8; MAXPATHLEN],        // volume name
        altflags: u64,                    // see mount-time flags below
        blocksize: u32,                   // fictitious block size of our "storage"
        daemon_timeout: u32,              // timeout in seconds for upcalls to daemon
        fsid: u32,                        // optional custom value for part of fsid[0]
        fssubtype: u32,                   // file system sub type id
        iosize: u32,                      // maximum size for reading or writing
        random: u32,                      // random "secret" from device
        rdev: u32,                        // dev_t for the /dev/osxfuse{n} in question
    }

    use super::FuseMountOption;
    use regex::Regex;
    pub fn get_mount_options() -> Vec<FuseMountOption> {
        fn empty_parser(_args: &mut FuseMountArgs, _mount_option: &FuseMountOption, _option: &str) {
        }
        fn parse_fuse_flag(
            args: &mut FuseMountArgs,
            mount_option: &FuseMountOption,
            _option: &str,
        ) {
            if let Some(flag) = mount_option.fuse_flag {
                args.altflags |= flag;
            }
        }

        fn parse_fsname(args: &mut FuseMountArgs, _mount_option: &FuseMountOption, option: &str) {
            let name = String::from(option.split('=').last().unwrap()); //Safe to use unwrap here, becuase option is always valid.
            copy_slice(
                CString::new(name).expect("CString::new failed!").as_bytes(),
                &mut args.fsname,
            );
        }
        fn name_match(mount_option: &FuseMountOption, option: &str) -> bool {
            option == mount_option.name
        }
        fn key_value_match(mount_option: &FuseMountOption, option: &str) -> bool {
            let name = String::from(mount_option.name.split('=').nth(0).unwrap()); //Safe to use unwrap here, becuase name is always valid.
            let regex_str = format!(r"^{}=[^\s]+$", name);
            let option_regex = Regex::new(regex_str.as_str()).unwrap(); //Safe to use unwrap here, becuase regex_str is always valid.
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
        pub fn parse(options: &[&str]) -> FuseMountArgs {
            let fsname = CString::new("macfuse").expect("CString::new failed");
            let fstypename = CString::new("").expect("CString::new failed");
            let volname = CString::new("OSXFUSE Volume 0 (macfuse)").expect("CString::new failed");

            let mut fsname_slice = [0_u8; MAXPATHLEN];
            copy_slice(fsname.as_bytes(), &mut fsname_slice);
            let mut fstypename_slice = [0_u8; MFSTYPENAMELEN];
            copy_slice(fstypename.as_bytes(), &mut fstypename_slice);
            let mut volname_slice = [0_u8; MAXPATHLEN];
            copy_slice(volname.as_bytes(), &mut volname_slice);

            let mut args = FuseMountArgs {
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
                let key = op.split('=').collect::<Vec<_>>()[0].to_string();
                let option = mount_options_map.get(&key).unwrap(); // Safe to use unwrap here, because key always exists
                (option.parser)(&mut args, &option, &op)
            });
            args
        }

        pub fn set_mntpath(&mut self, mntpath: [u8; MAXPATHLEN]) {
            self.mntpath = mntpath;
        }

        pub fn set_random(&mut self, drandom: u32) {
            self.random = drandom;
        }

        pub fn set_rdev(&mut self, rdev: u32) {
            self.rdev = rdev;
        }
    }

    pub fn copy_slice<T: Copy>(from: &[T], to: &mut [T]) {
        debug_assert!(to.len() >= from.len());
        to[..from.len()].copy_from_slice(&from);
    }

    pub fn parse_mount_flag(options: &[&str]) -> i32 {
        let mut flag: i32 = 0;
        options.iter().for_each(|&op| {
            let mount_options = get_mount_options();
            let option = mount_options
                .iter()
                .find(|x| (x.validator)(x, &op))
                .unwrap();
            if let Some(f) = option.flag {
                flag |= f;
            }
        });
        flag
    }
}

#[cfg(target_os = "linux")]
pub fn umount(short_path: &Path) -> i32 {
    use nix::unistd;
    use std::process::Command;

    let mntpnt = short_path.as_os_str();

    if unistd::geteuid().is_root() {
        // direct umount
        #[cfg(target_arch = "aarch64")]
        let result = unsafe { libc::umount2(mntpnt as *const _ as *const u8, MNT_FORCE) };
        #[cfg(target_arch = "x86_64")]
        let result =
            unsafe { libc::umount2(mntpnt as *const _ as *const u8 as *const i8, MNT_FORCE) };

        result
    } else {
        // use fusermount to umount
        let umount_handle = Command::new("fusermount")
            .arg("-uz") // lazy umount
            .arg(mntpnt)
            .output()
            .expect("fusermount command failed to start");
        if umount_handle.status.success() {
            0
        } else {
            // should be safe to use unwrap() here
            let stderr = String::from_utf8(umount_handle.stderr).unwrap();
            debug!("fusermount failed to umount: {}", stderr);
            -1
        }
    }
}

#[cfg(target_os = "linux")]
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
fn fuser_mount(mount_point: &Path, options: &[&str]) -> RawFd {
    use nix::cmsg_space;
    use nix::sys::socket::{
        self, AddressFamily, ControlMessageOwned, MsgFlags, SockFlag, SockType,
    };
    use nix::sys::uio::IoVec;
    use std::process::Command;

    let _args = FuseMountArgs::parse(options);

    let (local, remote) = socket::socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .expect("failed to create socket pair");

    let mount_handle = Command::new("fusermount")
        .arg("-o")
        .arg("nosuid,nodev,noexec,nonempty") // rw,async,noatime,auto_unmount
        .arg(mount_point.as_os_str())
        .env("_FUSE_COMMFD", remote.to_string())
        .output()
        .expect("fusermount command failed to start");

    assert!(mount_handle.status.success());

    let mut buf = [0u8; 5];
    let iov = [IoVec::from_mut_slice(&mut buf[..])];
    let mut cmsgspace = cmsg_space!([RawFd; 1]);
    let msg = socket::recvmsg(local, &iov, Some(&mut cmsgspace), MsgFlags::empty())
        .expect("failed to receive from fusermount");

    let mut mount_fd = -1;
    for cmsg in msg.cmsgs() {
        if let ControlMessageOwned::ScmRights(fd) = cmsg {
            assert_eq!(fd.len(), 1);
            mount_fd = fd[0];
        } else {
            panic!("unexpected cmsg");
        }
    }

    mount_fd
}

#[cfg(target_os = "linux")]
fn direct_mount(mount_point: &Path, options: &[&str]) -> RawFd {
    use nix::sys::stat::SFlag;
    use nix::unistd;

    let _args = FuseMountArgs::parse(options);
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

    let full_path = fs::canonicalize(mount_point).expect("fail to get full path of mount point");
    let cstr_path = full_path
        .to_str()
        .expect("full mount path to string failed");

    let mnt_sb: FileStat;
    let result = stat::stat(&full_path);
    match result {
        Ok(sb) => mnt_sb = sb,
        Err(e) => {
            error!("get mount point stat failed! {}", e);
            return -1;
        }
    }

    let mntpath = CString::new(cstr_path).expect("CString::new failed");
    let fstype = CString::new("fuse").expect("CString::new failed");
    let fsname = CString::new("/dev/fuse").expect("CString::new failed");

    let opts = format!(
        "fd={},rootmode={:o},user_id={},group_id={}",
        dev_fd,
        mnt_sb.st_mode & SFlag::S_IFMT.bits(),
        unistd::getuid().as_raw(),
        unistd::getgid().as_raw()
    );
    let opts = CString::new(&*opts).expect("CString::new failed");
    debug!("direct mount opts: {:?}", &opts);
    unsafe {
        let result = libc::mount(
            fsname.as_ptr(),
            mntpath.as_ptr(),
            fstype.as_ptr(),
            MS_NOSUID | MS_NODEV,
            opts.as_ptr() as *const c_void,
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
            libc::perror(mount_fail_str.as_ptr() as *const i8);

            -1
        }
    }
}

#[cfg(any(target_os = "macos"))]
pub fn umount(mount_point: &Path) -> i32 {
    let mntpnt = mount_point.as_os_str();
    #[allow(unsafe_code)]
    unsafe { libc::unmount(mntpnt as *const _ as *const u8 as *const i8, MNT_FORCE) }
}

#[cfg(any(target_os = "macos"))]
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
    let result = unsafe { fuse_read_random(fd, &mut drandom as *mut _).unwrap() };
    if result == 0 {
        debug!("successfully read drandom={}", drandom);
    } else {
        let ioctl_fail_str = "ioctl read random secret failed!";
        #[allow(unsafe_code)]
        unsafe {
            libc::perror(ioctl_fail_str.as_ptr() as *const i8);
        }
        return -1;
    }

    let full_path =
        fs::canonicalize(mount_point).expect("fail to get full path of mount point, {}");
    let cstr_path = full_path
        .to_str()
        .expect("full mount path to string failed");

    let mntpath = CString::new(cstr_path).expect("CString::new failed");
    let fstype = CString::new("osxfuse").expect("CString::new failed");

    let mut mntpath_slice = [0_u8; MAXPATHLEN];
    copy_slice(mntpath.as_bytes(), &mut mntpath_slice);

    args.set_mntpath(mntpath_slice);
    args.set_random(drandom);
    args.set_rdev(sb.st_rdev as u32);

    // Default mount flags.
    let mut flag = MNT_NOSUID | MNT_NODEV | MNT_NOUSERXATTR | MNT_NOATIME;
    let parsed_flag = parse_mount_flag(options);
    flag |= parsed_flag;

    #[allow(unsafe_code)]
    unsafe {
        let result = libc::mount(
            fstype.as_ptr(),
            mntpath.as_ptr(),
            flag,
            &mut args as *mut _ as *mut c_void,
        );
        if result == 0 {
            debug!("mount {:?} to {:?} successfully!", mntpath, devpath);
            fd
        } else {
            let e = Errno::from_i32(errno::errno());
            debug!("errno={}, {:?}", errno::errno(), e);
            let mount_fail_str = "mount failed!";
            libc::perror(mount_fail_str.as_ptr() as *const i8);

            -1
        }
    }
}
