#![deny(
    // The following are allowed by default lints according to
    // https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html
    anonymous_parameters,
    bare_trait_objects,
    // box_pointers,
    elided_lifetimes_in_paths,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    // unreachable_pub, // This lint conflicts with clippy::redundant_pub_crate
    unsafe_code,
    unstable_features,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    // unused_results,
    variant_size_differences,

    // Treat warnings as errors
    // warnings, TODO: treat all wanings as errors

    clippy::all,
    clippy::restriction,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
)]
#![allow(
    clippy::module_name_repetitions, // repeation of module name in a struct name is not big deal
    clippy::implicit_return, // This is rust style
    clippy::panic,
)]

//! Fuse Low Level
use log::debug;
use std::ffi::OsStr;
use std::path::Path;

use clap::{App, Arg};

/// Fuse module
mod fuse;
/// Memfs module
mod memfs;

use memfs::MemoryFilesystem;

fn main() {
    env_logger::init();

    let matches = App::new("Fuse Low Level")
        .arg(Arg::with_name("mountpoint").required(true).index(1))
        .arg(
            Arg::with_name("options")
                .short("o")
                .value_name("OPTIONS")
                .help("Mount options")
                .multiple(true)
                .takes_value(true)
                .validator(|option| fuse::options_validator(option.as_str()))
                .number_of_values(1),
        )
        .get_matches();

    let mountpoint = OsStr::new(
        matches
            .value_of("mountpoint")
            .unwrap_or_else(|| panic!("Couldn't new mount point {:?}", matches)),
    ); // safe to use unwrap() here, because mountpoint is required
    let options: Vec<&str> = match matches.values_of("options") {
        Some(options) => options.flat_map(|o| o.split(',')).collect(),
        None => Vec::new(),
    };
    debug!("{:?}", &options);
    // TODO: add check function for mutual exclusive options

    let fs = MemoryFilesystem::new(&mountpoint);
    fuse::mount(fs, Path::new(&mountpoint), &options)
        .unwrap_or_else(|_| panic!("Couldn't mount filesystem {:?}", mountpoint));
}

#[cfg(test)]
#[allow(clippy::dbg_macro)]
#[allow(unsafe_code)]
mod test {
    #[test]
    fn test_tmp() {
        fn u64fn(u64ref: u64) {
            dbg!(u64ref);
        }
        let num: u64 = 100;
        let u64ref = &num;
        u64fn(*u64ref);
    }

    #[test]
    fn test_skip() {
        let v = vec![1, 2, 3, 4];
        for e in v.iter().skip(5) {
            dbg!(e);
        }
    }

    #[test]
    fn test_vec() {
        let mut v = vec![1, 2, 3, 4, 5];
        let cap = v.capacity();
        v.truncate(3);
        assert_eq!(v.len(), 3);
        assert_eq!(v.capacity(), cap);

        let mut v2 = vec![0; 3];
        v.append(&mut v2);
        assert_eq!(v.len(), 6);
        assert!(v2.is_empty());
    }

    #[test]
    fn test_map_swap() {
        use std::collections::{btree_map::Entry, BTreeMap};
        use std::ptr;
        use std::sync::RwLock;
        let mut map = BTreeMap::<String, Vec<u8>>::new();
        let (k1, k2, k3, k4) = ("A", "B", "C", "D");
        map.insert(k1.to_string(), vec![1]);
        map.insert(k2.to_string(), vec![2, 2]);
        map.insert(k3.to_string(), vec![3, 3]);
        map.insert(k4.to_string(), vec![4, 4, 4, 4]);

        let lock = RwLock::new(map);
        let mut map = lock.write().unwrap_or_else(|_| panic!());

        let e1: *mut _ = map.get_mut(k1).unwrap_or_else(|| panic!());
        let e2: *mut _ = map.get_mut(k2).unwrap_or_else(|| panic!());
        //std::mem::swap(e1, e2);
        unsafe {
            ptr::swap(e1, e2);
        }
        dbg!(&map.get(k1));
        dbg!(&map.get(k2));

        let e3 = map.get_mut(k3).unwrap_or_else(|| panic!());
        e3.push(3);
        dbg!(&map.get(k3));

        let k5 = "E";
        let e = map.entry(k5.to_string());
        if let Entry::Vacant(v) = e {
            v.insert(vec![5, 5, 5, 5, 5]);
        }
        dbg!(&map.get(k5));
    }
    #[test]
    fn test_map_entry() {
        use std::collections::BTreeMap;
        use std::mem;
        let mut m1 = BTreeMap::<String, Vec<u8>>::new();
        let mut m2 = BTreeMap::<String, Vec<u8>>::new();
        let (k1, k2, k3, k4, k5) = ("A", "B", "C", "D", "E");
        m1.insert(k1.to_string(), vec![1]);
        m1.insert(k2.to_string(), vec![2, 2]);
        m2.insert(k3.to_string(), vec![3, 3, 3]);
        m2.insert(k4.to_string(), vec![4, 4, 4, 4]);

        let e1 = &mut m1.entry(k1.to_string());
        let e2 = &mut m2.entry(k5.to_string());
        mem::swap(e1, e2);

        dbg!(m1);
        dbg!(m2);
    }
}
