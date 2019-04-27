//! `read-sym` utility
//!
//! Read symbol information from DLLs, SOs, Dylibs, and o/obj object files.

// Useful list from:
// https://github.com/rust-unofficial/patterns/blob/master/anti_patterns/deny-warnings.md
#![deny(
    missing_debug_implementations,
    missing_copy_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_qualifications,
    unused_results
)]

use std::{
    cmp,
    env,
    fs,
    io::Read,
    str,
};

use failure;
use goblin::Object;

type Res<T> = Result<T, failure::Error>;

fn main() -> Res<()> {
    let dll_filename = env::args().nth(1).expect("Expect filename");

    let mut file = fs::File::open(&dll_filename)?;
    let mut buffer = Vec::new();
    let _bytes_read: usize = file.read_to_end(&mut buffer)?;
    match Object::parse(&buffer)? {
        Object::PE(ref pe) => {
            handle_pe(pe)?;
        },
        Object::Unknown(magic) => {
            eprintln!("Unknown magic number {} (0x{:x})", magic, magic);
            failure::bail!(
                "Unhandled object type: {:?}",
                Object::Unknown(magic)
            );
        },
        obj => {
            failure::bail!("Unhandled object type: {:?}", obj);
        },
    }

    Ok(())
}

fn handle_pe(pe: &goblin::pe::PE) -> Res<()> {
    if !pe.is_lib {
        eprintln!("PE parsed, but is not a library.");
    }

    // Print exports as a table
    {
        #[derive(Copy, Clone, Debug)]
        struct ColWidth {
            offset:    usize,
            name:      usize,
            demangled: usize,
        }

        let mut colw = ColWidth {
            offset:    "Offset".len() + 2,
            name:      "Exported Name".len() + 2,
            demangled: "Demangled".len() + 2,
        };
        for export in &pe.exports {
            if let Some(name) = export.name {
                colw.name = colw.name.max(name.len());
                // TODO: Demangle names and check their length here
            }
        }
        println!(
            "Table format: {} entries: {}, {}, {}",
            pe.exports.len(),
            colw.offset,
            colw.name,
            colw.demangled,
        );

        // Each new column adds 3 to the width.
        // This does not include side padding.
        let table_width = colw.offset + (3 + colw.name) + (3 + colw.demangled);

        println!("+ {x:-<width$} +", x = "", width = table_width,);
        let title = format!(
            "Exports for: {}{}",
            pe.name.unwrap_or("\"\""),
            if pe.is_64 { " (x64)" } else { " (x86)" }
        );
        println!("| {:<width$} | ", title, width = table_width);

        let row_separator = format!(
            "+ {x:-<woffset$} + {x:-<wname$} + {x:-<wdemangled$} +",
            x = "",
            woffset = colw.offset,
            wname = colw.name,
            wdemangled = colw.demangled,
        );

        let mut exports: Vec<&_> = pe.exports.iter().collect();
        exports.sort_by(|e1, e2| {
            // If an export has no name, sort it at the beginning by ordinal
            // Otherwise, sort by name, ignoring case.
            #[cfg_attr(rustfmt, rustfmt::skip)]
            match (e1.name, e2.name) {
                (None,         None)         => e1.offset.cmp(&e2.offset),
                (None,         _)            => cmp::Ordering::Less,
                (_,            None)         => cmp::Ordering::Greater,
                (Some(ref n1), Some(ref n2)) => {
                    let n1 = n1.to_ascii_lowercase();
                    let n2 = n2.to_ascii_lowercase();
                    n1.cmp(&n2)
                },
            }
        });
        // Top of the header
        println!(
            "+ {x:-<woffset$} + {x:-<wname$} + {x:-<wdemangled$} +",
            x = "",
            woffset = colw.offset,
            wname = colw.name,
            wdemangled = colw.demangled,
        );
        // Header with column labels
        println!(
            "| {:^woffset$} | {:^wname$} | {:^wdemangled$} |",
            "Offset",
            "Exported Name",
            "Demangled",
            woffset = colw.offset,
            wname = colw.name,
            wdemangled = colw.demangled,
        );

        // Bottom of header
        println!("{}", row_separator);

        // Each row
        for export in &exports {
            println!(
                "| {:>woffset$} | {:<wname$} | {:<wdemangled$} |",
                format!("0x{:x}", export.offset),
                export.name.unwrap_or_default(),
                "*",
                woffset = colw.offset,
                wname = colw.name,
                wdemangled = colw.demangled,
            );
        }

        // Bottom of the table
        println!("{}", row_separator);
    }

    Ok(())
}
