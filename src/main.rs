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
};

use failure;
use goblin::Object;

type Res<T> = Result<T, failure::Error>;

#[derive(Clone, Debug)]
enum FormatData {
    Pe,
    Elf,
    MachO,
    // MacFat // ??
}

#[derive(Clone, Debug, Default)]
struct Symbol {
    name:       String,
    per_format: Option<FormatData>,
}

#[derive(Clone, Debug, Default)]
struct SharedLibrary {
    name:          Option<String>,
    symbols:       Vec<Symbol>,
    is_lib:        bool,
    is_64:         bool,
    little_endian: bool,
}

fn main() -> Res<()> {
    let mut file =
        fs::File::open(&env::args().nth(1).expect("Expect filename"))?;
    let mut buffer = Vec::new();
    let _bytes_read: usize = file.read_to_end(&mut buffer)?;

    let lib = match Object::parse(&buffer)? {
        Object::PE(ref pe) => handle_pe(pe)?,
        Object::Elf(ref elf) => handle_elf(elf)?,
        Object::Mach(ref mach) => {
            use goblin::mach::Mach;
            match mach {
                Mach::Fat(ref _fat) => {
                    failure::bail!("Fat Binaries not supported yet");
                },
                Mach::Binary(ref macho) => handle_macho(macho)?,
            }
        },
        Object::Unknown(magic) => {
            eprintln!("Unknown magic number {} (0x{:x})", magic, magic);
            failure::bail!(
                "Unhandled object type: {:?}",
                Object::Unknown(magic)
            );
        },
        obj => {
            failure::bail!("Unhandled object type: {:#?}", obj);
        },
    };

    println!("Found {} symbols", lib.symbols.len());

    // if format == table
    {
        display_as_table(&lib);
    }

    Ok(())
}

fn handle_pe(pe: &goblin::pe::PE) -> Res<SharedLibrary> {
    let symbols = pe
        .exports
        .iter()
        .map(|export| {
            Symbol {
                // PE libraries can export functions only by ordinal, so they
                // don't have a name. Don't care, just make it
                // empty instead.
                name:       export.name.unwrap_or_default().to_string(),
                per_format: Some(FormatData::Pe),
                /* per_format: FormatData::Pe {
                 *     ordinal: export.ordinal,
                 *     offset: export.offset,
                 * } */
            }
        })
        .collect();

    Ok(SharedLibrary {
        name: pe.name.map(str::to_string),
        symbols,
        is_lib: pe.is_lib,
        is_64: pe.is_64,
        little_endian: true, // Windows and its binaries always LE (mostly)
    })
}

fn handle_elf(elf: &goblin::elf::Elf) -> Res<SharedLibrary> {
    // Helpful resource:
    // http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-vi.html
    let strings = &elf.dynstrtab;

    let symbols = elf
        .dynsyms
        .iter()
        .map(|dynsym| {
            Symbol {
                name:       strings[dynsym.st_name].to_string(),
                per_format: Some(FormatData::Elf),
                /* per_format: Some(Format::Elf {
                 *      st_info: dynsym.st_info,
                 * }, */
            }
        })
        .collect();

    Ok(SharedLibrary {
        name: elf.soname.map(str::to_string),
        symbols,
        is_lib: elf.is_lib,
        is_64: elf.is_64,
        little_endian: elf.little_endian,
    })
}

fn handle_macho(macho: &goblin::mach::MachO) -> Res<SharedLibrary> {
    let exports = macho.exports()?;
    let symbols = exports
        .iter()
        .map(|export| {
            // use goblin::mach::exports::ExportInfo::*;
            // let export_type = match export.info {
            //     Regular { .. } => {},
            //     // ...
            //     // ...
            // };
            Symbol {
                name:       export.name.clone(),
                per_format: Some(FormatData::MachO),
            }
        })
        .collect();

    Ok(SharedLibrary {
        name: macho.name.map(str::to_string),
        symbols,
        is_lib: true, // ???
        is_64: macho.is_64,
        little_endian: macho.little_endian,
    })
}

fn display_as_table(lib: &SharedLibrary) {
    #[derive(Copy, Clone, Debug)]
    struct ColWidth {
        name:      usize,
        demangled: usize,
    }
    let mut colw = ColWidth {
        name:      "Exported Name".len() + 2,
        demangled: "Demangled".len() + 2,
    };
    for symbol in &lib.symbols {
        colw.name = colw.name.max(symbol.name.len());
    }
    colw.name = colw.name.min(60);
    println!(
        "Table format: {} entries: {}, {}",
        lib.symbols.len(),
        colw.name,
        colw.demangled,
    );

    // Each new column adds 3 to the width.
    // This does not include side padding.
    let table_width = colw.name + (3 + colw.demangled);

    println!("+ {x:-<width$} +", x = "", width = table_width,);
    let title = format!(
        "Symbols for: {} ({} {} Endian)",
        lib.name.as_ref().map(String::as_str).unwrap_or("<unnamed>"),
        if lib.is_64 { "x64" } else { "x86" },
        if lib.little_endian { "Little" } else { "Big" },
    );
    println!("| {:<width$} | ", title, width = table_width);

    let row_separator = format!(
        "+ {x:-<wname$} + {x:-<wdemangled$} +",
        x = "",
        wname = colw.name,
        wdemangled = colw.demangled,
    );

    // Top of the header
    println!(
        "+ {x:-<wname$} + {x:-<wdemangled$} +",
        x = "",
        wname = colw.name,
        wdemangled = colw.demangled,
    );
    // Header with column labels
    println!(
        "| {:^wname$} | {:^wdemangled$} |",
        "Symbol Name",
        "Demangled",
        wname = colw.name,
        wdemangled = colw.demangled,
    );

    // Bottom of header
    println!("{}", row_separator);

    // Each row
    for symbol in &lib.symbols {
        // TODO: Output this
        let _per_format = &symbol.per_format;
        println!(
            "| {:<wname$} | {:<wdemangled$} |",
            symbol.name,
            // TODO: demangle(symbol.name),
            "*",
            wname = colw.name,
            wdemangled = colw.demangled,
        );
    }

    // Bottom of the table
    println!("{}", row_separator);
}
