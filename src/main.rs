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
    env,
    fs,
    io::{
        self,
        Read,
        Write,
    },
};

use failure;
use goblin::Object;

type Res<T> = Result<T, failure::Error>;

/// The format that was found
#[derive(Copy, Clone, Debug)]
enum BinaryKind {
    Pe,
    Elf,
    MachO,
    // MacFat // ??
}

/// Extra data that's unique to a format
#[derive(Clone, Debug)]
enum BinaryKindExtra {
    Pe { offset: usize, rva: usize },
    Elf { sym: goblin::elf::sym::Sym },
    MachO { offset: u64, flags: u64 },
    // Others...?
}

#[derive(Clone, Debug)]
struct Symbol {
    name:  String,
    extra: BinaryKindExtra,
}

#[derive(Clone, Debug)]
struct SharedLibrary {
    name:          Option<String>,
    kind:          BinaryKind,
    symbols:       Vec<Symbol>,
    is_lib:        bool,
    is_64:         bool,
    little_endian: bool,
}

fn main() -> Res<()> {

    for arg in env::args().skip(1) {

        let mut file =
            fs::File::open(&arg)?;
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

        // if format == table
        {
            match display_as_table(&lib) {
                // No issues print table
                Ok(()) => {},
                // We lost our connection to stdout.
                // The most common cause of this - someone piped us into
                // `head` or `less` and quit before we wrote everything.
                // This is fine, and we should not complain about it.
                Err(ref err) if err.kind() == io::ErrorKind::BrokenPipe => {},
                // Something else failed - UNACCEPTABLE. COMPLAIN LOUDLY.
                Err(err) => {
                    Err(err)?;
                },
            }
        }
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
                name:  export.name.unwrap_or_default().to_string(),
                extra: BinaryKindExtra::Pe {
                    offset: export.offset,
                    rva:    export.rva,
                },
            }
        })
        .collect();

    Ok(SharedLibrary {
        name: pe.name.map(str::to_string),
        kind: BinaryKind::Pe,
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
                name:  strings[dynsym.st_name].to_string(),
                extra: BinaryKindExtra::Elf { sym: dynsym },
            }
        })
        .collect();

    Ok(SharedLibrary {
        name: elf.soname.map(str::to_string),
        kind: BinaryKind::Elf,
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
            use goblin::mach::exports::ExportInfo::*;
            let flags = match export.info {
                Regular { flags, .. } => flags,
                Reexport { flags, .. } => flags,
                Stub { flags, .. } => flags,
            };

            Symbol {
                name:  export.name.clone(),
                extra: BinaryKindExtra::MachO {
                    offset: export.offset,
                    flags,
                },
            }
        })
        .collect();

    Ok(SharedLibrary {
        name: macho.name.map(str::to_string),
        kind: BinaryKind::MachO,
        symbols,
        is_lib: true, // ???
        is_64: macho.is_64,
        little_endian: macho.little_endian,
    })
}

fn demangle(name: &str) -> String {
    let flags = msvc_demangler::DemangleFlags::llvm();

    if let Ok(sym) = msvc_demangler::demangle(name, flags) {
        sym
    } else {
        name.to_string()
    }
}

/// Formats a table of exported symbols.
///
/// ### Example
/// The following is a trimmed example from SDL on Windows
/// ```
///     + ------------------------------- +
///     | SDL2.dll (x64 Little Endian)    |
///     + ------------------- + --------- +
///     |        Name         | Demangled |
///     + ------------------- + --------- +
///     | SDL_AddEventWatch   | *         |
///     | SDL_AddHintCallback | *         |
///     | SDL_AddTimer        | *         |
///     | SDL_AllocFormat     | *         |
///     | SDL_AllocPalette    | *         |
///     | SDL_AllocRW         | *         |
///     | SDL_AtomicAdd       | *         |
///     | SDL_AtomicCAS       | *         |
///     | SDL_AtomicCASPtr    | *         |
///     | SDL_AtomicGet       | *         |
///     | SDL_AtomicGetPtr    | *         |
///     | SDL_AtomicLock      | *         |
///     | SDL_AtomicSet       | *         |
///     | SDL_AtomicSetPtr    | *         |
///     | SDL_AtomicTryLock   | *         |
///     + ------------------- + --------- +
///     | Found 15 exported symbols       |
///     + ------------------------------- +
/// ```
fn display_as_table(lib: &SharedLibrary) -> io::Result<()> {
    let handle = io::stdout();
    let mut stdout = handle.lock();

    // ==== FORMATTING =========================================================
    // Store width of each hard-coded column
    #[derive(Copy, Clone, Debug)]
    struct ColWidth {
        name:      usize,
        demangled: usize,
    }

    const COLUMN_SYM_NAME: &str = "Name";
    const COLUMN_DEMANGLED: &str = "Demangled";

    let mut colw = ColWidth {
        name:      COLUMN_SYM_NAME.len(),
        demangled: COLUMN_DEMANGLED.len(),
    };

    // Size the columns from the data
    for symbol in &lib.symbols {
        colw.name = colw.name.max(symbol.name.len());
        let demangled_name =demangle(&symbol.name);
        colw.demangled = colw.demangled.max(demangled_name.len());
    }

    // If the symbol names are crazy, or we hit a bug, limit the name length.
    colw.name = colw.name.min(200);

    // Each new column adds 3 to the width.
    // This does not include side padding.
    let table_width = colw.name + (3 + colw.demangled);

    // Title - goes in a separate cell at the top of the table.
    let title = format!(
        "{} ({} {} Endian)",
        lib.name.as_ref().map(String::as_str).unwrap_or("<unnamed>"),
        if lib.is_64 { "x64" } else { "x86" },
        if lib.little_endian { "Little" } else { "Big" },
    );

    // Footer - goes in a separate cell at the bottom of the table.
    let footer = format!("Found {} exported symbols", lib.symbols.len());

    // Separates groups of rows/cells with mid junctions
    let section_separator = format!(
        "+ {x:-<wname$} + {x:-<wdemangled$} +",
        x = "",
        wname = colw.name,
        wdemangled = colw.demangled,
    );

    // ==== TABLE HEADER =======================================================
    {
        // Top line, no mid-junctions
        writeln!(stdout, "+ {x:-<width$} +", x = "", width = table_width,)?;
        // Title
        writeln!(stdout, "| {:<width$} | ", title, width = table_width)?;

        // Title and labels separator
        writeln!(
            stdout,
            "+ {x:-<wname$} + {x:-<wdemangled$} +",
            x = "",
            wname = colw.name,
            wdemangled = colw.demangled,
        )?;
        // Labels
        writeln!(
            stdout,
            "| {:^wname$} | {:^wdemangled$} |",
            COLUMN_SYM_NAME,
            COLUMN_DEMANGLED,
            wname = colw.name,
            wdemangled = colw.demangled,
        )?;

        // Bottom line of header
        writeln!(stdout, "{}", section_separator)?;
    }

    // ==== TABLE ROWS =========================================================
    {
        for symbol in &lib.symbols {
            writeln!(
                stdout,
                "| {name:<wname$} | {demangled:<wdemangled$} |",
                name=symbol.name,
                demangled=demangle(&symbol.name),
                wname = colw.name,
                wdemangled = colw.demangled,
            )?;
        }
    }

    // ==== TABLE FOOTER ======================================================
    {
        // Bottom line, mid junctions
        writeln!(stdout, "{}", section_separator)?;

        // Footer
        writeln!(stdout, "| {:<width$} | ", footer, width = table_width)?;
        // Bottom line, no mid-junctions
        writeln!(stdout, "+ {x:-<width$} +", x = "", width = table_width,)?;
    }

    // Table is done, drop the lock on stdout on return
    Ok(())
}
